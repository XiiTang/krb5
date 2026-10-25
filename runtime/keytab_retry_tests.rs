//! A failed keytab acquisition is retried against the primary KDC only when a
//! replica answered (gic_keytab.c, as get_in_tkt.c's password path does).
use super::*;
use std::{cell::RefCell, rc::Rc};

/// krb5's error table base (krb5_err.et): a KDC error code `n` is returned
/// as `ERROR_TABLE_BASE + n`.
const ERROR_TABLE_BASE: i32 = -1_765_328_384;
const KDC_ERR_POLICY: i32 = 12;
const KDC_ERR_CLIENT_REVOKED: i32 = 18;
const KRB5_KDC_UNREACH: i32 = ERROR_TABLE_BASE + 156;

fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match content.len() {
        n if n < 0x80 => out.push(n as u8),
        n if n < 0x100 => out.extend([0x81, n as u8]),
        n => out.extend([0x82, (n >> 8) as u8, n as u8]),
    }
    out.extend_from_slice(content);
    out
}
fn integer(value: u8) -> Vec<u8> {
    der(0x02, &[value])
}
fn explicit(number: u8, content: Vec<u8>) -> Vec<u8> {
    der(0xa0 | number, &content)
}

/// A KRB-ERROR (RFC 4120 5.9.1) from the KDC of realm TEST.
fn krb_error(code: i32) -> Vec<u8> {
    let sname = der(
        0x30,
        &[
            explicit(0, integer(2)),
            explicit(
                1,
                der(0x30, &[der(0x1b, b"krbtgt"), der(0x1b, b"TEST")].concat()),
            ),
        ]
        .concat(),
    );
    let fields = [
        explicit(0, integer(5)),
        explicit(1, integer(30)),
        explicit(4, der(0x18, b"20260101000000Z")),
        explicit(5, integer(0)),
        explicit(6, integer(code as u8)),
        explicit(9, der(0x1b, b"TEST")),
        explicit(10, sname),
    ]
    .concat();
    der(0x7e, &der(0x30, &fields))
}

/// A version 2 keytab (keytab.txt) with one aes256-cts key for user@TEST.
fn keytab() -> Vec<u8> {
    let mut entry = Vec::new();
    entry.extend(1u16.to_be_bytes());
    for part in [&b"TEST"[..], b"user"] {
        entry.extend((part.len() as u16).to_be_bytes());
        entry.extend(part);
    }
    entry.extend(1u32.to_be_bytes()); // KRB5_NT_PRINCIPAL
    entry.extend(0u32.to_be_bytes());
    entry.push(1);
    entry.extend(18u16.to_be_bytes());
    entry.extend(32u16.to_be_bytes());
    entry.extend([0x42; 32]);
    entry.extend(1u32.to_be_bytes());
    let mut out = vec![5, 2];
    out.extend((entry.len() as i32).to_be_bytes());
    out.extend(entry);
    out
}

/// Acquire with the keytab through a scripted exclusive transport that
/// answers each request with the next reply; return the result and the number
/// of requests the transport saw.
fn acquire(replies: Vec<std::result::Result<Vec<u8>, ()>>) -> (Result<Credential>, usize) {
    let requests = Rc::new(RefCell::new(0usize));
    let seen = requests.clone();
    let mut replies = replies.into_iter();
    let keytab = keytab();
    let result = Credential::new(
        "user@TEST",
        "TEST",
        Source::Keytab {
            bytes: &keytab,
            initial_ticket_lifetime_seconds: 600,
        },
        false,
        Box::new(move |realm, request| {
            assert_eq!(realm, b"TEST");
            assert!(!request.is_empty());
            *seen.borrow_mut() += 1;
            replies.next().unwrap_or(Err(())).map(Zeroizing::new)
        }),
    );
    let count = *requests.borrow();
    (result, count)
}

#[test]
fn a_final_keytab_refusal_makes_one_exchange_and_keeps_its_error() {
    // A second exchange would answer with a different error and replace the
    // first: the exclusive transport records no replica, so none is made.
    let (result, requests) = acquire(vec![
        Ok(krb_error(KDC_ERR_CLIENT_REVOKED)),
        Ok(krb_error(KDC_ERR_POLICY)),
    ]);
    assert!(matches!(
        result,
        Err(Error::Native(code)) if code == ERROR_TABLE_BASE + KDC_ERR_CLIENT_REVOKED
    ));
    assert_eq!(requests, 1);
}

#[test]
fn an_unavailable_kdc_ends_keytab_acquisition_after_one_attempt() {
    let (result, requests) = acquire(vec![Err(()), Ok(krb_error(KDC_ERR_POLICY))]);
    assert!(matches!(result, Err(Error::Native(KRB5_KDC_UNREACH))));
    assert_eq!(requests, 1);
}

/// The replica decision needs krb5's own KDC location and I/O, which a
/// runtime context never performs: these contexts are built from an
/// in-memory profile naming loopback UDP KDCs.
#[cfg(unix)]
mod located {
    use super::*;
    use std::{
        collections::BTreeSet,
        net::UdpSocket,
        sync::{Arc, Mutex},
        thread::JoinHandle,
    };
    unsafe extern "C" {
        fn profile_init(files: *const *const c_char, profile: *mut *mut c_void) -> i64;
        fn profile_add_relation(
            profile: *mut c_void,
            names: *const *const c_char,
            value: *const c_char,
        ) -> i64;
        fn profile_release(profile: *mut c_void);
        fn krb5_init_context_profile(
            profile: *mut c_void,
            flags: i32,
            context: *mut *mut c_void,
        ) -> i32;
        fn krb5_free_context(context: *mut c_void);
        fn krb5_parse_name(
            context: *mut c_void,
            name: *const c_char,
            principal: *mut *mut c_void,
        ) -> i32;
        fn krb5_free_principal(context: *mut c_void, principal: *mut c_void);
        fn krb5_kt_import_memory(
            context: *mut c_void,
            name: *const c_char,
            data: *const c_void,
            len: usize,
            keytab: *mut *mut c_void,
        ) -> i32;
        fn krb5_kt_close(context: *mut c_void, keytab: *mut c_void) -> i32;
        fn krb5_get_init_creds_keytab(
            context: *mut c_void,
            creds: *mut c_void,
            client: *mut c_void,
            keytab: *mut c_void,
            start_time: i32,
            in_tkt_service: *const c_char,
            options: *mut c_void,
        ) -> i32;
        fn krb5_free_cred_contents(context: *mut c_void, creds: *mut c_void);
        fn krb5_set_kdc_recv_hook(context: *mut c_void, hook: RecvHook, data: *mut c_void);
    }
    #[repr(C)]
    struct Data {
        magic: i32,
        length: u32,
        data: *const c_char,
    }
    /// krb5_post_recv_fn (krb5.hin).
    type RecvHook = unsafe extern "C" fn(
        context: *mut c_void,
        data: *mut c_void,
        code: i32,
        realm: *const Data,
        message: *const Data,
        reply: *const Data,
        new_reply: *mut *mut Data,
    ) -> i32;
    /// The receive hook's state: a reply equal to `unreachable` is reported
    /// as KRB5_KDC_UNREACH, as if that KDC had not answered; `replaced`
    /// counts those replies.
    struct Unreachable {
        unreachable: Vec<u8>,
        replaced: usize,
    }
    unsafe extern "C" fn unreachable_hook(
        _context: *mut c_void,
        data: *mut c_void,
        code: i32,
        _realm: *const Data,
        _message: *const Data,
        reply: *const Data,
        _new_reply: *mut *mut Data,
    ) -> i32 {
        // SAFETY: data is the Unreachable acquire_located passed, live for
        // the acquisition; reply is the received reply when code is 0.
        unsafe {
            let state = &mut *data.cast::<Unreachable>();
            if code == 0 && !reply.is_null() {
                let reply = &*reply;
                let bytes =
                    std::slice::from_raw_parts(reply.data.cast::<u8>(), reply.length as usize);
                if bytes == state.unreachable.as_slice() {
                    state.replaced += 1;
                    return KRB5_KDC_UNREACH;
                }
            }
            code
        }
    }

    /// A loopback UDP KDC answering every request with one reply. It counts
    /// exchanges: a retransmitted datagram is the same exchange, and a new
    /// AS-REQ carries a new nonce.
    struct Kdc {
        port: u16,
        exchanges: Arc<Mutex<BTreeSet<Vec<u8>>>>,
        thread: Option<JoinHandle<()>>,
    }
    impl Kdc {
        fn answering(reply: Vec<u8>) -> Self {
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            let port = socket.local_addr().unwrap().port();
            let exchanges: Arc<Mutex<BTreeSet<Vec<u8>>>> = Default::default();
            let seen = exchanges.clone();
            let thread = std::thread::spawn(move || {
                let mut buffer = vec![0; 65536];
                loop {
                    let (len, from) = socket.recv_from(&mut buffer).unwrap();
                    // Drop's empty datagram ends the fixture.
                    if len == 0 {
                        break;
                    }
                    seen.lock().unwrap().insert(buffer[..len].to_vec());
                    socket.send_to(&reply, from).unwrap();
                }
            });
            Self {
                port,
                exchanges,
                thread: Some(thread),
            }
        }
        fn exchanges(&self) -> usize {
            self.exchanges.lock().unwrap().len()
        }
    }
    impl Drop for Kdc {
        fn drop(&mut self) {
            let waker = UdpSocket::bind("127.0.0.1:0").unwrap();
            waker.send_to(&[], ("127.0.0.1", self.port)).unwrap();
            self.thread.take().unwrap().join().unwrap();
        }
    }
    /// Acquire user@TEST with the keytab from realm TEST whose KDCs are
    /// `kdc` and whose primary is `primary`, with `hook` as the context's
    /// receive hook.
    fn acquire_located(name: &str, kdc: u16, primary: u16, hook: Option<&mut Unreachable>) -> i32 {
        let relations = [
            (["libdefaults", "default_realm"], "TEST".to_owned()),
            (["libdefaults", "dns_lookup_kdc"], "false".to_owned()),
            (["libdefaults", "dns_lookup_realm"], "false".to_owned()),
            (["libdefaults", "rdns"], "false".to_owned()),
        ];
        let realm = [
            ("kdc", format!("127.0.0.1:{kdc}")),
            ("primary_kdc", format!("127.0.0.1:{primary}")),
        ];
        let keytab_bytes = keytab();
        unsafe {
            let mut profile = ptr::null_mut();
            assert_eq!(profile_init(ptr::null(), &mut profile), 0);
            let add = |names: &[&str], value: &str| {
                let names: Vec<CString> = names.iter().map(|n| string(n).unwrap()).collect();
                let mut pointers: Vec<*const c_char> = names.iter().map(|n| n.as_ptr()).collect();
                pointers.push(ptr::null());
                let value = string(value).unwrap();
                assert_eq!(
                    profile_add_relation(profile, pointers.as_ptr(), value.as_ptr()),
                    0
                );
            };
            for (names, value) in &relations {
                add(names, value);
            }
            for (key, value) in &realm {
                add(&["realms", "TEST", key], value);
            }
            let mut context = ptr::null_mut();
            assert_eq!(krb5_init_context_profile(profile, 1, &mut context), 0);
            profile_release(profile);
            if let Some(hook) = hook {
                krb5_set_kdc_recv_hook(
                    context,
                    unreachable_hook,
                    (hook as *mut Unreachable).cast(),
                );
            }
            let mut client = ptr::null_mut();
            let principal = string("user@TEST").unwrap();
            assert_eq!(krb5_parse_name(context, principal.as_ptr(), &mut client), 0);
            let mut keytab = ptr::null_mut();
            let name = string(&format!("MEMORY:{name}")).unwrap();
            assert_eq!(
                krb5_kt_import_memory(
                    context,
                    name.as_ptr(),
                    keytab_bytes.as_ptr().cast(),
                    keytab_bytes.len(),
                    &mut keytab,
                ),
                0
            );
            // Opaque storage larger than krb5_creds; zero is its empty state.
            let mut creds = [0u64; 32];
            let creds = creds.as_mut_ptr().cast();
            let code = krb5_get_init_creds_keytab(
                context,
                creds,
                client,
                keytab,
                0,
                ptr::null(),
                ptr::null_mut(),
            );
            krb5_free_cred_contents(context, creds);
            krb5_kt_close(context, keytab);
            krb5_free_principal(context, client);
            krb5_free_context(context);
            code
        }
    }

    #[test]
    fn a_refusal_from_the_primary_is_not_retried() {
        let primary = Kdc::answering(krb_error(KDC_ERR_CLIENT_REVOKED));
        let code = acquire_located("retry-primary", primary.port, primary.port, None);
        assert_eq!(code, ERROR_TABLE_BASE + KDC_ERR_CLIENT_REVOKED);
        assert_eq!(primary.exchanges(), 1);
    }

    #[test]
    fn a_refusal_from_a_replica_is_retried_once_with_the_primary() {
        let replica = Kdc::answering(krb_error(KDC_ERR_POLICY));
        let primary = Kdc::answering(krb_error(KDC_ERR_CLIENT_REVOKED));
        let code = acquire_located("retry-replica", replica.port, primary.port, None);
        assert_eq!(code, ERROR_TABLE_BASE + KDC_ERR_CLIENT_REVOKED);
        assert_eq!((replica.exchanges(), primary.exchanges()), (1, 1));
    }

    #[test]
    fn an_unreachable_primary_keeps_the_replica_refusal() {
        // Both KDCs are owned; the receive hook turns the primary's answer
        // into KRB5_KDC_UNREACH.
        let replica = Kdc::answering(krb_error(KDC_ERR_POLICY));
        let primary = Kdc::answering(krb_error(KDC_ERR_CLIENT_REVOKED));
        let mut hook = Unreachable {
            unreachable: krb_error(KDC_ERR_CLIENT_REVOKED),
            replaced: 0,
        };
        let code = acquire_located(
            "retry-unreachable",
            replica.port,
            primary.port,
            Some(&mut hook),
        );
        assert_eq!(code, ERROR_TABLE_BASE + KDC_ERR_POLICY);
        assert_eq!((replica.exchanges(), primary.exchanges()), (1, 1));
        assert_eq!(hook.replaced, 1);
    }
}
