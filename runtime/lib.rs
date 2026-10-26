//! Execution-private MIT Kerberos primitives. The caller owns all KDC I/O.
//! Values are intentionally !Send and !Sync: one joined worker owns a credential
//! and its exchanges. No API reads a cache/keytab path or changes environment.
use std::{
    cell::RefCell,
    ffi::{CString, c_char, c_int, c_void},
    ptr::{self, NonNull},
    rc::Rc,
};
use zeroize::Zeroizing;
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidInput,
    InvalidState,
    PeerRejected(ErrorReply),
    PeerOffer(OfferFault),
    Credential(CredentialInput),
    Configuration(ConfigurationFault),
    Native(i32),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorReply {
    code: i32,
    text: Box<[u8]>,
    exchange: ReplyExchange,
}
impl ErrorReply {
    pub fn code(&self) -> i32 {
        self.code
    }
    pub fn text(&self) -> &[u8] {
        &self.text
    }
    pub fn exchange(&self) -> &ReplyExchange {
        &self.exchange
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplyExchange {
    As { realm: Box<[u8]> },
    Tgs { realm: Box<[u8]> },
    Ap,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfferFault {
    Length,
    Unoffered(SecurityLayer),
    Size,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialInput {
    Principal,
    Ccache,
    Keytab,
    Password,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigurationFault {
    LifetimeRange,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "Kerberos input is invalid",
            Self::InvalidState => "the Kerberos exchange is not in a state for this operation",
            Self::PeerRejected(_) => "the peer rejected the Kerberos exchange",
            Self::PeerOffer(_) => "the peer's security-layer offer is unusable",
            Self::Credential(_) => "a Kerberos credential input is invalid",
            Self::Configuration(_) => "a Kerberos configuration value is out of range",
            Self::Native(code) => {
                return write!(f, "Kerberos operation failed with native status {code}");
            }
        })
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;
pub type Transport = Box<dyn FnMut(&[u8], &[u8]) -> std::result::Result<Zeroizing<Vec<u8>>, ()>>;
#[repr(C)]
struct Buffer {
    data: *mut c_void,
    len: usize,
}
impl Default for Buffer {
    fn default() -> Self {
        Self {
            data: ptr::null_mut(),
            len: 0,
        }
    }
}
impl Buffer {
    fn take(&self) -> Zeroizing<Vec<u8>> {
        if self.len == 0 {
            Zeroizing::new(Vec::new())
        } else {
            // SAFETY: the successful native call returned its owned allocation.
            Zeroizing::new(
                unsafe { std::slice::from_raw_parts(self.data.cast::<u8>(), self.len) }.to_vec(),
            )
        }
    }
}
impl Drop for Buffer {
    fn drop(&mut self) {
        unsafe { imk_buffer_free(self) }
    }
}
#[repr(C)]
#[derive(Default)]
struct Status {
    kind: i32,
    input: i32,
}
struct Reply(NonNull<c_void>);
impl Reply {
    fn new() -> Result<Self> {
        let mut out = ptr::null_mut();
        let code = unsafe { imk_reply_new(&mut out) };
        if code != 0 {
            return Err(Error::Native(code));
        }
        Ok(Self(NonNull::new(out).ok_or(Error::InvalidInput)?))
    }
}
impl Drop for Reply {
    fn drop(&mut self) {
        unsafe { imk_reply_free(self.0.as_ptr()) }
    }
}
unsafe extern "C" {
    fn imk_reply_new(out: *mut *mut c_void) -> i32;
    fn imk_reply_free(reply: *mut c_void);
    fn imk_reply_get(
        reply: *const c_void,
        exchange: *mut i32,
        error: *mut i32,
        text: *mut *const c_void,
        len: *mut usize,
    ) -> c_int;
    fn imk_alloc(len: usize) -> *mut c_void;
    fn imk_buffer_free(buffer: *mut Buffer);
    fn imk_credential_new(
        principal: *const c_char,
        realm: *const c_char,
        data: *const c_void,
        len: usize,
        source: c_int,
        lifetime: u32,
        forwardable: c_int,
        callback: unsafe extern "C" fn(
            *mut c_void,
            *const c_void,
            usize,
            *const c_void,
            usize,
            *mut *mut c_void,
            *mut usize,
        ) -> c_int,
        context: *mut c_void,
        reply: *mut c_void,
        out: *mut *mut c_void,
        status: *mut Status,
    ) -> i32;
    fn imk_credential_free(credential: *mut c_void);
    fn imk_exchange_new(
        credential: *mut c_void,
        target: *const c_char,
        mechanism: c_int,
        delegate: c_int,
        out: *mut *mut c_void,
        status: *mut Status,
    ) -> i32;
    fn imk_exchange_free(exchange: *mut c_void);
    fn imk_step(
        exchange: *mut c_void,
        data: *const c_void,
        len: usize,
        out: *mut Buffer,
        complete: *mut c_int,
        status: *mut Status,
    ) -> i32;
    fn imk_wrap(
        exchange: *mut c_void,
        confidential: c_int,
        data: *const c_void,
        len: usize,
        out: *mut Buffer,
        status: *mut Status,
    ) -> i32;
    fn imk_unwrap(
        exchange: *mut c_void,
        confidential: c_int,
        data: *const c_void,
        len: usize,
        out: *mut Buffer,
        status: *mut Status,
    ) -> i32;
    fn imk_mic(
        exchange: *mut c_void,
        data: *const c_void,
        len: usize,
        out: *mut Buffer,
        status: *mut Status,
    ) -> i32;
    fn imk_wrap_limit(
        exchange: *mut c_void,
        confidential: c_int,
        output: u32,
        input: *mut u32,
        status: *mut Status,
    ) -> i32;
}
struct Callback {
    transport: RefCell<Transport>,
    last_realm: RefCell<Option<Box<[u8]>>>,
}
unsafe extern "C" fn transport(
    data: *mut c_void,
    realm: *const c_void,
    realm_len: usize,
    request: *const c_void,
    request_len: usize,
    out: *mut *mut c_void,
    len: *mut usize,
) -> c_int {
    // SAFETY: native calls are serialized on the owning thread and the Box is
    // retained until native credential destruction. Never unwind across C.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        let callback = &*data.cast::<Callback>();
        let realm = std::slice::from_raw_parts(realm.cast::<u8>(), realm_len);
        let request = std::slice::from_raw_parts(request.cast::<u8>(), request_len);
        *callback.last_realm.borrow_mut() = Some(realm.into());
        let response = (*callback.transport.borrow_mut())(realm, request)?;
        if response.is_empty() || response.len() > u32::MAX as usize {
            return Err(());
        }
        let allocation = imk_alloc(response.len());
        if allocation.is_null() {
            return Err(());
        }
        ptr::copy_nonoverlapping(response.as_ptr(), allocation.cast::<u8>(), response.len());
        *out = allocation;
        *len = response.len();
        Ok(())
    }));
    if matches!(result, Ok(Ok(()))) { 0 } else { 1 }
}
// The only native-result conversion and the only ErrorReply constructor.
fn check(code: i32, status: &Status, reply: &Reply, callback: &Callback) -> Result<()> {
    if code == 0 {
        return Ok(());
    }
    let error = match status.kind {
        2 => match status.input {
            1 => Error::Credential(CredentialInput::Principal),
            2 => Error::Credential(CredentialInput::Ccache),
            3 => Error::Credential(CredentialInput::Keytab),
            4 => Error::Credential(CredentialInput::Password),
            _ => Error::Native(code),
        },
        3 => Error::Configuration(ConfigurationFault::LifetimeRange),
        4 => Error::InvalidState,
        0 => {
            let (mut exchange, mut error, mut len) = (0, 0, 0);
            let mut text = ptr::null();
            if unsafe {
                imk_reply_get(
                    reply.0.as_ptr(),
                    &mut exchange,
                    &mut error,
                    &mut text,
                    &mut len,
                )
            } == 0
            {
                return Err(Error::Native(code));
            }
            let realm = || callback.last_realm.borrow().clone();
            let exchange = match exchange {
                1 => realm().map(|realm| ReplyExchange::As { realm }),
                2 => realm().map(|realm| ReplyExchange::Tgs { realm }),
                3 => Some(ReplyExchange::Ap),
                _ => None,
            };
            let Some(exchange) = exchange else {
                return Err(Error::Native(code));
            };
            // An omitted e-text has a NULL pointer. Never read it when empty.
            let text = if len == 0 {
                Box::<[u8]>::default()
            } else {
                // SAFETY: the selected slot owns these bytes until clear/free.
                unsafe { std::slice::from_raw_parts(text.cast::<u8>(), len) }.into()
            };
            Error::PeerRejected(ErrorReply {
                code: error,
                text,
                exchange,
            })
        }
        _ => Error::Native(code),
    };
    Err(error)
}
fn string(s: &str) -> Result<CString> {
    CString::new(s).map_err(|_| Error::InvalidInput)
}
struct Inner {
    native: NonNull<c_void>,
    reply: Reply,
    _callback: Box<Callback>,
}
impl Drop for Inner {
    fn drop(&mut self) {
        unsafe { imk_credential_free(self.native.as_ptr()) }
    }
}
#[derive(Clone)]
pub struct Credential(Rc<Inner>);
pub enum Source<'a> {
    Ccache(&'a [u8]),
    Keytab {
        bytes: &'a [u8],
        initial_ticket_lifetime_seconds: u32,
    },
    /// The principal's password, from which the initial ticket is requested.
    /// No prompter is offered: an expired password fails.
    Password {
        password: &'a [u8],
        initial_ticket_lifetime_seconds: u32,
    },
}
/// The GSS mechanism an exchange speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mechanism {
    /// Kerberos V5 (RFC 4121), protecting the session it opens.
    Kerberos,
    /// SPNEGO (RFC 4178) negotiating Kerberos, as HTTP Negotiate (RFC 4559)
    /// carries it.
    Spnego,
}
impl Credential {
    /// `forwardable` asks the KDC for a ticket that can be delegated; it
    /// applies to tickets requested here, not to an imported cache.
    pub fn new(
        principal: &str,
        realm: &str,
        source: Source<'_>,
        forwardable: bool,
        transport_fn: Transport,
    ) -> Result<Self> {
        let principal = string(principal)?;
        let realm = string(realm)?;
        let (bytes, source, lifetime) = match source {
            Source::Ccache(b) => (b, 0, 0),
            Source::Keytab {
                bytes,
                initial_ticket_lifetime_seconds,
            } => (bytes, 1, initial_ticket_lifetime_seconds),
            Source::Password {
                password,
                initial_ticket_lifetime_seconds,
            } => (password, 2, initial_ticket_lifetime_seconds),
        };
        let reply = Reply::new()?;
        let callback = Box::new(Callback {
            transport: RefCell::new(transport_fn),
            last_realm: RefCell::new(None),
        });
        let mut out = ptr::null_mut();
        let mut status = Status::default();
        check(
            unsafe {
                imk_credential_new(
                    principal.as_ptr(),
                    realm.as_ptr(),
                    bytes.as_ptr().cast(),
                    bytes.len(),
                    source,
                    lifetime,
                    forwardable.into(),
                    transport,
                    (&*callback as *const Callback).cast_mut().cast(),
                    reply.0.as_ptr(),
                    &mut out,
                    &mut status,
                )
            },
            &status,
            &reply,
            &callback,
        )?;
        Ok(Self(Rc::new(Inner {
            native: NonNull::new(out).ok_or(Error::InvalidInput)?,
            reply,
            _callback: callback,
        })))
    }
    /// A Kerberos exchange with `target`, delegating nothing.
    pub fn exchange(&self, target: &str) -> Result<Exchange> {
        self.exchange_with(target, Mechanism::Kerberos, false)
    }
    /// An exchange with the principal `target`. With `delegate` the
    /// credential is forwarded to it, and an exchange that completes without
    /// delegating fails.
    pub fn exchange_with(
        &self,
        target: &str,
        mechanism: Mechanism,
        delegate: bool,
    ) -> Result<Exchange> {
        let target = string(target)?;
        let mut out = ptr::null_mut();
        let mut status = Status::default();
        check(
            unsafe {
                imk_exchange_new(
                    self.0.native.as_ptr(),
                    target.as_ptr(),
                    match mechanism {
                        Mechanism::Kerberos => 0,
                        Mechanism::Spnego => 1,
                    },
                    delegate.into(),
                    &mut out,
                    &mut status,
                )
            },
            &status,
            &self.0.reply,
            &self.0._callback,
        )?;
        Ok(Exchange {
            native: NonNull::new(out).ok_or(Error::InvalidInput)?,
            _credential: self.clone(),
        })
    }
}
pub struct Exchange {
    native: NonNull<c_void>,
    _credential: Credential,
}
impl Drop for Exchange {
    fn drop(&mut self) {
        unsafe { imk_exchange_free(self.native.as_ptr()) }
    }
}
impl Exchange {
    pub fn step(&mut self, input: &[u8]) -> Result<(Zeroizing<Vec<u8>>, bool)> {
        let mut out = Buffer::default();
        let mut complete = 0;
        let mut status = Status::default();
        check(
            unsafe {
                imk_step(
                    self.native.as_ptr(),
                    input.as_ptr().cast(),
                    input.len(),
                    &mut out,
                    &mut complete,
                    &mut status,
                )
            },
            &status,
            &self._credential.0.reply,
            &self._credential.0._callback,
        )?;
        Ok((out.take(), complete != 0))
    }
    pub fn wrap(&mut self, confidential: bool, input: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let mut out = Buffer::default();
        let mut status = Status::default();
        check(
            unsafe {
                imk_wrap(
                    self.native.as_ptr(),
                    confidential.into(),
                    input.as_ptr().cast(),
                    input.len(),
                    &mut out,
                    &mut status,
                )
            },
            &status,
            &self._credential.0.reply,
            &self._credential.0._callback,
        )?;
        Ok(out.take())
    }
    pub fn unwrap(&mut self, confidential: bool, input: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let mut out = Buffer::default();
        let mut status = Status::default();
        check(
            unsafe {
                imk_unwrap(
                    self.native.as_ptr(),
                    confidential.into(),
                    input.as_ptr().cast(),
                    input.len(),
                    &mut out,
                    &mut status,
                )
            },
            &status,
            &self._credential.0.reply,
            &self._credential.0._callback,
        )?;
        Ok(out.take())
    }
    pub fn mic(&mut self, input: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let mut out = Buffer::default();
        let mut status = Status::default();
        check(
            unsafe {
                imk_mic(
                    self.native.as_ptr(),
                    input.as_ptr().cast(),
                    input.len(),
                    &mut out,
                    &mut status,
                )
            },
            &status,
            &self._credential.0.reply,
            &self._credential.0._callback,
        )?;
        Ok(out.take())
    }
    pub fn wrap_limit(&mut self, confidential: bool, output: u32) -> Result<u32> {
        let mut input = 0;
        let mut status = Status::default();
        check(
            unsafe {
                imk_wrap_limit(
                    self.native.as_ptr(),
                    confidential.into(),
                    output,
                    &mut input,
                    &mut status,
                )
            },
            &status,
            &self._credential.0.reply,
            &self._credential.0._callback,
        )?;
        Ok(input)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_large_kdc_reply_reaches_the_native_message_parser() {
        let result = Credential::new(
            "user@TEST",
            "TEST",
            Source::Password {
                password: b"password",
                initial_ticket_lifetime_seconds: 600,
            },
            false,
            Box::new(|_, request| {
                assert!(!request.is_empty());
                // An independent reply of this size passes both bridges. MIT
                // then classifies its leading zero as a wrong message type.
                Ok(Zeroizing::new(vec![0; 17 * 1024 * 1024]))
            }),
        );
        assert!(matches!(result, Err(Error::Native(-1_765_328_344))));
    }
    #[test]
    fn an_empty_or_nul_password_fails_before_any_request() {
        for password in [&b""[..], b"pass\0word"] {
            assert!(
                Credential::new(
                    "user@TEST",
                    "TEST",
                    Source::Password {
                        password,
                        initial_ticket_lifetime_seconds: 600,
                    },
                    false,
                    Box::new(|_, _| panic!("no request for an unusable password"))
                )
                .is_err()
            );
        }
    }
    #[test]
    fn malformed_material_and_nul_names_fail() {
        assert!(
            Credential::new(
                "user@TEST",
                "TEST",
                Source::Ccache(&[5, 4, 0]),
                false,
                Box::new(|_, _| panic!("no network for malformed cache"))
            )
            .is_err()
        );
        assert!(
            Credential::new(
                "user\0@TEST",
                "TEST",
                Source::Ccache(&[]),
                false,
                Box::new(|_, _| Err(()))
            )
            .is_err()
        );
    }
}

/// RFC 4752 mechanism state, including the authenticated security-layer offer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityLayer {
    AuthOnly,
    Integrity,
    Confidentiality,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Protection {
    pub confidential: bool,
    pub maximum_plaintext: u32,
    pub maximum_output_token: u32,
    pub maximum_input_token: u32,
}
pub struct SaslExchange {
    exchange: Exchange,
    layer: SecurityLayer,
    authzid: Zeroizing<String>,
    context_complete: bool,
    finished: bool,
    protection: Option<Protection>,
}
impl Credential {
    pub fn sasl_exchange(
        &self,
        target: &str,
        layer: SecurityLayer,
        authzid: Zeroizing<String>,
    ) -> Result<SaslExchange> {
        if authzid.contains('\0') {
            return Err(Error::InvalidInput);
        }
        Ok(SaslExchange {
            exchange: self.exchange(target)?,
            layer,
            authzid,
            context_complete: false,
            finished: false,
            protection: None,
        })
    }
}
fn offer(layer: SecurityLayer, offer: &[u8]) -> std::result::Result<(u8, u32), OfferFault> {
    if offer.len() != 4 {
        return Err(OfferFault::Length);
    }
    let maximum = u32::from_be_bytes([0, offer[1], offer[2], offer[3]]);
    let selected = match layer {
        SecurityLayer::AuthOnly => 1,
        SecurityLayer::Integrity => 2,
        SecurityLayer::Confidentiality => 4,
    };
    if offer[0] & selected == 0 {
        return Err(OfferFault::Unoffered(layer));
    }
    if (offer[0] & 6 == 0 && maximum != 0) || (layer != SecurityLayer::AuthOnly && maximum == 0) {
        return Err(OfferFault::Size);
    }
    Ok((selected, maximum))
}
impl SaslExchange {
    pub fn step(&mut self, input: &[u8]) -> Result<(Zeroizing<Vec<u8>>, bool)> {
        if self.finished {
            return Err(Error::InvalidState);
        }
        if !self.context_complete {
            let (bytes, complete) = self.exchange.step(input)?;
            self.context_complete = complete;
            return Ok((bytes, false));
        }
        let bytes = self.exchange.unwrap(false, input)?;
        let (selected, maximum) = offer(self.layer, &bytes).map_err(Error::PeerOffer)?;
        let mut selection = Zeroizing::new(vec![selected, 0, 0, 0]);
        if self.layer != SecurityLayer::AuthOnly {
            let confidential = self.layer == SecurityLayer::Confidentiality;
            // Bounded codec buffers; this is not a cumulative traffic quota.
            let input_token = 65536u32;
            let output_token = maximum.min(65536);
            let plaintext = self.exchange.wrap_limit(confidential, output_token)?;
            if plaintext == 0 {
                return Err(Error::PeerOffer(OfferFault::Size));
            }
            selection[1..4].copy_from_slice(&input_token.to_be_bytes()[1..4]);
            self.protection = Some(Protection {
                confidential,
                maximum_plaintext: plaintext,
                maximum_output_token: output_token,
                maximum_input_token: input_token,
            });
        }
        selection.extend_from_slice(self.authzid.as_bytes());
        let output = self.exchange.wrap(false, &selection)?;
        self.finished = true;
        Ok((output, true))
    }
    pub fn protection(&self) -> Result<Option<Protection>> {
        if !self.finished {
            return Err(Error::InvalidState);
        }
        Ok(self.protection)
    }
    pub fn exchange_mut(&mut self) -> &mut Exchange {
        &mut self.exchange
    }
}
#[cfg(test)]
mod keytab_retry_tests;

#[cfg(test)]
mod reply_tests;
#[cfg(test)]
mod test_support;
