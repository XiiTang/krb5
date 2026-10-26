use super::*;
use std::{cell::RefCell, rc::Rc};

pub(super) fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match content.len() {
        n if n < 0x80 => out.push(n as u8),
        n if n < 0x100 => out.extend([0x81, n as u8]),
        n => out.extend([0x82, (n >> 8) as u8, n as u8]),
    }
    out.extend_from_slice(content);
    out
}
pub(super) fn integer(value: u32) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(3);
    let mut bytes = bytes[start..].to_vec();
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    der(0x02, &bytes)
}
pub(super) fn explicit(number: u8, content: Vec<u8>) -> Vec<u8> {
    der(0xa0 | number, &content)
}

/// A KRB-ERROR (RFC 4120 5.9.1) from the KDC of realm TEST.
pub(super) fn krb_error(code: u32, text: Option<&[u8]>, e_data: Option<&[u8]>) -> Vec<u8> {
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
    let mut fields = [
        explicit(0, integer(5)),
        explicit(1, integer(30)),
        explicit(4, der(0x18, b"20260101000000Z")),
        explicit(5, integer(0)),
        explicit(6, integer(code)),
        explicit(9, der(0x1b, b"TEST")),
        explicit(10, sname),
    ]
    .concat();
    if let Some(text) = text {
        fields.extend(explicit(11, der(0x1b, text)));
    }
    if let Some(data) = e_data {
        fields.extend(explicit(12, der(0x04, data)));
    }
    der(0x7e, &der(0x30, &fields))
}

/// A version 2 keytab (keytab.txt) with one aes256-cts key for user@TEST.
pub(super) fn keytab() -> Vec<u8> {
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
pub(super) fn acquire(
    replies: Vec<std::result::Result<Vec<u8>, ()>>,
) -> (Result<Credential>, usize) {
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

pub(super) fn method_data(types: &[u32]) -> Vec<u8> {
    der(
        0x30,
        &types
            .iter()
            .flat_map(|t| {
                der(
                    0x30,
                    &[explicit(1, integer(*t)), explicit(2, der(4, &[]))].concat(),
                )
            })
            .collect::<Vec<_>>(),
    )
}

pub(super) fn gss_error_token(error: Vec<u8>) -> Vec<u8> {
    der(
        0x60,
        &[
            &b"\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x03\x00"[..],
            &error,
        ]
        .concat(),
    )
}

// FILE ccache v4 (ccmarshal.c), with independently encoded RFC 4120 Tickets.
pub(super) fn ccache(entries: &[&str]) -> Vec<u8> {
    fn data(value: &[u8]) -> Vec<u8> {
        [&(value.len() as u32).to_be_bytes()[..], value].concat()
    }
    fn principal(value: &str) -> Vec<u8> {
        let (name, realm) = value.split_once('@').unwrap();
        let parts: Vec<_> = name.split('/').collect();
        let mut out = [1u32.to_be_bytes(), (parts.len() as u32).to_be_bytes()].concat();
        out.extend(data(realm.as_bytes()));
        for part in parts {
            out.extend(data(part.as_bytes()));
        }
        out
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    let mut out = vec![5, 4, 0, 0];
    out.extend(principal("user@TEST"));
    for server in entries {
        let (name, realm) = server.split_once('@').unwrap();
        let sname = der(
            0x30,
            &[
                explicit(0, integer(2)),
                explicit(
                    1,
                    der(
                        0x30,
                        &name
                            .split('/')
                            .flat_map(|part| der(0x1b, part.as_bytes()))
                            .collect::<Vec<_>>(),
                    ),
                ),
            ]
            .concat(),
        );
        let ticket = der(
            0x61,
            &der(
                0x30,
                &[
                    explicit(0, integer(5)),
                    explicit(1, der(0x1b, realm.as_bytes())),
                    explicit(2, sname),
                    explicit(
                        3,
                        der(
                            0x30,
                            &[
                                explicit(0, integer(18)),
                                explicit(1, integer(1)),
                                explicit(2, der(4, &[0; 32])),
                            ]
                            .concat(),
                        ),
                    ),
                ]
                .concat(),
            ),
        );
        out.extend(principal("user@TEST"));
        out.extend(principal(server));
        out.extend(18u16.to_be_bytes());
        out.extend(data(&[0x42; 32]));
        for time in [now - 60, now - 60, now + 3600, 0] {
            out.extend(time.to_be_bytes());
        }
        out.push(0); // is_skey
        out.extend(0u32.to_be_bytes()); // flags
        out.extend(0u32.to_be_bytes()); // addresses
        out.extend(0u32.to_be_bytes()); // authdata
        out.extend(data(&ticket));
        out.extend(data(&[])); // second ticket
    }
    out
}
