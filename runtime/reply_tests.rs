use super::test_support::*;
use super::*;
use std::cell::Cell;

const BASE: i32 = -1_765_328_384;
fn scripted(source: Source<'_>, replies: Vec<Vec<u8>>) -> (Result<Credential>, Rc<Cell<usize>>) {
    let count = Rc::new(Cell::new(0));
    let seen = count.clone();
    let mut replies = replies.into_iter();
    let credential = Credential::new(
        "user@TEST",
        "TEST",
        source,
        false,
        Box::new(move |realm, request| {
            assert_eq!(realm, b"TEST");
            assert!(!request.is_empty());
            seen.set(seen.get() + 1);
            replies.next().map(Zeroizing::new).ok_or(())
        }),
    );
    (credential, count)
}
fn password() -> Source<'static> {
    Source::Password {
        password: b"password",
        initial_ticket_lifetime_seconds: 600,
    }
}
fn peer(error: Error, code: i32, exchange: ReplyExchange) -> ErrorReply {
    let Error::PeerRejected(reply) = error else {
        panic!("expected peer refusal, got {error:?}")
    };
    assert_eq!(reply.code(), code);
    assert_eq!(reply.exchange(), &exchange);
    reply
}
#[test]
fn a_final_as_refusal_is_selected_and_outlives_the_failed_credential() {
    let (result, count) = scripted(
        password(),
        vec![krb_error(18, Some(b"revoked"), Some(b"SECRET"))],
    );
    let reply = peer(
        result.err().unwrap(),
        18,
        ReplyExchange::As {
            realm: (*b"TEST").into(),
        },
    );
    assert_eq!(reply.text(), b"revoked");
    assert_eq!(count.get(), 1);
}
#[test]
fn preauth_required_then_a_local_failure_stays_native() {
    let (result, count) = scripted(
        password(),
        vec![krb_error(25, None, Some(&method_data(&[9999])))],
    );
    assert_eq!(result.err(), Some(Error::Native(BASE + 210)));
    assert_eq!(count.get(), 1);
}
#[test]
fn a_saved_preauth_failure_is_selected_after_its_fallback_fails() {
    let md = method_data(&[2]);
    let (result, count) = scripted(
        password(),
        vec![
            krb_error(25, None, Some(&md)),
            krb_error(24, None, Some(&md)),
        ],
    );
    peer(
        result.err().unwrap(),
        24,
        ReplyExchange::As {
            realm: (*b"TEST").into(),
        },
    );
    assert_eq!(count.get(), 2);
}
#[test]
fn a_consumed_tgs_retry_selects_the_final_reply() {
    let cache = ccache(&["krbtgt/TEST@TEST"]);
    let (credential, count) = scripted(
        Source::Ccache(&cache),
        vec![krb_error(7, None, None), krb_error(12, None, None)],
    );
    let result = credential
        .unwrap()
        .exchange("host/a.test@TEST")
        .unwrap()
        .step(&[]);
    let reply = peer(
        result.err().unwrap(),
        12,
        ReplyExchange::Tgs {
            realm: (*b"TEST").into(),
        },
    );
    assert!(reply.text().is_empty());
    assert_eq!(count.get(), 2);
}
#[test]
fn a_consumed_tgs_reply_is_not_promoted_for_a_later_local_failure() {
    let cache = ccache(&["krbtgt/TEST@TEST"]);
    let (credential, count) = scripted(
        Source::Ccache(&cache),
        vec![krb_error(40, Some(b"first"), None), vec![0; 8]],
    );
    let result = credential
        .unwrap()
        .exchange("host/a.test@TEST")
        .unwrap()
        .step(&[]);
    assert!(matches!(result, Err(Error::Native(_))), "{result:?}");
    assert_eq!(count.get(), 2);
}
fn local_credential(cache: &[u8]) -> Credential {
    Credential::new(
        "user@TEST",
        "TEST",
        Source::Ccache(cache),
        false,
        Box::new(|_, _| panic!("no KDC exchange")),
    )
    .unwrap()
}
#[test]
fn an_acceptor_refusal_survives_its_context_deletion() {
    let credential = local_credential(&ccache(&["host/a.test@TEST"]));
    let mut exchange = credential.exchange("host/a.test@TEST").unwrap();
    assert!(!exchange.step(&[]).unwrap().0.is_empty());
    peer(
        exchange
            .step(&gss_error_token(krb_error(36, None, None)))
            .unwrap_err(),
        36,
        ReplyExchange::Ap,
    );
}
#[test]
fn an_as_status_that_wraps_to_zero_is_not_selected() {
    let (result, count) = scripted(
        password(),
        vec![krb_error(1765328384, Some(b"first"), None), vec![0; 8]],
    );
    assert_eq!(result.err(), Some(Error::Native(BASE + 40)));
    assert_eq!(count.get(), 2);
}
#[test]
fn an_acceptor_error_code_that_is_zero_or_wraps_to_zero_is_not_a_refusal() {
    for code in [0, 1765328384] {
        let credential = local_credential(&ccache(&["host/a.test@TEST"]));
        let mut exchange = credential.exchange("host/a.test@TEST").unwrap();
        assert!(!exchange.step(&[]).unwrap().0.is_empty());
        let result = exchange.step(&gss_error_token(krb_error(code, None, None)));
        assert!(matches!(result, Err(Error::Native(_))), "{result:?}");
    }
}
#[test]
fn credential_inputs_are_typed() {
    let kt = keytab();
    let cases = [
        (
            "user@OTHER",
            Source::Ccache(&[]),
            Error::Credential(CredentialInput::Principal),
        ),
        (
            "user@TEST",
            Source::Ccache(&[5, 4, 0]),
            Error::Credential(CredentialInput::Ccache),
        ),
        (
            "user@TEST",
            Source::Keytab {
                bytes: &[5, 2, 0, 0, 0, 1],
                initial_ticket_lifetime_seconds: 600,
            },
            Error::Credential(CredentialInput::Keytab),
        ),
        (
            "user@TEST",
            Source::Password {
                password: b"",
                initial_ticket_lifetime_seconds: 600,
            },
            Error::Credential(CredentialInput::Password),
        ),
        (
            "user@TEST",
            Source::Password {
                password: b"pa\0ss",
                initial_ticket_lifetime_seconds: 600,
            },
            Error::Credential(CredentialInput::Password),
        ),
        (
            "user@TEST",
            Source::Keytab {
                bytes: &kt,
                initial_ticket_lifetime_seconds: 0,
            },
            Error::Configuration(ConfigurationFault::LifetimeRange),
        ),
    ];
    for (principal, source, error) in cases {
        assert_eq!(
            Credential::new(
                principal,
                "TEST",
                source,
                false,
                Box::new(|_, _| panic!("no KDC exchange"))
            )
            .err(),
            Some(error)
        );
    }
}
#[test]
fn a_later_call_never_reads_an_earlier_selection() {
    let cache = ccache(&["krbtgt/TEST@TEST"]);
    let (credential, count) = scripted(
        Source::Ccache(&cache),
        vec![krb_error(7, None, None), krb_error(12, None, None)],
    );
    let credential = credential.unwrap();
    peer(
        credential
            .exchange("host/a.test@TEST")
            .unwrap()
            .step(&[])
            .unwrap_err(),
        12,
        ReplyExchange::Tgs {
            realm: (*b"TEST").into(),
        },
    );
    let result = credential
        .exchange_with("host/b.test@TE/ST", Mechanism::Kerberos, false)
        .and_then(|mut e| e.step(&[]));
    assert!(matches!(result, Err(Error::Native(_))), "{result:?}");
    assert_eq!(count.get(), 2);
}
#[test]
fn security_layer_offers_are_typed() {
    for (layer, bytes, error) in [
        (
            SecurityLayer::Integrity,
            &b"\x02\0\0\0"[..],
            OfferFault::Size,
        ),
        (
            SecurityLayer::Integrity,
            &b"\x01\0\0\0"[..],
            OfferFault::Unoffered(SecurityLayer::Integrity),
        ),
        (
            SecurityLayer::AuthOnly,
            &b"\x01\0\0\x01"[..],
            OfferFault::Size,
        ),
        (
            SecurityLayer::AuthOnly,
            &b"\x01\0\0"[..],
            OfferFault::Length,
        ),
    ] {
        assert_eq!(offer(layer, bytes), Err(error));
    }
}
#[test]
fn protection_before_finish_is_invalid_state() {
    let credential = local_credential(&ccache(&["host/a.test@TEST"]));
    assert_eq!(
        credential
            .sasl_exchange(
                "host/a.test@TEST",
                SecurityLayer::Integrity,
                Zeroizing::new(String::new())
            )
            .unwrap()
            .protection(),
        Err(Error::InvalidState)
    );
}
#[test]
fn display_names_no_peer_text() {
    let (result, _) = scripted(
        password(),
        vec![krb_error(18, Some(b"revoked"), Some(b"SECRET"))],
    );
    assert_eq!(
        result.err().unwrap().to_string(),
        "the peer rejected the Kerberos exchange"
    );
}
