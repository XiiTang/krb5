# Boundless patches

The `boundless` branch carries these patches on MIT krb5 1.22.2. Each is
required by Boundless's private Kerberos runtime (`runtime/`): Execution-owned
credentials in memory, and KDC traffic only through the caller's transport,
which authorizes every KDC as Access does.

## Engine-selected KDC and acceptor refusals and typed runtime failures

W5-D12 (part of #67) distinguishes a peer's actual terminal KRB-ERROR from a
local native status with the same integer. AS give-up and saved-preauth-failure
returns select; the TGS decoder offers a candidate and its four terminal
returns promote it; the acceptor-error branch selects before deleting its
context. Every selected nonzero status reaches the runtime return without a
further exchange or code change. The exclusive send boundary discards a TGS
candidate before each exchange, so a consumed retry cannot become a later
local error's evidence. Zero statuses continue MIT's loop and are never selected.

The opaque reply slot lives outside native credentials and contexts. Context
copies borrow it; selection moves the code and e-text without allocating and
never reads e-data. The seven runtime entry points clear the slot before work.
The private Rust `check` alone constructs `ErrorReply`, using the callback's
addressed realm, and copies an empty text without reading its NULL pointer.
`finish` alone writes native status kinds and keeps allocation errors native.
Credential inputs, lifetime configuration, exchange state and security-layer
offers have typed errors; Display includes no peer text.

Regression evidence is in `runtime/reply_tests.rs`: final AS refusal surviving
failed credential destruction; PREAUTH_REQUIRED followed by local failure;
saved preauth fallback; TGS retry selection and candidate discard; acceptor
refusal surviving context deletion; zero and wrapping statuses; typed inputs,
offers and state; cross-call clearing; fixed Display. The existing final-keytab
refusal test in `runtime/keytab_retry_tests.rs` keeps its one-exchange assertion
and now checks the selected AS reply. The raw-context replica tests stay intact.

| Patch | Why | Regression |
| --- | --- | --- |
| Own Kerberos contexts, memory credentials and exclusive KDC transport | A runtime context sends KDC requests only through its callback and never reads a default cache, keytab, profile or plugin; credentials are imported from memory | `runtime/test_interop.c` with `runtime/test_interop.py`; Boundless `protocols::kerberos` tests against an owned KDC |
| Rename project integration to Boundless | The configure switch and symbols name the project | Builds |
| Preserve string pointer constness with current glibc | Builds against glibc 2.43 | Linux build |
| Build the private Kerberos runtime on Windows without native cache loading | The Windows build has the same isolation | Windows build |
| Password sources, forwardable tickets, SPNEGO initiators and requested delegation | An initial ticket can be requested with a password; a ticket is forwardable only when the caller asks; `gss_spnego_initiator_cred` gives SPNEGO the explicit credential, since a private runtime has no default credentials for it to acquire; an exchange chooses Kerberos or SPNEGO, and delegates only when asked, failing when it cannot | Boundless `independent_acceptor_takes_password_tickets_spnego_and_permitted_delegation` against an owned KDC and python-gssapi |

## KDC reply capacity (W11d)

The caller's transport owns the configured reply ceiling. The Rust callback
and C bridge retain only the native krb5_data unsigned 32-bit length capacity,
checking before allocation or narrowing. Their independent 16 MiB ceilings
previously refused a reply admitted by the caller.
`a_large_kdc_reply_reaches_the_native_message_parser` passes a 17 MiB reply
through both bridges and checks MIT's message-type classification. Boundless
checks announced KDC lengths against body_read_maximum_bytes before allocation.

## Keytab acquisition retries the primary only after a replica (#358)

`krb5_get_init_creds_keytab` retries a failed acquisition against the primary
KDC "if the reply did not come from the primary kdc", but upstream tests
`!k5_kdclist_any_replicas` (gic_keytab.c:316 at 1.22.2, unchanged on master),
a predicate `locate_kdc.c:971-1010` defines positively; the password path
(`get_in_tkt.c:2031-2037`) retries on the positive test. A runtime context's
exclusive transport returns before KDC location (`sendto_kdc.c:468-480`), so
no replica is ever recorded and every final refusal ran a second AS exchange
through the caller's transport. A second refusal could replace the original
refusal; an unreachable or unresolvable retry already restored it
(gic_keytab.c:326). The
condition now matches its comment and the password path.

Regressions, `runtime/keytab_retry_tests.rs`:

- `a_final_keytab_refusal_makes_one_exchange_and_keeps_its_error`: a scripted
  exclusive transport answers CLIENT_REVOKED, then POLICY. One exchange and
  CLIENT_REVOKED; before, two exchanges and POLICY.
- `an_unavailable_kdc_ends_keytab_acquisition_after_one_attempt`: a failed
  transport is `KRB5_KDC_UNREACH` after one attempt (the early exit).
- Through krb5's own KDC location with loopback UDP KDCs (Unix):
  `a_refusal_from_the_primary_is_not_retried` (before, two exchanges),
  `a_refusal_from_a_replica_is_retried_once_with_the_primary` (before, no
  retry and the replica's refusal), and
  `an_unreachable_primary_keeps_the_replica_refusal` (both KDCs owned; the
  existing receive hook reports the primary's answer as `KRB5_KDC_UNREACH`,
  and the replica's saved refusal is restored).
