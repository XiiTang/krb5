# Boundless patches

The `boundless` branch carries these patches on MIT krb5 1.22.2. Each is
required by Boundless's private Kerberos runtime (`runtime/`): Execution-owned
credentials in memory, and KDC traffic only through the caller's transport,
which authorizes every KDC as Access does.

| Patch | Why | Regression |
| --- | --- | --- |
| Own Kerberos contexts, memory credentials and exclusive KDC transport | A runtime context sends KDC requests only through its callback and never reads a default cache, keytab, profile or plugin; credentials are imported from memory | `runtime/test_interop.c` with `runtime/test_interop.py`; Boundless `protocols::kerberos` tests against an owned KDC |
| Rename project integration to Boundless | The configure switch and symbols name the project | Builds |
| Preserve string pointer constness with current glibc | Builds against glibc 2.43 | Linux build |
| Build the private Kerberos runtime on Windows without native cache loading | The Windows build has the same isolation | Windows build |
| Password sources, forwardable tickets, SPNEGO initiators and requested delegation | An initial ticket can be requested with a password; a ticket is forwardable only when the caller asks; `gss_spnego_initiator_cred` gives SPNEGO the explicit credential, since a private runtime has no default credentials for it to acquire; an exchange chooses Kerberos or SPNEGO, and delegates only when asked, failing when it cannot | Boundless `independent_acceptor_takes_password_tickets_spnego_and_permitted_delegation` against an owned KDC and python-gssapi |
