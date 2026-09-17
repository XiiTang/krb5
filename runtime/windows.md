# Private Windows build

The Rust build script supports native Windows x86_64 with MSVC, nmake, Perl,
and the sed/awk/cat/mv tools supplied by Git for Windows. Keep MSVC's linker
before Git's tools on PATH. It builds only the upstream include, util and lib
subdirectories, without the ticket manager or a system Kerberos installation.

`BOUNDLESS_STATIC_GSS` selects the linked GSS mechanisms. The private runtime
also disables `krb5_win_ccdll_load`: a caller-owned memory credential must not
cause loading of a native credential-cache provider. Runtime's explicit realm,
transport callback and in-memory credential imports remain the public contract.

The build publishes the four private DLLs and their import libraries in Cargo's
OUT_DIR. Cargo supplies that directory when running tests/examples. A product
installer must bundle all four DLLs beside its executables and apply its normal
publisher/hash checks; the build does not install them globally.

Verified on Windows 11 x86_64 with MSVC 14.44 and Rust 1.97:

- `cargo test`: native compilation, DLL loading and malformed-material test pass.
- A disposable `krbcc64.dll` whose only effect is creating a test marker was
  placed in a test working directory. Calling `krb5_init_runtime_context` with
  the previous loader behavior created the marker. Calling the same API with
  the private build succeeded without loading that DLL or creating the marker.
  The fixture and marker were removed afterward.

These checks do not claim a complete Windows KDC interoperability matrix.
