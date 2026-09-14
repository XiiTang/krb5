//! Execution-private MIT Kerberos primitives. The caller owns all KDC I/O.
//! Values are intentionally !Send and !Sync: one joined worker owns a credential
//! and its exchanges. No API reads a cache/keytab path or changes environment.
use std::{
    ffi::{CString, c_char, c_int, c_void},
    ptr::{self, NonNull},
    rc::Rc,
};
use zeroize::Zeroizing;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidInput,
    Native(i32),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Kerberos operation failed ({self:?})")
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
unsafe extern "C" {
    fn imk_alloc(len: usize) -> *mut c_void;
    fn imk_buffer_free(buffer: *mut Buffer);
    fn imk_credential_new(
        principal: *const c_char,
        realm: *const c_char,
        data: *const c_void,
        len: usize,
        keytab: c_int,
        lifetime: u32,
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
        out: *mut *mut c_void,
    ) -> i32;
    fn imk_credential_free(credential: *mut c_void);
    fn imk_exchange_new(
        credential: *mut c_void,
        target: *const c_char,
        out: *mut *mut c_void,
    ) -> i32;
    fn imk_exchange_free(exchange: *mut c_void);
    fn imk_step(
        exchange: *mut c_void,
        data: *const c_void,
        len: usize,
        out: *mut Buffer,
        complete: *mut c_int,
    ) -> i32;
    fn imk_wrap(
        exchange: *mut c_void,
        confidential: c_int,
        data: *const c_void,
        len: usize,
        out: *mut Buffer,
    ) -> i32;
    fn imk_unwrap(
        exchange: *mut c_void,
        confidential: c_int,
        data: *const c_void,
        len: usize,
        out: *mut Buffer,
    ) -> i32;
    fn imk_mic(exchange: *mut c_void, data: *const c_void, len: usize, out: *mut Buffer) -> i32;
    fn imk_wrap_limit(
        exchange: *mut c_void,
        confidential: c_int,
        output: u32,
        input: *mut u32,
    ) -> i32;
}
struct Callback {
    transport: Transport,
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
        let callback = &mut *data.cast::<Callback>();
        let realm = std::slice::from_raw_parts(realm.cast::<u8>(), realm_len);
        let request = std::slice::from_raw_parts(request.cast::<u8>(), request_len);
        let response = (callback.transport)(realm, request)?;
        if response.is_empty() || response.len() > 16 * 1024 * 1024 {
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
fn check(code: i32) -> Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(Error::Native(code))
    }
}
fn string(s: &str) -> Result<CString> {
    CString::new(s).map_err(|_| Error::InvalidInput)
}
struct Inner {
    native: NonNull<c_void>,
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
}
impl Credential {
    pub fn new(
        principal: &str,
        realm: &str,
        source: Source<'_>,
        transport_fn: Transport,
    ) -> Result<Self> {
        let principal = string(principal)?;
        let realm = string(realm)?;
        let (bytes, keytab, lifetime) = match source {
            Source::Ccache(b) => (b, 0, 0),
            Source::Keytab {
                bytes,
                initial_ticket_lifetime_seconds,
            } => (bytes, 1, initial_ticket_lifetime_seconds),
        };
        let mut callback = Box::new(Callback {
            transport: transport_fn,
        });
        let mut out = ptr::null_mut();
        check(unsafe {
            imk_credential_new(
                principal.as_ptr(),
                realm.as_ptr(),
                bytes.as_ptr().cast(),
                bytes.len(),
                keytab,
                lifetime,
                transport,
                (&mut *callback as *mut Callback).cast(),
                &mut out,
            )
        })?;
        Ok(Self(Rc::new(Inner {
            native: NonNull::new(out).ok_or(Error::InvalidInput)?,
            _callback: callback,
        })))
    }
    pub fn exchange(&self, target: &str) -> Result<Exchange> {
        let target = string(target)?;
        let mut out = ptr::null_mut();
        check(unsafe { imk_exchange_new(self.0.native.as_ptr(), target.as_ptr(), &mut out) })?;
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
        check(unsafe {
            imk_step(
                self.native.as_ptr(),
                input.as_ptr().cast(),
                input.len(),
                &mut out,
                &mut complete,
            )
        })?;
        Ok((out.take(), complete != 0))
    }
    pub fn wrap(&mut self, confidential: bool, input: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let mut out = Buffer::default();
        check(unsafe {
            imk_wrap(
                self.native.as_ptr(),
                confidential.into(),
                input.as_ptr().cast(),
                input.len(),
                &mut out,
            )
        })?;
        Ok(out.take())
    }
    pub fn unwrap(&mut self, confidential: bool, input: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let mut out = Buffer::default();
        check(unsafe {
            imk_unwrap(
                self.native.as_ptr(),
                confidential.into(),
                input.as_ptr().cast(),
                input.len(),
                &mut out,
            )
        })?;
        Ok(out.take())
    }
    pub fn mic(&mut self, input: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let mut out = Buffer::default();
        check(unsafe {
            imk_mic(
                self.native.as_ptr(),
                input.as_ptr().cast(),
                input.len(),
                &mut out,
            )
        })?;
        Ok(out.take())
    }
    pub fn wrap_limit(&mut self, confidential: bool, output: u32) -> Result<u32> {
        let mut input = 0;
        check(unsafe {
            imk_wrap_limit(
                self.native.as_ptr(),
                confidential.into(),
                output,
                &mut input,
            )
        })?;
        Ok(input)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_material_and_nul_names_fail() {
        assert!(
            Credential::new(
                "user@TEST",
                "TEST",
                Source::Ccache(&[5, 4, 0]),
                Box::new(|_, _| panic!("no network for malformed cache"))
            )
            .is_err()
        );
        assert!(
            Credential::new(
                "user\0@TEST",
                "TEST",
                Source::Ccache(&[]),
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
impl SaslExchange {
    pub fn step(&mut self, input: &[u8]) -> Result<(Zeroizing<Vec<u8>>, bool)> {
        if self.finished {
            return Err(Error::InvalidInput);
        }
        if !self.context_complete {
            let (bytes, complete) = self.exchange.step(input)?;
            self.context_complete = complete;
            return Ok((bytes, false));
        }
        let offer = self.exchange.unwrap(false, input)?;
        if offer.len() != 4 {
            return Err(Error::InvalidInput);
        }
        let maximum = u32::from_be_bytes([0, offer[1], offer[2], offer[3]]);
        let selected = match self.layer {
            SecurityLayer::AuthOnly => 1,
            SecurityLayer::Integrity => 2,
            SecurityLayer::Confidentiality => 4,
        };
        if offer[0] & selected == 0 || (offer[0] & 6 == 0 && maximum != 0) {
            return Err(Error::InvalidInput);
        }
        let mut selection = Zeroizing::new(vec![selected, 0, 0, 0]);
        if self.layer != SecurityLayer::AuthOnly {
            if maximum == 0 {
                return Err(Error::InvalidInput);
            }
            let confidential = self.layer == SecurityLayer::Confidentiality;
            // Bounded codec buffers; this is not a cumulative traffic quota.
            let input_token = 65536u32;
            let output_token = maximum.min(65536);
            let plaintext = self.exchange.wrap_limit(confidential, output_token)?;
            if plaintext == 0 {
                return Err(Error::InvalidInput);
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
            return Err(Error::InvalidInput);
        }
        Ok(self.protection)
    }
    pub fn exchange_mut(&mut self) -> &mut Exchange {
        &mut self.exchange
    }
}
