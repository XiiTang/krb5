#ifndef BOUNDLESS_KERBEROS_NATIVE_H
#define BOUNDLESS_KERBEROS_NATIVE_H
#include <stddef.h>
#include <stdint.h>
typedef struct imk_credential imk_credential;
typedef struct imk_exchange imk_exchange;
typedef int (*imk_transport)(void *, const void *, size_t, const void *, size_t, void **, size_t *);
typedef struct { void *data; size_t len; } imk_buffer;
void *imk_alloc(size_t);
void imk_buffer_free(imk_buffer *);
enum { IMK_SOURCE_CCACHE = 0, IMK_SOURCE_KEYTAB = 1, IMK_SOURCE_PASSWORD = 2 };
enum { IMK_MECHANISM_KERBEROS = 0, IMK_MECHANISM_SPNEGO = 1 };
int32_t imk_credential_new(const char *, const char *, const void *, size_t,
                         int, uint32_t, int, imk_transport, void *, imk_credential **);
void imk_credential_free(imk_credential *);
int32_t imk_exchange_new(imk_credential *, const char *, int, int, imk_exchange **);
void imk_exchange_free(imk_exchange *);
int32_t imk_step(imk_exchange *, const void *, size_t, imk_buffer *, int *);
int32_t imk_wrap(imk_exchange *, int, const void *, size_t, imk_buffer *);
int32_t imk_unwrap(imk_exchange *, int, const void *, size_t, imk_buffer *);
int32_t imk_mic(imk_exchange *, const void *, size_t, imk_buffer *);
int32_t imk_wrap_limit(imk_exchange *, int, uint32_t, uint32_t *);
#endif
