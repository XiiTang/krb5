#ifndef BOUNDLESS_KERBEROS_NATIVE_H
#define BOUNDLESS_KERBEROS_NATIVE_H
#include <stddef.h>
#include <stdint.h>
typedef struct imk_credential imk_credential;
typedef struct imk_exchange imk_exchange;
typedef struct _krb5_runtime_reply imk_reply;
enum { IMK_STATUS_NATIVE = 0, IMK_STATUS_CREDENTIAL = 2,
       IMK_STATUS_CONFIGURATION = 3, IMK_STATUS_STATE = 4 };
enum { IMK_INPUT_NONE = 0, IMK_INPUT_PRINCIPAL = 1, IMK_INPUT_CCACHE = 2,
       IMK_INPUT_KEYTAB = 3, IMK_INPUT_PASSWORD = 4 };
enum { IMK_EXCHANGE_AS = 1, IMK_EXCHANGE_TGS = 2, IMK_EXCHANGE_AP = 3 };
typedef struct { int32_t kind; int32_t input; } imk_status;
int32_t imk_reply_new(imk_reply **);
void imk_reply_free(imk_reply *);
int imk_reply_get(const imk_reply *, int32_t *, int32_t *, const void **, size_t *);
typedef int (*imk_transport)(void *, const void *, size_t, const void *, size_t, void **, size_t *);
typedef struct { void *data; size_t len; } imk_buffer;
void *imk_alloc(size_t);
void imk_buffer_free(imk_buffer *);
enum { IMK_SOURCE_CCACHE = 0, IMK_SOURCE_KEYTAB = 1, IMK_SOURCE_PASSWORD = 2 };
enum { IMK_MECHANISM_KERBEROS = 0, IMK_MECHANISM_SPNEGO = 1 };
int32_t imk_credential_new(const char *, const char *, const void *, size_t,
                         int, uint32_t, int, imk_transport, void *, imk_reply *, imk_credential **, imk_status *);
void imk_credential_free(imk_credential *);
int32_t imk_exchange_new(imk_credential *, const char *, int, int, imk_exchange **, imk_status *);
void imk_exchange_free(imk_exchange *);
int32_t imk_step(imk_exchange *, const void *, size_t, imk_buffer *, int *, imk_status *);
int32_t imk_wrap(imk_exchange *, int, const void *, size_t, imk_buffer *, imk_status *);
int32_t imk_unwrap(imk_exchange *, int, const void *, size_t, imk_buffer *, imk_status *);
int32_t imk_mic(imk_exchange *, const void *, size_t, imk_buffer *, imk_status *);
int32_t imk_wrap_limit(imk_exchange *, int, uint32_t, uint32_t *, imk_status *);
#endif
