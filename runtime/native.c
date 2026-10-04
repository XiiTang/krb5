/* The MIT engine owns credentials, ASN.1, GSS context and cryptography. */
#include "native.h"
#include <krb5.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

struct imk_credential {
    krb5_context context;
    krb5_ccache cache;
    krb5_principal principal;
    gss_cred_id_t handle;
    imk_transport transport;
    void *transport_data;
};
struct imk_exchange {
    imk_credential *credential;
    gss_ctx_id_t context;
    gss_name_t target;
    gss_OID mechanism;
    /* A SPNEGO exchange's own credential; Kerberos uses the credential's. */
    gss_cred_id_t spnego;
    OM_uint32 requested;
    OM_uint32 required;
    int complete;
};
/* SPNEGO, RFC 4178: 1.3.6.1.5.5.2. */
static gss_OID_desc spnego_oid = {6, (void *)"\x2b\x06\x01\x05\x05\x02"};
static void wipe(void *p, size_t n) {
    volatile unsigned char *v = p;
    while (n--) *v++ = 0;
}
void *imk_alloc(size_t n) { return malloc(n ? n : 1); }
void imk_buffer_free(imk_buffer *b) {
    if (b->data) { wipe(b->data, b->len); free(b->data); }
    b->data = NULL; b->len = 0;
}
static int32_t take_gss(OM_uint32 major, OM_uint32 minor, gss_buffer_t token, imk_buffer *out) {
    OM_uint32 ignored;
    int32_t ret = 0;
    out->data = NULL; out->len = 0;
    if (major != GSS_S_COMPLETE && major != GSS_S_CONTINUE_NEEDED) ret = minor ? (int32_t)minor : EPROTO;
    else if (token->length) {
        out->data = imk_alloc(token->length);
        if (!out->data) ret = ENOMEM;
        else { out->len = token->length; memcpy(out->data, token->value, token->length); }
    }
    if (token->value) wipe(token->value, token->length);
    gss_release_buffer(&ignored, token);
    return ret;
}
static krb5_error_code transport(krb5_context ctx, void *data,
                                 const krb5_data *realm, const krb5_data *request,
                                 krb5_data **replacement, krb5_data **reply) {
    imk_credential *c = data;
    imk_buffer bytes = {0};
    krb5_data value;
    krb5_error_code ret;
    *replacement = NULL; *reply = NULL;
    if (!c->transport || c->transport(c->transport_data, realm->data, realm->length,
                                     request->data, request->length, &bytes.data, &bytes.len)) {
        imk_buffer_free(&bytes);
        return KRB5_KDC_UNREACH;
    }
    if (!bytes.len || bytes.len > 16 * 1024 * 1024 || !bytes.data) {
        imk_buffer_free(&bytes); return KRB5KRB_ERR_RESPONSE_TOO_BIG;
    }
    value.magic = 0; value.data = bytes.data; value.length = bytes.len;
    ret = krb5_copy_data(ctx, &value, reply);
    imk_buffer_free(&bytes);
    return ret;
}
void imk_credential_free(imk_credential *c) {
    OM_uint32 ignored;
    if (!c) return;
    if (c->handle) gss_release_cred(&ignored, &c->handle);
    if (c->cache) krb5_cc_destroy(c->context, c->cache);
    krb5_free_principal(c->context, c->principal);
    krb5_free_context(c->context);
    wipe(c, sizeof(*c)); free(c);
}
int32_t imk_credential_new(const char *principal, const char *realm,
                         const void *bytes, size_t len, int source,
                         uint32_t lifetime, int forwardable,
                         imk_transport callback, void *data,
                         imk_credential **out) {
    imk_credential *c = calloc(1, sizeof(*c));
    krb5_principal actual = NULL;
    krb5_keytab kt = NULL;
    krb5_get_init_creds_opt *options = NULL;
    krb5_creds ticket = {0};
    char *password = NULL;
    krb5_data random;
    unsigned char random_bytes[16];
    char name[7+32+1];
    const char hex[] = "0123456789abcdef";
    OM_uint32 major, minor;
    int32_t ret = 0;
    size_t i;
    *out = NULL;
    if (!c) return ENOMEM;
    c->transport = callback; c->transport_data = data;
    ret = krb5_init_runtime_context(realm, transport, c, &c->context);
    if (ret) goto done;
    ret = krb5_parse_name(c->context, principal, &c->principal);
    if (ret) goto done;
    if (krb5_princ_realm(c->context, c->principal)->length != strlen(realm) ||
        memcmp(krb5_princ_realm(c->context, c->principal)->data, realm, strlen(realm))) {
        ret = EINVAL; goto done;
    }
    if (source == IMK_SOURCE_CCACHE) {
        ret = krb5_cc_import_memory(c->context, bytes, len, &c->cache);
        if (ret) goto done;
        ret = krb5_cc_get_principal(c->context, c->cache, &actual);
        if (ret) goto done;
        if (!krb5_principal_compare(c->context, actual, c->principal)) { ret = EINVAL; goto done; }
    } else if (source == IMK_SOURCE_KEYTAB || source == IMK_SOURCE_PASSWORD) {
        if (!lifetime || lifetime > INT32_MAX) { ret = EINVAL; goto done; }
        ret = krb5_get_init_creds_opt_alloc(c->context, &options);
        if (ret) goto done;
        krb5_get_init_creds_opt_set_tkt_life(options, lifetime);
        krb5_get_init_creds_opt_set_renew_life(options, 0);
        /* A ticket is forwardable only for an Access that allows delegation. */
        krb5_get_init_creds_opt_set_forwardable(options, forwardable != 0);
        krb5_get_init_creds_opt_set_proxiable(options, 0);
        krb5_get_init_creds_opt_set_canonicalize(options, 0);
        if (source == IMK_SOURCE_KEYTAB) {
            random.magic = 0; random.data = (char *)random_bytes; random.length = sizeof(random_bytes);
            ret = krb5_c_random_make_octets(c->context, &random);
            if (ret) goto done;
            memcpy(name, "MEMORY:", 7);
            for (i=0; i<16; i++) { name[7+2*i]=hex[random_bytes[i]>>4]; name[8+2*i]=hex[random_bytes[i]&15]; }
            name[39]=0;
            ret = krb5_kt_import_memory(c->context, name, bytes, len, &kt);
            if (ret) goto done;
            ret = krb5_get_init_creds_keytab(c->context, &ticket, c->principal, kt, 0, NULL, options);
        } else {
            /* No prompter: an expired password fails rather than asking. */
            if (!len || len > 4096 || memchr(bytes, 0, len)) { ret = EINVAL; goto done; }
            password = calloc(1, len + 1);
            if (!password) { ret = ENOMEM; goto done; }
            memcpy(password, bytes, len);
            ret = krb5_get_init_creds_password(c->context, &ticket, c->principal, password,
                                               NULL, NULL, 0, NULL, options);
        }
        if (ret) goto done;
        ret = krb5_cc_new_unique(c->context, "MEMORY", NULL, &c->cache);
        if (ret) goto done;
        ret = krb5_cc_initialize(c->context, c->cache, c->principal);
        if (ret) goto done;
        ret = krb5_cc_store_cred(c->context, c->cache, &ticket);
        if (ret) goto done;
    } else { ret = EINVAL; goto done; }
    major = gss_krb5_import_cred_context(&minor, c->context, c->cache, c->principal, &c->handle);
    if (major != GSS_S_COMPLETE) { ret = minor ? (int32_t)minor : EPROTO; goto done; }
    *out = c;
done:
    if (password) { wipe(password, len); free(password); }
    krb5_free_principal(c->context, actual);
    krb5_free_cred_contents(c->context, &ticket);
    if (options) krb5_get_init_creds_opt_free(c->context, options);
    if (kt) krb5_kt_close(c->context, kt);
    if (ret) imk_credential_free(c);
    return ret;
}
void imk_exchange_free(imk_exchange *e) {
    OM_uint32 ignored;
    if (!e) return;
    if (e->context) gss_delete_sec_context(&ignored, &e->context, GSS_C_NO_BUFFER);
    if (e->target) gss_release_name(&ignored, &e->target);
    if (e->spnego) gss_release_cred(&ignored, &e->spnego);
    wipe(e,sizeof(*e)); free(e);
}
/* A Kerberos exchange protects the session it opens (SASL, SSH); a SPNEGO
 * exchange authenticates one HTTP request, whose server may confirm it or
 * not.  Delegation is asked for, and then required, only when requested. */
int32_t imk_exchange_new(imk_credential *c, const char *target, int mechanism,
                         int delegate, imk_exchange **out) {
    imk_exchange *e = calloc(1,sizeof(*e));
    gss_buffer_desc name = {strlen(target), (void *)target};
    gss_cred_id_t inner = GSS_C_NO_CREDENTIAL;
    OM_uint32 major,minor;
    *out=NULL;
    if (!e) return ENOMEM;
    e->credential=c;
    if (mechanism == IMK_MECHANISM_KERBEROS) {
        e->mechanism=(gss_OID)gss_mech_krb5;
        e->required=GSS_C_MUTUAL_FLAG|GSS_C_INTEG_FLAG|GSS_C_REPLAY_FLAG|GSS_C_SEQUENCE_FLAG;
        e->requested=e->required|GSS_C_CONF_FLAG;
    } else if (mechanism == IMK_MECHANISM_SPNEGO) {
        e->mechanism=&spnego_oid;
        e->requested=GSS_C_MUTUAL_FLAG|GSS_C_REPLAY_FLAG|GSS_C_SEQUENCE_FLAG|GSS_C_INTEG_FLAG;
        e->required=0;
        major=gss_krb5_import_cred_context(&minor,c->context,c->cache,c->principal,&inner);
        if (major == GSS_S_COMPLETE)
            major=gss_spnego_initiator_cred(&minor,inner,&e->spnego);
        else
            inner=GSS_C_NO_CREDENTIAL;
        if (major != GSS_S_COMPLETE) { imk_exchange_free(e); return minor ? (int32_t)minor : EPROTO; }
    } else { imk_exchange_free(e); return EINVAL; }
    if (delegate) { e->requested|=GSS_C_DELEG_FLAG; e->required|=GSS_C_DELEG_FLAG; }
    /* An explicit principal: no DNS or realm mapping chooses the target. */
    major=gss_import_name(&minor,&name,GSS_KRB5_NT_PRINCIPAL_NAME,&e->target);
    if (major != GSS_S_COMPLETE) { imk_exchange_free(e); return minor ? (int32_t)minor : EPROTO; }
    *out=e; return 0;
}
int32_t imk_step(imk_exchange *e, const void *data, size_t len, imk_buffer *out, int *complete) {
    gss_buffer_desc input={len,(void *)data},output=GSS_C_EMPTY_BUFFER;
    OM_uint32 major,minor,flags=0;
    int32_t ret;
    *complete=0;
    if(e->complete) return EINVAL;
    major=gss_init_sec_context(&minor,e->spnego ? e->spnego : e->credential->handle,&e->context,
          e->target,e->mechanism,e->requested,0,GSS_C_NO_CHANNEL_BINDINGS,&input,NULL,&output,&flags,NULL);
    ret=take_gss(major,minor,&output,out);
    if(ret) return ret;
    /* A delegation the exchange did not ask for is refused at once. */
    if((flags&GSS_C_DELEG_FLAG) && !(e->requested&GSS_C_DELEG_FLAG)) {
        imk_buffer_free(out); return EPROTO;
    }
    if(major==GSS_S_COMPLETE) {
        if((flags&e->required)!=e->required) { imk_buffer_free(out); return EPROTO; }
        e->complete=1; *complete=1;
    }
    return 0;
}
int32_t imk_wrap(imk_exchange *e,int confidential,const void *data,size_t len,imk_buffer *out) {
    gss_buffer_desc input={len,(void *)data},output=GSS_C_EMPTY_BUFFER;
    OM_uint32 major,minor; int encrypted=0; int32_t ret;
    if(!e->complete) return EINVAL;
    major=gss_wrap(&minor,e->context,confidential,GSS_C_QOP_DEFAULT,&input,&encrypted,&output);
    ret=take_gss(major,minor,&output,out);
    if(!ret && (!!encrypted != !!confidential)) { imk_buffer_free(out); return EPROTO; }
    return ret;
}
int32_t imk_unwrap(imk_exchange *e,int confidential,const void *data,size_t len,imk_buffer *out) {
    gss_buffer_desc input={len,(void *)data},output=GSS_C_EMPTY_BUFFER;
    OM_uint32 major,minor; int encrypted=0; gss_qop_t qop; int32_t ret;
    if(!e->complete) return EINVAL;
    major=gss_unwrap(&minor,e->context,&input,&output,&encrypted,&qop);
    ret=take_gss(major,minor,&output,out);
    if(!ret && (major!=GSS_S_COMPLETE || (!!encrypted != !!confidential) || qop!=GSS_C_QOP_DEFAULT)) {
        imk_buffer_free(out); return EPROTO;
    }
    return ret;
}
int32_t imk_mic(imk_exchange *e,const void *data,size_t len,imk_buffer *out) {
    gss_buffer_desc input={len,(void *)data},output=GSS_C_EMPTY_BUFFER;
    OM_uint32 major,minor;
    if(!e->complete) return EINVAL;
    major=gss_get_mic(&minor,e->context,GSS_C_QOP_DEFAULT,&input,&output);
    return take_gss(major,minor,&output,out);
}
int32_t imk_wrap_limit(imk_exchange *e,int confidential,uint32_t output,uint32_t *input) {
    OM_uint32 major,minor;
    if(!e->complete) return EINVAL;
    major=gss_wrap_size_limit(&minor,e->context,confidential,GSS_C_QOP_DEFAULT,output,input);
    return major==GSS_S_COMPLETE ? 0 : (minor ? (int32_t)minor : EPROTO);
}
