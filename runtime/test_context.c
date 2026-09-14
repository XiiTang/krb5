#include "k5-int.h"
#include <assert.h>
#include <string.h>
static krb5_error_code callback(krb5_context ctx, void *data, const krb5_data *realm,
                                const krb5_data *request, krb5_data **replacement, krb5_data **reply) {
    int *calls = data;
    krb5_data answer = string2data("owned reply");
    (*calls)++;
    assert(data_eq_string(*realm,"NO-DISCOVERY.invalid"));
    assert(data_eq_string(*request,"request"));
    *replacement = NULL;
    if (*calls == 1) return krb5_copy_data(ctx,&answer,reply);
    if (*calls == 2) return 0; /* No response must never enable a native fallback. */
    return ENOENT;
}
int main(void) {
    krb5_context ctx, copied;
    krb5_data request=string2data("request"),realm=string2data("NO-DISCOVERY.invalid"), reply;
    int primary=0,calls=0;
    assert(krb5_init_runtime_context("NO-DISCOVERY.invalid",callback,&calls,&ctx)==0);
    assert(ctx->profile_secure && ctx->kdc_io_exclusive && !ctx->trace_callback);
    assert(krb5_copy_context(ctx,&copied)==0);
    assert(krb5_sendto_kdc(copied,&request,&realm,&reply,&primary,0)==0);
    assert(data_eq_string(reply,"owned reply"));
    krb5_free_data_contents(copied,&reply);
    assert(krb5_sendto_kdc(copied,&request,&realm,&reply,&primary,0)==KRB5_KDC_UNREACH);
    assert(krb5_sendto_kdc(copied,&request,&realm,&reply,&primary,0)==ENOENT);
    assert(calls==3);
    krb5_set_kdc_send_hook_exclusive(copied,NULL,NULL);
    assert(krb5_sendto_kdc(copied,&request,&realm,&reply,&primary,0)==KRB5_KDC_UNREACH);
    krb5_free_context(copied);
    krb5_free_context(ctx);
    return 0;
}
