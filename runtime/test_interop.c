#include "native.h"
#include <krb5.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
struct transport_state { int port; int calls; int fail; };
static int exact(int fd,void *data,size_t len,int write_data) {
    unsigned char *p=data;
    while(len){ssize_t n=write_data ? write(fd,p,len):read(fd,p,len); if(n<=0)return 1;p+=n;len-=n;}
    return 0;
}
static int io(void *data,const void *realm,size_t realm_len,const void *request,size_t request_len,void **reply,size_t *reply_len) {
    struct transport_state *state=data;
    struct sockaddr_in addr={0};
    struct timeval timeout={5,0};
    uint32_t n;
    int fd,ret=1;
    state->calls++;
    assert(realm_len==sizeof("BOUNDLESS.TEST")-1 && memcmp(realm,"BOUNDLESS.TEST",sizeof("BOUNDLESS.TEST")-1)==0);
    if(state->fail)return 1;
    fd=socket(AF_INET,SOCK_STREAM,0);assert(fd>=0);
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
    addr.sin_family=AF_INET;addr.sin_port=htons(state->port);addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(connect(fd,(struct sockaddr *)&addr,sizeof(addr)))goto done;
    n=htonl(request_len);
    if(exact(fd,&n,4,1)||exact(fd,(void*)request,request_len,1)||exact(fd,&n,4,0))goto done;
    *reply_len=ntohl(n);assert(*reply_len<1024*1024);
    *reply=imk_alloc(*reply_len);assert(*reply);
    if(exact(fd,*reply,*reply_len,0))goto done;
    ret=0;
 done: close(fd);return ret;
}
static imk_buffer file(const char *path){
    imk_buffer b={0};FILE *f=fopen(path,"rb");assert(f);
    assert(fseek(f,0,SEEK_END)==0);b.len=ftell(f);rewind(f);b.data=imk_alloc(b.len);assert(b.data);
    assert(fread(b.data,1,b.len,f)==b.len);fclose(f);return b;
}
static void roundtrip(imk_credential *credential,gss_cred_id_t acceptor){
    imk_exchange *exchange;
    gss_ctx_id_t server=GSS_C_NO_CONTEXT;
    gss_buffer_desc input,output=GSS_C_EMPTY_BUFFER,plain,wrapped=GSS_C_EMPTY_BUFFER;
    imk_buffer token={0},reply={0};
    OM_uint32 major,minor,flags;int complete=0,encrypted=0;uint32_t limit;
    const char payload[]="exact protected bytes";
    assert(imk_exchange_new(credential,"imap/server.test@BOUNDLESS.TEST",&exchange)==0);
    assert(imk_step(exchange,NULL,0,&token,&complete)==0 && !complete && token.len);
    input.length=token.len;input.value=token.data;
    major=gss_accept_sec_context(&minor,&server,acceptor,&input,GSS_C_NO_CHANNEL_BINDINGS,NULL,NULL,&output,&flags,NULL,NULL);
    if(major)fprintf(stderr,"accept failed: %u/%u\n",major,minor);
    assert(major==GSS_S_COMPLETE);
    imk_buffer_free(&token);
    assert(imk_step(exchange,output.value,output.length,&token,&complete)==0 && complete);
    assert(token.len==0);imk_buffer_free(&token);gss_release_buffer(&minor,&output);
    for(int confidential=0;confidential<=1;confidential++){
        assert(imk_wrap_limit(exchange,confidential,65536,&limit)==0 && limit>0 && limit<=65536);
        assert(imk_wrap(exchange,confidential,payload,sizeof(payload),&token)==0);
        input.value=token.data;input.length=token.len;
        assert(gss_unwrap(&minor,server,&input,&output,&encrypted,NULL)==GSS_S_COMPLETE && encrypted==confidential);
        assert(output.length==sizeof(payload)&&memcmp(output.value,payload,sizeof(payload))==0);
        gss_release_buffer(&minor,&output);imk_buffer_free(&token);
        plain.value=(void*)payload;plain.length=sizeof(payload);
        assert(gss_wrap(&minor,server,confidential,GSS_C_QOP_DEFAULT,&plain,&encrypted,&wrapped)==GSS_S_COMPLETE);
        assert(imk_unwrap(exchange,confidential,wrapped.value,wrapped.length,&reply)==0);
        assert(reply.len==sizeof(payload)&&memcmp(reply.data,payload,reply.len)==0);
        imk_buffer_free(&reply);
        assert(imk_unwrap(exchange,confidential,wrapped.value,wrapped.length,&reply)!=0); /* reject replay supplementary status */
        imk_buffer_free(&reply);gss_release_buffer(&minor,&wrapped);
    }
    assert(imk_mic(exchange,payload,sizeof(payload),&token)==0);
    input.value=token.data;input.length=token.len;
    assert(gss_verify_mic(&minor,server,&plain,&input,NULL)==GSS_S_COMPLETE);
    imk_buffer_free(&token);
    imk_exchange_free(exchange);gss_delete_sec_context(&minor,&server,GSS_C_NO_BUFFER);
}
int main(int argc,char **argv){
    imk_credential *credential=NULL;
    imk_buffer keytab,ccache;
    struct transport_state transport={0};
    krb5_context ctx;krb5_keytab server_key;krb5_principal service;
    gss_cred_id_t acceptor=GSS_C_NO_CREDENTIAL;
    OM_uint32 major,minor;int32_t ret;int after_first;
    assert(argc==5);transport.port=atoi(argv[1]);keytab=file(argv[2]);ccache=file(argv[4]);
    assert(krb5_init_runtime_context("BOUNDLESS.TEST",NULL,NULL,&ctx)==0);
    assert(krb5_kt_resolve(ctx,argv[3],&server_key)==0);
    assert(krb5_parse_name(ctx,"imap/server.test@BOUNDLESS.TEST",&service)==0);
    major=gss_krb5_import_cred(&minor,NULL,service,server_key,&acceptor);
    if(major)fprintf(stderr,"import acceptor failed: %u/%u\n",major,minor);
    assert(major==GSS_S_COMPLETE);
    ret=imk_credential_new("user@BOUNDLESS.TEST","BOUNDLESS.TEST",keytab.data,keytab.len,1,3600,io,&transport,&credential);
    if(ret)fprintf(stderr,"credential failed: %d\n",ret);
    assert(ret==0 && transport.calls>0);
    roundtrip(credential,acceptor);after_first=transport.calls;
    roundtrip(credential,acceptor);assert(transport.calls==after_first); /* private cached service ticket */
    imk_credential_free(credential);credential=NULL;
    ret=imk_credential_new("user@BOUNDLESS.TEST","BOUNDLESS.TEST",ccache.data,ccache.len,0,0,io,&transport,&credential);
    assert(ret==0);roundtrip(credential,acceptor);imk_credential_free(credential);credential=NULL;
    transport.calls=0;transport.fail=1;
    assert(imk_credential_new("user@BOUNDLESS.TEST","BOUNDLESS.TEST",keytab.data,keytab.len,1,3600,io,&transport,&credential)!=0);
    assert(credential==NULL && transport.calls==1);
    imk_buffer_free(&keytab);imk_buffer_free(&ccache);
    gss_release_cred(&minor,&acceptor);krb5_free_principal(ctx,service);krb5_kt_close(ctx,server_key);krb5_free_context(ctx);
    puts("keytab, frozen ccache, mutual GSS, cached service ticket, integrity, confidentiality, replay, MIC, exclusive KDC failure: passed");return 0;
}
