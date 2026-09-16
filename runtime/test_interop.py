"""Owned loopback MIT KDC; no use of the operator's realm, cache or keytabs."""
from pathlib import Path
import os, socket, subprocess, tempfile, time
ROOT=Path(__file__).resolve().parents[1]
BUILD=ROOT/'build'
def run(args,env):
    result=subprocess.run([str(a) for a in args],env=env,capture_output=True,text=True)
    if result.returncode: raise RuntimeError(result.stdout+result.stderr)
    return result
with tempfile.TemporaryDirectory(prefix='boundless-kdc-') as temp:
    p=Path(temp);os.chmod(p,0o700)
    with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
    config=p/'krb5.conf'
    config.write_text(f'''[libdefaults]
 default_realm = BOUNDLESS.TEST
 dns_lookup_kdc = false
 dns_lookup_realm = false
 rdns = false
 dns_canonicalize_hostname = false
[realms]
 BOUNDLESS.TEST = {{
  kdc = 127.0.0.1:{port}
  database_name = {p}/principal
  key_stash_file = {p}/stash
  acl_file = {p}/acl
  admin_keytab = {p}/kadm5.keytab
  max_life = 1d
  max_renewable_life = 0
 }}
[kdcdefaults]
 kdc_listen = 127.0.0.1:{port}
 kdc_tcp_listen = 127.0.0.1:{port}
''')
    env=dict(os.environ,KRB5_CONFIG=str(config),KRB5_KDC_PROFILE=str(config),KRB5CCNAME=f'FILE:{p}/ccache',KRB5RCACHETYPE='none')
    run([BUILD/'kadmin/dbutil/kdb5_util','create','-s','-P','owned-fixture-master-password','-r','BOUNDLESS.TEST'],env)
    for principal in ['user','imap/server.test']:
        run([BUILD/'kadmin/cli/kadmin.local','-r','BOUNDLESS.TEST','-q',f'addprinc -randkey {principal}'],env)
    for principal,name in [('user','user.keytab'),('imap/server.test','server.keytab')]:
        run([BUILD/'kadmin/cli/kadmin.local','-r','BOUNDLESS.TEST','-q',f'ktadd -k {p/name} -norandkey {principal}'],env)
    log=(p/'kdc.log').open('w')
    server=subprocess.Popen([str(BUILD/'kdc/krb5kdc'),'-n','-r','BOUNDLESS.TEST'],env=env,stdout=log,stderr=log)
    try:
        for attempt in range(100):
            if server.poll() is not None: raise RuntimeError((p/'kdc.log').read_text())
            try:
                with socket.create_connection(('127.0.0.1',port),timeout=.1):break
            except OSError:time.sleep(.03)
        else:raise RuntimeError('fixture KDC did not listen')
        run([BUILD/'clients/kinit/kinit','-k','-t',p/'user.keytab','user@BOUNDLESS.TEST'],env)
        # Client must succeed even with a deliberately unusable default profile/cache/keytab.
        client_env=dict(env,KRB5_CONFIG=str(p/'absent-profile'),KRB5_CLIENT_KTNAME='FILE:/does-not-exist',KRB5CCNAME='FILE:/does-not-exist',KRB5_TRACE=str(p/'forbidden.trace'),GSS_MECH_CONFIG=str(p/'absent-mech'))
        result=run([BUILD/'test_runtime_interop',port,p/'user.keytab',f'FILE:{p}/server.keytab',p/'ccache'],client_env)
        print(result.stdout,end='')
        assert not (p/'forbidden.trace').exists()
    finally:
        server.terminate()
        try:server.wait(timeout=5)
        except subprocess.TimeoutExpired:server.kill();server.wait()
        log.close()
