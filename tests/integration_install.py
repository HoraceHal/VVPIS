"""Full install smoke test on disposable GitHub-hosted Linux runners only.

ACME is replaced by a local test CA. This is never a production install option.
"""
import contextlib
import ipaddress
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import time
import unittest.mock
import urllib.request


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted':
        raise SystemExit('Refusing full-install test outside a disposable GitHub-hosted runner')
    if os.geteuid() != 0:
        raise SystemExit('Run this CI-only harness with sudo')
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from vvpis import config as c
    from vvpis import installer as i
    # On GitHub-hosted VMs these are disposable, preinstalled web servers.
    for service in ['apache2', 'nginx']:
        subprocess.run(['systemctl', 'stop', service], capture_output=True)
    s = c.new_state('8.8.4.4', '8.8.4.4')
    with tempfile.TemporaryDirectory(prefix='vvpis-ci-ca-') as temp:
        temp = Path(temp)
        def test_certificate(state, email):
            c.CERT.mkdir(parents=True, exist_ok=True)
            key, cert = c.CERT / 'privkey.pem', c.CERT / 'fullchain.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '7',
                '-subj', '/CN=VVPIS-CI-ONLY', '-addext', 'subjectAltName=IP:8.8.4.4',
                '-addext', 'basicConstraints=critical,CA:TRUE', '-keyout', str(key), '-out', str(cert)],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            key.chmod(0o600)
            original_bundle = Path('/etc/ssl/certs/ca-certificates.crt').read_bytes()
            combined = temp / 'combined-ca.pem'
            combined.write_bytes(original_bundle + b'\n' + cert.read_bytes())
            os.environ['SSL_CERT_FILE'] = str(combined)
            i.sync_certificate()
        with unittest.mock.patch.object(i, 'certificate', test_certificate), unittest.mock.patch.object(i, 'info'):
            i.install(Path(__file__).resolve().parents[1], s)
        from vvpis import health
        if not health.main(no_repair=True):
            raise RuntimeError('Installed stack failed local and end-to-end egress checks')
        for kind in ['Trojan', 'Hysteria2']:
            if kind == 'Trojan' and not health.trojan_egress(s):
                raise RuntimeError('Trojan end-to-end test failed')
            if kind == 'Hysteria2' and not health.hysteria_egress(s, c.STATE / 'health'):
                raise RuntimeError('Hysteria2 end-to-end test failed')
        # Native frontend over the real TLS -> Xray fallback -> nginx -> bridge path.
        ctx = ssl.create_default_context()
        with __import__('socket').create_connection(('127.0.0.1', 443), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=s['host']) as connection:
                request = 'GET /sub/' + s['sub_id'] + '?html=1 HTTP/1.1\r\nHost: ' + s['host'] + '\r\nAccept: text/html\r\nConnection: close\r\n\r\n'
                connection.sendall(request.encode())
                body = b''
                while True:
                    block = connection.recv(65536)
                    if not block:
                        break
                    body += block
                if b' 200 ' not in body.split(b'\r\n', 1)[0] or b'window.__SUB_PAGE_DATA__=' not in body:
                    raise RuntimeError('Native frontend TLS/fallback path failed')
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        base = 'http://127.0.0.1:' + str(c.PORTS['bridge'])
        for agent, marker in [('Clash-Verge/2', b'type: hysteria2'), ('Quantumult%20X/1', b'trojan=')]:
            req = urllib.request.Request(base + '/sub/' + s['sub_id'], headers={'User-Agent': agent})
            with opener.open(req, timeout=10) as response:
                if marker not in response.read():
                    raise RuntimeError('Client format test failed')
        for unit in i.UNITS:
            subprocess.run(['systemctl', 'is-active', '--quiet', unit], check=True)
        # Counters should continue to exist independently of removing the services.
        assert (c.STATE / 'subscriptions/identities.db').exists()
        with unittest.mock.patch('builtins.input', return_value=s['host']):
            i.uninstall()
        assert i.STATE_FILE.exists() and (c.STATE / 'x-ui/x-ui.db').exists()
        print(json.dumps({'full_install': True, 'native_https_frontend': True, 'trojan_egress': True,
                          'hysteria_egress': True, 'clash_and_qx': True, 'uninstall_preserves_data': True,
                          'certificate': 'CI-only test CA; public ACME not tested'}))


if __name__ == '__main__':
    main()
