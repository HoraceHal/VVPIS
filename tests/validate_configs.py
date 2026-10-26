"""Validate generated configs using installed binaries, without starting services."""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vvpis import config as c
import yaml


def main():
    binaries = {
        'nginx': os.environ.get('VVPIS_TEST_NGINX', shutil.which('nginx') or 'nginx'),
        'xray': os.environ.get('VVPIS_TEST_XRAY', '/usr/local/x-ui/bin/xray-linux-amd64'),
        'mihomo': os.environ.get('VVPIS_TEST_MIHOMO', '/usr/local/bin/vpn-egress-mihomo'),
    }
    with tempfile.TemporaryDirectory(prefix='vvpis-validation-') as tmp:
        temp = Path(tmp)
        state = c.new_state('vpn.example.com', '8.8.4.4')
        key, cert = temp / 'key.pem', temp / 'cert.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-subj', '/CN=vpn.example.com', '-keyout', str(key), '-out', str(cert)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        template = json.loads(c.xui_settings(state)['xrayTemplateConfig'])
        node = c.inbound(state)
        stream = json.loads(node['streamSettings'])
        stream['tlsSettings']['certificates'][0].update(certificateFile=str(cert), keyFile=str(key))
        template['inbounds'].append({'tag': 'test-trojan', 'listen': '127.0.0.1', 'port': 24443,
            'protocol': 'trojan', 'settings': json.loads(node['settings']), 'streamSettings': stream})
        xray = temp / 'xray.json'
        xray.write_text(json.dumps(template))
        subprocess.run([binaries['xray'], 'run', '-test', '-config', str(xray)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for mode in ['direct', 'hybrid']:
            s = dict(state, mode=mode, airport_url='https://example.com/provider.yaml' if mode == 'hybrid' else '')
            path = temp / ('gateway-' + mode + '.yaml')
            path.write_text(yaml.safe_dump(c.gateway(s)))
            result = subprocess.run([binaries['mihomo'], '-t', '-d', str(temp), '-f', str(path)],
                                    capture_output=True, text=True)
            if result.returncode:
                raise RuntimeError('Mihomo validation failed: ' + result.stderr[-400:] + result.stdout[-400:])
        nginx = temp / 'nginx.conf'
        rendered = c.nginx(state)
        sockets = []
        try:
            for original in ['listen 80;', 'listen 127.0.0.1:' + str(c.PORTS['fallback']) + ' proxy_protocol;', 'listen 127.0.0.1:' + str(c.PORTS['masquerade']) + ';']:
                sock = socket.socket()
                sock.bind(('127.0.0.1', 0))
                sockets.append(sock)
                replacement = 'listen 127.0.0.1:' + str(sock.getsockname()[1]) + (' proxy_protocol;' if 'proxy_protocol' in original else ';')
                rendered = rendered.replace(original, replacement)
        finally:
            for sock in sockets:
                sock.close()
        nginx.write_text('pid ' + str(temp / 'nginx.pid') + ';\nerror_log stderr;\nevents {}\nhttp {\ninclude /etc/nginx/mime.types;\n' + rendered + '\n}\n')
        result = subprocess.run([binaries['nginx'], '-t', '-c', str(nginx), '-p', str(temp)],
                                capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError('Nginx validation failed: ' + result.stderr[-600:])
        print(json.dumps({'xray_config': True, 'mihomo_direct': True, 'mihomo_hybrid': True, 'nginx_config': True,
                          'live_services_modified': False}))


if __name__ == '__main__':
    main()
