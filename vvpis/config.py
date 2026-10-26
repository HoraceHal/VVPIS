"""Pure configuration builders. Importing this module never changes the host."""
import hashlib
import ipaddress
import json
import re
import secrets
from pathlib import Path

PORTS = dict(panel=25103, subscription=25104, bridge=25105, stats=25106,
             gateway=25107, controller=25108, fallback=25109, masquerade=25110, api=62789)
CONFIG = Path('/etc/vvpis')
STATE = Path('/var/lib/vvpis')
LIB = Path('/usr/local/lib/vvpis')
CERT = Path('/etc/letsencrypt/live/vvpis')


def host_name(value):
    value = value.strip().rstrip('.').lower()
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        value = value.encode('idna').decode('ascii')
        if len(value) > 253 or '.' not in value or any(
            not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x)
            for x in value.split('.')):
            raise ValueError('请输入公网 IPv4 或有效完整域名')
        return value
    if address.version != 4 or not address.is_global:
        raise ValueError('需要公网 IPv4；IPv6-only 暂不支持')
    return str(address)


def new_state(host, public_ip, bandwidth=200, ssh_port=22):
    host, public_ip = host_name(host), str(ipaddress.IPv4Address(public_ip))
    if not ipaddress.ip_address(public_ip).is_global:
        raise ValueError('节点地址必须是公网 IPv4')
    if not 1 <= int(bandwidth) <= 100000 or not 1 <= int(ssh_port) <= 65535:
        raise ValueError('带宽或 SSH 端口超出范围')
    return dict(schema=1, host=host, public_ip=public_ip, bandwidth=int(bandwidth),
                ssh_port=int(ssh_port), panel_path='/manage-' + secrets.token_hex(16) + '/',
                username='owner_' + secrets.token_hex(4), password=secrets.token_urlsafe(30),
                sub_id=secrets.token_hex(24), trojan_password=secrets.token_urlsafe(32),
                hmac_secret=secrets.token_hex(32), stats_secret=secrets.token_urlsafe(32),
                gateway_user='vvpis', gateway_password=secrets.token_urlsafe(32),
                controller_secret=secrets.token_urlsafe(32), mode='direct',
                airport_url='', installed=False)


def addresses(s):
    base = 'https://' + s['host']
    return dict(frontend=base + '/sub/' + s['sub_id'] + '?html=1',
                backend=base + s['panel_path'], subscription=base + '/sub/' + s['sub_id'],
                clash=base + '/clash/' + s['sub_id'])


def bridge_config(s):
    return dict(server=s['public_ip'], tls_name=s['host'], public_host=s['host'],
                hmac_secret=s['hmac_secret'], stats_secret=s['stats_secret'],
                owner_hash=hashlib.sha256(s['sub_id'].encode()).hexdigest(),
                node_name='Hysteria2', trojan_name='Trojan-TLS', ports=PORTS)


def xui_settings(s):
    base = 'https://' + s['host']
    template = {'log': {'loglevel': 'warning', 'access': 'none'},
                'api': {'tag': 'api', 'services': ['HandlerService', 'LoggerService', 'StatsService', 'RoutingService']},
                'stats': {}, 'policy': {'levels': {'0': {'statsUserUplink': True, 'statsUserDownlink': True, 'statsUserOnline': True}},
                    'system': {'statsInboundUplink': True, 'statsInboundDownlink': True}},
                'inbounds': [{'tag': 'api', 'listen': '127.0.0.1', 'port': PORTS['api'], 'protocol': 'tunnel',
                    'settings': {'rewriteAddress': '127.0.0.1'}}],
                'outbounds': [{'tag': 'gateway', 'protocol': 'socks', 'settings': {'servers': [
                    {'address': '127.0.0.1', 'port': PORTS['gateway'],
                     'users': [{'user': s['gateway_user'], 'pass': s['gateway_password']}]}]}},
                    {'tag': 'blocked', 'protocol': 'blackhole'}],
                'routing': {'domainStrategy': 'AsIs', 'rules': [
                    {'type': 'field', 'inboundTag': ['api'], 'outboundTag': 'api'},
                    {'type': 'field', 'network': 'tcp,udp', 'outboundTag': 'gateway'}]}}
    return dict(webListen='127.0.0.1', webPort=str(PORTS['panel']), webBasePath=s['panel_path'],
                subEnable='true', subListen='127.0.0.1', subPort=str(PORTS['subscription']),
                subPath='/sub/', subURI=base + '/sub/', subTitle='Private Link', subThemeDir='',
                subClashEnable='true', subClashPath='/clash/', subClashURI=base + '/clash/',
                subClashAutoDetect='true', subJsonEnable='false', subProfileMode='builtin',
                subEncrypt='true', subUpdates='12', remarkTemplate='{{INBOUND}}',
                subClashEnableRouting='true', subClashRules=json.dumps(['MATCH,PROXY']),
                xrayTemplateConfig=json.dumps(template), sessionMaxAge='120',
                timeLocation='UTC', trafficDiff='0', expireDiff='0')


def inbound(s, port=443, listen='0.0.0.0'):
    return dict(enable=True, remark='Trojan-TLS', listen=listen, port=port, protocol='trojan',
                total=0, expiryTime=0,
                settings=json.dumps({'clients': [{'password': s['trojan_password'], 'email': 'owner',
                    'enable': True, 'limitIp': 0, 'totalGB': 0, 'expiryTime': 0,
                    'subId': s['sub_id'], 'reset': 0}],
                    'fallbacks': [{'dest': '127.0.0.1:' + str(PORTS['fallback']), 'xver': 1}]}),
                streamSettings=json.dumps({'network': 'tcp', 'security': 'tls', 'tlsSettings': {
                    'serverName': s['host'], 'minVersion': '1.2', 'maxVersion': '1.3',
                    'alpn': ['http/1.1'], 'rejectUnknownSni': False, 'certificates': [{
                        'certificateFile': str(CERT / 'fullchain.pem'),
                        'keyFile': str(CERT / 'privkey.pem'), 'oneTimeLoading': False}]},
                    'tcpSettings': {'acceptProxyProtocol': False, 'header': {'type': 'none'}}}),
                sniffing=json.dumps({'enabled': False, 'destOverride': ['http', 'tls'], 'routeOnly': True}),
                shareAddr=s['public_ip'], shareAddrStrategy='custom')


def gateway(s):
    probe = dict(url='https://cp.cloudflare.com/generate_204', interval=30,
                 timeout=8000, lazy=False, **{'expected-status': 204})
    data = {'mixed-port': PORTS['gateway'], 'bind-address': '127.0.0.1', 'allow-lan': False,
            'mode': 'rule', 'log-level': 'warning', 'ipv6': False,
            'authentication': [s['gateway_user'] + ':' + s['gateway_password']],
            'external-controller': '127.0.0.1:' + str(PORTS['controller']),
            'secret': s['controller_secret'], 'profile': {'store-selected': False},
            'geodata-loader': 'memconservative', 'proxies': [], 'proxy-groups': [],
            'dns': {'enable': True, 'ipv6': False, 'enhanced-mode': 'redir-host',
                    'default-nameserver': ['1.1.1.1', '1.0.0.1'],
                    'nameserver': ['https://1.1.1.1/dns-query', 'https://1.0.0.1/dns-query']}}
    if s.get('airport_url'):
        data['proxy-providers'] = {'backup': {'type': 'http', 'url': s['airport_url'],
            'path': './providers/backup.yaml', 'interval': 21600,
            'health-check': {'enable': True, 'url': probe['url'], 'interval': 120,
                             'timeout': 8000, 'lazy': False}}}
        data['proxy-groups'] = [dict(name='AIRPORT', type='url-test', use=['backup'], tolerance=150,
            **probe), dict(name='SERVER-FIRST', type='fallback', proxies=['DIRECT', 'AIRPORT'], **probe)]
    choice = 'SERVER-FIRST' if s.get('mode') == 'hybrid' and s.get('airport_url') else 'DIRECT'
    private = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
               '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4', '240.0.0.0/4']
    data['rules'] = ['IP-CIDR,' + net + ',REJECT' for net in private] + ['MATCH,' + choice]
    return data


def hysteria(s):
    return {'listen': ':443', 'tls': {'cert': str(STATE / 'hysteria/tls/cert.pem'),
            'key': str(STATE / 'hysteria/tls/key.pem')},
            'auth': {'type': 'http', 'http': {'url': 'http://127.0.0.1:' + str(PORTS['bridge']) + '/auth'}},
            'trafficStats': {'listen': '127.0.0.1:' + str(PORTS['stats']), 'secret': s['stats_secret']},
            'ignoreClientBandwidth': True, 'congestion': {'type': 'bbr', 'bbrProfile': 'standard'},
            'quic': {'initStreamReceiveWindow': 8388608, 'maxStreamReceiveWindow': 8388608,
                     'initConnReceiveWindow': 20971520, 'maxConnReceiveWindow': 20971520,
                     'maxIdleTimeout': '30s', 'maxIncomingStreams': 1024},
            'outbounds': [{'name': 'gateway', 'type': 'socks5', 'socks5': {
                'addr': '127.0.0.1:' + str(PORTS['gateway']),
                'username': s['gateway_user'], 'password': s['gateway_password']}}],
            'masquerade': {'type': 'proxy', 'proxy': {
                'url': 'http://127.0.0.1:' + str(PORTS['masquerade']), 'rewriteHost': True}}}


def nginx(s):
    host, panel, p = s['host'], s['panel_path'], PORTS
    return f'''limit_req_zone $binary_remote_addr zone=vvpis_sub:1m rate=5r/s;
server {{
 listen 80;
 server_name {host};
 server_tokens off;
 access_log off;
 location ^~ /.well-known/acme-challenge/ {{ root /var/www/vvpis-acme; }}
 location / {{ return 301 https://{host}$request_uri; }}
}}
server {{
 listen 127.0.0.1:{p['masquerade']};
 server_name localhost;
 server_tokens off;
 access_log off;
 root /var/www/vvpis;
 location / {{ try_files /index.html =404; }}
}}
server {{
 listen 127.0.0.1:{p['fallback']} proxy_protocol;
 set_real_ip_from 127.0.0.1;
 real_ip_header proxy_protocol;
 server_name {host};
 server_tokens off;
 access_log off;
 add_header X-Content-Type-Options nosniff always;
 add_header Referrer-Policy no-referrer always;
 add_header X-Robots-Tag "noindex, nofollow" always;
 add_header X-Frame-Options DENY always;
 location = / {{ root /var/www/vvpis; try_files /index.html =404; }}
 location = /robots.txt {{ return 200 "User-agent: *\\nDisallow: /\\n"; }}
 location {panel} {{
  proxy_pass http://127.0.0.1:{p['panel']};
  proxy_http_version 1.1;
  proxy_set_header Host $host;
  proxy_set_header X-Forwarded-Proto https;
  proxy_set_header X-Forwarded-For $remote_addr;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header Upgrade $http_upgrade;
  proxy_set_header Connection "upgrade";
  proxy_read_timeout 300s;
 }}
 location ~ "^/sub/assets/[A-Za-z0-9][A-Za-z0-9._-]*\\.(js|css|woff2?|ttf|svg|png|webp)$" {{
  limit_except GET HEAD {{ deny all; }}
  proxy_pass http://127.0.0.1:{p['subscription']};
  proxy_hide_header Cache-Control;
  gzip on;
  gzip_comp_level 4;
  gzip_min_length 1024;
  gzip_types application/javascript text/javascript text/css image/svg+xml;
  gzip_vary on;
  add_header Cache-Control "public, max-age=31536000, immutable";
  add_header X-Content-Type-Options nosniff always;
 }}
 location ~ "^/(sub|clash|mihomo|clash-legacy)/[A-Za-z0-9_-]{{16,128}}$" {{
  limit_req zone=vvpis_sub burst=30 nodelay;
  proxy_pass http://127.0.0.1:{p['bridge']};
  proxy_set_header Host $host;
  proxy_set_header X-Forwarded-Proto https;
  proxy_set_header X-Forwarded-For $remote_addr;
  proxy_hide_header Content-Security-Policy;
  add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'" always;
  add_header Cache-Control no-store always;
  add_header Referrer-Policy no-referrer always;
  add_header X-Robots-Tag "noindex, nofollow" always;
 }}
 location / {{ return 404; }}
}}
'''


def service(command, user=None, after='', state_dir=None, memory='128M'):
    identity = ('User=' + user + '\nGroup=' + user) if user else ''
    directory = ('StateDirectory=vvpis/' + state_dir + '\nStateDirectoryMode=0700') if state_dir else ''
    caps = 'AmbientCapabilities=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE' if user == 'vvpis-hysteria' else ''
    return f'''[Unit]
Description=VVPIS managed service
After=network-online.target {after}
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5
[Service]
Type=simple
ExecStart={command}
Restart=on-failure
RestartSec=3
{identity}
{directory}
WorkingDirectory={STATE / state_dir if state_dir else LIB}
Environment=GOMEMLIMIT=128MiB
Environment=XUI_LOG_FOLDER={STATE / "x-ui/logs"}
Environment=XUI_BIN_FOLDER={LIB / "x-ui/bin"}
Environment=XUI_DB_FOLDER={STATE / 'x-ui'}
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ReadWritePaths={STATE} /etc/vvpis
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
LimitNOFILE=32768
MemoryMax={memory}
UMask=0077
{caps}
[Install]
WantedBy=multi-user.target
'''
