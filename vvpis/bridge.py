#!/usr/bin/env python3
"""Add Hysteria2 to authenticated subscriptions without sharing a server-wide password."""
import base64
import contextlib
import hashlib
import hmac
import json
import os
import pathlib
import re
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import yaml

CONFIG = pathlib.Path(os.environ.get('VVPIS_CONFIG_DIR', '/etc/vvpis')) / 'bridge.json'
STATE = pathlib.Path(os.environ.get('VVPIS_STATE_DIR', '/var/lib/vvpis')) / 'subscriptions/identities.db'
SID_PATTERN = r'[A-Za-z0-9_-]{16,128}'


class Bridge:
    def __init__(self, config, state=STATE):
        self.config, self.state = config, state
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.lock = threading.RLock()
        self.cache = {}
        self.online = {}
        self.online_updated = 0
        with self.db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS identities (id TEXT PRIMARY KEY, sid TEXT UNIQUE NOT NULL)')
            db.execute('''CREATE TABLE IF NOT EXISTS traffic (
                id TEXT PRIMARY KEY, epoch TEXT NOT NULL, last_tx INTEGER NOT NULL,
                last_rx INTEGER NOT NULL, total_tx INTEGER NOT NULL, total_rx INTEGER NOT NULL,
                last_activity INTEGER NOT NULL)''')

    @contextlib.contextmanager
    def db(self):
        connection = sqlite3.connect(self.state, timeout=5)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def fetch(self, path, headers=None):
        req = urllib.request.Request('http://127.0.0.1:' + str(self.config['ports']['subscription']) + path, headers=headers or {})
        with self.opener.open(req, timeout=6) as response:
            return response.read(2 * 1024 * 1024), response.headers

    def info(self, sid, fresh=False):
        if not re.fullmatch(SID_PATTERN, sid):
            return None
        with self.lock:
            cached = self.cache.get(sid)
            if not fresh and cached and time.monotonic() - cached[0] < 2:
                return cached[1]
        try:
            raw, _ = self.fetch('/sub/' + sid + '?format=info')
            info = json.loads(raw)
            if not isinstance(info, dict) or info.get('sId') != sid:
                return None
        except (OSError, ValueError):
            return None
        with self.lock:
            # Bound memory independently of arbitrary subscription requests.
            if len(self.cache) >= 128:
                self.cache.clear()
            self.cache[sid] = (time.monotonic(), info)
        return info

    @staticmethod
    def eligible(info):
        if not info or not info.get('enabled'):
            return False
        try:
            # Hysteria traffic is separate from x-ui: never bypass a metered quota.
            if int(info.get('totalByte') or 0) > 0:
                return False
            expire = float(info.get('expire') or 0)
            if expire > 1e11:
                expire /= 1000
            return not expire or expire > time.time()
        except (TypeError, ValueError):
            return False

    def token(self, sid):
        signature = hmac.new(self.config['hmac_secret'].encode(), sid.encode(), hashlib.sha256).hexdigest()
        return sid + '.' + signature

    def authenticate(self, auth):
        legacy = self.config.get('legacy_auth')
        if legacy and hmac.compare_digest(auth, legacy):
            return 'legacy-admin'
        match = re.fullmatch('(' + SID_PATTERN + r')\.([0-9a-f]{64})', auth)
        if not match:
            return None
        sid = match[1]
        if not hmac.compare_digest(auth, self.token(sid)) or not self.eligible(self.info(sid)):
            return None
        identity = 'sub-' + hashlib.sha256(sid.encode()).hexdigest()
        with self.db() as db:
            db.execute('INSERT OR IGNORE INTO identities(id,sid) VALUES(?,?)', (identity, sid))
        return identity

    def node(self, sid):
        return {'name': self.config.get('node_name', 'Hysteria2'), 'type': 'hysteria2', 'server': self.config['server'], 'port': 443,
                'password': self.token(sid), 'skip-cert-verify': False,
                'bbr-profile': 'standard', 'sni': self.config['tls_name'], 'udp': True}

    def uri(self, sid):
        return 'hysteria2://' + urllib.parse.quote(self.token(sid), safe='') + '@' + self.config['server'] + ':443/?insecure=0&sni=' + urllib.parse.quote(self.config['tls_name'], safe='') + '#' + self.config.get('node_name', 'Hysteria2')

    @staticmethod
    def subscription_format(path, query, user_agent, accept=''):
        """Negotiate known client formats without sending private URLs to converters."""
        if query.get('html') == ['1'] or query.get('format') == ['info'] or path.startswith('/clash-legacy/'):
            return 'passthrough'
        requested = query.get('target', query.get('format', ['']))[0].lower()
        aliases = {'qx': 'qx', 'quantumult-x': 'qx', 'quantumultx': 'qx',
                   'clash': 'mihomo', 'mihomo': 'mihomo', 'clashmeta': 'mihomo',
                   'raw': 'raw', 'shadowrocket': 'raw', 'v2ray': 'raw', 'v2rayng': 'raw'}
        if requested:
            if requested not in aliases:
                raise ValueError('Unsupported client format')
            return aliases[requested]
        if query.get('view') == ['html'] or ('text/html' in accept.lower() and query.get('view') != ['raw']):
            return 'passthrough'
        if path.startswith(('/clash/', '/mihomo/')):
            return 'mihomo'
        ua = user_agent.lower()
        if re.search(r'quantumult(?:[ /_-]|%20)*x\b|quantumult/', ua):
            return 'qx'
        if any(name in ua for name in ('clash', 'mihomo', 'stash')):
            return 'mihomo'
        return 'raw'

    def quantumult(self, sid):
        raw, headers = self.fetch('/sub/' + sid, {'User-Agent': 'Private-QX-Adapter/2.0', 'Accept': 'text/plain'})
        text = raw.decode('utf-8')
        if '://' not in text:
            text = base64.b64decode(text + '=' * (-len(text) % 4), validate=True).decode('utf-8')
        lines = []
        for line in text.splitlines():
            uri = urllib.parse.urlsplit(line)
            if uri.scheme != 'trojan':
                continue
            query = urllib.parse.parse_qs(uri.query)
            if query.get('security', ['tls'])[0] != 'tls' or query.get('type', ['tcp'])[0] not in ('tcp', 'raw'):
                continue
            host, port = uri.hostname, uri.port or 443
            password = urllib.parse.unquote(uri.username or '')
            sni = query.get('sni', query.get('peer', [host]))[0]
            name = urllib.parse.unquote(uri.fragment) or self.config.get('trojan_name', 'Trojan-TLS')
            if not host or not password or any(any(c in value for c in ',\r\n') for value in (host, password, sni, name)):
                continue
            endpoint = '[' + host + ']' if ':' in host else host
            lines.append(f'trojan={endpoint}:{port}, password={password}, over-tls=true, tls-host={sni}, tls-verification=true, fast-open=false, udp-relay=true, tag={name}')
        if not lines:
            raise ValueError('No compatible Trojan node')
        return ('\n'.join(lines) + '\n').encode('utf-8'), headers

    def transform(self, sid, path, raw, content_type):
        if 'json' in content_type:
            data = json.loads(raw)
            if isinstance(data, dict) and data.get('sId') == sid:
                return json.dumps(self.merge_info(sid, data), ensure_ascii=False).encode(), content_type
        text = raw.decode('utf-8')
        if 'text/html' in content_type:
            # Keep the installed 3x-ui frontend intact. Only enrich its native
            # view-model with the same persisted accounting and node data that
            # the subscription response already provides.
            marker = 'window.__SUB_PAGE_DATA__='
            if marker not in text:
                return raw, content_type
            offset = text.index(marker) + len(marker)
            data, length = json.JSONDecoder().raw_decode(text[offset:])
            if not isinstance(data, dict) or data.get('sId') != sid:
                return raw, content_type
            data = self.merge_info(sid, data)
            if self.eligible(data):
                links = list(data.get('links') or [])
                extra = self.uri(sid)
                if extra not in links:
                    links.append(extra)
                data['links'] = links
            payload = json.dumps(data, ensure_ascii=False, separators=(',', ':'))
            for unsafe, escaped in [('<', r'\u003c'), ('>', r'\u003e'), ('&', r'\u0026'),
                                    ('\u2028', r'\u2028'), ('\u2029', r'\u2029')]:
                payload = payload.replace(unsafe, escaped)
            return (text[:offset] + payload + text[offset + length:]).encode(), content_type
        if not self.eligible(self.info(sid)) or path.startswith('/clash-legacy/'):
            return raw, content_type
        if 'yaml' in content_type or re.search(r'(?m)^proxies:', text):
            data = yaml.safe_load(text)
            if not isinstance(data, dict) or not isinstance(data.get('proxies'), list):
                return raw, content_type
            data['ipv6'] = False
            data['proxies'] = [n for n in data['proxies'] if n.get('name') != self.config.get('node_name', 'Hysteria2')] + [self.node(sid)]
            for group in data.get('proxy-groups', []):
                if group.get('type') in ('select', 'url-test', 'fallback', 'load-balance') and isinstance(group.get('proxies'), list):
                    if self.config.get('node_name', 'Hysteria2') not in group['proxies']:
                        group['proxies'].append(self.config.get('node_name', 'Hysteria2'))
                if group.get('name') == 'PROXY' and self.config.get('trojan_name', 'Trojan-TLS') in group.get('proxies', []):
                    # Keep an authenticated backup; never fall back to DIRECT.
                    group.update(type='fallback', proxies=[self.config.get('node_name', 'Hysteria2'), self.config.get('trojan_name', 'Trojan-TLS')],
                                 url='https://cp.cloudflare.com/generate_204', interval=30,
                                 timeout=8000, lazy=False, **{'expected-status': 204})
            # Complete profiles can carry DNS policy; raw node URIs cannot.
            # This profile's PROXY group has literal-IP first hops, so bootstrap
            # DNS through that group cannot depend on resolving its own node.
            encrypted = ['https://1.1.1.1/dns-query#PROXY', 'https://1.0.0.1/dns-query#PROXY']
            dns = data.setdefault('dns', {})
            dns.update(enable=True, ipv6=bool(data.get('ipv6', False)),
                       **{'enhanced-mode': 'fake-ip', 'prefer-h3': False,
                          'respect-rules': False, 'default-nameserver': encrypted,
                          'proxy-server-nameserver': encrypted, 'nameserver': encrypted,
                          'direct-nameserver': encrypted, 'fallback': [],
                          'nameserver-policy': {}, 'proxy-server-nameserver-policy': {}})
            # Supply capture settings without enabling a device VPN unilaterally.
            tun = data.setdefault('tun', {})
            tun.update(**{'auto-route': True, 'auto-detect-interface': True,
                          'strict-route': True, 'dns-hijack': ['any:53', 'tcp://any:53']})
            routes = tun.setdefault('route-exclude-address', [])
            endpoint = self.config['server'] + '/32'
            if endpoint not in routes:
                routes.append(endpoint)
            return yaml.safe_dump(data, allow_unicode=True, sort_keys=False).encode(), 'application/yaml; charset=utf-8'
        if 'json' in content_type or text.lstrip().startswith(('{', '[')):
            return raw, content_type
        encoded = False
        if '://' not in text:
            try:
                text = base64.b64decode(text + '=' * (-len(text) % 4), validate=True).decode()
                encoded = True
            except (ValueError, UnicodeError):
                return raw, content_type
        if not any(line.startswith(('trojan://', 'vless://', 'vmess://', 'ss://')) for line in text.splitlines()):
            return raw, content_type
        lines = [line for line in text.splitlines() if not (
            line.startswith(('hysteria2://', 'hy2://')) and
            urllib.parse.unquote(urllib.parse.urlsplit(line).fragment) == self.config.get('node_name', 'Hysteria2'))]
        body = ('\n'.join(lines + [self.uri(sid)]) + '\n').encode()
        return (base64.b64encode(body) if encoded else body), content_type

    def stats(self, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request('http://127.0.0.1:' + str(self.config['ports']['stats']) + path, data=data,
                                     headers={'Authorization': self.config['stats_secret'], 'Content-Type': 'application/json'})
        with self.opener.open(req, timeout=3) as response:
            raw = response.read(1024 * 1024)
            return json.loads(raw) if raw else None

    @staticmethod
    def server_epoch():
        # A process generation distinguishes a restart from a repeated sample.
        boot = pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        for pid in pathlib.Path('/sys/fs/cgroup/system.slice/vvpis-hysteria.service/cgroup.procs').read_text().split():
            proc = pathlib.Path('/proc') / pid
            if proc.joinpath('comm').read_text().strip() == 'hysteria':
                ticks = proc.joinpath('stat').read_text().rsplit(')', 1)[1].split()[19]
                return boot + ':' + pid + ':' + ticks
        raise OSError('Hysteria process unavailable')

    def record_traffic(self, snapshot, epoch):
        with self.lock, self.db() as db:
            for identity, values in snapshot.items():
                if not re.fullmatch(r'(sub-[0-9a-f]{64}|legacy-admin)', identity):
                    continue
                tx, rx = int(values.get('tx', 0)), int(values.get('rx', 0))
                if not 0 <= tx < 2**63 or not 0 <= rx < 2**63:
                    continue
                old = db.execute('SELECT epoch,last_tx,last_rx,total_tx,total_rx,last_activity FROM traffic WHERE id=?', (identity,)).fetchone()
                if old:
                    reset = old[0] != epoch or tx < old[1] or rx < old[2]
                    delta_tx, delta_rx = (tx, rx) if reset else (tx - old[1], rx - old[2])
                    if not reset and not delta_tx and not delta_rx:
                        continue
                    total_tx, total_rx = old[3] + delta_tx, old[4] + delta_rx
                    active = int(time.time() * 1000) if delta_tx or delta_rx else old[5]
                else:
                    total_tx, total_rx, active = tx, rx, int(time.time() * 1000) if tx or rx else 0
                db.execute('INSERT OR REPLACE INTO traffic VALUES(?,?,?,?,?,?,?)',
                           (identity, epoch, tx, rx, total_tx, total_rx, active))

    def collect_traffic(self):
        epoch = self.server_epoch()
        snapshot = self.stats('/traffic')  # Never clear the producer's counters.
        if epoch == self.server_epoch() and isinstance(snapshot, dict):
            self.record_traffic(snapshot, epoch)

    def usage(self, sid):
        identities = ['sub-' + hashlib.sha256(sid.encode()).hexdigest()]
        if hashlib.sha256(sid.encode()).hexdigest() == self.config.get('owner_hash'):
            identities.append('legacy-admin')
        with self.lock, self.db() as db:
            rows = [db.execute('SELECT total_tx,total_rx,last_activity FROM traffic WHERE id=?', (identity,)).fetchone() for identity in identities]
            rows = [row for row in rows if row]
            return {'up': sum(row[0] for row in rows), 'down': sum(row[1] for row in rows),
                    'last_online': max((row[2] for row in rows), default=0),
                    'online': time.monotonic() - self.online_updated < 15 and any(self.online.get(identity) for identity in identities),
                    'persistent': True}

    @staticmethod
    def byte_label(value):
        number = float(value)
        for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB'):
            if number < 1024 or unit == 'TiB':
                return ('%.2f' % number).rstrip('0').rstrip('.') + ' ' + unit
            number /= 1024

    def merge_info(self, sid, info):
        usage = self.usage(sid)
        result = dict(info)
        result['uploadByte'] = int(info.get('uploadByte', 0)) + usage['up']
        result['downloadByte'] = int(info.get('downloadByte', 0)) + usage['down']
        for label, key in [('upload', 'uploadByte'), ('download', 'downloadByte')]:
            result[label] = self.byte_label(result[key])
        result['used'] = self.byte_label(result['uploadByte'] + result['downloadByte'])
        if int(info.get('totalByte') or 0) > 0:
            result['remained'] = self.byte_label(max(0, int(info['totalByte']) - result['uploadByte'] - result['downloadByte']))
        result['isOnline'] = bool(info.get('isOnline') or usage['online'])
        result['lastOnline'] = max(int(info.get('lastOnline') or 0), usage['last_online'])
        result['trafficScope'] = 'Trojan + Hysteria2; persisted since this installation'
        return result

    def revoke_disabled(self):
        online = self.stats('/online')
        if not isinstance(online, dict):
            return
        with self.lock:
            self.online, self.online_updated = online, time.monotonic()
        with self.db() as db:
            identities = dict(db.execute('SELECT id,sid FROM identities'))
        kick = []
        for identity, count in online.items():
            if not count:
                continue
            if identity == 'legacy-admin':
                if not self.config.get('legacy_auth'):
                    kick.append(identity)
            elif identity in identities and not self.eligible(self.info(identities[identity], fresh=True)):
                kick.append(identity)
        if kick:
            self.stats('/kick', kick)

    def revocation_loop(self):
        while True:
            for operation in (self.collect_traffic, self.revoke_disabled):
                try:
                    operation()
                except (OSError, ValueError, sqlite3.Error):
                    # Authentication still fails closed; one failed sample cannot stop revocation.
                    pass
            time.sleep(5)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32
    slots = threading.BoundedSemaphore(16)

    def process_request(self, request, address):
        request.settimeout(10)
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


class Handler(BaseHTTPRequestHandler):
    server_version = ''
    sys_version = ''

    def log_message(self, *_):
        pass

    def send_body(self, status, body, content_type='application/json; charset=utf-8', headers=None, head=False):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Vary', 'User-Agent, Accept')
        self.send_header('X-Content-Type-Options', 'nosniff')
        for name in ['Subscription-Userinfo', 'Profile-Update-Interval', 'Profile-Title', 'Profile-Web-Page-Url', 'Content-Disposition']:
            if headers and headers.get(name):
                self.send_header(name, headers[name])
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def do_POST(self):
        if self.path != '/auth':
            self.send_body(404, b'{}')
            return
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= 4096:
                raise ValueError()
            data = json.loads(self.rfile.read(size))
            identity = self.server.bridge.authenticate(data.get('auth', ''))
            self.send_body(200, json.dumps({'ok': bool(identity), 'id': identity or ''}).encode())
        except (OSError, ValueError, TypeError, AttributeError):
            self.send_body(200, b'{"ok":false,"id":""}')

    def do_HEAD(self):
        self.subscription(True)

    def do_GET(self):
        self.subscription(False)

    def subscription(self, head):
        split = urllib.parse.urlsplit(self.path)
        usage = re.fullmatch(r'/usage/(' + SID_PATTERN + ')', split.path)
        if usage:
            if self.server.bridge.info(usage[1]):
                self.send_body(200, json.dumps(self.server.bridge.usage(usage[1])).encode(), head=head)
            else:
                self.send_body(404, b'{}', head=head)
            return
        match = re.fullmatch(r'/(sub|clash|mihomo|clash-legacy)/(' + SID_PATTERN + ')', split.path)
        if not match:
            self.send_body(404, b'{}', head=head)
            return
        try:
            headers = {k: self.headers[k] for k in ['User-Agent', 'Accept'] if self.headers.get(k)}
            try:
                query = urllib.parse.parse_qs(split.query)
                kind = self.server.bridge.subscription_format(split.path, query, headers.get('User-Agent', ''), headers.get('Accept', ''))
            except ValueError:
                self.send_body(400, b'{"error":"unsupported target; use qx, mihomo, or raw"}', head=head)
                return
            if kind == 'qx':
                raw, upstream_headers = self.server.bridge.quantumult(match[2])
                content_type = 'text/plain; charset=utf-8'
            else:
                upstream_path = self.path if kind == 'passthrough' else '/' + ('mihomo' if kind == 'mihomo' else 'sub') + '/' + match[2]
                if kind == 'raw':
                    headers = {'User-Agent': 'Private-Universal-Adapter/2.0', 'Accept': 'text/plain'}
                elif kind == 'mihomo':
                    # Native frontend download buttons use ?view=raw. Do not
                    # let a browser's Accept header turn a YAML download into HTML.
                    headers['Accept'] = 'text/plain'
                    if query.get('view') == ['raw']:
                        upstream_path += '?view=raw'
                raw, upstream_headers = self.server.bridge.fetch(upstream_path, headers)
                content_type = upstream_headers.get('Content-Type', 'text/plain; charset=utf-8')
                raw, content_type = self.server.bridge.transform(match[2], upstream_path.split('?')[0], raw, content_type)
            # Subscription headers and the page must report the same combined usage.
            upstream_headers = dict(upstream_headers)
            upstream_headers['Profile-Web-Page-Url'] = 'https://' + self.server.bridge.config['public_host'] + '/sub/' + match[2] + '?html=1'
            info = self.server.bridge.info(match[2])
            if info and upstream_headers.get('Subscription-Userinfo'):
                combined = self.server.bridge.merge_info(match[2], info)
                value = upstream_headers['Subscription-Userinfo']
                value = re.sub(r'(?<=upload=)\d+', str(combined['uploadByte']), value)
                upstream_headers['Subscription-Userinfo'] = re.sub(r'(?<=download=)\d+', str(combined['downloadByte']), value)
            self.send_body(200, raw, content_type, upstream_headers, head)
        except urllib.error.HTTPError as error:
            self.send_body(404 if error.code in (400, 404) else 502, b'{}', head=head)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            self.send_body(502, b'{"error":"subscription unavailable"}', head=head)


if __name__ == '__main__':
    bridge = Bridge(json.loads(CONFIG.read_text()))
    server = Server(('127.0.0.1', bridge.config['ports']['bridge']), Handler)
    server.bridge = bridge
    threading.Thread(target=bridge.revocation_loop, daemon=True).start()
    server.serve_forever()
