"""Bounded local health recovery; an Internet outage must not trigger restarts."""
import contextlib
import fcntl
import hashlib
import hmac
import json
import os
import shutil
import socket
import sqlite3
import ssl
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from . import config as c


def restart_allowed(history, now):
    history = [t for t in history if now - t < 3600]
    return not history or (now - history[-1] >= 900 and len(history) < 2)


def http_ok(url, marker=None):
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(url, timeout=4) as response:
            body = response.read(1024 * 1024)
            return response.status == 200 and (marker is None or marker in body)
    except Exception:
        return False


def fallback_ok(port):
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=3) as stream:
            stream.sendall(b'PROXY TCP4 127.0.0.1 127.0.0.1 31337 443\r\nGET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
            return b' 200 ' in stream.recv(512).split(b'\r\n', 1)[0]
    except OSError:
        return False


def tls_ok(host):
    try:
        with socket.create_connection(('127.0.0.1', 443), timeout=4) as raw:
            with ssl.create_default_context().wrap_socket(raw, server_hostname=host) as secure:
                expire = ssl.cert_time_to_seconds(secure.getpeercert()['notAfter'])
                return True, round((expire - time.time()) / 3600, 1)
    except Exception:
        return False, 0


def trojan_egress(s):
    # Only this probe is external; failure is informational, never a restart trigger.
    for target in ['cp.cloudflare.com', 'www.gstatic.com']:
        try:
            with socket.create_connection(('127.0.0.1', 443), timeout=5) as raw:
                with ssl.create_default_context().wrap_socket(raw, server_hostname=s['host']) as stream:
                    stream.settimeout(5)
                    domain = target.encode()
                    stream.sendall(hashlib.sha224(s['trojan_password'].encode()).hexdigest().encode() + b'\r\n' +
                        b'\x01\x03' + bytes([len(domain)]) + domain + (80).to_bytes(2, 'big') + b'\r\n' +
                        ('GET /generate_204 HTTP/1.1\r\nHost: ' + target + '\r\nConnection: close\r\n\r\n').encode())
                    if b' 204 ' in stream.recv(2048).split(b'\r\n', 1)[0]:
                        return True
        except Exception:
            pass
    return False


def hysteria_egress(s, folder):
    import tempfile
    import yaml
    with tempfile.TemporaryDirectory(prefix='probe-', dir=folder) as temp:
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        token = s['sub_id'] + '.' + hmac.new(s['hmac_secret'].encode(), s['sub_id'].encode(), hashlib.sha256).hexdigest()
        client = {'server': '127.0.0.1:443', 'auth': token,
                  'tls': {'sni': s['host'], 'insecure': False},
                  'socks5': {'listen': '127.0.0.1:' + str(port)}}
        path = Path(temp) / 'client.yaml'
        path.write_text(yaml.safe_dump(client))
        path.chmod(0o600)
        env = dict(os.environ, GOMEMLIMIT='32MiB')
        process = subprocess.Popen([str(c.LIB / 'hysteria'), 'client', '-c', str(path)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
        try:
            end = time.monotonic() + 6
            while time.monotonic() < end:
                if process.poll() is not None:
                    return False
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=0.3):
                        break
                except OSError:
                    time.sleep(0.15)
            for host in ['cp.cloudflare.com', 'www.gstatic.com']:
                result = subprocess.run(['curl', '--silent', '--output', '/dev/null', '--write-out', '%{http_code}',
                    '--max-time', '5', '--proxy', 'socks5h://127.0.0.1:' + str(port),
                    'http://' + host + '/generate_204'], capture_output=True, text=True, timeout=7)
                if result.returncode == 0 and result.stdout == '204':
                    return True
            return False
        except (OSError, subprocess.TimeoutExpired):
            return False
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

def main(no_repair=False):
    from .installer import STATE_FILE, read_state, atomic, root
    root()
    s = read_state()
    folder = c.STATE / 'health'
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (folder / 'check.lock').open('w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        previous = json.loads((folder / 'state.json').read_text()) if (folder / 'state.json').exists() else {}
        base = 'http://127.0.0.1:'
        checks = {
            'vvpis-panel': http_ok(base + str(c.PORTS['panel']) + s['panel_path']) and
                           http_ok(base + str(c.PORTS['subscription']) + '/sub/' + s['sub_id'] + '?format=info'),
            'vvpis-subscriptions': http_ok(base + str(c.PORTS['bridge']) + '/sub/' + s['sub_id'] + '?format=info'),
            'nginx': fallback_ok(c.PORTS['fallback']),
        }
        try:
            req = urllib.request.Request(base + str(c.PORTS['controller']) + '/version',
                headers={'Authorization': 'Bearer ' + s['controller_secret']})
            with urllib.request.urlopen(req, timeout=4) as response:
                checks['vvpis-gateway'] = response.status == 200
        except Exception:
            checks['vvpis-gateway'] = False
        try:
            req = urllib.request.Request(base + str(c.PORTS['stats']) + '/online',
                headers={'Authorization': s['stats_secret']})
            with urllib.request.urlopen(req, timeout=4) as response:
                checks['vvpis-hysteria'] = response.status == 200
        except Exception:
            checks['vvpis-hysteria'] = False
        certificate, hours = tls_ok(s['host'])
        egress = trojan_egress(s) if certificate else False
        hy2_egress = hysteria_egress(s, folder) if certificate and checks['vvpis-hysteria'] and checks['vvpis-subscriptions'] else False
        # Disabled accounts are intentional. Do not turn that into a local fault.
        try:
            with sqlite3.connect('file:' + str(c.STATE / 'x-ui/x-ui.db') + '?mode=ro', uri=True) as db:
                row = db.execute('SELECT enable FROM clients WHERE sub_id=?', (s['sub_id'],)).fetchone()
                if row is not None and not row[0]:
                    egress = None
                    hy2_egress = None
                    for name in ['vvpis-panel', 'vvpis-subscriptions']:
                        checks[name] = subprocess.run(['systemctl', 'is-active', '--quiet', name]).returncode == 0
        except sqlite3.Error:
            pass
        now, repaired = time.time(), []
        failures = previous.get('failures', {})
        history = previous.get('history', {})
        for unit, good in checks.items():
            failures[unit] = 0 if good else failures.get(unit, 0) + 1
            recent = [v for v in history.get(unit, []) if now - v < 86400]
            history[unit] = recent
            if not good and failures[unit] >= 2 and len(repaired) < 2 and not no_repair and restart_allowed(recent, now):
                history[unit].append(now)
                # Persist the budget before invoking systemd, even if restart fails.
                atomic(folder / 'state.json', json.dumps({'failures': failures, 'history': history}))
                try:
                    result = subprocess.run(['systemctl', 'restart', unit], capture_output=True, timeout=15)
                    repaired.append({'unit': unit, 'ok': result.returncode == 0})
                except subprocess.TimeoutExpired:
                    repaired.append({'unit': unit, 'ok': False})
        disk = shutil.disk_usage('/')
        warnings = []
        if hours < 48:
            warnings.append('certificate_near_expiry')
        if disk.free < 1024**3:
            warnings.append('disk_space_low')
        result = dict(checked_at=now, local_ok=all(checks.values()), egress_ok=egress,
                      certificate_ok=certificate, certificate_hours=hours, hysteria_egress_ok=hy2_egress, warnings=warnings,
                      checks=checks, repaired=repaired, failures=failures, history=history)
        atomic(folder / 'state.json', json.dumps(result))
        print(json.dumps({k: result[k] for k in ['local_ok', 'egress_ok', 'hysteria_egress_ok', 'certificate_ok', 'certificate_hours', 'warnings', 'repaired']}, ensure_ascii=False))
        return result['local_ok'] and certificate and egress is not False and hy2_egress is not False


if __name__ == '__main__':
    main()
