"""Host installer and management operations. Called explicitly by the CLI only."""
import contextlib
import getpass
import http.cookiejar
import ipaddress
import json
import os
import platform
import pwd
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from . import config as c
from .fetch import install_binaries, request

STATE_FILE = c.CONFIG / 'state.json'
UNITS = ['vvpis-panel', 'vvpis-gateway', 'vvpis-subscriptions', 'vvpis-hysteria']


def root():
    if os.geteuid() != 0:
        raise RuntimeError('请使用 sudo bash install.sh 或 sudo vvpis')


def read_state():
    s = json.loads(STATE_FILE.read_text())
    if s.get('schema') != 1:
        raise RuntimeError('未知的安装状态格式')
    return s


def atomic(path, content, mode=0o600, owner=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise RuntimeError('拒绝覆盖符号链接: ' + str(path))
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content.encode() if isinstance(content, str) else content)
        os.chmod(name, mode)
        if owner:
            person = pwd.getpwnam(owner)
            os.chown(name, 0, person.pw_gid)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def save_state(s):
    atomic(STATE_FILE, json.dumps(s, ensure_ascii=False, indent=2) + '\n')


def run(args, *, env=None, cwd=None, timeout=600, quiet=True):
    result = subprocess.run([str(x) for x in args], env=env, cwd=cwd,
                            capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        # Never echo argv: it can contain a password or a private subscription URL.
        message = result.stderr[-1000:] if result.stderr else result.stdout[-1000:]
        if STATE_FILE.exists():
            s = read_state()
            for key in ['password', 'trojan_password', 'sub_id', 'hmac_secret', 'stats_secret',
                        'gateway_password', 'controller_secret', 'airport_url']:
                if s.get(key):
                    message = message.replace(s[key], '[redacted]')
        raise RuntimeError(Path(str(args[0])).name + ' 执行失败: ' + message.strip())
    if not quiet:
        print(result.stdout)
    return result.stdout.strip()


def discover_ip():
    for url in ['https://api.ipify.org?format=json', 'https://api4.ipify.org?format=json']:
        try:
            value = json.loads(request(url, 1024))['ip']
            if ipaddress.ip_address(value).version == 4:
                return c.host_name(value)
        except Exception:
            pass
    return ''


def preflight(resume=False):
    root()
    if sys.platform != 'linux' or not Path('/run/systemd/system').exists():
        raise RuntimeError('需要使用 systemd 的 Ubuntu 22.04/24.04/26.04 或 Debian 12/13')
    os_info = {}
    for line in Path('/etc/os-release').read_text().splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            os_info[key] = value.strip('"')
    supported = {'ubuntu': ['22.04', '24.04', '26.04'], 'debian': ['12', '13']}
    if os_info.get('VERSION_ID') not in supported.get(os_info.get('ID'), []):
        raise RuntimeError('当前系统版本不在支持范围；请使用干净的受支持系统')
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    if not arch:
        raise RuntimeError('仅支持 amd64 和 arm64')
    if sys.version_info < (3, 10):
        raise RuntimeError('需要 Python 3.10 或更高版本')
    if Path('/etc/x-ui/x-ui.db').exists() or Path('/www/server/panel').exists():
        raise RuntimeError('检测到已有 3x-ui/宝塔；请使用独立新服务器，脚本不会覆盖现有站点')
    if not resume:
        if c.LIB.exists() or STATE_FILE.exists():
            raise RuntimeError('检测到已有 VVPIS；使用管理菜单或 install --resume，不重新生成凭证')
        for name, kind, address, port in [('HTTP', socket.SOCK_STREAM, '0.0.0.0', 80),
                ('HTTPS/Trojan', socket.SOCK_STREAM, '0.0.0.0', 443),
                ('Hysteria2', socket.SOCK_DGRAM, '0.0.0.0', 443)] + [
                (key, socket.SOCK_STREAM, '127.0.0.1', value) for key, value in c.PORTS.items()]:
            with socket.socket(socket.AF_INET, kind) as listener:
                try:
                    listener.bind((address, port))
                except OSError:
                    raise RuntimeError(f'{name} 的 {address}:{port} 已占用；未修改现有服务') from None
        enabled = Path('/etc/nginx/sites-enabled')
        if enabled.exists() and any(p.name != 'default' for p in enabled.iterdir()):
            raise RuntimeError('检测到已有 Nginx 站点；请使用独立新服务器')
    elif not STATE_FILE.exists() or not c.LIB.joinpath('versions.json').exists():
        raise RuntimeError('没有可继续的 VVPIS 安装状态')
    mem_kib = int(re.search(r'MemTotal:\s+(\d+)', Path('/proc/meminfo').read_text())[1])
    if mem_kib < 700000:
        raise RuntimeError('内存不足，建议至少 1GiB，推荐 2GiB')
    if shutil.disk_usage('/').free < 2 * 1024**3:
        raise RuntimeError('可用磁盘不足 2GiB')
    return arch


def install_packages(project):
    env = dict(os.environ, DEBIAN_FRONTEND='noninteractive')
    print('安装基础组件…', flush=True)
    run(['apt-get', '-o', 'DPkg::Lock::Timeout=90', 'update', '-qq'], env=env)
    run(['apt-get', '-o', 'DPkg::Lock::Timeout=90', 'install', '-y', '-qq',
         'nginx', 'python3', 'python3-venv', 'python3-yaml', 'ca-certificates',
         'curl', 'openssl', 'iproute2'], env=env)
    if not Path('/opt/vvpis-certbot/bin/certbot').exists():
        run([sys.executable, '-m', 'venv', '/opt/vvpis-certbot'])
    version = json.loads((project / 'versions.json').read_text())['certbot']
    run(['/opt/vvpis-certbot/bin/python', '-m', 'pip', 'install', '--quiet', 'certbot==' + version])


def make_users():
    c.CONFIG.mkdir(mode=0o711, parents=True, exist_ok=True)
    c.CONFIG.chmod(0o711)
    c.STATE.mkdir(mode=0o711, parents=True, exist_ok=True)
    c.STATE.chmod(0o711)
    for suffix, state_dir in [('subscriptions', 'subscriptions'), ('gateway', 'gateway'), ('hysteria', 'hysteria')]:
        name = 'vvpis-' + suffix
        try:
            person = pwd.getpwnam(name)
        except KeyError:
            run(['useradd', '--system', '--user-group', '--no-create-home', '--home-dir', str(c.STATE / state_dir),
                 '--shell', '/usr/sbin/nologin', name])
            person = pwd.getpwnam(name)
        directory = c.STATE / state_dir
        directory.mkdir(mode=0o700, exist_ok=True)
        os.chown(directory, person.pw_uid, person.pw_gid)
        directory.chmod(0o700)
    for name in ['x-ui', 'x-ui/logs', 'health']:
        (c.STATE / name).mkdir(mode=0o700, exist_ok=True)


def copy_project(project):
    if project.resolve() == c.LIB.resolve():
        return
    c.LIB.mkdir(parents=True, exist_ok=True)
    for name in ['vvpis', 'versions.json']:
        source, dest = project / name, c.LIB / name
        if source.is_dir():
            shutil.copytree(source, dest, dirs_exist_ok=True, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        else:
            shutil.copyfile(source, dest)
    atomic('/usr/local/bin/vvpis', '#!/bin/sh\ncd /usr/local/lib/vvpis\nexec /usr/bin/python3 -m vvpis.cli "$@"\n', 0o755)


def dump_yaml(value):
    import yaml
    return yaml.safe_dump(value, allow_unicode=True, sort_keys=False)


def sync_certificate():
    root()
    cert = c.CERT / 'fullchain.pem'
    key = c.CERT / 'privkey.pem'
    run(['openssl', 'x509', '-in', cert, '-noout', '-checkend', '86400'])
    destination = c.STATE / 'hysteria/tls'
    destination.mkdir(mode=0o750, parents=True, exist_ok=True)
    group = pwd.getpwnam('vvpis-hysteria').pw_gid
    os.chown(destination, 0, group)
    for source, name in [(cert, 'cert.pem'), (key, 'key.pem')]:
        atomic(destination / name, source.read_bytes(), 0o640, 'vvpis-hysteria')
    # Hysteria reloads file certificates on new handshakes; Xray reloads them
    # periodically when oneTimeLoading=false. Do not restart working tunnels.


def certificate(s, email):
    args = ['/opt/vvpis-certbot/bin/certbot', 'certonly', '--webroot', '-w', '/var/www/vvpis-acme',
            '--cert-name', 'vvpis', '--non-interactive', '--agree-tos']
    args += ['--email', email] if email else ['--register-unsafely-without-email']
    try:
        ipaddress.ip_address(s['host'])
        args += ['--preferred-profile', 'shortlived', '--ip-address', s['host']]
    except ValueError:
        ips = {item[4][0] for item in socket.getaddrinfo(s['host'], 80, socket.AF_INET)}
        if s['public_ip'] not in ips:
            raise RuntimeError('域名 A 记录没有指向本机公网 IP；请使用 DNS-only 解析后重试')
        # A wrong AAAA record makes ACME validation fail even when A is correct.
        try:
            ipv6 = socket.getaddrinfo(s['host'], 80, socket.AF_INET6)
        except socket.gaierror:
            ipv6 = []
        if ipv6:
            raise RuntimeError('当前部署只使用 IPv4；请移除该子域名的 AAAA 记录后重试')
        args += ['-d', s['host']]
    print('申请受信任 HTTPS 证书，请确保云防火墙放行 TCP 80…', flush=True)
    try:
        run(args, timeout=240)
    except RuntimeError:
        raise RuntimeError('证书申请失败。检查公网 TCP 80、A/AAAA 解析、云安全组；修复后选择继续安装。不会降级到不受信任证书。') from None
    sync_certificate()


def write_nginx(s):
    Path('/var/www/vvpis-acme/.well-known/acme-challenge').mkdir(parents=True, exist_ok=True)
    atomic('/var/www/vvpis/index.html', '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Edge Service</title><style>body{font:18px system-ui;margin:12vh auto;max-width:480px;padding:24px;color:#526070}h1{color:#24304a}</style><h1>Edge Service</h1><p>Service operational.</p></html>', 0o644)
    atomic('/etc/nginx/sites-available/vvpis', c.nginx(s), 0o644)
    default = Path('/etc/nginx/sites-enabled/default')
    if default.is_symlink() and default.resolve() == Path('/etc/nginx/sites-available/default'):
        default.unlink()
    enabled = Path('/etc/nginx/sites-enabled/vvpis')
    if not enabled.exists():
        enabled.symlink_to('/etc/nginx/sites-available/vvpis')
    run(['nginx', '-t'])
    run(['systemctl', 'enable', '--now', 'nginx'])
    run(['systemctl', 'reload', 'nginx'])


def initialize_panel(s):
    env = dict(os.environ, XUI_DB_FOLDER=str(c.STATE / 'x-ui'), XUI_BIN_FOLDER=str(c.LIB / 'x-ui/bin'))
    run([c.LIB / 'x-ui/x-ui', 'setting', '-username', s['username'], '-password', s['password'],
         '-port', str(c.PORTS['panel']), '-listenIP', '127.0.0.1', '-webBasePath', s['panel_path']],
        env=env, cwd=c.LIB / 'x-ui')
    database = c.STATE / 'x-ui/x-ui.db'
    with sqlite3.connect(database, timeout=15) as db:
        for key, value in c.xui_settings(s).items():
            if db.execute('SELECT 1 FROM settings WHERE key=?', (key,)).fetchone():
                db.execute('UPDATE settings SET value=? WHERE key=?', (value, key))
            else:
                db.execute('INSERT INTO settings(key,value) VALUES(?,?)', (key, value))


def services(s):
    atomic(c.CONFIG / 'bridge.json', json.dumps(c.bridge_config(s)), 0o640, 'vvpis-subscriptions')
    atomic(c.CONFIG / 'gateway.yaml', dump_yaml(c.gateway(s)), 0o640, 'vvpis-gateway')
    atomic(c.CONFIG / 'hysteria.yaml', dump_yaml(c.hysteria(s)), 0o640, 'vvpis-hysteria')
    units = {
        'vvpis-gateway': c.service(f'{c.LIB}/mihomo -d {c.STATE}/gateway -f {c.CONFIG}/gateway.yaml',
                                   'vvpis-gateway', state_dir='gateway', memory='192M'),
        'vvpis-panel': c.service(f'{c.LIB}/x-ui/x-ui', after='vvpis-gateway.service', memory='256M').replace('ReadWritePaths=' + str(c.STATE), 'ReadWritePaths=' + str(c.LIB / 'x-ui/bin') + ' ' + str(c.STATE)),
        'vvpis-subscriptions': c.service('/usr/bin/python3 -m vvpis.bridge', 'vvpis-subscriptions',
                                          after='vvpis-panel.service', state_dir='subscriptions', memory='96M'),
        'vvpis-hysteria': c.service(f'{c.LIB}/hysteria server -c {c.CONFIG}/hysteria.yaml', 'vvpis-hysteria',
                                     after='vvpis-subscriptions.service vvpis-gateway.service nginx.service',
                                     state_dir='hysteria', memory='256M')}
    # Python modules live in LIB, independently from per-service state directories.
    for name, unit in units.items():
        unit = unit.replace('Environment=GOMEMLIMIT=128MiB', 'Environment=GOMEMLIMIT=128MiB\nEnvironment=PYTHONPATH=' + str(c.LIB))
        atomic('/etc/systemd/system/' + name + '.service', unit, 0o644)
    atomic('/etc/systemd/system/vvpis-health.service', f'''[Unit]
Description=VVPIS bounded health check and local recovery
After=network-online.target
[Service]
Type=oneshot
WorkingDirectory={c.LIB}
ExecStart=/usr/bin/python3 -m vvpis.health
TimeoutStartSec=110
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths={c.STATE}/health
''', 0o644)
    atomic('/etc/systemd/system/vvpis-health.timer', '[Unit]\nDescription=VVPIS health timer\n[Timer]\nOnBootSec=3min\nOnUnitActiveSec=2min\nRandomizedDelaySec=10\n[Install]\nWantedBy=timers.target\n', 0o644)
    atomic('/etc/systemd/system/vvpis-cert-renew.service', '[Unit]\nDescription=VVPIS certificate renewal\nAfter=network-online.target nginx.service\n[Service]\nType=oneshot\nExecStart=/opt/vvpis-certbot/bin/certbot renew --cert-name vvpis --quiet --no-random-sleep-on-renew --deploy-hook "/usr/local/bin/vvpis cert-sync"\n', 0o644)
    atomic('/etc/systemd/system/vvpis-cert-renew.timer', '[Unit]\nDescription=VVPIS hourly certificate check\n[Timer]\nOnCalendar=hourly\nRandomizedDelaySec=600\nPersistent=true\n[Install]\nWantedBy=timers.target\n', 0o644)
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', '--now', *UNITS])


def wait_port(port, timeout=25):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=1):
                return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError('本地服务端口未就绪: ' + str(port))


def create_inbound(s):
    wait_port(c.PORTS['panel'])
    api_base = 'http://127.0.0.1:' + str(c.PORTS['panel']) + s['panel_path'].rstrip('/')
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(jar))
    def csrf():
        return json.load(opener.open(api_base + '/csrf-token', timeout=10))['obj']
    token = csrf()
    login = urllib.request.Request(api_base + '/login',
        data=urllib.parse.urlencode({'username': s['username'], 'password': s['password']}).encode(),
        headers={'X-CSRF-Token': token})
    if not json.load(opener.open(login, timeout=10)).get('success'):
        raise RuntimeError('管理后台初始化登录失败')
    token = csrf()
    def api(path, body=None):
        req = urllib.request.Request(api_base + path, data=json.dumps(body).encode() if body is not None else None,
            headers={'Content-Type': 'application/json', 'X-CSRF-Token': token})
        result = json.load(opener.open(req, timeout=20))
        if not result.get('success'):
            raise RuntimeError('管理后台初始化 API 请求失败')
        return result.get('obj')
    existing = api('/panel/api/inbounds/list') or []
    if not any(i.get('port') == 443 and i.get('protocol') == 'trojan' for i in existing):
        body = c.inbound(s)
        settings = json.loads(body['settings'])
        for member in s.get('members', []):
            settings['clients'].append({'password': member['password'], 'email': member['name'], 'enable': True,
                'limitIp': 0, 'totalGB': 0, 'expiryTime': 0, 'subId': member['sub_id'], 'reset': 0})
        body['settings'] = json.dumps(settings)
        api('/panel/api/inbounds/add', body)
    wait_port(c.PORTS['bridge'])
    wait_port(443)
    req = urllib.request.Request('http://127.0.0.1:' + str(c.PORTS['bridge']) + '/sub/' + s['sub_id'] + '?html=1')
    page = urllib.request.urlopen(req, timeout=15).read()
    if b'window.__SUB_PAGE_DATA__=' not in page:
        raise RuntimeError('原版前端检查未通过')


def firewall(s):
    if shutil.which('ufw') and 'Status: active' in run(['ufw', 'status']):
        for port in [str(s['ssh_port']) + '/tcp', '80/tcp', '443/tcp', '443/udp']:
            run(['ufw', 'allow', port])
    # Never reset a firewall, enable a previously inactive firewall, or alter SSH.


def tune():
    data = 'net.core.rmem_max = 16777216\nnet.core.wmem_max = 16777216\nnet.ipv4.tcp_mtu_probing = 1\n'
    try:
        run(['modprobe', 'tcp_bbr'])
        if 'bbr' in run(['sysctl', '-n', 'net.ipv4.tcp_available_congestion_control']):
            data += 'net.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr\n'
    except RuntimeError:
        print('当前内核不能启用 BBR，保留系统拥塞控制。')
    atomic('/etc/sysctl.d/90-vvpis.conf', data, 0o644)
    run(['sysctl', '-p', '/etc/sysctl.d/90-vvpis.conf'])


def install(project, settings=None, email='', resume=False):
    arch = preflight(resume)
    s = read_state() if resume else settings
    if not s:
        raise RuntimeError('缺少安装参数')
    root()
    c.CONFIG.mkdir(mode=0o711, parents=True, exist_ok=True)
    save_state(s)
    copy_project(project)
    try:
        install_packages(project)
        make_users()
        install_binaries(project, c.LIB, arch)
        write_nginx(s)
        firewall(s)
        certificate(s, email or s.get('email', ''))
        initialize_panel(s)
        services(s)
        create_inbound(s)
        tune()
        run(['systemctl', 'enable', '--now', 'vvpis-cert-renew.timer', 'vvpis-health.timer'])
        s['installed'] = True
        save_state(s)
        print('\n安装完成。账号不限额不代表云服务器套餐免费或无限流量。')
        info(s)
    except BaseException:
        print('\n安装没有完成。已保存独立凭证；修正提示的问题后运行 sudo vvpis install --resume。', file=sys.stderr)
        raise


def info(s=None):
    root()
    s = s or read_state()
    links = c.addresses(s)
    print('\n========== VVPIS ==========')
    print('前端页面: ' + links['frontend'])
    print('管理后台: ' + links['backend'])
    print('通用订阅: ' + links['subscription'])
    print('Clash 下载: ' + links['clash'])
    print('管理员账号: ' + s['username'])
    print('管理员密码: ' + s['password'])
    for member in s.get('members', []):
        print(member['name'] + ' 订阅: https://' + s['host'] + '/sub/' + member['sub_id'])
    print('流量配额: 不限额；到期: 不设置；共享带宽参考: ' + str(s['bandwidth']) + 'Mbps')
    print('运行模式: ' + s['mode'])
    print('凭证只保存在本机 /etc/vvpis/state.json (root 0600)，请勿公开。')
    ports(s)


def ports(s=None):
    s = s or (read_state() if STATE_FILE.exists() else {'ssh_port': 22})
    print('\n云防火墙/安全组入站必须放行:')
    print('  TCP ' + str(s['ssh_port']) + '  SSH 管理（保持现有来源限制）')
    print('  TCP 80   HTTPS 证书申请与自动续期')
    print('  TCP 443  Trojan + HTTPS 前端/后台/订阅')
    print('  UDP 443  Hysteria2')
    print('25103–25110、62789 为本机内部服务，禁止在云安全组中开放。')
    print('云防火墙由你在云控制台配置；脚本不会索要云账号密码。')


def change_mode(mode, airport_url=None):
    root()
    s = read_state()
    if airport_url is not None:
        u = urllib.parse.urlsplit(airport_url)
        if u.scheme != 'https' or not u.hostname or u.username or u.password or u.fragment:
            raise ValueError('请输入 HTTPS Clash/Mihomo 订阅 URL，不支持 URL 用户密码认证')
        ip_list = socket.getaddrinfo(u.hostname, u.port or 443)
        if not ip_list or any(not ipaddress.ip_address(item[4][0]).is_global for item in ip_list):
            raise ValueError('机场订阅必须使用公网地址')
        import yaml
        # Validate that it really is a supported local conversion-free provider.
        doc = yaml.safe_load(request(airport_url, 4 * 1024 * 1024))
        if not isinstance(doc, dict) or not isinstance(doc.get('proxies'), list) or not doc['proxies']:
            raise ValueError('机场需提供含 proxies 的 Clash/Mihomo YAML 订阅；不会发送到第三方转换网站')
        s['airport_url'] = airport_url
    if mode == 'hybrid' and not s.get('airport_url'):
        raise ValueError('混合模式需要先导入你有权使用的机场 Clash 订阅')
    s['mode'] = mode
    target = c.CONFIG / 'gateway.yaml'
    old = target.read_bytes()
    atomic(target, dump_yaml(c.gateway(s)), 0o640, 'vvpis-gateway')
    try:
        run([c.LIB / 'mihomo', '-t', '-d', c.STATE / 'gateway', '-f', target])
        req = urllib.request.Request('http://127.0.0.1:' + str(c.PORTS['controller']) + '/configs',
            data=json.dumps({'payload': dump_yaml(c.gateway(s))}).encode(), method='PUT',
            headers={'Authorization': 'Bearer ' + s['controller_secret'], 'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=20) as result:
            if result.status >= 300:
                raise RuntimeError('网关拒绝更新')
    except BaseException:
        atomic(target, old, 0o640, 'vvpis-gateway')
        raise
    save_state(s)
    print('模式已保存: ' + mode + '。已有连接可能继续沿用原出口。')


def cleanup():
    root()
    # Only managed download/cache artifacts; never delete databases or certificates.
    before = shutil.disk_usage('/').free
    run(['apt-get', 'clean'])
    run(['journalctl', '--vacuum-time=7d'])
    after = shutil.disk_usage('/').free
    print('已清理软件包缓存及旧归档日志；可用空间变化约 %.1f MiB。' % ((after - before) / 1024**2))


def uninstall():
    root()
    s = read_state()
    print('卸载会停止 VVPIS 服务；默认保留凭证、证书和用量数据。')
    if input('输入服务器地址确认 ' + s['host'] + ': ').strip() != s['host']:
        print('已取消')
        return
    for name in ['vvpis-health.timer', 'vvpis-health.service', 'vvpis-cert-renew.timer', 'vvpis-cert-renew.service'] + UNITS:
        subprocess.run(['systemctl', 'disable', '--now', name], capture_output=True)
    for name in UNITS + ['vvpis-health', 'vvpis-cert-renew']:
        for suffix in ['.service', '.timer']:
            path = Path('/etc/systemd/system') / (name + suffix)
            if path.is_file() and 'VVPIS' in path.read_text():
                path.unlink()
    for name in ['/etc/nginx/sites-enabled/vvpis', '/etc/nginx/sites-available/vvpis',
                 '/etc/sysctl.d/90-vvpis.conf', '/usr/local/bin/vvpis']:
        path = Path(name)
        if path.exists() or path.is_symlink():
            path.unlink()
    run(['systemctl', 'daemon-reload'])
    run(['nginx', '-t'])
    run(['systemctl', 'reload', 'nginx'])
    print('服务已卸载；/etc/vvpis 与 /var/lib/vvpis 中的数据保留，未卸载共享系统软件。')
