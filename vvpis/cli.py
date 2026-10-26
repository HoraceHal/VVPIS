"""Interactive menu and explicit management commands."""
import argparse
import getpass
import json
import os
import secrets
import sys
from pathlib import Path


def wizard(args):
    from . import installer as i
    from .config import new_state
    i.root()
    if args.resume:
        i.install(Path(__file__).resolve().parent.parent, resume=True)
        return
    if i.STATE_FILE.exists():
        print('已有安装状态，不会重置账号。使用 info 或 install --resume。')
        return
    i.preflight()
    detected = args.public_ip or i.discover_ip()
    public_ip = args.public_ip or input('本机公网 IPv4 [' + detected + ']: ').strip() or detected
    host = args.host or input('前端地址（公网 IPv4 或已解析的子域名）[' + public_ip + ']: ').strip() or public_ip
    email = args.email if args.email is not None else input('证书通知邮箱（推荐，回车跳过）: ').strip()
    bandwidth = args.bandwidth or int(input('公网共享带宽 Mbps [200]: ').strip() or '200')
    ssh_parts = os.environ.get('SSH_CONNECTION', '').split()
    default_ssh = int(ssh_parts[3]) if len(ssh_parts) == 4 else 22
    if len(ssh_parts) != 4:
        import subprocess, re
        result = subprocess.run(['/usr/sbin/sshd', '-T'], capture_output=True, text=True)
        match = re.search(r'^port (\d+)$', result.stdout, re.M)
        if match:
            default_ssh = int(match[1])
    ssh_port = args.ssh_port or int(input('当前 SSH 端口 [' + str(default_ssh) + ']: ').strip() or str(default_ssh))
    members = args.users or int(input('用户数量（1–20，含主用户）[1]: ').strip() or '1')
    if not 1 <= members <= 20:
        raise ValueError('用户数量需在 1–20 之间')
    state = new_state(host, public_ip, bandwidth, ssh_port)
    state['email'] = email
    state['members'] = [dict(name='member-' + str(n), password=secrets.token_urlsafe(32),
                            sub_id=secrets.token_hex(24)) for n in range(2, members + 1)]
    i.ports(state)
    print('\n即将安装原版 3x-ui 前端、Trojan、Hysteria2 和本机订阅/出口服务。')
    print('默认服务器直出；机场备用可在安装后通过菜单导入。账号默认不限额、不设到期。')
    if not args.yes and input('确认这是一台独立新服务器，输入 INSTALL 开始: ').strip() != 'INSTALL':
        print('已取消，未安装。')
        return
    i.install(Path(__file__).resolve().parent.parent, state, email=email)


def menu():
    from . import installer as i
    while True:
        print('''
┌──────────────────────────────────────┐
│               VVPIS                  │
├──────────────────────────────────────┤
│ 1  安装到独立新服务器                 │
│ 2  继续未完成的安装                   │
│ 3  查看前端、后台、订阅与账号         │
│ 4  查看需要开放的端口                 │
│ 5  健康检查与运行状态                 │
│ 6  固定服务器直出                     │
│ 7  配置服务器优先、机场备用           │
│ 8  检查/续期 HTTPS 证书               │
│ 9  清理安装缓存和旧归档日志           │
│ 10 卸载服务（保留账号与统计）         │
│ 0  退出                               │
└──────────────────────────────────────┘''')
        value = input('请选择: ').strip()
        if value == '0':
            return
        try:
            if value in ['1', '2']:
                parser = make_parser()
                wizard(parser.parse_args(['install'] + (['--resume'] if value == '2' else [])))
            elif value == '3':
                i.info()
            elif value == '4':
                i.ports()
            elif value == '5':
                from .health import main as health
                health(no_repair=True)
            elif value == '6':
                i.change_mode('direct')
            elif value == '7':
                old = i.read_state()
                print('请输入有权使用的 HTTPS Clash/Mihomo 订阅；回车沿用已保存地址。')
                url = getpass.getpass('机场订阅（隐藏输入）: ').strip()
                if not url and not old.get('airport_url'):
                    print('未提供订阅，已取消。')
                    continue
                i.change_mode('hybrid', url or None)
            elif value == '8':
                i.run(['systemctl', 'start', 'vvpis-cert-renew.service'], timeout=300)
                print('证书续期检查完成；未到续期时间时不会重复申请。')
            elif value == '9':
                i.cleanup()
            elif value == '10':
                i.uninstall()
            else:
                print('无效选项。')
        except (OSError, ValueError, RuntimeError) as error:
            print('操作未完成: ' + str(error))


def make_parser():
    parser = argparse.ArgumentParser(description='VVPIS private proxy installer')
    commands = parser.add_subparsers(dest='command')
    install = commands.add_parser('install', help='安装或继续安装')
    for name in ['host', 'public-ip', 'email']:
        install.add_argument('--' + name)
    for name in ['bandwidth', 'ssh-port', 'users']:
        install.add_argument('--' + name, type=int)
    install.add_argument('--yes', action='store_true')
    install.add_argument('--resume', action='store_true')
    for name in ['info', 'ports', 'doctor', 'renew', 'cert-sync', 'cleanup', 'uninstall']:
        commands.add_parser(name)
    mode = commands.add_parser('mode')
    mode.add_argument('value', choices=['direct', 'hybrid'])
    mode.add_argument('--airport-stdin', action='store_true', help='从标准输入读取私密订阅地址')
    return parser


def main(argv=None):
    args = make_parser().parse_args(argv)
    if not args.command:
        menu()
        return
    from . import installer as i
    if args.command == 'install':
        wizard(args)
    elif args.command == 'info':
        i.info()
    elif args.command == 'ports':
        i.ports()
    elif args.command == 'doctor':
        from .health import main as health
        raise SystemExit(0 if health(no_repair=True) else 1)
    elif args.command == 'renew':
        i.root()
        i.run(['systemctl', 'start', 'vvpis-cert-renew.service'], timeout=300)
    elif args.command == 'cert-sync':
        i.sync_certificate()
    elif args.command == 'cleanup':
        i.cleanup()
    elif args.command == 'uninstall':
        i.uninstall()
    elif args.command == 'mode':
        i.change_mode(args.value, sys.stdin.readline().strip() if args.airport_stdin else None)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\n已取消；如已进入安装阶段，可用 install --resume 继续。', file=sys.stderr)
        raise SystemExit(130)
    except (OSError, ValueError, RuntimeError) as error:
        print('VVPIS: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
