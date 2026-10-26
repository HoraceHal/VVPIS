# VVPIS

[![Checks](https://github.com/HoraceHal/VVPIS/actions/workflows/checks.yml/badge.svg)](https://github.com/HoraceHal/VVPIS/actions/workflows/checks.yml)

用于**独立新 VPS** 的交互式安装与管理脚本。沿用 3x-ui 原版订阅前端，提供 Trojan TLS + Hysteria2、通用订阅、真实用量统计、证书自动续期及可选机场备用。

**复制或 Fork 本仓库，可以在自己的服务器安装。每台服务器会生成独立账号、密钥和订阅，不会获得仓库作者的服务器、机场或凭证。**

## 快速开始

在新服务器的 SSH 终端执行，不能在 Windows 本机执行。推荐先下载查看，再运行：

```bash
curl --proto '=https' --tlsv1.2 -fsSLo vvpis-install.sh https://raw.githubusercontent.com/HoraceHal/VVPIS/main/install.sh
less vvpis-install.sh
sudo bash vvpis-install.sh
```

也可以克隆整个仓库：

```bash
git clone https://github.com/HoraceHal/VVPIS.git
cd VVPIS
sudo bash install.sh
```

若服务器缺少 `curl` 或 `git`，先通过系统软件包管理器安装对应工具。

选择菜单中的「安装到独立新服务器」，按提示填写公网 IPv4、访问地址、邮箱、共享带宽和用户数。访问地址可以直接使用公网 IPv4，也可以使用**已指向本机、DNS-only 的子域名**。

安装完成后，会显示：

- 3x-ui 原版用户订阅前端地址。
- 随机路径的管理后台地址、管理员账号和密码。
- 主用户和所创建成员的订阅地址。
- 必须在云防火墙放行的端口。

以后运行 `sudo vvpis` 可以再次打开管理菜单，运行 `sudo vvpis info` 重新查看地址和凭证。

## 需要开放的端口

| 入站端口 | 用途 | 在哪里放行 |
| --- | --- | --- |
| 当前 SSH 的 TCP 端口，通常 22 | 服务器管理 | 保持现有规则及来源限制 |
| TCP 80 | HTTPS 证书申请、续期 | 云安全组/轻量服务器防火墙 |
| TCP 443 | Trojan、HTTPS 前端、后台、订阅 | 云安全组/轻量服务器防火墙 |
| UDP 443 | Hysteria2 | 云安全组/轻量服务器防火墙 |

25103–25110 和 62789 都是**本机内部端口**，不需要也不应该向公网开放。若 UFW 已启用，脚本会补充上述规则；不会重置规则、关闭防火墙或更改 SSH。其他本机防火墙及云安全组仍需你核对。

## 功能与默认行为

- **原版前端**：3x-ui 原版页面，深浅色、二维码、客户端导入、真实流量数据，不加载旧定制主题。
- **通用订阅**：同一个 SUB 地址自动适配 Clash Verge/Mihomo、Quantumult X、Shadowrocket、v2rayN/v2rayNG。也保留原版的 Clash 格式下载地址。
- **两个协议**：Clash/Mihomo 和支持 Hysteria2 的通用客户端可获取两个节点；QX 返回兼容的 Trojan 节点。
- **不限额账号**：默认不设置代理流量额度和到期时间。云服务器的流量包、计费、带宽仍按套餐执行；填写带宽只作管理参考，不人为保证满速。
- **独立凭证**：可在安装时创建 1–20 个用户，每人有不同订阅和节点凭证；之后通过 3x-ui 管理。
- **持久化用量**：合计 Trojan 与独立 Hysteria2 用量；Hysteria2 计数约每 5 秒落盘，进程重启不重复累计。原版页面刷新后显示更新后的用量。
- **TLS**：IP 或域名受信任证书，IP 证书短期有效并每小时检查续期。不会因申请失败自动切换不受信任证书。
- **直出与混合**：默认固定服务器直出；可选服务器优先、机场备用，探测异常后使用备用出口。它不按“VPN 标签”自动切换。
- **稳定性**：适用时启用 BBR + fq；Hysteria2 使用标准 BBR、自适应传输，不填写夸大的固定速度。提供健康检查、有限次数的本地故障恢复和外网端到端探测。
- **前端性能**：带文件指纹的静态资源压缩和缓存；私密页面、订阅及用量不缓存。
- **无周期备份**：默认不建立备份任务。卸载默认保留账号、证书和统计数据。

若以后在面板中设置有限流量配额，独立 Hysteria2 会对该账号关闭，而不是绕过 3x-ui 的有限配额。当前合计统计不会反写为 3x-ui 原生 Trojan 计数。

## 系统条件

- 使用 systemd 的 Ubuntu 22.04/24.04/26.04，或 Debian 12/13；Python 3.10+。
- amd64 或 arm64，至少约 1GiB 内存，推荐 2GiB；至少 2GiB 可用磁盘。
- 独立公网 IPv4，能够接收入站 TCP 80/443 和 UDP 443。
- 能访问 GitHub、Ubuntu/Debian 软件源、PyPI 和 Let's Encrypt。
- **使用独立新服务器**。已有网站、宝塔、其他 3x-ui 或端口冲突时，脚本会拒绝覆盖。
- 当前不支持 IPv6-only。使用子域名时，A 指向本机、删除该子域名的 AAAA、关闭普通 CDN 代理；不要改游戏网站主域名的解析。

## 管理命令

```bash
sudo vvpis                       # 交互菜单
sudo vvpis info                  # 地址、用户及凭证（不要公开输出）
sudo vvpis ports                 # 云安全组端口说明
sudo vvpis doctor                # 只检查，不自动修复
sudo vvpis mode direct           # 固定服务器直出
sudo vvpis renew                 # 检查证书续期
sudo vvpis cleanup               # 清理安装缓存和旧归档日志
sudo vvpis install --resume      # 继续失败安装，保留凭证
sudo vvpis uninstall             # 停止并卸载服务，保留数据
```

安装过程卡在证书申请时，先修复 TCP 80、云安全组和 DNS，再继续安装。不要反复删除状态重新申请，以免触发 CA 的频率限制。

### 可选机场备用

安装后打开 `sudo vvpis`，选择「配置服务器优先、机场备用」，输入你**有权使用的 HTTPS Clash/Mihomo YAML 订阅**。输入隐藏，存储在本机受限配置文件，不进入仓库；不经过第三方订阅转换网站。

也可通过标准输入提供，避免把私密 URL 写到命令行参数和历史中：

```bash
read -r -s -p 'Airport URL: ' AIRPORT_URL; echo
printf '%s\n' "$AIRPORT_URL" | sudo vvpis mode hybrid --airport-stdin
unset AIRPORT_URL
```

只接受包含 `proxies` 的 Clash/Mihomo 订阅，不接受需要外部转换的原始链接集合。模式切换作用于此服务器的所有用户；新连接采用新出口，已有连接可能沿用旧出口。机场订阅按自身额度计费，主服务器不会变成住宅 IP。

### 批量部署

填写每台机器自己的地址，不要复制已安装服务器的 `/etc/vvpis`：

```bash
sudo bash install.sh install \
  --host vpn.example.com --public-ip YOUR_PUBLIC_IPV4 \
  --email you@example.com --bandwidth 200 --ssh-port 22 --users 3 --yes
```

`YOUR_PUBLIC_IPV4` 必须替换为该服务器的真实公网 IPv4。IP 模式下将 `--host` 也填为同一个公网 IPv4。

## 版本与更新

组件和 amd64/arm64 的 SHA256 固定在 [versions.json](versions.json)。下载校验不符会中止；不会静默追随上游 `latest`。安装器启动时固定本仓库的一个具体 commit，避免安装中途取到混合版本。

本版不是自动升级器。重新运行安装脚本不会自动重置现有实例；现有账号请通过管理菜单维护。升级上游组件前应在测试机器更新版本、校验和及集成测试，再发布新的安装器版本。

## 检查与实际边界

- 单元测试覆盖独立凭证、格式协商、认证拒绝、用量持久化、重复样本、重启、脚本注入转义、路径越界与恢复预算。
- 配置验证使用真实 Xray、Mihomo、Nginx 二进制；不会重载现网服务。
- GitHub Actions 的 Ubuntu 24.04 **临时虚拟机**运行完整安装、本地 HTTPS 前端、Trojan/Hysteria2 外网连接和保留数据卸载测试。
- CI 用**仅测试使用的本地 CA**代替公网 ACME。真正的公网证书、云安全组、具体地区网络及真实机场备用，需要在目标服务器验证。
- Ubuntu 22.04 有单元测试；Ubuntu 26.04 和 Debian 12/13 进行了版本预检支持，但本仓库 CI 没有覆盖这些系统的完整安装。arm64 下载已固定，完整安装 CI 当前为 amd64。
- 客户端 TUN、系统 DNS、WebRTC 和 IPv6 还受设备设置影响，安装服务器不能保证每个客户端都无泄露。见[部署说明](docs/DEPLOYMENT.md)。

IP 的机房/住宅属性与第三方 VPN 标签取决于出口供应商和检测数据库，安装脚本不修改这些记录。

## 项目文件

- `install.sh`：本地或单文件下载入口。
- `vvpis/cli.py`：交互菜单及命令。
- `vvpis/installer.py`：预检、安装、证书、地址显示、模式切换与保留数据卸载。
- `vvpis/config.py`：可独立验证的配置生成器。
- `vvpis/bridge.py`：原版前端数据衔接、QX 适配、Hysteria2 认证与持久化计数。
- `vvpis/health.py`：本地健康检查、两种协议的实际连通探测、有限恢复。
- `tests/`：单元、配置和临时 VM 安装测试。

[架构与实现计划](docs/PLAN.md) · [部署及排错](docs/DEPLOYMENT.md) · [安全边界](SECURITY.md)

安装器自身使用 MIT License；3x-ui、Xray、Hysteria2、Mihomo 和 Certbot 保留各自的上游许可证。本仓库不包含这些组件的二进制或任何现网密钥。
