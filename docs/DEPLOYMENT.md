# 部署与排错

## 安装前

使用独立新系统，并准备好云控制台。先放行已有 SSH、TCP 80/443、UDP 443；脚本只能配置本机已启用的 UFW，不能修改云安全组。

使用域名时只新增对应子域名的 A 记录，不更改其他网站的解析。A 指向这台机器公网 IPv4；当前安装器不接管 IPv6，删除此子域名的 AAAA，并使用 DNS-only。普通 CDN 橙云不能直接承载本方案的原生 Trojan TCP 与 Hysteria2 UDP。

IP 模式使用 Let's Encrypt 的短期 IP 证书。TCP 80 必须在安装和日后续期时都保持可达。参考：[Let's Encrypt IP 证书和 Certbot](https://letsencrypt.org/2026/03/11/shorter-certs-certbot)。

## 安装失败

不要删除 `/etc/vvpis/state.json` 重新生成。菜单选择继续安装，或执行：

```bash
sudo vvpis install --resume
```

- `端口已占用`：使用新服务器；不要终止现有网站来强行安装。
- `证书申请失败`：检查 TCP 80、云安全组、A/AAAA、DNS-only 和 CA 频率限制。
- `下载校验不符`：中止是预期行为，检查上游发布文件或网络；不要跳过 SHA256。
- `订阅不可用`：先 `sudo vvpis doctor`；检查四个核心服务是否都正常。
- `机场订阅格式错误`：提供 Clash/Mihomo YAML，脚本不会把私密链接发送给第三方转换服务。

## 运行排查

```bash
sudo vvpis doctor
sudo systemctl status vvpis-panel vvpis-gateway vvpis-subscriptions vvpis-hysteria
sudo systemctl list-timers 'vvpis-*'
sudo journalctl -u vvpis-panel -u vvpis-subscriptions -u vvpis-hysteria -n 60 --no-pager
```

分享日志前遮住公网地址、完整订阅令牌和其他个人信息。`sudo vvpis info` 的输出包含管理员密码，不应公开。

## 客户端

- Clash Verge/Mihomo：导入 SUB 地址或原版页面的 Clash 地址，选择 PROXY 回退组。该配置提供代理 DNS、TUN 严格路由和 UDP/TCP 53 劫持参数；TUN 是否开启仍由客户端决定。
- Quantumult X：导入同一个 SUB 地址作为服务器资源，返回 Trojan 原生格式；QX 不会因本脚本获得原生 Hysteria2 支持。
- Shadowrocket、v2rayN/v2rayNG：导入 SUB 地址；能用哪些协议还取决于客户端版本。
- DNS 和 WebRTC 需在实际设备复测。HTTP 代理本身不一定接管 UDP 或系统全部 DNS；服务器安装正常不等于设备端没有泄露。

默认不需要关闭 Windows 的 IPv6。若要采用 IPv4-only 的设备策略，请在具体客户端和网卡上核对，并保留恢复方法；服务器脚本不会替你改变电脑语言、时区或系统网络设置。

## 数据与卸载

默认卸载只停止并删除 VVPIS 管理的服务、Nginx 入口和调优文件，保留 `/etc/vvpis`、`/var/lib/vvpis` 以及证书。不会删除共享 Nginx 软件、重置防火墙或移除其他站点。

完整销毁数据需要管理员另行明确处理，不提供会顺带清空整个 `/etc`、`/var/lib` 或系统日志的“一键清空”。

## 支持范围

CI 的完整安装测试使用临时 Ubuntu 24.04 VM 和本地测试 CA，不能代替目标机器的公网 ACME、网络质量和真实机场备用验证。新版本请先在独立测试服务器试用，再用于长期服务。
