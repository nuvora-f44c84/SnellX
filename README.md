# SnellX

Linux VPS 的 Snell v6 一键安装、管理、保守网络优化与可回滚基础安全加固。

这是独立的管理脚本，不是 Surge / Snell 官方项目；Snell 二进制运行时从官方站点下载，不随本仓库分发。SnellX 的版本号与 Snell 服务端版本号不同。

## 一键安装

以 **root** 登录 VPS 后执行（需要 `curl` 和 CA 证书）：

```bash
curl --proto '=https' --tlsv1.2 -fL --retry 3 https://raw.githubusercontent.com/nuvora-f44c84/SnellX/main/install.sh -o snellx-install.sh && bash snellx-install.sh
```

入口会下载固定版本的完整安装器，验证内置 SHA-256 和 Bash 语法，再从真实文件执行。下载或校验失败时不会执行安装。SHA-256 用于验证发布内容完整性，不是独立数字签名；你仍需信任本仓库及 GitHub。执行前可打开下载的 `snellx-install.sh` 审阅。

默认流程：检测系统 → 安装 Snell v6 → 安装 `snellx` 菜单 → 保守网络参数调整 → 基础安全加固 → 本机健康检查。

安装完成输入：

```bash
snellx
```

需要 Linux + glibc + systemd；支持官方提供的 AMD64、i386、ARM64。非 systemd / Alpine 等不适配环境会停止。已有第三方 Snell 安装或同名管理工具时不覆盖、不自动迁移。

## 可选用法

先用上方命令的 `curl` 部分下载入口，再选择执行：

```bash
bash snellx-install.sh diagnose                        # 只读系统/网络诊断
bash snellx-install.sh install --network off --security off # 只安装 Snell
bash snellx-install.sh security                        # 只做安全加固，不重装 Snell
bash snellx-install.sh security-status                 # 查看安全状态
bash snellx-install.sh rollback-security               # 回滚本工具安全配置
```

指定发布版可把入口 URL 中的 `main` 改为对应 tag（如 `v1.1.0`）。完整单文件及校验文件也可在 [Releases](https://github.com/nuvora-f44c84/SnellX/releases) 下载，上传至 VPS 后执行 `bash snell-auto.sh`。不要直接把完整 `snell-auto.sh` 管道传给 Bash，它需要安装自身的持久副本。

## 功能和边界

- 首装随机选择未占用 TCP 端口、生成 PSK，重复执行保留现有配置。
- 管理菜单支持配置查看、修改 PSK/端口、重启、日志、健康检查和 Snell v6 自动更新。
- 网络参数按内核能力和有效内存选择；保留已有 BBR / BBR2 / BBR3，不承诺最优线路或突破服务商限速。
- 安全模块保留 SSH 认证方式/端口及 IPv6，验证后只 reload SSH；符合条件时部署 Fail2ban，已有管理员配置不接管。
- 防火墙加固部分只审计，不启用、重置或修改默认策略；安装器会在已启用的 UFW/firewalld 中放行 Snell TCP，Fail2ban 会按规则封禁攻击来源。
- 自动更新设置只适配已安装 unattended-upgrades 的 Debian/Ubuntu，保留更新来源并禁止自动重启。
- 不重启 VPS，不更换内核，不修改路由或 DNS。重启/升级 Snell 会中断现有代理连接。
- 回滚不能卸载已安装软件包或撤销已发生的软件更新；配置被手工改过会报告冲突。保留服务商 VNC / 串口入口。
- 首装和手动更新安装官方最新 v6（目前只有 beta/rc）；每日自动更新默认只安装正式版，可用 `snellx channel prerelease` 改为也跟进 beta/rc。只有本机检查，不能代替用户本地到 VPS 的真实连通和吞吐测试。
- `snellx uninstall [--purge]` 依次回滚安全加固、网络参数并卸载全部组件。

详细说明、路径及回滚命令见 [操作手册](outputs/README.md)。请勿在公开 Issue 上传 PSK、私钥、完整连接配置或未脱敏日志。

## 开发和验证

Python 3.9+、Bash。构建与测试无需 root，使用临时目录和模拟系统命令，不操作真实 VPS：

```bash
python3 scripts/build-snell-auto.py
python3 scripts/render-release-installer.py
for test_file in tests/test-*.py; do python3 "$test_file" || exit; done
bash tests/snell-net-tests.sh
```

GitHub Actions 在 Ubuntu 上运行同样的离线回归测试及构建一致性检查。它不等于真实 systemd、SSH 重连或防火墙封禁动作的部署验收。

发布流程：更新 `release.json` 和 `RELEASE_NOTES.md`，重新构建并生成入口，合并到 main 后推送同名 tag（如 `git tag v1.1.0 && git push origin v1.1.0`）。Release 工作流会重新构建、核对哈希与 `install.sh` 一致，并自动创建 Release、上传 `snell-auto.sh` 和 `.sha256`。入口依赖这些附件；合并到推送 tag 之间，main 上的一键命令会因下载不到附件而安全中止。
