# Snell Auto：单文件安装、网络参数与基础安全加固

只需把 **snell-auto.sh** 上传到 Linux VPS 的 /root，以 root 执行：

```bash
bash /root/snell-auto.sh
```

单文件内包含安装器、snellx 菜单、网络模块和安全模块，无需上传其他文件。运行时从 Surge 官方站点读取版本、下载二进制，依赖通过 VPS 配置的软件源安装。新装默认启用 v6 自动更新；已有安装保留原开关。

## 支持与检测

需要 Linux + glibc + systemd，支持官方提供的 AMD64、i386、ARM64 架构。识别 apt、dnf、yum、pacman、zypper 包管理器；Alpine/musl、非 systemd 及不支持的架构会提示后停止。Arch 不执行 pacman -Sy 局部升级，使用现有索引安装依赖。

自动显示系统、内核、虚拟化、有效内存（包括 cgroup 限额）、双栈默认路由、MTU、实际网卡队列及 TCP 参数。第三方安装的 Snell、服务或管理脚本会阻止安装，避免覆盖。支持本工具的已有安装、半完成安装及默认卸载后保留配置的重装。

## 自动安装内容

- 按版本号比较官方全部 v6 下载链接，避免误取页面中旧版本；阻止自动降级。
- 首装生成空闲 TCP 端口和 32 位随机 PSK；重跑保留现有配置。默认 mode=default。
- 系统有 IPv6 全局地址及默认路由时同时监听双栈；不据此宣称 IPv6 外网已实测可用。
- 独立 snell 用户、systemd 沙箱、开机启动、异常重启。
- 服务状态与 MainPID 监听归属检查，升级失败恢复旧二进制，配置修改失败回滚。
- 对已启用的 UFW/firewalld 添加 Snell TCP 放行；不启用或重置防火墙。
- 自动安装 snellx / snell-net / snell-security / snell-auto，应用网络参数后重启 Snell。
- 默认执行基础安全加固；已有管理员策略或无法可靠判断的环境会保留并报告跳过项。
- 输出 Surge 节点配置（包含 PSK，请勿公开转发）。

服务商的安全组或 NAT 端口映射仍需自行放行；本机监听检查不能替代客户端连通验证。

## 网络参数选择

网络模块按内存与内核能力选择保守参数，不承诺自动找到最优线路：

| 检测项 | 行为 |
|---|---|
| 已有 BBR / BBR2 / BBR3 | 保留 |
| 其他拥塞算法 | 尝试加载系统自带 tcp_bbr，可用才改为 BBR |
| 容器或内核权限不明确 | 跳过 sysctl，Snell 安装仍可继续 |
| 默认队列 fq / fq_codel / cake | 保留；其他情况尝试设置 fq |
| TCP MTU 黑洞探测 | 设为 1；已有 2 时保留 |
| TCP 接收缓冲自动调整 | 启用 |
| 缓冲上限 | 按内存选择，不降低更大的现有值 |

| 有效内存 | 建议上限 |
|---|---:|
| ≤ 512 MiB | 4 MiB |
| ≤ 1 GiB | 8 MiB |
| ≤ 2 GiB | 16 MiB |
| > 2 GiB | 32 MiB |

缓冲上限不是每条连接立即占用的内存。脚本保留 TCP 缓冲的最小值和初始值。虚拟网卡速率不代表真实套餐限速，不用于推断吞吐量。

default_qdisc 只是新队列的默认值，脚本不替换活动网卡队列。已有 TCP 连接可能沿用原拥塞算法。诊断会分别显示默认值和实际队列。

逐项备份、写入、读回验证，全部成功后原子提交持久配置；失败恢复本次操作前状态，再次调用先处理未完成事务。手动 rollback 恢复**首次成功优化之前**的参数和本工具配置，不撤销更早的其他网络设置。没有定时断线检测或断线自动回滚。

网络模块不修改路由、网卡 MTU、DNS、IPv6 开关或 SSH，不更换内核，不重启 VPS，不部署公开测速端口。判断优化收益仍需从用户本地向 VPS 做同一路径的双向对比测试。

## 基础安全加固

安全模块采用独立配置和备份，不沿用旧 `vps-hardening.sh`。默认随安装执行，也可以单独执行。它不是全面安全审计，也不保证服务器不会被入侵。

| 项目 | 自动处理与边界 |
|---|---|
| 内核参数 | 条件允许时启用文件链接/临时文件保护、内核信息访问限制和 SYN cookies；保留更严格值，容器或权限不明时跳过 |
| SSH | 禁止空密码及 X11 转发，登录宽限最多 120 秒，提升日志级别；保留密码/密钥/root 登录策略、端口、监听地址及 TCP 转发 |
| SSH 验证 | 修改前后检查语法、有效配置和当前连接上下文；仅 reload，不 restart；自定义启动参数或无法确认生效时跳过 |
| Fail2ban | 已有安装不接管；符合条件的新装启用独立 SSH jail，10 分钟失败 8 次封禁 15 分钟，当前 SSH 来源加入白名单 |
| Fail2ban 前提 | 可验证的 SSH 服务/端口/来源、systemd 日志后端和防火墙 action；条件不满足即跳过，不强行启用 |
| 系统自动更新 | Debian/Ubuntu 且已安装 unattended-upgrades 时，保留现有更新来源、排除和周期，补齐未设置的周期，禁止自动重启；明确禁用的策略不覆盖 |
| 更新调度 | 已活动 APT timer 保持原状；只 enable 未启用 timer，不立即启动补跑更新，下次开机开始调度 |
| 防火墙 | 仅审计状态与监听端口，不启用/重置全局防火墙，不修改默认策略；Fail2ban 启用后仍会按其 jail 添加封禁规则 |

不会修改 SSH 密码、要求更换密钥、关闭 IPv6、更换内核或重启 VPS。新软件包仅从已有软件源安装，不添加第三方源。`--no-packages` 可禁止安全模块安装依赖。

内核加固参数为 `fs.protected_hardlinks`、`fs.protected_symlinks`、`fs.protected_fifos`、`fs.protected_regular`、`kernel.kptr_restrict`、`kernel.dmesg_restrict` 和 `net.ipv4.tcp_syncookies`。不使用本次启动无法撤销的 BPF 禁用设置。

Fail2ban 当前来源白名单不能替代密钥登录，公网地址变化后应重新核对。VNC 控制台运行时通常没有 `SSH_CONNECTION`，无法确认来源就不会自动部署 Fail2ban。

重复执行保留首次基线，配置写入记录内容校验值。发现用户后续编辑时停止覆盖/回滚并报告冲突；操作中断留下的事务，会在下次 apply/rollback 时先尝试恢复。此机制不能替代失联后的自动定时回滚。

自动更新沿用实际 `Allowed-Origins` / `Origins-Pattern`，**可能不限于安全更新**；不会在本次流程里运行全系统升级。不自动新装 unattended-upgrades，因为其安装过程可能另行启用包自带更新策略，超出本工具配置的回滚范围。安装其他依赖本身仍会修改软件包。安全回滚恢复本工具的配置、运行态参数和所管理服务的首次基线，**不会卸载已安装软件包，也不能撤销已发生的软件更新**。没有断线自动回滚计时器；执行前仍建议保留服务商 VNC/串口入口。

## 使用

```bash
snellx                      # 管理菜单
snellx show                 # 连接配置（含 PSK）
snellx update               # 检查更新
snellx restart              # 重启 Snell，会中断现有连接
snellx psk                  # 修改/随机生成 PSK
snellx port                 # 修改/随机生成端口
snellx timer                # 开关自动更新
snellx channel              # 查看自动更新通道；snellx channel prerelease 允许自动装 beta/rc
snellx check                # 本机健康检查
snellx diagnose             # 检测系统与网络
snellx optimize             # 再次应用网络参数
snellx rollback-network     # 恢复首次优化前状态
snellx security-status      # 查看安全配置、服务与执行报告
snellx security             # 应用基础安全加固
snellx security --no-packages # 加固，但不安装安全组件
snellx rollback-security    # 恢复首次安全加固前状态
snellx uninstall            # 回滚加固和网络参数后卸载全部组件（--purge 连配置/PSK 一起清除）
```

```bash
# 安装前只读检测，不安装依赖
bash /root/snell-auto.sh diagnose

# 可选探测：把示例 IP 换成目标 IP；4 个 ICMP 包，最多 10 秒
bash /root/snell-auto.sh diagnose --probe 203.0.113.10

# 安装时不调网络
bash /root/snell-auto.sh install --network off

# 只安装 Snell，不调网络、不做安全加固
bash /root/snell-auto.sh install --network off --security off

# 仅做安全加固，不执行 Snell 安装/重启流程
bash /root/snell-auto.sh security
bash /root/snell-auto.sh security-status
bash /root/snell-auto.sh rollback-security

# 安装后禁用自动更新
bash /root/snell-auto.sh install --no-auto-update
```

独立的 optimize / rollback 不重启 Snell，必要时随后执行 snellx restart。修改 PSK/端口后需同步更新 Surge。旧端口防火墙规则会保留，确认无其他用途后可手动删除。

## 更新、恢复与路径

自动更新定时器在开机 15 分钟后检查，随机延迟最多 1 小时；随后约每 24 小时检查，另加随机延迟。使用单调时钟，不承诺补跑关机期间任务。

只更新 v6，不自动切到 v7；同一基础版本按 beta、rc、正式版排序。

自动更新默认使用 **stable 通道：定时任务只自动安装正式版**。官方预发布版曾改变协议，需要同步升级 Surge，所以不会在无人值守时自动装上。首次安装和手动 `snellx update` 仍安装官方最新版（含 beta/rc）；目前 v6 只有预发布版。需要自动跟进 beta/rc 时执行 `snellx channel prerelease`，或安装时加 `--auto-update-channel prerelease`。

下载使用 HTTPS、固定官方域名（仅允许 HTTPS 跳转），检查压缩包成员、ELF 架构和程序 v6 版本；版本检查以 snell 低权限用户执行。SHA-256 用于本地比较是否变化，**并非对照官方签名或官方校验和**。

| 内容 | 路径 |
|---|---|
| Snell 配置 | /etc/snell-server/snell-server.conf |
| 服务 / 定时器 | snell-server.service / snell-update.timer |
| 安装归属与版本 | /var/lib/snell-server/ |
| 旧程序备份 | /var/lib/snell-server/backups/ |
| 网络持久参数 | /etc/sysctl.d/zzzz-snell-auto-network.conf |
| 网络备份与事务 | /var/lib/snell-net/ |
| 安全备份与执行报告 | /var/lib/snell-security/ |
| 安全内核参数 | /etc/sysctl.d/zzzz-snell-auto-security.conf |
| SSH 非认证项 | /etc/ssh/sshd_config.d/00-snell-auto-security.conf |
| SSH 防暴力破解 jail | /etc/fail2ban/jail.d/snell-auto-sshd.local |
| APT 周期 / 禁止自动重启 | /etc/apt/apt.conf.d/99snell-auto-periodic / 99zz-snell-auto-no-reboot |

```bash
snellx uninstall          # 回滚安全加固和网络参数 → 卸载 Snell → 删除管理工具；保留配置和 PSK
snellx uninstall --purge  # 同上，并清除配置、PSK、状态、备份和 snell 系统用户
```

任一回滚失败时卸载会停止，管理工具保留以便处理后重试。防火墙放行规则不删除，确认无其他用途后可手动删除。只想卸载 Snell 服务、保留加固和网络参数时，可用 `snell-manager uninstall [--purge]`；之后 `snellx` 仍可执行回滚和卸载命令。程序、工具和配置备份各保留最近 5 份。旧安全加固脚本 vps-hardening.sh 未纳入自动流程。

## 构建与验证

修改 snell-v6.sh、snellx、snell-net.sh、snell-security.sh 或 ../scripts/snell-auto-launcher.sh 后，在项目根目录执行：

```bash
python3 scripts/build-snell-auto.py
python3 tests/test-snell-installer.py
python3 tests/test-snell-bundle.py
python3 tests/test-snell-menu.py
python3 tests/test-snell-security.py
bash tests/snell-net-tests.sh
```

构建同时生成 snell-auto.sh.sha256。已执行 Bash 语法、离线模拟、回滚故障测试和官方页面解析验证；当前开发环境没有运行中的 Docker，尚未进行真实 Linux/systemd 安装和吞吐验证。

官方依据：[Snell 发布说明](https://kb.nssurge.com/surge-knowledge-base/release-notes/snell)、[Surge Snell 参数](https://manual.nssurge.com/policies/snell.html)、[Linux TCP 文档](https://docs.kernel.org/networking/ip-sysctl.html)、[OpenSSH 配置](https://man.openbsd.org/sshd_config)、[Fail2ban 配置](https://github.com/fail2ban/fail2ban/blob/master/config/jail.conf)、[Ubuntu 自动更新](https://ubuntu.com/server/docs/how-to/software/automatic-updates/)。
