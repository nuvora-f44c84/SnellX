#!/usr/bin/env bash
# Release bootstrap. Generated install.sh pins a release and its bundle digest.
# This template is not a runnable release until its three placeholders are set.

snell_release_usage() {
  cat <<'USAGE'
Snell 一键安装入口（固定发行版 + SHA-256 校验）

  sudo bash install.sh                         安装 Snell、网络优化和安全加固
  sudo bash install.sh install --network off   不调整网络参数
  sudo bash install.sh install --security off  不应用安全加固
  bash install.sh diagnose                     只读环境检测，不需要 root
  sudo bash install.sh security                单独应用安全加固
  sudo bash install.sh security-status         查看安全加固状态
  sudo bash install.sh rollback-security       回滚本工具的安全配置
  bash install.sh --help                       显示帮助，不联网

仅支持 Linux VPS。下载的安装包通过固定 SHA-256 与 Bash 语法检查后才运行。
其余参数原样传给 snell-auto.sh。不修改本地 Surge 配置；重启 Snell 可能中断现有代理连接。
USAGE
}

snell_release_is_root() { [[ "$(id -u)" == 0 ]]; }

# A subshell confines options and traps when a caller sources this file.
snell_release_main() (
  set -uo pipefail
  umask 077
  local repository='__GITHUB_REPOSITORY__'
  local release_tag='__RELEASE_TAG__'
  local expected_sha256='__BUNDLE_SHA256__'
  local release_tmp='' payload='' checksum='' actual_sha256='' argument

  snell_release_error() { printf '[snell-auto] 错误：%s\n' "$*" >&2; }
  snell_release_cleanup() {
    local result=$?
    if [[ -n "$release_tmp" && -d "$release_tmp" ]]; then
      rm -rf -- "$release_tmp" || :
    fi
    return "$result"
  }

  for argument in "$@"; do
    case "$argument" in -h|--help|help) snell_release_usage; return 0 ;; esac
  done
  [[ "$(uname -s)" == Linux ]] || {
    snell_release_error '请将此文件上传到 Linux VPS 后运行。'; return 1;
  }
  [[ $# -ne 0 ]] || set -- install
  if [[ "$1" != diagnose ]] && ! snell_release_is_root; then
    snell_release_error '安装或管理操作需要 root；请使用 root 或 sudo 运行。'
    return 1
  fi
  # Reject an unrendered or malformed release rather than guessing a URL.
  if [[ ! "$repository" =~ ^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]+$ ]] ||
     [[ ! "$release_tag" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] ||
     [[ ! "$expected_sha256" =~ ^[a-f0-9]{64}$ ]]; then
    snell_release_error '发行信息无效；请下载正式发布的 install.sh，而非源码模板。'
    return 1
  fi
  command -v curl >/dev/null 2>&1 || {
    snell_release_error '缺少 curl；请先用系统包管理器安装 curl 和 ca-certificates。'; return 1;
  }
  if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
    snell_release_error '缺少 SHA-256 校验工具：需要 sha256sum 或 shasum。'
    return 1
  fi
  release_tmp="$(mktemp -d /tmp/snell-release.XXXXXXXX)" || {
    snell_release_error '无法创建私有临时目录。'; return 1;
  }
  [[ -n "$release_tmp" && -d "$release_tmp" ]] || {
    snell_release_error '临时目录创建结果无效。'; return 1;
  }
  trap snell_release_cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  payload="$release_tmp/snell-auto.sh"
  printf '[snell-auto] 下载发行版 %s（%s）……\n' "$release_tag" "$repository"
  if ! curl --fail --location --silent --show-error \
    --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --connect-timeout 15 --max-time 120 --retry 2 \
    --output "$payload" \
    "https://github.com/$repository/releases/download/$release_tag/snell-auto.sh"; then
    snell_release_error '下载失败，未执行安装包。'
    return 1
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    checksum="$(sha256sum -- "$payload")" || {
      snell_release_error '无法计算安装包 SHA-256，未执行。'; return 1;
    }
  else
    checksum="$(shasum -a 256 -- "$payload")" || {
      snell_release_error '无法计算安装包 SHA-256，未执行。'; return 1;
    }
  fi
  actual_sha256="${checksum%% *}"
  if [[ "$actual_sha256" != "$expected_sha256" ]]; then
    snell_release_error '安装包 SHA-256 不匹配，已拒绝执行；请勿跳过校验。'
    return 1
  fi
  if ! bash -n "$payload"; then
    snell_release_error '安装包 Bash 语法检查失败，未执行。'
    return 1
  fi
  printf '[snell-auto] 校验通过，开始执行。\n'
  # Do not exec: EXIT must remove the private directory. Stdin stays untouched.
  bash "$payload" "$@"
)

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  snell_release_main "$@"
fi
