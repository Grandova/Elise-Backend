#!/usr/bin/env bash
set -euo pipefail

REPO="Grandova/Elise-Backend"
CONF_DIR="/etc/elise"
ELISE_DIR="/usr/local/elise"
BIN_DIR="/usr/local/bin"
SYSTEMD_DIR="/etc/systemd/system"
SYSTEMD_RUN_DIR="/run/systemd/system"
OPENRC_FILE="/etc/init.d/elise"
LOCK_DIR="/run/elise-install.lock"
WORK=""
SERVICE_MANAGER=""
WAS_ACTIVE=false
REPLACED=false
LOCKED=false

die() { printf 'Elise: %s\n' "$*" >&2; exit 1; }

service_action() {
    if [[ "$SERVICE_MANAGER" == systemd ]]; then
        systemctl "$1" elise.service
    else
        rc-service elise "$1"
    fi
}

cleanup() {
    local result=$? entry dest
    trap - EXIT
    if (( result != 0 )) && $REPLACED; then
        printf '安装失败，恢复此前的二进制和服务文件。\n' >&2
        rm -f -- "$BIN_DIR/.elise.new" || result=1
        for entry in binary service instance; do
            case "$entry" in
                binary) dest="$BIN_DIR/elise" ;;
                service) dest="$SERVICE_FILE" ;;
                instance) dest="$SYSTEMD_DIR/elise@.service" ;;
            esac
            [[ "$entry" != instance || "$SERVICE_MANAGER" == systemd ]] || continue
            if [[ -f "$WORK/old-$entry" ]]; then
                cp -p "$WORK/old-$entry" "$dest.restore" && mv -f "$dest.restore" "$dest" || result=1
            elif [[ -f "$WORK/new-$entry" ]]; then
                rm -f -- "$dest" || result=1
            fi
        done
        if [[ "$SERVICE_MANAGER" == systemd ]]; then systemctl daemon-reload || result=1; fi
        if $WAS_ACTIVE; then service_action restart || result=1; fi
    fi
    if [[ -n "$WORK" && -d "$WORK" ]]; then rm -rf -- "$WORK"; fi
    if $LOCKED; then rmdir -- "$LOCK_DIR" || result=1; fi
    exit "$result"
}

main() {
    local mode=stable version="" arch entry dest
    if [[ "${1:-}" == --help || "${1:-}" == -h ]]; then
        printf '用法: bash install.sh [x.y.z | vx.y.z | --beta]\n无参数安装最新正式版；--beta 安装最近发布的测试版。\n'
        return
    fi
    (( $# <= 1 )) || die "指定版本与 --beta 不能同时使用"
    if (( $# == 1 )); then
        if [[ "$1" == --beta ]]; then
            mode=beta
        elif [[ "$1" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$ ]]; then
            mode=version
            version="v${1#v}"
        else
            die "无效参数；使用 --help 查看用法"
        fi
    fi
    [[ "$(uname -s)" == Linux ]] || die "仅支持 Linux"
    [[ "$(id -u)" == 0 ]] || die "请以 root 运行"
    case "$(uname -m)" in
        x86_64|amd64) arch=amd64 ;;
        aarch64|arm64) arch=arm64 ;;
        *) die "Unsupported: 当前发布仅提供 Linux amd64/arm64" ;;
    esac
    if command -v systemctl >/dev/null 2>&1 && [[ -d "$SYSTEMD_RUN_DIR" ]]; then
        SERVICE_MANAGER=systemd
        SERVICE_FILE="$SYSTEMD_DIR/elise.service"
    elif command -v rc-service >/dev/null 2>&1 && command -v rc-update >/dev/null 2>&1; then
        SERVICE_MANAGER=openrc
        SERVICE_FILE="$OPENRC_FILE"
    else
        die "未检测到运行中的 systemd 或 OpenRC；容器请使用前台 run 命令"
    fi
    for entry in curl python3; do
        command -v "$entry" >/dev/null 2>&1 || die "缺少 $entry；请先安装 curl、ca-certificates、python3"
    done
    mkdir "$LOCK_DIR" 2>/dev/null || die "已有安装在运行，或锁目录尚未清理：$LOCK_DIR"
    LOCKED=true
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    WORK=$(mktemp -d)
    python3 - "$WORK" "$REPO" "$mode" "$version" "$arch" <<'PY'
import hashlib, json, pathlib, re, shutil, subprocess, sys, tarfile

root = pathlib.Path(sys.argv[1])
repo, mode, requested, arch = sys.argv[2:]
api = "https://api.github.com/repos/" + repo + "/releases"

def download(url, destination):
    if not url.startswith("https://"):
        sys.exit("拒绝非 HTTPS 下载地址")
    subprocess.run([
        "curl", "--fail", "--silent", "--show-error", "--location",
        "--proto", "=https", "--proto-redir", "=https",
        "--connect-timeout", "15", "--max-time", "300", "--retry", "3",
        "--retry-delay", "2", "--output", str(destination), url,
    ], check=True)

if mode == "beta":
    candidates = []
    for page in range(1, 101):
        download(api + f"?per_page=100&page={page}", root / "response.json")
        releases = json.loads((root / "response.json").read_text(encoding="utf-8"))
        if not isinstance(releases, list):
            sys.exit("无效 Releases 响应")
        candidates.extend(r for r in releases if r.get("prerelease") and not r.get("draft"))
        if len(releases) < 100:
            break
    else:
        sys.exit("Release 分页超过上限，无法确定最新测试版")
    if not candidates:
        sys.exit("没有已发布的测试版；不会退回正式版")
    release = max(candidates, key=lambda r: r.get("published_at") or "")
else:
    endpoint = "/latest" if mode == "stable" else "/tags/" + requested
    download(api + endpoint, root / "response.json")
    release = json.loads((root / "response.json").read_text(encoding="utf-8"))

tag = release.get("tag_name", "")
if release.get("draft") or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", tag):
    sys.exit("无效或未公开的 Release")
if (mode == "stable" and release.get("prerelease")) or (mode == "beta" and not release.get("prerelease")):
    sys.exit("Release 渠道不匹配")
if mode == "version" and tag != requested:
    sys.exit("Release 版本不匹配")

name = f"elise-linux-{arch}.tar.gz"
assets = {a["name"]: a for a in release.get("assets", []) if a.get("state") == "uploaded"}
for asset, local in ((name, "package.tar.gz"), (name + ".sha256", "checksum")):
    expected = f"https://github.com/{repo}/releases/download/{tag}/{asset}"
    if assets.get(asset, {}).get("browser_download_url") != expected:
        sys.exit(f"Release 缺少匹配资产：{asset}")
    download(expected, root / local)

parts = (root / "checksum").read_text(encoding="utf-8").split()
digest = hashlib.sha256()
with (root / "package.tar.gz").open("rb") as src:
    for chunk in iter(lambda: src.read(1024 * 1024), b""):
        digest.update(chunk)
if len(parts) != 2 or parts[0].lower() != digest.hexdigest() or parts[1] not in (name, "*" + name):
    sys.exit("SHA-256 校验失败，保留现有安装")

required = {"elise", "elise.service", "elise@.service", "elise.openrc"}
optional = {"elise.sh"}
allowed = required | optional | {"example/" + f for f in ("elise.conf", "routes.toml", "dns.yml", "blockList", "whiteList")}
with tarfile.open(root / "package.tar.gz", "r:gz") as archive:
    members = archive.getmembers()
    seen = set()
    for member in members:
        if member.isdir() and member.name in ("elise", "elise/example"):
            continue
        relative = member.name[len("elise/"):]
        if not member.name.startswith("elise/") or relative not in allowed or not member.isfile() or relative in seen or member.size > 200 * 1024 * 1024:
            sys.exit("发布包包含无效路径、链接、重复文件或异常大小")
        seen.add(relative)
    if not required.issubset(seen):
        sys.exit("发布包缺少必要文件")
    for member in members:
        if not member.isfile():
            continue
        target = root / member.name
        target.parent.mkdir(parents=True, exist_ok=True)
        with archive.extractfile(member) as src, target.open("wb") as dst:
            shutil.copyfileobj(src, dst)
(root / "version").write_text(tag, encoding="utf-8")
print(f"已校验 Elise {tag} / Linux {arch}")
PY
    version=$(cat "$WORK/version")
    chmod 755 "$WORK/elise/elise"
    [[ "$("$WORK/elise/elise" --version)" == "elise ${version#v}" ]] || die "二进制版本或运行平台不匹配"
    if [[ "$SERVICE_MANAGER" == systemd ]]; then
        if systemctl is-active --quiet elise.service; then WAS_ACTIVE=true; fi
    elif rc-service elise status >/dev/null 2>&1; then
        WAS_ACTIVE=true
    fi
    mkdir -p "$ELISE_DIR" "$BIN_DIR" "$CONF_DIR" "$(dirname "$SERVICE_FILE")"
    for entry in binary service instance; do
        case "$entry" in
            binary) dest="$ELISE_DIR/elise" ;;
            service) dest="$SERVICE_FILE" ;;
            instance) dest="$SYSTEMD_DIR/elise@.service" ;;
        esac
        [[ "$entry" != instance || "$SERVICE_MANAGER" == systemd ]] || continue
        if [[ -e "$dest" ]]; then cp -p "$dest" "$WORK/old-$entry"; else touch "$WORK/new-$entry"; fi
    done
    for entry in elise.conf dns.yml blockList whiteList; do
        if [[ ! -e "$CONF_DIR/$entry" ]]; then
            install -m 600 "$WORK/elise/example/$entry" "$CONF_DIR/$entry"
        fi
    done
    REPLACED=true
    install -m 755 "$WORK/elise/elise" "$ELISE_DIR/.elise.new"
    mv -f "$ELISE_DIR/.elise.new" "$ELISE_DIR/elise"
    if [[ -f "$WORK/elise/elise.sh" ]]; then
        install -m 755 "$WORK/elise/elise.sh" "$BIN_DIR/.elise.sh.new"
        sed -i 's/\r$//' "$BIN_DIR/.elise.sh.new" 2>/dev/null || true
        mv -f "$BIN_DIR/.elise.sh.new" "$BIN_DIR/elise"
    elif ! curl -fsSL "https://raw.githubusercontent.com/$REPO/main/scripts/elise.sh" -o "$BIN_DIR/elise" 2>/dev/null || ! chmod 755 "$BIN_DIR/elise"; then
        ln -sf "$ELISE_DIR/elise" "$BIN_DIR/elise"
    else
        sed -i 's/\r$//' "$BIN_DIR/elise" 2>/dev/null || true
    fi
    ln -sf "$BIN_DIR/elise" /usr/bin/elise 2>/dev/null || true
    if [[ "$SERVICE_MANAGER" == systemd ]]; then
        install -m 644 "$WORK/elise/elise.service" "$SERVICE_FILE"
        install -m 644 "$WORK/elise/elise@.service" "$SYSTEMD_DIR/elise@.service"
        sed -i 's/\r$//' "$SERVICE_FILE" "$SYSTEMD_DIR/elise@.service" 2>/dev/null || true
        systemctl daemon-reload
    else
        install -m 755 "$WORK/elise/elise.openrc" "$SERVICE_FILE"
        sed -i 's/\r$//' "$SERVICE_FILE" 2>/dev/null || true
    fi
    if $WAS_ACTIVE; then service_action restart; fi
    REPLACED=false
    printf '已安装 Elise %s。已有配置已保留：%s/elise.conf\n' "$version" "$CONF_DIR"
    if ! $WAS_ACTIVE; then
        printf '填写面板配置后启动：\n'
        if [[ "$SERVICE_MANAGER" == systemd ]]; then
            printf '  systemctl enable --now elise\n  journalctl -u elise -f\n'
        else
            printf '  rc-update add elise default\n  rc-service elise start\n'
        fi
    fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
