#!/usr/bin/env python3


import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

REPO_OWNER = "Grandova"
REPO_NAME = "Elise-Backend"
TARGET_AMD64 = "x86_64-unknown-linux-musl"
TARGET_ARM64 = "aarch64-unknown-linux-musl"


def get_project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def get_cargo_version(root: Path) -> str:
    cargo_toml = root / "Cargo.toml"
    with open(cargo_toml, "r", encoding="utf-8") as f:
        content = f.read()
    m = re.search(r'\[package\][\s\S]*?version\s*=\s*"([^"]+)"', content)
    if not m:
        raise RuntimeError("无法在 Cargo.toml 中解析 package.version")
    return m.group(1)


def get_github_token() -> str:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        return token.strip()

    try:
        p = subprocess.run(
            ["git", "credential", "fill"],
            input="protocol=https\nhost=github.com\n",
            text=True,
            capture_output=True,
            check=True,
        )
        for line in p.stdout.splitlines():
            if line.startswith("password="):
                return line.split("=", 1)[1].strip()
    except Exception as e:
        print(f"[WARN] 无法通过 git credential 提取 Token: {e}", file=sys.stderr)

    raise RuntimeError(
        "未找到 GitHub 访问凭证。请设置环境变量 GITHUB_TOKEN，或确保 git credential 配置正确。"
    )


def run_command(cmd, cwd=None):
    print(f"==> 执行命令: {' '.join(str(c) for c in cmd)}")
    res = subprocess.run(cmd, cwd=cwd)
    if res.returncode != 0:
        raise RuntimeError(f"命令执行失败，退出码: {res.returncode}")


def build_binaries(root: Path):
    print("\n==========================================")
    print(" 步骤 1/4: 使用 cargo zigbuild 本地交叉编译")
    print("==========================================")

    print(f"--> 构建目标 1: {TARGET_AMD64} (Linux amd64)")
    run_command(["cargo", "zigbuild", "--target", TARGET_AMD64, "--release"], cwd=root)

    print(f"--> 构建目标 2: {TARGET_ARM64} (Linux arm64)")
    run_command(["cargo", "zigbuild", "--target", TARGET_ARM64, "--release"], cwd=root)


def package_arch(root: Path, arch: str, binary_path: Path) -> tuple[Path, Path]:
    dist_dir = root / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)
    archive_name = f"elise-linux-{arch}.tar.gz"
    archive_path = dist_dir / archive_name
    sha256_path = dist_dir / f"{archive_name}.sha256"

    print(f"--> 打包架构 {arch} 到 {archive_name}...")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        stage_elise = tmp_path / "elise"
        stage_example = stage_elise / "example"
        stage_example.mkdir(parents=True, exist_ok=True)

        stage_bin = stage_elise / "elise"
        with open(binary_path, "rb") as f_in, open(stage_bin, "wb") as f_out:
            f_out.write(f_in.read())

        for script_name in ["elise.service", "elise@.service", "elise.openrc", "elise.sh"]:
            src_file = root / "scripts" / script_name
            if src_file.exists():
                with open(src_file, "rb") as f_in, open(stage_elise / script_name, "wb") as f_out:
                    f_out.write(f_in.read().replace(b"\r\n", b"\n"))

        for ex_name in ["elise.conf", "routes.toml", "dns.yml", "blockList", "whiteList"]:
            src_file = root / "example" / ex_name
            if src_file.exists():
                with open(src_file, "rb") as f_in, open(stage_example / ex_name, "wb") as f_out:
                    f_out.write(f_in.read().replace(b"\r\n", b"\n"))

        with tarfile.open(archive_path, "w:gz") as tar:
            for item in stage_elise.rglob("*"):
                arcname = str(item.relative_to(tmp_path)).replace("\\", "/")
                tarinfo = tar.gettarinfo(str(item), arcname=arcname)
                tarinfo.uid = 0
                tarinfo.gid = 0
                tarinfo.uname = "root"
                tarinfo.gname = "root"
                if item.is_file():
                    if item.name in ["elise", "elise.sh"]:
                        tarinfo.mode = 0o755
                    else:
                        tarinfo.mode = 0o644
                    with open(item, "rb") as f:
                        tar.addfile(tarinfo, f)
                elif item.is_dir():
                    tarinfo.mode = 0o755
                    tar.addfile(tarinfo)

    hasher = hashlib.sha256()
    with open(archive_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    digest = hasher.hexdigest()
    with open(sha256_path, "w", encoding="utf-8") as f:
        f.write(f"{digest}  {archive_name}\n")

    print(f"    包大小: {archive_path.stat().st_size / 1024 / 1024:.2f} MB, SHA256: {digest[:16]}...")
    return archive_path, sha256_path


def package_release(root: Path) -> list[Path]:
    print("\n==========================================")
    print(" 步骤 2/4: 封装标准发布包及 SHA256 校验文件")
    print("==========================================")

    bin_amd64 = root / "target" / TARGET_AMD64 / "release" / "elise"
    bin_arm64 = root / "target" / TARGET_ARM64 / "release" / "elise"

    if not bin_amd64.exists():
        raise FileNotFoundError(f"未找到 amd64 二进制文件: {bin_amd64}")
    if not bin_arm64.exists():
        raise FileNotFoundError(f"未找到 arm64 二进制文件: {bin_arm64}")

    artifacts = []
    a1, s1 = package_arch(root, "amd64", bin_amd64)
    a2, s2 = package_arch(root, "arm64", bin_arm64)
    artifacts.extend([a1, s1, a2, s2])
    return artifacts


def get_or_create_release(token: str, tag: str) -> dict:
    headers = {
        "Authorization": f"token {token}",
        "User-Agent": "Elise-Release-Script",
        "Accept": "application/vnd.github.v3+json",
    }

    get_url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/releases/tags/{tag}"
    req = urllib.request.Request(get_url, headers=headers)
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            print(f"--> 已存在 Release: {tag} (ID: {data['id']})")
            return data
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise

    print(f"--> 创建新 Release: {tag}...")
    create_url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/releases"
    payload = json.dumps({
        "tag_name": tag,
        "name": tag,
        "draft": False,
        "prerelease": "-" in tag,
        "generate_release_notes": True,
    }).encode("utf-8")

    req = urllib.request.Request(
        create_url,
        data=payload,
        headers={**headers, "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode())
        print(f"--> 成功创建 Release: {tag} (ID: {data['id']})")
        return data


def upload_asset(token: str, release: dict, file_path: Path):
    name = file_path.name
    headers = {
        "Authorization": f"token {token}",
        "User-Agent": "Elise-Release-Script",
        "Accept": "application/vnd.github.v3+json",
    }

    for asset in release.get("assets", []):
        if asset["name"] == name:
            del_url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/releases/assets/{asset['id']}"
            print(f"    - 删除已有同名资源: {name} (Asset ID: {asset['id']})")
            del_req = urllib.request.Request(del_url, headers=headers, method="DELETE")
            try:
                with urllib.request.urlopen(del_req):
                    pass
            except Exception as e:
                print(f"      [WARN] 删除老资源失败 (可忽略): {e}")
            break

    upload_url = release["upload_url"].split("{")[0] + f"?name={urllib.parse.quote(name)}"
    content_type = "application/gzip" if name.endswith(".tar.gz") else "text/plain"
    content_length = file_path.stat().st_size

    print(f"    - 上传 {name} ({content_length / 1024 / 1024:.2f} MB)...")

    with open(file_path, "rb") as f:
        file_bytes = f.read()

    req = urllib.request.Request(
        upload_url,
        data=file_bytes,
        headers={
            **headers,
            "Content-Type": content_type,
            "Content-Length": str(content_length),
        },
    )
    with urllib.request.urlopen(req) as resp:
        res_data = json.loads(resp.read().decode())
        print(f"      [OK] 上传成功 (Asset ID: {res_data['id']})")


def upload_all_assets(token: str, release: dict, artifacts: list[Path]):
    print("\n==========================================")
    print(" 步骤 3/4: 上传发布资产至 GitHub Release")
    print("==========================================")
    for art in artifacts:
        upload_asset(token, release, art)


def main():
    parser = argparse.ArgumentParser(description="Elise 本地编译与 GitHub Release 发布工具")
    parser.add_argument("--skip-build", action="store_true", help="跳过 cargo zigbuild 编译")
    parser.add_argument("--skip-package", action="store_true", help="跳过打包步骤")
    parser.add_argument("--tag", type=str, default=None, help="显式指定发布 Tag (默认取 Cargo.toml)")
    args = parser.parse_args()

    root = get_project_root()
    version = get_cargo_version(root)
    tag = args.tag or f"v{version}"

    print(f"Elise 本地发布工具启动: 当前版本 = {version}, Tag = {tag}")

    if not args.skip_build:
        build_binaries(root)
    else:
        print("[SKIP] 跳过本地编译步骤")

    if not args.skip_package:
        artifacts = package_release(root)
    else:
        dist_dir = root / "dist"
        artifacts = [
            dist_dir / "elise-linux-amd64.tar.gz",
            dist_dir / "elise-linux-amd64.tar.gz.sha256",
            dist_dir / "elise-linux-arm64.tar.gz",
            dist_dir / "elise-linux-arm64.tar.gz.sha256",
        ]
        print("[SKIP] 跳过打包步骤，使用已有产物")

    token = get_github_token()
    release = get_or_create_release(token, tag)
    upload_all_assets(token, release, artifacts)

    print("\n==========================================")
    print(" 步骤 4/4: 发布完成！")
    print(f" Release 地址: {release['html_url']}")
    print("==========================================")


if __name__ == "__main__":
    main()
