"""Pinned release downloads with mandatory digest and archive validation."""
import gzip
import hashlib
import json
import os
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import time
from pathlib import Path


def request(url, limit=8 * 1024 * 1024):
    req = urllib.request.Request(url, headers={'User-Agent': 'VVPIS/1.0', 'Accept': '*/*'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=45) as response:
        body = response.read(limit + 1)
    if len(body) > limit:
        raise ValueError('下载超过大小限制')
    return body


def download(url, target, digest):
    if not url.startswith('https://') or len(digest) != 64:
        raise ValueError('必须使用 HTTPS 和已固定的 SHA256')
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'VVPIS/1.0'})
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            sha, size = hashlib.sha256(), 0
            with opener.open(req, timeout=60) as response, target.open('wb') as output:
                while True:
                    block = response.read(1024 * 1024)
                    if not block:
                        break
                    size += len(block)
                    if size > 512 * 1024 * 1024:
                        raise ValueError('下载超过大小限制')
                    sha.update(block)
                    output.write(block)
            if sha.hexdigest() != digest:
                raise ValueError('上游文件 SHA256 不符，已中止安装')
            return
        except (OSError, urllib.error.URLError):
            if attempt == 2:
                raise RuntimeError('上游下载失败；请检查 GitHub 连通性') from None
            time.sleep(attempt + 1)
        finally:
            if target.exists() and 'sha' in locals() and sha.hexdigest() != digest:
                target.unlink()


def extract_safe(archive, destination):
    destination = destination.resolve()
    with tarfile.open(archive) as tar:
        members = tar.getmembers()
        for item in members:
            path = (destination / item.name).resolve()
            if not path.is_relative_to(destination) or not (item.isfile() or item.isdir()):
                raise ValueError('压缩包包含越界路径或链接')
        # Python 3.10 compatible: every member was validated before extraction.
        tar.extractall(destination, members=members)


def install_binaries(project, destination, arch):
    manifest = json.loads((project / 'versions.json').read_text())
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='vvpis-download-') as directory:
        scratch = Path(directory)
        for name in ['xui', 'hysteria', 'mihomo']:
            component = manifest[name]
            item = component['assets'][arch]
            tag = urllib.parse.quote(component['version'], safe='')
            url = 'https://github.com/' + component['repository'] + '/releases/download/' + tag + '/' + item['name']
            archive = scratch / item['name']
            print('下载并校验 ' + name + ' ' + component['version'], flush=True)
            download(url, archive, item['sha256'])
            if name == 'xui':
                extract_safe(archive, destination)
                for path in (destination / 'x-ui').rglob('*'):
                    if path.is_file() and (path.name == 'x-ui' or path.name.startswith('xray-linux-')):
                        path.chmod(0o755)
            elif name == 'mihomo':
                target = destination / 'mihomo'
                with gzip.open(archive, 'rb') as source, target.open('wb') as output:
                    while True:
                        block = source.read(1024 * 1024)
                        if not block:
                            break
                        output.write(block)
                target.chmod(0o755)
            else:
                os.replace(archive, destination / 'hysteria')
                (destination / 'hysteria').chmod(0o755)
    return manifest
