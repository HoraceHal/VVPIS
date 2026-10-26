#!/usr/bin/env bash
set -Eeuo pipefail
# Download this file, inspect it, then execute with sudo on a dedicated Linux VPS.
if [[ "$(uname -s)" != Linux ]]; then
  printf '%s\n' 'VVPIS requires a Linux server; do not run it on your Windows computer.' >&2
  exit 1
fi
if [[ ${EUID} -ne 0 ]]; then
  exec sudo bash "$0" "$@"
fi
if ! command -v python3 >/dev/null; then
  if ! command -v apt-get >/dev/null; then
    printf '%s\n' 'Use Ubuntu 22.04/24.04/26.04 or Debian 12/13.' >&2
    exit 1
  fi
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 ca-certificates
fi
source_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
temporary_dir=''
cleanup_bootstrap() {
  if [[ -n "${temporary_dir}" && -d "${temporary_dir}" ]]; then
    rm -rf -- "${temporary_dir}"
  fi
}
trap cleanup_bootstrap EXIT
if [[ ! -f "${source_dir}/vvpis/cli.py" ]]; then
  temporary_dir="$(mktemp -d -t vvpis-source-XXXXXXXX)"
  python3 - "${temporary_dir}" <<'PY'
import io, json, pathlib, re, sys, tarfile, urllib.request
folder = pathlib.Path(sys.argv[1]).resolve()
headers = {'User-Agent': 'VVPIS-bootstrap/1.0'}
def get(url, limit):
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as r:
        b = r.read(limit + 1)
    if len(b) > limit: raise SystemExit('Source archive too large')
    return b
try:
    meta = json.loads(get('https://api.github.com/repos/HoraceHal/VVPIS/commits/main', 1000000))
    sha = meta['sha']
    if not re.fullmatch(r'[0-9a-f]{40}', sha): raise ValueError('Invalid commit')
    body = get('https://codeload.github.com/HoraceHal/VVPIS/tar.gz/' + sha, 10000000)
    with tarfile.open(fileobj=io.BytesIO(body), mode='r:gz') as t:
        members = t.getmembers()
        for m in members:
            target = (folder / m.name).resolve()
            if not target.is_relative_to(folder) or not (m.isfile() or m.isdir()):
                raise ValueError('Unsafe source archive')
        t.extractall(folder, members=members)
    print('Using VVPIS commit ' + sha)
except Exception as e:
    raise SystemExit('Cannot download VVPIS source. Check GitHub access/rate limits; alternatively git clone the repository. ' + str(e))
PY
  source_dir="$(find "${temporary_dir}" -mindepth 1 -maxdepth 1 -type d -name 'VVPIS-*' -print -quit)"
  [[ -n "${source_dir}" && -f "${source_dir}/vvpis/cli.py" ]] || { printf '%s\n' 'Missing installer source' >&2; exit 1; }
fi
cd -- "${source_dir}"
python3 -m vvpis.cli "$@"
