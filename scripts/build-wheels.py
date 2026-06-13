#!/usr/bin/env python3
"""Build PyPI wheels that carry the released notenv binaries.

Each platform wheel contains exactly one file of substance: the prebuilt
static binary, placed under the wheel's data/scripts directory so installers
(pip, uv, pipx) drop it straight onto the environment's PATH. No Python shim,
no Python code at all; `uv tool install notenv` works because a wheel is just
a documented zip layout.

Standard library only, by intent: this script is part of the supply chain.
Output is reproducible: file timestamps inside the wheels come from
SOURCE_DATE_EPOCH (clamped to the zip format's 1980 floor).

Usage (CI runs this over GoReleaser's dist/ after a release build):
    build-wheels.py --version 1.2.3 --dist dist --out dist/wheels
"""

import argparse
import base64
import hashlib
import os
import re
import sys
import time
import zipfile
from pathlib import Path

# goos/goarch -> wheel platform tag(s). Static CGO_ENABLED=0 binaries run on
# any libc, so the linux wheels carry glibc and musl tags at once.
PLATFORM_TAGS = {
    ("linux", "amd64"): "manylinux_2_17_x86_64.manylinux2014_x86_64.musllinux_1_1_x86_64",
    ("linux", "arm64"): "manylinux_2_17_aarch64.manylinux2014_aarch64.musllinux_1_1_aarch64",
    ("darwin", "amd64"): "macosx_10_12_x86_64",
    ("darwin", "arm64"): "macosx_11_0_arm64",
    ("windows", "amd64"): "win_amd64",
    ("windows", "arm64"): "win_arm64",
}

METADATA_TEMPLATE = """\
Metadata-Version: 2.1
Name: notenv
Version: {version}
Summary: Your .env, encrypted and off your disk, with no infrastructure to run.
Home-page: https://dvgils.github.io/notenv/
License: Apache-2.0
Project-URL: Documentation, https://dvgils.github.io/notenv/
Project-URL: Source, https://github.com/DvGils/notenv
Project-URL: Changelog, https://github.com/DvGils/notenv/blob/main/CHANGELOG.md
Classifier: License :: OSI Approved :: Apache Software License
Classifier: Operating System :: OS Independent
Classifier: Topic :: Security
Description-Content-Type: text/markdown

{readme}"""


def record_hash(data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
    return "sha256=" + digest.decode()


def zip_date() -> tuple:
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "315532800"))
    epoch = max(epoch, 315532800)  # the zip format starts at 1980
    t = time.gmtime(epoch)
    return (t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec)


def find_binaries(dist: Path):
    """Yield (binary path, goos, goarch) for every released binary under
    GoReleaser's dist layout (one directory per target, named with the goos
    and goarch as tokens)."""
    for path in sorted(dist.rglob("notenv")) + sorted(dist.rglob("notenv.exe")):
        if not path.is_file():
            continue
        tokens = re.split(r"[_/]", str(path.parent.relative_to(dist)))
        goos = next((t for t in tokens if t in {"linux", "darwin", "windows"}), None)
        goarch = next((t for t in tokens if t in {"amd64", "arm64"}), None)
        if goos and goarch:
            yield path, goos, goarch


def build_wheel(binary: Path, goos: str, goarch: str, version: str, readme: str, out: Path) -> Path:
    platform = PLATFORM_TAGS[(goos, goarch)]
    wheel_name = f"notenv-{version}-py3-none-{platform}.whl"
    dist_info = f"notenv-{version}.dist-info"
    script_name = "notenv.exe" if goos == "windows" else "notenv"
    script_path = f"notenv-{version}.data/scripts/{script_name}"

    metadata = METADATA_TEMPLATE.format(version=version, readme=readme).encode()
    wheel_meta = (
        "Wheel-Version: 1.0\n"
        "Generator: notenv build-wheels (stdlib)\n"
        "Root-Is-Purelib: false\n"
        + "".join(f"Tag: py3-none-{tag}\n" for tag in platform.split("."))
    ).encode()

    date = zip_date()
    records = []
    out.mkdir(parents=True, exist_ok=True)
    wheel = out / wheel_name
    with zipfile.ZipFile(wheel, "w", zipfile.ZIP_DEFLATED) as zf:

        def add(arcname: str, data: bytes, mode: int) -> None:
            info = zipfile.ZipInfo(arcname, date)
            info.external_attr = (mode | 0o100000) << 16  # regular file + mode
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, data)
            records.append(f"{arcname},{record_hash(data)},{len(data)}")

        add(script_path, binary.read_bytes(), 0o755)
        add(f"{dist_info}/METADATA", metadata, 0o644)
        add(f"{dist_info}/WHEEL", wheel_meta, 0o644)
        records.append(f"{dist_info}/RECORD,,")
        record = "\n".join(records) + "\n"
        info = zipfile.ZipInfo(f"{dist_info}/RECORD", date)
        info.external_attr = (0o644 | 0o100000) << 16
        zf.writestr(info, record)
    return wheel


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="PEP 440 version (the tag without the v)")
    parser.add_argument("--dist", required=True, type=Path, help="GoReleaser dist directory")
    parser.add_argument("--out", required=True, type=Path, help="directory to write wheels into")
    parser.add_argument("--readme", type=Path, default=Path("README.md"))
    args = parser.parse_args()

    if not re.fullmatch(r"\d+\.\d+\.\d+((a|b|rc)\d+)?(\.post\d+)?(\.dev\d+)?", args.version):
        print(f"version {args.version!r} is not a release-shaped PEP 440 version", file=sys.stderr)
        return 1
    readme = args.readme.read_text()

    built = 0
    for binary, goos, goarch in find_binaries(args.dist):
        wheel = build_wheel(binary, goos, goarch, args.version, readme, args.out)
        print(f"built {wheel}")
        built += 1
    if built != len(PLATFORM_TAGS):
        print(f"built {built} wheels, expected {len(PLATFORM_TAGS)}: is {args.dist} a full release dist?", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
