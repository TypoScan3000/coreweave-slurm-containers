#!/bin/bash
# SPDX-FileCopyrightText: 2026 CoreWeave, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
# SPDX-PackageName: slurm-containers
#
# Usage: [CA_DENYLIST=<file>] check-trust-stores.sh [root]
#
# Scans root (default /, one filesystem, skipping /proc /sys /dev) for PEM/DER certificate
# files, CA bundles and Java keystores holding a certificate whose public key (SPKI SHA-256)
# is listed in CA_DENYLIST (default /usr/share/sunk/ca-denylist.txt). Source certs under
# /usr/share/ca-certificates that are `!`-disabled in /etc/ca-certificates.conf are ignored.
# Prints each offending path, CN and SPKI and exits 1 if any are found, 0 if none, 2 on
# error. Requires python3; uses keytool for non-JKS keystores.
set -euo pipefail

exec python3 -I - "${CA_DENYLIST:-/usr/share/sunk/ca-denylist.txt}" "${1:-/}" <<'EOF'
import base64
import hashlib
import os
import re
import shutil
import struct
import subprocess
import sys
import time

denylist_path, root = sys.argv[1], os.path.abspath(sys.argv[2])
try:
    deny = {}
    with open(denylist_path) as f:
        for line in f:
            if line.strip() and not line.lstrip().startswith("#"):
                spki, cn = line.split(None, 1)
                deny[spki.lower()] = cn.strip()
    if not deny:
        raise ValueError(f"no entries in {denylist_path}")
    root_dev = os.lstat(root).st_dev
except (OSError, ValueError) as e:
    print(f"check-trust-stores: {e}", file=sys.stderr)
    sys.exit(2)

PEM_RE = re.compile(rb"-----BEGIN (?:TRUSTED )?CERTIFICATE-----([A-Za-z0-9+/=\s]+?)-----END")
CERT_SUFFIXES = (".pem", ".crt", ".cer", ".cert", ".der")
KEYSTORE_SUFFIXES = (".jks", ".keystore", ".truststore")
NAME_HINTS = ("cacert", "ca-bundle", "ca_bundle", "ca-certificates")
MAX_SIZE = 64 << 20
SKIP = {os.path.join(root, d) for d in ("proc", "sys", "dev")}
try:
    with open(os.path.join(root, "etc/ca-certificates.conf")) as f:
        src = os.path.join(root, "usr/share/ca-certificates")
        DISABLED = {os.path.join(src, l[1:].strip()) for l in f if l.startswith("!")}
except OSError:
    DISABLED = set()


def tlv(b, i):
    """Value start and end of the DER element at offset i."""
    n, i = b[i + 1], i + 2
    if n & 0x80:
        k = n & 0x7F
        n, i = int.from_bytes(b[i : i + k], "big"), i + k
    if i + n > len(b):
        raise ValueError("truncated DER")
    return i, i + n


def spki_sha256(cert):
    # Certificate > tbsCertificate > [0] version?, serial, signature, issuer, validity,
    # subject, subjectPublicKeyInfo. Trailing bytes (TRUSTED CERTIFICATE aux) are ignored.
    if cert[:1] != b"\x30":
        return None
    i = tlv(cert, tlv(cert, 0)[0])[0]
    if cert[i] == 0xA0:
        i = tlv(cert, i)[1]
    for _ in range(5):
        i = tlv(cert, i)[1]
    return hashlib.sha256(cert[i : tlv(cert, i)[1]]).hexdigest()


def jks_certs(d):
    pos = 12
    version, count = struct.unpack(">II", d[4:12])

    def take(n):
        nonlocal pos
        pos += n
        return d[pos - n : pos]

    def skip_utf():
        take(struct.unpack(">H", take(2))[0])

    for _ in range(count):
        tag = struct.unpack(">I", take(4))[0]
        skip_utf()  # alias
        take(8)  # timestamp
        if tag == 1:  # private key entry + chain
            take(struct.unpack(">I", take(4))[0])
            certs = struct.unpack(">I", take(4))[0]
        elif tag == 2:  # trusted cert entry
            certs = 1
        else:
            raise ValueError(f"unsupported JKS entry tag {tag}")
        for _ in range(certs):
            if version == 2:
                skip_utf()  # cert type
            yield take(struct.unpack(">I", take(4))[0])


def keytool_certs(path):
    keytool = shutil.which("keytool")
    if not keytool:
        raise ValueError("not JKS and keytool not found")
    storepass = "changeit"
    try:
        with open("/etc/default/cacerts") as f:
            m = re.search(r"^storepass=['\"]?([^'\"\n]*)", f.read(), re.M)
            storepass = m.group(1) if m else storepass
    except OSError:
        pass
    out = subprocess.run(
        [keytool, "-list", "-rfc", "-keystore", path, "-storepass", storepass],
        capture_output=True,
        check=True,
        timeout=60,
    ).stdout
    return pem_certs(out)


def pem_certs(d):
    for m in PEM_RE.finditer(d):
        try:
            yield base64.b64decode(m.group(1))
        except ValueError:
            continue


def certs_in(path, name, d):
    if d[:4] == b"\xfe\xed\xfe\xed":
        return jks_certs(d)
    if b"-----BEGIN " in d:
        return pem_certs(d)
    if (name == "cacerts" or name.endswith(KEYSTORE_SUFFIXES)) and d[:1] in (b"\x30", b"\xce"):
        return keytool_certs(path)  # PKCS12 / JCEKS
    if name.endswith(CERT_SUFFIXES):
        return [d]
    return []


def candidate(name):
    n = name.lower()
    return n.endswith(CERT_SUFFIXES + KEYSTORE_SUFFIXES) or any(h in n for h in NAME_HINTS)


start = time.monotonic()
hits = scanned = disabled = 0
stack = [root]
while stack:
    try:
        entries = list(os.scandir(stack.pop()))
    except OSError:
        continue
    for e in entries:
        try:
            if e.is_dir(follow_symlinks=False):
                if e.path not in SKIP and e.stat(follow_symlinks=False).st_dev == root_dev:
                    stack.append(e.path)
                continue
            if not (e.is_file(follow_symlinks=False) and candidate(e.name)):
                continue
            if e.stat(follow_symlinks=False).st_size > MAX_SIZE:
                continue
            with open(e.path, "rb") as f:
                d = f.read()
            scanned += 1
            for cert in certs_in(e.path, e.name, d):
                spki = spki_sha256(cert)
                if spki not in deny:
                    continue
                if e.path in DISABLED:
                    disabled += 1
                    continue
                hits += 1
                print(f"DENYLISTED {e.path}: {deny[spki]} (SPKI {spki})")
        except (OSError, ValueError, IndexError, struct.error, subprocess.SubprocessError) as err:
            print(f"warning: skipped {e.path}: {err}", file=sys.stderr)

elapsed = time.monotonic() - start
print(
    f"check-trust-stores: {hits} denylisted certificate(s) in {scanned} files under {root}"
    f" ({disabled} disabled source certs ignored, {elapsed:.1f}s)"
)
sys.exit(1 if hits else 0)
EOF
