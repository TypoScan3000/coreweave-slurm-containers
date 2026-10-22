#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 CoreWeave, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
# SPDX-PackageName: slurm-containers

# Deselects the root CAs implicated in the eMudhra intermediate CA compromise from the system
# trust store, and fails if any of them remain in the generated bundle.
set -euo pipefail

# Entries in /etc/ca-certificates.conf to deselect. Deselections persist across ca-certificates
# package upgrades.
DISTRUSTED_CERTS=(
  mozilla/Comodo_AAA_Services_root.crt
  mozilla/emSign_ECC_Root_CA_-_C3.crt
  mozilla/emSign_ECC_Root_CA_-_G3.crt
  mozilla/emSign_Root_CA_-_C1.crt
)

# SHA-256 of the DER-encoded SubjectPublicKeyInfo of each distrusted root, used to verify the
# bundle regardless of certificate file names.
declare -Ar DISTRUSTED_SPKIS=(
  [bd153ed7b0434f6886b17bce8bbe84ed340c7132d702a8f4fa318f756ecbd6f3]='AAA Certificate Services'
  [8d417db2dd8bf5e3084d1e3f196d583849d81bdd4c00c70b9d39369e96b8c782]='emSign ECC Root CA - G3'
  [c619e4780ed8e0abeda24ad732567de4383a7ea941338f6d1a7d1b49ac792fe9]='emSign Root TLS CA - G3'
  [0a6c2b2ca5b364207954171987ac9d2178561569d8205457e77ca90c32ede282]='emSign Root CS CA - G3'
  [b7408b4d2be0238ba37004dd34e276c6019bd2f24c9db7d4980f5f6c359a4bcc]='emSign Root CA - C1'
  [eabc185c4e82d942b1a5978ba3c0181487d6b3b9974e5c49f72f6d0bd9637150]='emSign ECC Root CA - C3'
)

for cert in "${DISTRUSTED_CERTS[@]}"; do
  sed -i "s|^${cert}\$|!${cert}|" /etc/ca-certificates.conf
done
update-ca-certificates

work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT
awk -v dir="$work_dir" '/-----BEGIN CERTIFICATE-----/ { n++ } n { print > (dir "/" n ".pem") }' \
  /etc/ssl/certs/ca-certificates.crt

for pem in "$work_dir"/*.pem; do
  spki=$(openssl x509 -in "$pem" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | cut -d ' ' -f 1)
  if [[ -n ${DISTRUSTED_SPKIS[$spki]:-} ]]; then
    echo "ERROR: ${DISTRUSTED_SPKIS[$spki]} is still trusted in /etc/ssl/certs/ca-certificates.crt" >&2
    exit 1
  fi
done
