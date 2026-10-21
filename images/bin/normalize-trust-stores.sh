#!/bin/bash
# SPDX-FileCopyrightText: 2026 CoreWeave, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
# SPDX-PackageName: slurm-containers
#
# Usage: normalize-trust-stores.sh
#
# Removes the roots listed in $CA_DENYLIST (default /usr/share/sunk/ca-denylist.txt) from
# the OS trust store and the Java keystore, then points the CA bundles shipped by pip
# packages (certifi, botocore), conda and the AWS CLI at the system bundle. Idempotent.
set -euo pipefail

denylist=${CA_DENYLIST:-/usr/share/sunk/ca-denylist.txt}
bundle=/etc/ssl/certs/ca-certificates.crt
keystore=/etc/ssl/certs/java/cacerts
conf=/etc/ca-certificates.conf

denied_spkis=$(awk '!/^[[:space:]]*(#|$)/ { print tolower($1) }' "${denylist}")

is_denied() {
  local spki
  spki=$(openssl x509 -in "$1" -noout -pubkey 2>/dev/null |
    openssl pkey -pubin -outform DER 2>/dev/null | sha256sum) || return 1
  grep -qxF "${spki%% *}" <<<"${denied_spkis}"
}

# Matched by public key, so file names don't matter. The source certs are kept and their
# `!` entries stop ca-certificates upgrades from re-enabling them.
disable=()
while IFS= read -r -d '' crt; do
  if is_denied "${crt}"; then disable+=("${crt#/usr/share/ca-certificates/}"); fi
done < <(find /usr/share/ca-certificates -type f -name '*.crt' -print0)
if [ "${#disable[@]}" -gt 0 ]; then
  updated=$(awk 'NR == FNR { deny[$0]; next } $0 in deny { $0 = "!" $0 } 1' \
    <(printf '%s\n' "${disable[@]}") "${conf}")
  printf '%s\n' "${updated}" >"${conf}"
fi
while IFS= read -r -d '' crt; do
  if is_denied "${crt}"; then rm -fv "${crt}"; fi
done < <(find /usr/local/share/ca-certificates -type f -name '*.crt' -print0 2>/dev/null)

# --fresh only passes additions to the Java hook, so rebuild the keystore from scratch.
regen_keystore=false
if [ -f "${keystore}" ] && [ -x /etc/ca-certificates/update.d/jks-keystore ]; then
  rm -f "${keystore}"
  regen_keystore=true
fi
update-ca-certificates --fresh
[ -s "${bundle}" ] || { echo "${bundle} is missing or empty" >&2; exit 1; }
if ${regen_keystore} && [ ! -s "${keystore}" ]; then
  echo "failed to regenerate ${keystore}" >&2
  exit 1
fi

# Symlinks rather than copies so later update-ca-certificates runs propagate.
# conda hardlinks pkgs/ into its prefix, so the pkgs/ copies are replaced as well.
find / -xdev -type f \( \
  -path '*/certifi/cacert.pem' -o \
  -path '*/botocore/cacert.pem' -o \
  -path '/opt/conda/ssl/cacert.pem' -o \
  -path '/opt/conda/*/ssl/cacert.pem' \
  \) -print0 | xargs -0 -r -t -n 1 ln -sfn "${bundle}"

if [ -x /opt/conda/bin/conda ]; then
  /opt/conda/bin/conda config --system --set ssl_verify "${bundle}"
fi
