#!/usr/bin/env bash
# Fail when a binary needs a newer glibc than the oldest one we support.
#
# The relay links DuckDB through CGO, so the binary depends on the glibc of
# the machine that built it. Building on a new runner image quietly raises
# the requirement (v0.2.0 needed GLIBC_2.43 and would not start on Ubuntu
# 24.04 or Debian 12). The release build runs in golang:1.26-bookworm, whose
# glibc is 2.36; this check keeps it there.
#
# Usage: check-glibc.sh <binary> [max-version]   (default max-version 2.36)
set -euo pipefail

binary="${1:?usage: check-glibc.sh <binary> [max-version]}"
max_allowed="${2:-2.36}"

versions="$(objdump -T "$binary" | grep -o 'GLIBC_[0-9][0-9.]*' | sed 's/^GLIBC_//' | sort -Vu)"
if [ -z "$versions" ]; then
  echo "::error::No GLIBC symbol versions found in $binary; is it a dynamically linked ELF binary?"
  exit 1
fi

highest="$(printf '%s\n' "$versions" | tail -n1)"
echo "$binary needs glibc $highest (allowed: $max_allowed or older)"

if [ "$(printf '%s\n%s\n' "$highest" "$max_allowed" | sort -V | tail -n1)" != "$max_allowed" ]; then
  echo "::error::$binary needs GLIBC_$highest, newer than the supported $max_allowed. Symbols above the limit:"
  objdump -T "$binary" | grep 'GLIBC_' | while read -r line; do
    v="$(printf '%s' "$line" | grep -o 'GLIBC_[0-9][0-9.]*' | sed 's/^GLIBC_//')"
    if [ "$(printf '%s\n%s\n' "$v" "$max_allowed" | sort -V | tail -n1)" != "$max_allowed" ]; then
      echo "  $line"
    fi
  done
  exit 1
fi
