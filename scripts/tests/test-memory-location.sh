#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Thin wrapper for the scripts/memory-location.py pytest suite.
#
# Run: bash scripts/tests/test-memory-location.sh   (from repo root; non-zero on failure)
set -u
cd "$(dirname "$0")/../.."

exec python3 -m pytest scripts/tests/test_memory_location.py -q
