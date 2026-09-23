#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Thin wrapper for the scripts/learning-ledger.py pytest suite.
#
# Run: bash scripts/tests/test-learning-ledger.sh   (from repo root; non-zero on failure)
set -u
cd "$(dirname "$0")/../.."

exec python3 -m pytest scripts/tests/test_learning_ledger.py -q
