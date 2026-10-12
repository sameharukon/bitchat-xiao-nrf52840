#!/bin/sh
# Builds the sketch against host stubs (OpenSSL-backed SHA-256, Ed25519, and
# X25519) and runs the public MESSAGE acceptance tests.
set -eu
cd "$(dirname "$0")"
out="${TMPDIR:-/tmp}/bitchat_public_message_test"
c++ -std=c++17 -Wall -Wno-unused-parameter -Istubs \
  -include stubs/arduino_stub.h -x c++ public_message_test.cpp \
  -o "$out" -lcrypto
"$out"
