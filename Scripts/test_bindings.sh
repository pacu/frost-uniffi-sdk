#!/bin/bash

ROOT_DIR=$(pwd)
SCRIPT_DIR="${SCRIPT_DIR:-$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )}"



if [[ "$OSTYPE" == "darwin"* ]]; then
ARCH=$(arch)

if [[ "$ARCH" == "arm64" ]]; then
TARGET="aarch64-apple-darwin"
else
TARGET="x86_64-apple-darwin"
fi


BINARIES_DIR="$ROOT_DIR/target/$TARGET/debug"
else 
BINARIES_DIR="$ROOT_DIR/target/debug"
fi

BINDINGS_DIR="$ROOT_DIR/frost_go_ffi"

pushd $BINDINGS_DIR
LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-}:$BINARIES_DIR" \
	CGO_LDFLAGS="-lfrost_uniffi_sdk -L$BINARIES_DIR -lm -ldl" \
	CGO_ENABLED=1 \
	go test -v