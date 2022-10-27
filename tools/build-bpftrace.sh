#!/bin/bash -e

git clone --depth=1 https://github.com/iovisor/bpftrace
git submodule update --init --recursive
mkdir -p bin
pushd bpftrace
./build-static.sh
popd
cp bpftrace/build-static/src/bpftrace bin
rm -rf bpftrace

