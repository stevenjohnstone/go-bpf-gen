#!/bin/bash -e

git clone --branch sjj/sanitise-prog-name https://github.com/stevenjohnstone/bpftrace
mkdir -p bin
pushd bpftrace
./build-static.sh
popd
cp bpftrace/build-static/src/bpftrace bin
rm -rf bpftrace

