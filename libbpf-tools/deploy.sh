#!/bin/bash
set -eux

SKIP_BUILD=
# yes

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
pushd $SCRIPT_DIR > /dev/null

EXTERNAL_BUILD_SCRIPT=../../libbpf/src/build_riscv.sh
file -E $EXTERNAL_BUILD_SCRIPT
RES_LIBPF=`dirname $EXTERNAL_BUILD_SCRIPT`/libbpf.so.1.4.0

if [[ $SKIP_BUILD == "" ]]; then

    pushd `dirname $EXTERNAL_BUILD_SCRIPT` > /dev/null
    ./`basename $EXTERNAL_BUILD_SCRIPT`
    popd > /dev/null

    ./build.sh riscv64

fi

file -E $RES_LIBPF

OUT_DIR=libbpf.applications.riscv64
mkdir -p libbpf.applications.riscv64

cp `file * | grep ELF | cut -d : -f 1`  $OUT_DIR
cp $RES_LIBPF                           $OUT_DIR

zip -r $OUT_DIR.zip $OUT_DIR

popd > /dev/null