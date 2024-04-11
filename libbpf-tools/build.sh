#!/bin/bash

set -eu

# Check if an argument is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <ARCH (riscv64|armv7l)>"
    exit 1
fi

# Assign the argument to ARCH variable
ARCH="$1"

# Check the value of ARCH
if [ "$ARCH" != "riscv64" ] && [ "$ARCH" != "armv7l" ]; then
    echo "Invalid ARCH value. Allowed values are riscv64 and armv7l."
    exit 1
fi

if [ "$ARCH" == "armv7l" ]; then


LIBS_DIR=./armv7l_libs

if ! [ -d "$LIBS_DIR" ]; then
    mkdir -p $LIBS_DIR
    pushd $LIBS_DIR > /dev/null
    sdb pull /usr/lib/libelf.so.1 .
    sdb pull /lib/libz.so.1 .
    sdb pull /usr/lib/ld-linux.so.3 .
    ln -s libelf.so.1 libelf.so
    ln -s libz.so.1 libz.so
    popd > /dev/null
else
    echo skipping sdb pull
fi


elif [ "$ARCH" == "riscv64" ]; then

LIBS_DIR=./riscv_libs

if ! [ -d "$LIBS_DIR" ]; then
    mkdir -p $LIBS_DIR
    pushd $LIBS_DIR > /dev/null
    sdb pull /usr/lib64/libelf.so.1 .
    sdb pull /usr/lib64/libz.so.1 .
    sdb pull /lib/ld-linux-riscv64-lp64d.so.1 .
    ln -s libelf.so.1 libelf.so
    ln -s libz.so.1 libz.so
    popd > /dev/null
else
    echo skipping sdb pull
fi


fi

cp /usr/include/libelf.h $LIBS_DIR
cp /usr/include/gelf.h $LIBS_DIR
cp /usr/include/zlib.h $LIBS_DIR
cp /usr/include/zconf.h $LIBS_DIR


if [ "$ARCH" == "riscv64" ]; then
compiler=riscv64-linux-gnu-g
ARCH_TRANSLATED=riscv
ARCH_FLAGS=
else
compiler=arm-linux-gnueabi-g
# ARCH_FLAGS below come from https://gist.github.com/fm4dd/c663217935dc17f0fc73c9c81b0aa845
# ARCH_FLAGS="-mcpu=cortex-a72 -mfloat-abi=soft -mfpu=neon-fp-armv8"
# ARCH_FLAGS below come from native gcc on RPI-4.
ARCH_FLAGS="-mfloat-abi=softfp -mtune=cortex-a8 -mtls-dialect=gnu -marm -march=armv7-a"
ARCH_TRANSLATED=arm
fi

STATIC= # STATIC="-static -static-libgcc -static-libstdc++"



EXTRA_CFLAGS="$ARCH_FLAGS " EXTRA_LDFLAGS=" $STATIC -L$LIBS_DIR  -Wl,--export-dynamic,--dynamic-linker=/lib/ld-linux-riscv64-lp64d.so.1" CROSS_COMPILE=$compiler ARCH=$ARCH_TRANSLATED make  # -j12 # --debug=b