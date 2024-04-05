#!/bin/bash

set -eu

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

cp /usr/include/libelf.h $LIBS_DIR
cp /usr/include/gelf.h $LIBS_DIR
cp /usr/include/zlib.h $LIBS_DIR
cp /usr/include/zconf.h $LIBS_DIR

compiler=arm-linux-gnueabi-g
STATIC= # STATIC="-static -static-libgcc -static-libstdc++"

# ARCH_FLAGS below come from https://gist.github.com/fm4dd/c663217935dc17f0fc73c9c81b0aa845
# ARCH_FLAGS="-mcpu=cortex-a72 -mfloat-abi=soft -mfpu=neon-fp-armv8"

# ARCH_FLAGS below come from native gcc on RPI-4.
ARCH_FLAGS="-mfloat-abi=softfp -mtune=cortex-a8 -mtls-dialect=gnu -marm -march=armv7-a"

EXTRA_CFLAGS="$ARCH_FLAGS " EXTRA_LDFLAGS=" $STATIC -L$LIBS_DIR  -Wl,--export-dynamic,--dynamic-linker=/usr/lib/ld-linux.so.3" CROSS_COMPILE=$compiler make  # -j12 # --debug=b