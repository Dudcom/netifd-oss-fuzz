#!/bin/bash -eu

apt-get update
apt-get install -y build-essential cmake pkg-config git libjson-c-dev

DEPS_DIR="$PWD/deps"
mkdir -p "$DEPS_DIR"
cd "$DEPS_DIR"

if [ ! -d "libubox" ]; then
    echo "Downloading libubox..."
    git clone https://github.com/openwrt/libubox.git
    cd libubox
    rm -rf tests examples
    cd ..
fi

cd libubox
# Patch CMakeLists.txt to remove examples subdirectory reference
if [ -f CMakeLists.txt ]; then
    sed -i '/ADD_SUBDIRECTORY(examples)/d' CMakeLists.txt
    sed -i '/add_subdirectory(examples)/d' CMakeLists.txt
    sed -i '/ADD_SUBDIRECTORY.*examples/d' CMakeLists.txt
    sed -i '/add_subdirectory.*examples/d' CMakeLists.txt
fi
mkdir -p build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX="$DEPS_DIR/install" \
         -DCMAKE_C_FLAGS="$CFLAGS" \
         -DBUILD_LUA=OFF \
         -DBUILD_EXAMPLES=OFF \
         -DBUILD_TESTS=OFF \
         -DBUILD_STATIC=ON \
         -DBUILD_SHARED_LIBS=OFF
make -j$(nproc)
make install
cd "$DEPS_DIR"

if [ ! -d "uci" ]; then
    echo "Downloading libuci..."
    git clone https://git.openwrt.org/project/uci.git
    cd uci
    rm -rf tests
    cd ..
fi

cd uci
mkdir -p build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX="$DEPS_DIR/install" \
         -DCMAKE_C_FLAGS="$CFLAGS" \
         -DBUILD_LUA=OFF \
         -DBUILD_TESTS=OFF \
         -DBUILD_SHARED_LIBS=OFF
make -j$(nproc)
make install
cd "$DEPS_DIR"

if [ ! -d "libnl-tiny" ]; then
    echo "Downloading libnl-tiny..."
    git clone https://git.openwrt.org/project/libnl-tiny.git
    cd libnl-tiny
    rm -rf tests
    cd ..
fi

cd libnl-tiny
mkdir -p build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX="$DEPS_DIR/install" \
         -DCMAKE_C_FLAGS="$CFLAGS" \
         -DBUILD_TESTS=OFF \
         -DBUILD_SHARED_LIBS=OFF
make -j$(nproc)
make install
cd "$DEPS_DIR"

if [ ! -d "ubus" ]; then
    echo "Downloading libubus..."
    git clone https://git.openwrt.org/project/ubus.git
    cd ubus
    rm -rf tests examples
    cd ..
fi

cd ubus
# Patch CMakeLists.txt to remove examples subdirectory reference
if [ -f CMakeLists.txt ]; then
    sed -i '/ADD_SUBDIRECTORY(examples)/d' CMakeLists.txt
    sed -i '/add_subdirectory(examples)/d' CMakeLists.txt
    sed -i '/ADD_SUBDIRECTORY.*examples/d' CMakeLists.txt
    sed -i '/add_subdirectory.*examples/d' CMakeLists.txt
fi
mkdir -p build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX="$DEPS_DIR/install" \
         -DCMAKE_C_FLAGS="$CFLAGS" \
         -DBUILD_LUA=OFF \
         -DBUILD_EXAMPLES=OFF \
         -DBUILD_TESTS=OFF \
         -DBUILD_SHARED_LIBS=OFF
make -j$(nproc)
make install
cd "$DEPS_DIR"

# Download and extract proper udebug headers
if [ ! -d "udebug" ]; then
    echo "Downloading udebug for headers..."
    git clone https://github.com/openwrt/udebug.git
fi

echo "Extracting udebug headers..."
mkdir -p "$DEPS_DIR/install/include"
cp udebug/udebug.h "$DEPS_DIR/install/include/"

# Create minimal udebug implementation for linking
echo "Creating minimal udebug implementation..."
cat > "$DEPS_DIR/udebug_minimal.c" << 'EOF'
#include "udebug.h"
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

/* Only implement functions that are NOT static inline in udebug.h */

void udebug_init(struct udebug *ctx) {
    memset(ctx, 0, sizeof(*ctx));
}

void udebug_auto_connect(struct udebug *ctx, const char *path) {
    /* No-op for fuzzing */
}

void udebug_free(struct udebug *ctx) {
    /* No-op for fuzzing */
}

int udebug_buf_init(struct udebug_buf *buf, size_t entries, size_t size) {
    memset(buf, 0, sizeof(*buf));
    return 0;
}

int udebug_buf_add(struct udebug *ctx, struct udebug_buf *buf, const struct udebug_buf_meta *meta) {
    return 0;
}

void udebug_buf_free(struct udebug_buf *buf) {
    /* No-op for fuzzing */
}

void *udebug_entry_append(struct udebug_buf *buf, const void *data, uint32_t len) {
    static char dummy[1024];
    return dummy;
}

int udebug_entry_printf(struct udebug_buf *buf, const char *fmt, ...) {
    return 0;
}

int udebug_entry_vprintf(struct udebug_buf *buf, const char *fmt, va_list ap) {
    return 0;
}

void udebug_entry_add(struct udebug_buf *buf) {
    /* No-op for fuzzing */
}

void udebug_ubus_ring_init(struct udebug *ctx, struct udebug_ubus_ring *ring) {
    /* No-op for fuzzing */
}

/* Match the exact signature from udebug.h */
void udebug_ubus_apply_config(struct udebug *ud, struct udebug_ubus_ring *rings, int n,
                              struct blob_attr *data, bool enabled) {
    /* No-op for fuzzing */
}
EOF

# Compile the minimal udebug implementation
echo "Compiling minimal udebug..."
$CC $CFLAGS -I"$DEPS_DIR/install/include" -c "$DEPS_DIR/udebug_minimal.c" -o "$DEPS_DIR/udebug_minimal.o"

cd ..

: "${CFLAGS:=-O2 -fPIC}"
: "${LDFLAGS:=}"
: "${PKG_CONFIG_PATH:=}"
: "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"  # Default to libFuzzer if not provided

# Add flag to suppress C23 extension warnings
export CFLAGS="$CFLAGS -Wno-c23-extensions"

export PKG_CONFIG_PATH="$DEPS_DIR/install/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
export CFLAGS="$CFLAGS -I$DEPS_DIR/install/include"
export LDFLAGS="$LDFLAGS -L$DEPS_DIR/install/lib"

export CFLAGS="$CFLAGS -D_GNU_SOURCE -DDUMMY_MODE=1 -DDEBUG -std=gnu99"
export CFLAGS="$CFLAGS -I$DEPS_DIR/install/include/libnl-tiny"

# Generate ethtool-modes.h if script exists
if [ -f "make_ethtool_modes_h.sh" ]; then
    echo "Generating ethtool-modes.h..."
    ./make_ethtool_modes_h.sh $CC > ethtool-modes.h || echo "Warning: Failed to generate ethtool-modes.h"
fi

echo "Compiling netifd source files..."
$CC $CFLAGS -c main.c -o main.o
$CC $CFLAGS -c utils.c -o utils.o
$CC $CFLAGS -c system-dummy.c -o system-dummy.o
$CC $CFLAGS -c tunnel.c -o tunnel.o
$CC $CFLAGS -c handler.c -o handler.o
$CC $CFLAGS -c interface.c -o interface.o
$CC $CFLAGS -c interface-ip.c -o interface-ip.o
$CC $CFLAGS -c interface-event.c -o interface-event.o
$CC $CFLAGS -c iprule.c -o iprule.o
$CC $CFLAGS -c proto.c -o proto.o
$CC $CFLAGS -c proto-static.c -o proto-static.o
$CC $CFLAGS -c proto-shell.c -o proto-shell.o
$CC $CFLAGS -c config.c -o config.o
$CC $CFLAGS -c device.c -o device.o
$CC $CFLAGS -c bridge.c -o bridge.o
$CC $CFLAGS -c veth.c -o veth.o
$CC $CFLAGS -c vlan.c -o vlan.o
$CC $CFLAGS -c alias.c -o alias.o
$CC $CFLAGS -c macvlan.c -o macvlan.o
$CC $CFLAGS -c ubus.c -o ubus.o
$CC $CFLAGS -c vlandev.c -o vlandev.o
$CC $CFLAGS -c wireless.c -o wireless.o
$CC $CFLAGS -c extdev.c -o extdev.o
$CC $CFLAGS -c bonding.c -o bonding.o
$CC $CFLAGS -c vrf.c -o vrf.o

echo "Compiling fuzzer..."
$CC $CFLAGS -c netifd_fuzz.c -o netifd_fuzz.o

echo "Linking fuzzer statically..."
# Link with full paths to static libraries to avoid linker issues
$CC $CFLAGS $LIB_FUZZING_ENGINE netifd_fuzz.o \
    utils.o system-dummy.o tunnel.o handler.o \
    interface.o interface-ip.o interface-event.o \
    iprule.o proto.o proto-static.o proto-shell.o \
    config.o device.o bridge.o veth.o vlan.o alias.o \
    macvlan.o ubus.o vlandev.o wireless.o extdev.o \
    bonding.o vrf.o \
    $DEPS_DIR/udebug_minimal.o \
    $DEPS_DIR/install/lib/libubox.a \
    $DEPS_DIR/install/lib/libuci.a \
    $DEPS_DIR/install/lib/libnl-tiny.a \
    $DEPS_DIR/install/lib/libubus.a \
    $LDFLAGS -static -ljson-c \
    -o $OUT/netifd_fuzzer
rm -f *.o

echo "Build completed successfully!"
echo "Fuzzer binary: $OUT/netifd_fuzzer"
