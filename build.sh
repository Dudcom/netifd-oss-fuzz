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
    # Create empty examples directory to avoid cmake errors
    mkdir -p examples
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
    # Create empty examples directory to avoid cmake errors
    mkdir -p examples
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

if [ ! -d "udebug" ]; then
    echo "Downloading udebug..."
    git clone https://github.com/openwrt/udebug.git
    cd udebug
    rm -rf tests
    # Create empty examples directory to avoid cmake errors
    mkdir -p examples
    cd ..
fi

cd udebug
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
         -DBUILD_TESTS=OFF \
         -DBUILD_SHARED_LIBS=OFF
make -j$(nproc)
make install
cd "$DEPS_DIR"

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
$CC $CFLAGS $LIB_FUZZING_ENGINE netifd_fuzz.o \
    utils.o system-dummy.o tunnel.o handler.o \
    interface.o interface-ip.o interface-event.o \
    iprule.o proto.o proto-static.o proto-shell.o \
    config.o device.o bridge.o veth.o vlan.o alias.o \
    macvlan.o ubus.o vlandev.o wireless.o extdev.o \
    bonding.o vrf.o \
    $LDFLAGS -static -lubox -luci -lnl-tiny -ljson-c -lubus \
    -o $OUT/netifd_fuzzer
rm -f *.o

echo "Build completed successfully!"
echo "Fuzzer binary: $OUT/netifd_fuzzer"
