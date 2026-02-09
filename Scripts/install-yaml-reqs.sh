#!/bin/bash
set -e

PREFIX="$HOME/.local"
export CPATH="$PREFIX/include:$CPATH"
export LIBRARY_PATH="$PREFIX/lib:$LIBRARY_PATH"
export LD_LIBRARY_PATH="$PREFIX/lib:$LD_LIBRARY_PATH"

# Download and install libyaml


cd /tmp
curl -LO https://github.com/yaml/libyaml/releases/download/0.2.5/yaml-0.2.5.tar.gz
tar -xf yaml-0.2.5.tar.gz
cd yaml-0.2.5
./configure --prefix="$PREFIX"
make -j$(nproc)
make install

# Build and install libcyaml
rm -rf /tmp/libcyaml
cd /tmp
git clone --depth=1 https://github.com/tlsa/libcyaml.git
cd libcyaml
make -j$(nproc)
make install PREFIX="$PREFIX"

# Add symlink for libcyaml.so.1 if needed
if [ ! -f "$PREFIX/lib/libcyaml.so.1" ]; then
  echo "Creating symlink: libcyaml.so.1 -> libcyaml.so.2.0.0"
  ln -s "$PREFIX/lib/libcyaml.so.2.0.0" "$PREFIX/lib/libcyaml.so.1"
fi

echo "libyaml and libcyaml installed to $PREFIX"
