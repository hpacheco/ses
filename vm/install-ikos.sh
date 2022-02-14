#/bin/sh

git clone https://github.com/NASA-SW-VnV/ikos
cd ikos
mkdir build
cd build
cmake \
    -DCMAKE_INSTALL_PREFIX="/usr/local/" \
    -DLLVM_CONFIG_EXECUTABLE="/usr/bin/llvm-config-9" \
    ..
make
sudo make install
