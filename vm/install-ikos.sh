#/bin/sh

sudo apt update
sudo apt install -y libsqlite3-dev libboost-thread-dev libboost-test-dev libboost-filesystem-dev libtbb-dev binfmt-support
# download packages
mkdir -p deb
wget -nc -P deb http://mirrors.kernel.org/ubuntu/pool/main/libf/libffi/libffi7_3.3-4_amd64.deb
wget -nc -P deb http://mirrors.kernel.org/ubuntu/pool/universe/l/llvm-toolchain-9/libllvm9_9.0.1-12_amd64.deb
wget -nc -P deb http://mirrors.kernel.org/ubuntu/pool/universe/l/llvm-toolchain-9/llvm-9-runtime_9.0.1-12_amd64.deb
wget -nc -P deb http://mirrors.kernel.org/ubuntu/pool/universe/l/llvm-toolchain-9/libllvm9_9.0.1-12_amd64.deb
wget -nc -P deb http://mirrors.kernel.org/ubuntu/pool/universe/l/llvm-toolchain-9/llvm-9-tools_9.0.1-12_amd64.deb
wget -nc -P deb http://mirrors.kernel.org/ubuntu/pool/main/l/llvm-toolchain-9/libllvm9_9.0.1-12_amd64.deb
wget -nc -P deb http://mirrors.kernel.org/ubuntu/pool/universe/l/llvm-toolchain-9/libclang-cpp9_9.0.1-12_amd64.deb
wget -nc -P deb http://mirrors.kernel.org/ubuntu/pool/universe/l/llvm-toolchain-9/llvm-9-dev_9.0.1-12_amd64.deb
wget -nc -P deb http://mirrors.kernel.org/ubuntu/pool/universe/l/llvm-toolchain-9/clang-9_9.0.1-12_amd64.deb
wget -nc -P deb http://mirrors.kernel.org/ubuntu/pool/universe/l/llvm-toolchain-9/libclang-common-9-dev_9.0.1-12_amd64.deb
wget -nc -P deb http://security.ubuntu.com/ubuntu/pool/main/g/gcc-9/libstdc++-9-dev_9.3.0-17ubuntu1~20.04_amd64.deb
wget -nc -P deb http://security.ubuntu.com/ubuntu/pool/main/g/gcc-9/libgcc-9-dev_9.3.0-17ubuntu1~20.04_amd64.deb
wget -nc -P deb http://security.ubuntu.com/ubuntu/pool/universe/g/gcc-9/libobjc-9-dev_9.3.0-17ubuntu1~20.04_amd64.deb
wget -nc -P deb http://security.ubuntu.com/ubuntu/pool/main/g/gcc-9/gcc-9-base_9.3.0-17ubuntu1~20.04_amd64.deb
wget -nc -P deb http://security.ubuntu.com/ubuntu/pool/main/g/gcc-9/libasan5_9.3.0-17ubuntu1~20.04_amd64.deb
wget -nc -P deb http://mirrors.kernel.org/ubuntu/pool/universe/l/llvm-toolchain-9/llvm-9_9.0.1-12_amd64.deb
sudo dpkg -i deb/*.deb
# manually install ubuntu focal packages
git clone https://github.com/NASA-SW-VnV/ikos
cd ikos
mkdir build
cd build
cmake \
    -DCMAKE_INSTALL_PREFIX="/usr/local/" \
    -DLLVM_CONFIG_EXECUTABLE="/usr/bin/llvm-config-9" \
    -DCLANG_EXECUTABLE="/usr/bin/clang-9" \
    ..
make
sudo make install
cd ../..
