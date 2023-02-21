FROM ubuntu:22.04
USER root

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && apt-get install -yq libsqlite3-dev libboost-thread-dev libboost-test-dev libboost-filesystem-dev libtbb-dev binfmt-support git autotools-dev automake cmake g++ clang-14 clang-tools-14 libgmp-dev libz-dev libstdc++6
RUN apt-get install -yq python3-distutils
RUN git clone https://github.com/NASA-SW-VnV/ikos
RUN mkdir ikos/build
RUN cd ikos/build && \
  cmake \
    -DCMAKE_INSTALL_PREFIX="/usr/local/" \
    -DLLVM_CONFIG_EXECUTABLE="/usr/bin/llvm-config-14" \
    -DCMAKE_CXX_COMPILER="/usr/bin/clang++-14" \
    ..
 RUN cd ikos/build && make && make install
