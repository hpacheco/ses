#!/bin/bash -ex

INST_DIR=$PWD

# build valgrind
curl https://sourceware.org/pub/valgrind/valgrind-3.18.1.tar.bz2 | tar xj
cd valgrind-3.18.1
./autogen.sh
./configure --prefix=$INST_DIR
make -j $(nproc)
make install

# build capstone
cd taintgrind && \
    wget https://github.com/capstone-engine/capstone/archive/refs/tags/4.0.2.tar.gz -O capstone.tar.gz && \
    tar xf capstone.tar.gz && \
    sh configure_capstone.sh `pwd`/../build && \
    cd capstone-4.0.2 && \
    sh make_capstone.sh

git clone --depth 1 https://github.com/wmkhoo/taintgrind.git
cd taintgrind
../autogen.sh
./configure --prefix=$INST_DIR
make -j $(nproc)
make install
cd ../../

cd bin
for i in *
do
	mv $i taintgrind-$i
done
	
