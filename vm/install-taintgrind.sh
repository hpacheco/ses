#!/bin/bash -ex

INST_DIR=$PWD

curl https://sourceware.org/pub/valgrind/valgrind-3.18.1.tar.bz2 | tar xj
cd valgrind-3.18.1
./autogen.sh
./configure --prefix=$INST_DIR
make -j $(nproc)
make install

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