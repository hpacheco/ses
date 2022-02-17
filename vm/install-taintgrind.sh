#!/bin/bash -ex

curl https://sourceware.org/pub/valgrind/valgrind-3.18.1.tar.bz2 | tar xj
cd valgrind-3.18.1 && \
  git clone --depth 1 https://github.com/wmkhoo/taintgrind.git && \
  cd taintgrind && \
    ./build_taintgrind.sh && \
    sudo cp -r ../build/* /usr/local/ && \
    sudo cp log2dot.py /usr/local/bin/ && \
cd ../.. && sudo cp taintgrind-log2dot /usr/local/bin


