#/bin/sh

sudo apt update
sudo apt install -y curl wget gedit vim pkg-config cmake autotools-dev automake docker docker.io git
sudo sudo apt-get install -y gcc g++ cmake libgmp-dev libboost-dev libboost-filesystem-dev \
    libboost-thread-dev libboost-test-dev python3 python3-pygments libsqlite3-dev libtbb-dev \
    libz-dev libedit-dev llvm-9 llvm-9-dev llvm-9-tools clang-9
sudo apt install -y clang clang-tools valgrind
sudo apt install -y libmysql++-dev libpam0g-dev libmysqlcppconn-dev
sudo apt install -y python3-distutils 
sh install-taintgrind.sh
sh install-ikos.sh
sh install-frama-c.sh
