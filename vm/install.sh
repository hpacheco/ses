#/bin/sh

sudo apt update
sudo apt install -yq software-properties-common
sudo apt install -yq curl wget gedit vim pkg-config cmake autotools-dev automake docker docker.io git
sudo sudo apt-get install -y gcc g++ cmake libgmp-dev libboost-dev libboost-filesystem-dev \
    libboost-thread-dev libboost-test-dev python3 python3-pygments libsqlite3-dev libtbb-dev \
    libz-dev libedit-dev gcc-multilib
sudo apt install -yq clang clang-tools valgrind
sudo apt install -yq libmysql++-dev libpam0g-dev libmysqlcppconn-dev
sudo apt install -yq python3-distutils
sh install-timecop.sh
sh install-fuzz.sh
sh install-web.sh
