#/bin/sh

ARCH=$(dpkg --print-architecture)

sudo apt update
sudo apt install -yq software-properties-common
sudo apt install -yq curl wget gedit vim pkg-config cmake autotools-dev automake docker.io git
sudo sudo apt-get install -y gcc g++ cmake libgmp-dev libboost-dev libboost-filesystem-dev \
    libboost-thread-dev libboost-test-dev python3 python3-pygments libsqlite3-dev libtbb-dev \
    libz-dev libedit-dev
sudo apt install -yq libmysql++-dev libpam0g-dev libmysqlcppconn-dev
sudo apt install -yq python3-setuptools

if [ $ARCH = arm64 ]; then
	sudo apt install -y qemu-user-static qemu-system-arm
fi

#sh install-low.sh
#sh install-fuzz.sh
#sh install-web.sh
