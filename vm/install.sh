#/bin/sh

# add ubuntu repositories for older packages
sudo apt update
sudo apt install -y python-software-properties
sudo add-apt-repository 'deb http://cz.archive.ubuntu.com/ubuntu focal main universe'
sudo add-apt-repository 'deb http://security.ubuntu.com/ubuntu focal-security main'
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 3B4FE6ACC0B21F32 871920D1991BC93C

sudo cp ubuntu.prefs /etc/apt/preferences.d/ubuntu
sudo chown root /etc/apt/preferences.d/ubuntu.prefs

sudo apt update
sudo apt install -y curl wget gedit vim pkg-config cmake autotools-dev automake docker docker.io git
sudo sudo apt-get install -y gcc g++ cmake libgmp-dev libboost-dev libboost-filesystem-dev \
    libboost-thread-dev libboost-test-dev python3 python3-pygments libsqlite3-dev libtbb-dev \
    libz-dev libedit-dev llvm-9 llvm-9-dev llvm-9-tools clang-9 gcc-multilib
sudo apt install -y clang clang-tools valgrind
sudo apt install -y libmysql++-dev libpam0g-dev libmysqlcppconn-dev
sudo apt install -y python3-distutils
sh install-taintgrind.sh
sh install-ikos.sh
sh install-frama-c.sh
sh install-timecop.sh
sh install-web.sh
sh install-fuzz.sh
