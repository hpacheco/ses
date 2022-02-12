#/bin/sh

sudo apt update
sudo apt install gedit autotools-dev automake
sudo apt install clang clang-tools valgrind
./install-taintgrind.sh
