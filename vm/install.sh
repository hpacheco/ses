#/bin/sh

sudo apt update
sudo apt install gedit autotools-dev automake docker
sudo apt install clang clang-tools valgrind
sh install-taintgrind.sh
