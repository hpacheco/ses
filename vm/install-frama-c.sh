#/bin/sh

# 1. Install opam (OCaml package manager)
sudo apt install -y opam z3 cvc4
opam init

sudo apt install -y libgdk-pixbuf2.0-0
# manually install old packages not currently found in kali repos
wget -nc -P deb http://ftp.us.debian.org/debian/pool/main/g/gtk+2.0/libgtk2.0-dev_2.24.33-2_amd64.deb
wget -nc -P deb http://mirrors.kernel.org/ubuntu/pool/universe/g/gtksourceview2/libgtksourceview2.0-common_2.10.5-3_all.deb
wget -nc -P deb http://ftp.us.debian.org/debian/pool/main/g/gtksourceview2/libgtksourceview2.0-dev_2.10.5-3_amd64.deb
wget -nc -P deb http://ftp.de.debian.org/debian/pool/main/g/gtksourceview2/libgtksourceview2.0-0_2.10.5-3_amd64.deb
sudo dpkg -i deb/*.deb

# 2. Install Frama-C's dependencies
opam install depext
opam depext frama-c

# 3. Install Frama-C itself
opam install frama-c
eval $(opam env)
why3 config detect
frama-c -wp-detect

