#/bin/sh

# 1. Install opam (OCaml package manager)
sudo apt install -y opam z3 cvc4 
opam init

# manually install old packages not currently found in kali repos
sudo dpkg -i libgtk2.0-dev_2.24.33-2_amd64.deb
sudo dpkg -i libgtksourceview2.0-common_2.10.5-3_all.deb
sudo dpkg -i libgtksourceview2.0-0_2.10.5-3_amd64.deb
sudo dpkg -i libgtksourceview2.0-dev_2.10.5-3_amd64.deb  

# 2. Install Frama-C's dependencies
opam install depext
opam depext frama-c

# 3. Install Frama-C itself
opam install frama-c
eval $(opam env)
why3 config detect
frama-c -wp-detect

