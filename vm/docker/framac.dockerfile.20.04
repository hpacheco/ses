FROM ubuntu:20.04
USER root

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && apt-get install -yq opam z3 cvc4
RUN opam init --yes --disable-sandboxing
RUN apt-get install -yq libgdk-pixbuf2.0-0 gir1.2-gtk-2.0 libglib2.0-dev libgdk-pixbuf2.0-dev libpango1.0-dev libatk1.0-dev  libcairo2-dev libx11-dev libxext-dev libxinerama-dev libxi-dev libxrandr-dev libxcursor-dev libxfixes-dev libxcomposite-dev libxdamage-dev libgtk2.0-dev libgtksourceview2.0-common libgtksourceview2.0 libgtksourceview2.0-0
RUN opam install --yes depext
RUN opam depext frama-c
RUN opam install --yes frama-c
RUN eval $(opam env) && why3 config detect && frama-c -wp-detect
CMD eval $(opam env) && /bin/bash


