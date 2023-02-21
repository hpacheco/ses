FROM ubuntu:20.04
USER root

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && apt-get install -yq curl git wget autotools-dev automake build-essential python3 graphviz
RUN curl https://sourceware.org/pub/valgrind/valgrind-3.18.1.tar.bz2 | tar xj
RUN cd valgrind-3.18.1 && git clone --depth 1 https://github.com/wmkhoo/taintgrind.git
RUN cd valgrind-3.18.1/taintgrind && ./build_taintgrind.sh
RUN cp -r valgrind-3.18.1/build/* /usr/local/
RUN cp valgrind-3.18.1/taintgrind/log2dot.py /usr/local/bin/
COPY taintgrind-log2dot /usr/local/bin


