
build-ikos:
	sudo docker build -f ikos.dockerfile . -t hugopacheco/ikos
    
build-framac:
	sudo docker build -f framac.dockerfile . -t hugopacheco/framac

build-taintgrind:
	sudo docker build -f taintgrind.dockerfile . -t hugopacheco/taintgrind

build-ctverif:
	sudo docker build -f ctverif.dockerfile . -t hugopacheco/ctverif

build-symcc:
	git clone https://github.com/eurecom-s3/symcc
	cd symcc && \
	  git submodule init && \
		git submodule update && \
		sudo docker build -t hugopacheco/symcc .

build-klee-taint:
	git clone https://github.com/hpacheco/klee-taint
	cd klee-taint && sudo docker build -f Dockerfile . -t hugopacheco/klee-taint

build-klee-taint-ct:
	git clone https://github.com/hpacheco/klee-taint-ct
	cd klee-taint-ct && sudo docker build -f Dockerfile . -t hugopacheco/klee-taint-ct
