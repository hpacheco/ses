run-docker-juiceshop:
	sudo docker pull bkimminich/juice-shop
	sudo docker run --rm -p 3000:3000 bkimminich/juice-shop

build-juiceshop:
	git clone https://github.com/hpacheco/juice-shop.git
	cd juice-shop && npm install

run-juiceshop:
	cd juice-shop && npm start

e2e-juiceshop:
	cd juice-shop && npm run protractor

start-mutillidae:
	sudo systemctl restart php8.1-fpm
	sudo systemctl restart apache2
	sudo systemctl restart mysql
	sudo systemctl restart slapd

run-dependency-check:
	./dependency-check/bin/dependency-check.sh --enableExperimental --scan juice-shop

run-dfsan:
	rm -rf clang-dfsan
	git clone https://github.com/mcopik/clang-dfsan
	cd clang-dfsan && \
	  sudo sh build-cfsan.sh && \
	  sudo docker run -v ${HOME}:${HOME} -it mcopik/clang-dfsan:cfsan-9.0

run-smack:
	sudo docker run -v ${HOME}:${HOME} -it smackers/smack

run-ctverif:
	sudo docker build -f ctverif.dockerfile . -t ctverif
	sudo docker run -v ${HOME}:${HOME} -it ctverif

run-driller:
	sudo docker run  -v /home/kali:/home/kali -it shellphish/mechaphish

run-fuzzolic:
	sudo docker run -v /home/kali:/home/kali -u 0 -ti --rm ercoppa/fuzzolic-runner-v1

build-symcc:
	git clone https://github.com/eurecom-s3/symcc
	cd symcc && \
	  git submodule init && \
		git submodule update && \
		sudo docker build -t hugopacheco/symcc .

run-symcc:
	cd symcc && sudo docker run -v /home/kali:/home/kali -it --rm hugopacheco/symcc

run-klee:
	sudo docker pull klee/klee:2.1
	sudo docker run --rm -v ${HOME}:${HOME} -ti --ulimit='stack=-1:-1' klee/klee:2.1

build-klee-taint:
	git clone https://github.com/hpacheco/klee-taint
	cd klee-taint && sudo docker build -f Dockerfile . -t hugopacheco/klee-taint

run-klee-taint:
	sudo docker run -v /home/kali:/home/kali -it hugopacheco/klee-taint

build-klee-taint-ct:
	git clone https://github.com/hpacheco/klee-taint-ct
	cd klee-taint-ct && sudo docker build -f Dockerfile . -t hugopacheco/klee-taint-ct

run-klee-taint-ct:
	sudo docker run -v /home/kali:/home/kali -it hugopacheco/klee-taint-ct
