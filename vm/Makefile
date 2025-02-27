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
	sudo docker run -v ${HOME}:${HOME} -it --platform linux/amd64 mcopik/clang-dfsan:cfsan-9.0

run-infer:
	sudo docker run -v ${HOME}:${HOME} -it hugopacheco/infer

run-smack:
	sudo docker run -v ${HOME}:${HOME} -it --platform linux/amd64 smackers/smack

run-framac:
	sudo docker run -v ${HOME}:${HOME} -it --rm --net=host --env="DISPLAY" -v ${HOME}/.Xauthority:/root/.Xauthority:ro hugopacheco/framac

run-ikos:
	sudo docker run -v ${HOME}:${HOME} -p8080:8080 -it hugopacheco/ikos

run-taintgrind:
	sudo docker run -v ${HOME}:${HOME} -it --platform linux/amd64 hugopacheco/taintgrind

run-ctverif:
	sudo docker run -v ${HOME}:${HOME} -it --platform linux/amd64 hugopacheco/ctverif

run-driller:
	sudo docker run  -v /home/kali:/home/kali -it --platform linux/amd64 shellphish/mechaphish

run-fuzzolic:
	sudo docker run -v /home/kali:/home/kali -u 0 -ti --platform linux/amd64 --rm ercoppa/fuzzolic-runner-v1

run-symcc:
	sudo docker run -v /home/kali:/home/kali -it --platform linux/amd64 --rm hugopacheco/symcc
    
run-angora:
	sudo docker run -v /home/kali:/home/kali -it --platform linux/amd64 --rm zjuchenyuan/angora

run-klee:
	sudo docker pull klee/klee:3.0
	sudo docker run --rm -v ${HOME}:${HOME} -ti --platform linux/amd64 --ulimit='stack=-1:-1' klee/klee:3.0

run-klee-taint:
	sudo docker run -v /home/kali:/home/kali -it --platform linux/amd64 hugopacheco/klee-taint

run-klee-taint-ct:
	sudo docker run -v /home/kali:/home/kali -it --platform linux/amd64 hugopacheco/klee-taint-ct
	
run-binsec:
	sudo docker run -v /home/kali:/home/kali -it --platform linux/amd64 binsec/binsec
