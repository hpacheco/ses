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
