FROM smackers/smack
USER root

RUN apt-get update
RUN apt-get install -y ruby npm dotnet-sdk-6.0 z3 vim
ENV PATH="${PATH}:/root/.dotnet/tools"
RUN dotnet tool install --global boogie
RUN git clone https://github.com/hpacheco/bam-bam-boogieman && \
  cd bam-bam-boogieman && \
  gem build bam-bam-boogieman.gemspec && \
  gem install bam-bam-boogieman-*.gem
RUN gem install sorbet sorbet-runtime rake rspec
RUN npm i -g ctverif
COPY ctverif.h /usr/include/
