#set the DEBUG=* env var to debug ctverif
FROM smackers/smack
USER root

RUN apt-get update
RUN apt-get install -y ruby npm dotnet-sdk-6.0 z3 vim
ENV PATH="${PATH}:/root/.dotnet/tools"
RUN dotnet tool install --global boogie --version 2.9.6
RUN git clone https://github.com/hpacheco/bam-bam-boogieman && \
  cd bam-bam-boogieman && \
  gem build bam-bam-boogieman.gemspec && \
  gem install bam-bam-boogieman-*.gem
RUN gem install sorbet sorbet-runtime rake rspec
RUN git clone https://github.com/michael-emmi/ctverif
RUN cd ctverif && npm link
COPY ctverif.h /usr/include/
