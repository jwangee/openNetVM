
FROM ch8728847/nf:base
MAINTAINER "Jianfeng Wang <pkueewjf@gmail.com>"

RUN apt-get -yq update && apt-get -yq install iputils-ping bash sudo libnuma-dev bc vim

RUN mkdir /app/onvm
COPY onvm /app/onvm

RUN mkdir /app/examples
COPY examples /app/examples

RUN mkdir /app/scripts
COPY scripts /app/scripts
