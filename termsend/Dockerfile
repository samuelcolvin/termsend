FROM python:3.8-slim

#RUN apk add -U gcc g++ musl-dev zlib-dev libuv libffi-dev make openssl-dev git

RUN apt-get update > /dev/null && \
    apt-get install -y gcc && \
    rm -rf /var/lib/apt/lists/*

RUN pip install -U pip setuptools
ADD ./requirements.txt /home/root/requirements.txt
RUN pip install -r /home/root/requirements.txt

WORKDIR /home/root/

ADD ./ /home/root/site-deploy/
ARG COMMIT
ARG BUILD_TIME
ENV PYTHONUNBUFFERED=1 \
    ON_DOCKER=1 \
    COMMIT=$COMMIT \
    BUILD_TIME=$BUILD_TIME

CMD ["./site-deploy/run.py"]
