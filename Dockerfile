FROM alpine:3.7

RUN apk add --no-cache python3 git \
    && pip3 install pyyaml requests ns1-python \
    && apk del --no-cache git

COPY . /app

# How often to run in minutes
ENV FREQUENCY=5

COPY crontab /etc/crontabs/root
CMD /app/prepare-crontab.sh && crond -f -d 8
CMD /app/dynamic-dns.py