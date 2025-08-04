FROM ubuntu:24.04@sha256:4f1db91d9560cf107b5832c0761364ec64f46777aa4ec637cca3008f287c975e AS base

FROM pwn.red/jail

COPY --from=base / /srv
COPY ./babyheap /srv/app/run
COPY ./flag.txt /srv/app/flag.txt

ENV JAIL_CONNS_PER_IP=3
