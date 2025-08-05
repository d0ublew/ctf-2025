#!/usr/bin/env bash

patchelf \
    --no-sort \
    --set-interpreter ld-linux-x86-64.so.2 \
    --replace-needed libc.so.6 ./libc.so.6 \
    --output babyheap.patched \
    babyheap
