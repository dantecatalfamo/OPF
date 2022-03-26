#!/bin/sh

GOOS=openbsd go build
scp ./OPF 192.168.0.8:
ssh -t 192.168.0.8 doas ./OPF
