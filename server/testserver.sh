#!/bin/sh
set -e

echo "Compining..."
GOOS=openbsd go build -v
echo "Copying..."
scp ./OPF 192.168.0.8:
echo "Running..."
ssh -t 192.168.0.8 doas ./OPF
