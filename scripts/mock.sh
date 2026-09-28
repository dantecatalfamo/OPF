#!/bin/sh
# Runs the mock API server (opf -mock) and the UI dev server together,
# for working on the frontend without OpenBSD. Ctrl-C stops both.
set -e
cd "$(dirname "$0")/.."

bin=$(mktemp -d)/opf
go build -o "$bin" ./cmd/opf
# Not 8080, which other development servers often use; Vite proxies
# /api here (ui/vite.config.ts).
"$bin" -mock -listen 127.0.0.1:18080 &
api=$!
trap 'kill $api 2>/dev/null' EXIT INT TERM
sleep 1
if ! kill -0 $api 2>/dev/null; then
	echo "mock: the API server didn't start (is port 18080 in use?)" >&2
	exit 1
fi

cd ui
[ -d node_modules ] || npm install
npm run dev
