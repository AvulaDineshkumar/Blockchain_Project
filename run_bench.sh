#!/bin/sh
# Resumable benchmark driver: 2 processes at a time so timings are not distorted by CPU contention.
# Re-run until every CSV has 101 lines (pbft/pow/central). Each call stops after $1 seconds (default 140).
cd "$(dirname "$0")"
B=${1:-140}
export BENCH_DEADLINE=$(python3 -c "import time;print(time.time()+$B)")
( for n in 13 4; do python3 -m ehrchain.benchmark pbft --nodes $n --out bench_pbft_n$n.csv --budget $B; done ) > logs/procA.log 2>&1 &
( for n in 10 7; do python3 -m ehrchain.benchmark pbft --nodes $n --out bench_pbft_n$n.csv --budget $B; done
  python3 -m ehrchain.benchmark central --out bench_central.csv --budget $B
  python3 -m ehrchain.benchmark pow --out bench_pow.csv --budget $B ) > logs/procB.log 2>&1 &
wait
wc -l results/bench_*.csv
