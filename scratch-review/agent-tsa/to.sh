#!/bin/sh
# usage: to.sh SECONDS cmd args...   (SIGALRM kills cmd after SECONDS)
secs=$1; shift
exec perl -e 'alarm shift @ARGV; exec @ARGV or die "exec: $!"' "$secs" "$@"
