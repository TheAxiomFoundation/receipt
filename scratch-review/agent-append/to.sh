#!/bin/sh
# usage: to.sh SECONDS cmd...
secs=$1; shift
exec perl -e 'alarm shift; exec @ARGV or die "exec: $!"' "$secs" "$@"
