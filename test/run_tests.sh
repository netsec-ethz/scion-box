#!/bin/bash

BASEDIR=$(realpath $(dirname `[[ -L "$0" ]] && readlink -f "$0" || echo "$0"`)/..)
TESTDIR="$BASEDIR/test"

PYTHONPATH="$SC:$SC/python:$BASEDIR/sub/util" python3 -m unittest discover $TESTDIR
