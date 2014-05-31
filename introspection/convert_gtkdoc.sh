#!/bin/sh

mkdir output 2>/dev/null

OUTPUT=`basename $1`

gtkdoc-mkhtml TEST $1
