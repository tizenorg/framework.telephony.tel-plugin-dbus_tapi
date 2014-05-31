#!/bin/sh

mkdir output 2>/dev/null

OUTPUT=`basename $1`

xsltproc -o output/$OUTPUT.html /usr/share/xml/docbook/stylesheet/docbook-xsl/html/docbook.xsl $1
