#!/bin/sh

cut_bct=`tempfile`
dec_bct=`tempfile`

dd if=$1 of=$cut_bct bs=16 skip=1
`dirname $0`/decrypt.sh $cut_bct $dec_bct
dd if=$1 of=$2 bs=16 count=1
dd if=$dec_bct of=$2 bs=16 seek=1

rm -f $cut_bct $dec_bct
