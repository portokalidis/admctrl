#!/bin/sh

if [ $# -eq 0 ]; then
LINUX_VERSION=`uname -r`
else
LINUX_VERSION=$1
fi


if [[ $LINUX_VERSION > "2.5.0" ]]; then
echo "Compiling module for linux kernel versions 2.5 and later"
make -f Makefile MAKEFOR=$LINUX_VERSION
else
echo "Compiling module for linux kernel versions prior to 2.5"
make -f Makefile.2 MAKEFOR=$LINUX_VERSION
fi
