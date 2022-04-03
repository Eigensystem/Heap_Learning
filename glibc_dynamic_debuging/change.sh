#!/bin/bash

# patchelf --replace-needed old_ld  new_ld
FOLDER=$(cd "$(dirname "$0")";pwd)
LDD=$(ldd $2 | awk '{print $1}' | sed -n '2p')	
sudo patchelf --set-interpreter $FOLDER/$1/ld-$1.so --set-rpath $FOLDER/$1 $(pwd)/$2
sudo patchelf --replace-needed  $LDD  $FOLDER/$1/libc-$1.so $(pwd)/$2
