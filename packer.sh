#!/bin/bash 


DATA_DIR=Root
TMP_DIR=tmp_save

if ! [ -f creds ]; then
  read -p "Enter password: " passw
  echo $passw > creds
fi

passw=$(<creds)

if [ "$1" = "push" ]; then
    rm -rf $TMP_DIR
    message=$2
    if [ -z ${message} ]; then
        message="kokoko"
    fi
    cp -R $DATA_DIR $TMP_DIR
    gpgdir -e $TMP_DIR -Obfuscate-filenames --pw-file=creds
    git add $TMP_DIR/* && \
    git commit -m "${message}" && \
    git push && \
    exit 0
fi
if [ "$1" = "pull" ]; then
    git pull && \
    rm -rf Root && \
    gpgdir -d $TMP_DIR -O --pw-file=creds && \
    mv $TMP_DIR $DATA_DIR && \
    exit 0
fi

exit 2