#!/bin/bash 


DATA_DIR="$2"
ENCRYPTED_DIR="0"



if [ "$1" = "push" ]; then

    if [ -z ${DATA_DIR} ]; then
        echo "DATA_DIR is necessary"
        exit 1
    fi

    rm -rf $ENCRYPTED_DIR
    message=$3
    if [ -z ${message} ]; then
        message="update"
    fi
    python encrypt.py --folder $DATA_DIR
    git add meta $ENCRYPTED_DIR/* && \
    git commit -m "${message}" && \
    git push && \
    exit 0
fi

if [ "$1" = "pull" ]; then
    git pull && \
    python encrypt.py --decrypt && \
    exit 0
fi

exit 2