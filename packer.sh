#!/bin/bash 


DATA_DIR=Root
BACKUP_DIR=Root_backup
ENCRYPTED_DIR="0"

if [ "$1" = "push" ]; then
    rm -rf $ENCRYPTED_DIR
    message=$2
    if [ -z ${message} ]; then
        message="kokoko"
    fi
    python encrypt.py --folder $DATA_DIR
    git add meta $ENCRYPTED_DIR/* && \
    git commit -m "${message}" && \
    git push && \
    exit 0
fi
if [ "$1" = "pull" ]; then
    git pull && \
    mv $DATA_DIR $BACKUP_DIR && \
    python encrypt.py --decrypt
    exit 0
fi

exit 2