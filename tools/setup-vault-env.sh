#!/bin/bash
set -eux
if [ -z "$(which vault)" ]; then
    VAULT_VERSION=1.4.2
    SUFFIX=zip
    case `uname -s` in
        Darwin)
            OS=darwin
            ;;
        Linux)
            OS=linux
            ;;
        *)
            echo "Unsupported OS"
            exit 1
    esac
    case `uname -m` in
         x86_64)
             MACHINE=amd64
             ;;
         *)
            echo "Unsupported machine"
            exit 1
    esac
    TARBALL_NAME=vault_${VAULT_VERSION}_${OS}_${MACHINE}
    test ! -d "$TARBALL_NAME" && mkdir ${TARBALL_NAME} && wget https://releases.hashicorp.com/vault/${VAULT_VERSION}/${TARBALL_NAME}.${SUFFIX} && unzip -d ${TARBALL_NAME} ${TARBALL_NAME}.${SUFFIX} && rm ${TARBALL_NAME}.${SUFFIX}
    export VAULT_CONFIG_PATH=$(pwd)/$TARBALL_NAME/vault.json
    export PATH=$PATH:$(pwd)/$TARBALL_NAME
fi

$*
