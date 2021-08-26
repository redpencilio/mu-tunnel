#!/bin/bash

apk add gpg

# Read input

read -r -p "Enter key to turn into public key: " INFILENAME
read -r -p "Enter key identity: " EMAIL
read -r -p "Enter output filename: " OUTFILENAME

echo "" # Newline

GPGTMPHOME=$(mktemp -d)

gpg --homedir "$GPGTMPHOME" --import "/data/app/config/tunnel/keys/$INFILENAME"
gpg --homedir "$GPGTMPHOME" --export "$EMAIL" > "/data/app/config/tunnel/keys/$OUTFILENAME"

rm -rf "$GPGTMPHOME"

echo "Stored key in config/tunnel/keys/$OUTFILENAME"
