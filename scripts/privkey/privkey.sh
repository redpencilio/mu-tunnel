#!/bin/sh

apk add gnupg

# Read input

read -r -p "Enter key identity (email): " EMAIL
read -r -p "Enter output filename: " FILENAME
read -r -p "Enter expire time: " EXPIRE
read -r -s -p "Enter passphrase: " PASSPHRASE

echo "" # Newline

CONFIGFILE=$(mktemp)
cat <<EOF > "$CONFIGFILE"
Key-Type: EdDSA
Key-Curve: Ed25519
Subkey-Type: ECDH
Subkey-Curve: Curve25519

Name-Email: $EMAIL
Passphrase: $PASSPHRASE

Expire-Date: $EXPIRE
EOF

mkdir -p /data/app/config/tunnel/keys

GPGTMPHOME=$(mktemp -d)

gpg --homedir "$GPGTMPHOME" --batch --expert --full-gen-key "$CONFIGFILE"
gpg --homedir "$GPGTMPHOME" --export-secret-keys --armor "$EMAIL" > "/data/app/config/tunnel/keys/$FILENAME"

rm -rf "$GPGTMPHOME"
rm "$CONFIGFILE"

echo "Stored key in config/tunnel/keys/$FILENAME"
