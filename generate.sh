#!/bin/bash

echo -n "Randomly generated AES_KEY: "
openssl rand -hex 20
echo -n "Randomly generated AES_IV: "
openssl rand -hex 20

echo "Randomly generated RSA Keys are placed inside signing folder."
mkdir signing 2>/dev/null
openssl genrsa -out ./signing/private.key 4096 2>/dev/null 1>/dev/null
openssl rsa -in ./signing/private.key -out ./signing/public.key -pubout 2>/dev/null 1>/dev/null

echo "Put this base64 encoded public key in php file: "
cat ./signing/public.key | base64
