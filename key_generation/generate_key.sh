#!/bin/bash
## NOTE: Run this script in the root directory of the project
#./key_generation/generate_key.sh

#https://developers.google.com/pay/api/processors/guides/implementation/prepare-your-key
# Create keys directory if it doesn't exist
if [ -d "keys" ]; then
  # Warn user and only continue if they accept
  echo "WARNING: keys directory already exists!!!"
  echo "-- Continuing will override directory and removeeverything in it!!!"
  echo
  read -n 1 -p "Do you want to continue? (y/n): " choice
  echo
  #
  if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
    echo "Continuing..."
    rm -rf keys/*
    touch keys/.gitkeep
  elif [[ "$choice" == "n" || "$choice" == "N" ]]; then
    echo "User chose not to continue.  Exiting."
    exit
  else
    echo "Invalid input.  Exiting."
    exit
  fi
else
  mkdir -p keys
fi

# 1.) Generate a private key
openssl ecparam -name prime256v1 -genkey -noout -out keys/key.pem

# View the private key
echo "Private Key:"
openssl ec -in keys/key.pem -pubout -text -noout

# 2.) Generate a base64-encoded public key
openssl ec -in keys/key.pem -pubout -text -noout 2> /dev/null | grep "pub:" -A5 | sed 1d | xxd -r -p | base64 | paste -sd "\0" - | tr -d '\n\r ' > keys/publicKey.txt

# Verify no spaces
echo "Public Key:"
od -bc keys/publicKey.txt

# 3.) Generate a base64-encoded private key in PKCS #8 format
openssl pkcs8 -topk8 -inform PEM -outform DER -in keys/key.pem -nocrypt | base64 | paste -sd "\0" - > keys/pk8.pem

# View PKCS #8 private key
echo "PKCS #8 Private Key:"
od -bc keys/pk8.pem

# 4.) Validate a checksum of the public key with Google
cat keys/publicKey.txt | openssl dgst -sha256 > keys/publicKey.txt.sha256.txt

# Your Google point of contact coordinates a phone call with you.
# We require you to read the checksum of your PRODUCTION public key out loud to your Google point of contact.
# When you read the checksum, skip eventual prefixes such as (stdin)=, that might result from the openssl command.

# Set appropriate permissions
chmod 600 keys/key.pem
chmod 600 keys/pk8.pem
chmod 644 keys/publicKey.txt

echo "Keys generated successfully!" 
