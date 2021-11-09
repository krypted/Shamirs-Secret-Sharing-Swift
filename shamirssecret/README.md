# shamirssecret

A description of this package.

- Encrypt: Create an ECC key pair and encrypt the input string with the public key. The private key and the encrypted string will be saved to files.
shamirssecret encrypt "abc123xyz" -k privatekey.txt -s encryptedtext.txt

- Shard: Create shares from the private key file.
shamirssecret shard privatekey.txt -d shares.txt

- Deshard: Load the ECC key from the shares file.
shamirssecret deshard shares.txt -k privatekey2.txt

- Decrypt: Decrypt string with a private ECC key.
shamirssecret decrypt -s encryptedtext.txt -k privatekey.txt
