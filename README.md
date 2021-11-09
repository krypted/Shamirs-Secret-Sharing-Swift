# Shamirs-Secret-Sharing-Swift
Ported Shamirs Secret Sharing Into A Swift Package

Based on Adi Shamir's Secret Sharing (https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing). The intent is to split a secret into multiple parts, called shares. The shares can then be used to reconstruct the original secret. 

Now you can copy the binary version to your Mac's bin folder to run it directly:
cp shamirssecret /usr/local/bin/shamirssecret

# Binary Usage
- Encrypt: Create an ECC key pair and encrypt the input string with the public key. The private key and the encrypted string will be saved to files.
`shamirssecret encrypt "abc123xyz" -k privatekey.txt -s encryptedtext.txt`

- Shard: Create shares from the private key file.

`shamirssecret shard privatekey.txt -d shares.txt`

- Deshard: Load the ECC key from the shares file.

`shamirssecret deshard shares.txt -k privatekey2.txt`

- Decrypt: Decrypt string with a private ECC key.

`shamirssecret decrypt -s encryptedtext.txt -k privatekey.txt`

- Generate shares from a secret and dump them into a new file:

`shamirssecret create 89001 -m 4 -t 7 -d shares000`

- Solve the secret from the saved file:

`shamirssecret solve shares000`

## Swift Package Usage
- Build the script. You only need to build one time: `swift build`
- Run with command: `swift run shamirssecret <secret> -m <minimum_shares> -t <total_shares>`
- For example: `swift run shamirssecret 98801 -m 5 -t 7`
- For a quick test, you can ignore the two last arguments. They'll be set to the default 3 and 6.
 
## Troubleshooting
- If the script errors a boatload of unknowns, open the Xcode Project, click the main.swift, and build.
- If the script errors out with "xcrun: error: unable to find utility "xctest", not a developer tool or in PATH" then make sure to CD into the Sources directory of the project.
- If the script errors out with "error: root manifest not found", check that `xcode-select -p` returns with:
/Applications/Xcode.app/Contents/Developer. If not, set the location for Command Line Tools in Xcode by opening Xcode then clicking Preferences, then Locations.
