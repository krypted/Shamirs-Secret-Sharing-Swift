# Shamirs-Secret-Sharing-Swift
Ported Shamirs Secret Sharing Into A Swift Package

Based on Adi Shamir's Secret Sharing (https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing). The intent is to split a secret into multiple parts, called shares. The shares can then be used to reconstruct the original secret. 

## Usage:
- Build the script. You only need to build one time: swift build
- Run with command: swift run shamirssecret <secret> -m <minimum_shares> -t <total_shares>
- For example: swift run shamirssecret 98801 -m 5 -t 7
- For a quick test, you can ignore the two last arguments. They'll be set to the default 3 and 6.
 
## Troubleshooting:
If the script errors out with "xcrun: error: unable to find utility "xctest", not a developer tool or in PATH" then make sure to CD into the Sources directory of the project.
  
If the script errors out with "error: root manifest not found", check that `xcode-select -p` returns with:
/Applications/Xcode.app/Contents/Developer
  
If not, set the location for Command Line Tools in Xcode by opening Xcode then clicking Preferences, then Locations.
