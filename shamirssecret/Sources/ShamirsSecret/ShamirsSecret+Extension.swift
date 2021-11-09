import ArgumentParser
import Foundation
import BigInt
import CryptorECC

import Foundation

@available(macOS 10.13, *)
extension ShamirsSecret{
    
    struct Create: ParsableCommand {
        public static let configuration = CommandConfiguration(abstract: "Create shares from a given secret.")
        @Argument()
        var secret: String
        
        @Option(name: [.customLong("minimum"), .customShort("m")], help: "The minimum shares. It must be smaller than the total shares.")
            var minimumShares: Int?
        @Option(name: [.customLong("total"), .customShort("t")], help: "The total shares.")
            var totalShares: Int?
        @Option(name: [.customLong("dump"), .customShort("d")], help: "The path to save the shares to a new text file.")
            var dumpURL: String?
      
        func validate() throws {
            if (minimumShares == nil && totalShares == nil) || (minimumShares != nil && totalShares != nil) {
                
            }
            else {
                throw ValidationError("Must provide both minimum shares and total shares. Or ignore both.")
            }
            if BigInt(secret) == nil {
                throw ValidationError("Cannot convert input to BigInt")
            }
        }
        
        func run() throws {
            if let secretBigInt = BigInt(secret) {
                process(secret: secretBigInt, minimum: minimumShares, total: totalShares, dumpFileName: dumpURL)
            }
        }
    }
    
    struct Solve: ParsableCommand {
        public static let configuration = CommandConfiguration(abstract: "Solve secret from text file")
        
        @Argument(help: "The input file to read shares", completion: .file())
            var input: String
        
        func validate() throws {
            if  FileManager.default.fileExists(atPath: input) == false {
                throw ValidationError("Input URL does not exist!")
            }
        }
        
        func run() throws {
            getSecretFromFile(filePath: input)
        }
    }
    
    @available(macOS 10.13, *)
    struct Encrypt: ParsableCommand {
        public static let configuration = CommandConfiguration(abstract: "Create a ECC key pair and encrypt the input string with the public key. The the private key and the encrypted string will be saved to files.")
        
        @Argument(help: "A string that need to be encrypted.")
            var string: String
        
        @Option(name: [.customLong("keyname"), .customShort("k")], help: "The name of the file to save the private ECC key.")
            var keyOutputName: String?
        
        @Option(name: [.customLong("stringname"), .customShort("s")], help: "The name of the file to save encrypted string.")
            var stringOutputName: String?
        
        func validate() throws {
            
        }
        
        func run() throws {
            encryptStringWithECC(string, keyOutputName: keyOutputName ?? "eccKey", stringOutputname: stringOutputName ?? "stringOutputFile.txt")
        }
    }
    
    struct Decrypt: ParsableCommand {
        public static let configuration = CommandConfiguration(abstract: "Decrypt string with a private ECC key.")
        
        @Option(name: [.customLong("stringpath"), .customShort("s")], help: "The name of the file to get encrypted string.", completion: .file())
            var stringPath: String
        
        @Option(name: [.customLong("keypath"), .customShort("k")], help: "The name of the file to get the private ECC key.", completion: .file())
            var keyPath: String
        
        func validate() throws {
            if  FileManager.default.fileExists(atPath: stringPath) == false {
                throw ValidationError("String URL does not exist!")
            }
            if  FileManager.default.fileExists(atPath: keyPath) == false {
                throw ValidationError("Key URL does not exist!")
            }
        }
        
        func run() throws {
            decryptStringWithECC(stringPath: stringPath, keyPath: keyPath)
        }
    }
    
    struct Shard: ParsableCommand {
        public static let configuration = CommandConfiguration(abstract: "Create shares from a ECC key.")
        @Argument( help: "The name of the file to get the private ECC key.", completion: .file())
            var keyPath: String
        
        @Option(name: [.customLong("minimum"), .customShort("m")], help: "The minimum shares. It must be smaller than the total shares.")
            var minimumShares: Int?
        @Option(name: [.customLong("total"), .customShort("t")], help: "The total shares.")
            var totalShares: Int?
        @Option(name: [.customLong("dump"), .customShort("d")], help: "The path to save the shares to a new text file.")
            var dumpURL: String?
      
        func validate() throws {
            if  FileManager.default.fileExists(atPath: keyPath) == false {
                throw ValidationError("Input URL does not exist!")
            }
            if (minimumShares == nil && totalShares == nil) || (minimumShares != nil && totalShares != nil) {
                
            }
            else {
                throw ValidationError("Must provide both minimum shares and total shares. Or ignore both.")
            }
        }
        
        func run() throws {
            getShardFromECCKey(keyPath: keyPath, minimum: minimumShares, total: totalShares, dumpFileName: dumpURL)
        }
    }
    
    struct Deshard: ParsableCommand {
        public static let configuration = CommandConfiguration(abstract: "Load the ECC key from the shares file")
        
        @Argument(help: "The shares file", completion: .file())
            var input: String
        
        @Option(name: [.customLong("keyname"), .customShort("k")], help: "The name of the file to save the private ECC key.")
            var keyOutputName: String?
        
        func validate() throws {
            if  FileManager.default.fileExists(atPath: input) == false {
                throw ValidationError("Input URL does not exist!")
            }
        }
        
        func run() throws {
            getECCKeyFromShard(shardPath: input, keyFileName: keyOutputName)
        }
    }

}

