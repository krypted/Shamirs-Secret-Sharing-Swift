import ArgumentParser
import Foundation
import BigInt
import RNCryptor
import CryptorECC


// 12th Mersenne Prime
// (for this application we want a known prime number as close as
// possible to our security level; e.g.  desired security level of 128
// bits -- too large and all the ciphertext is large; too small and
// security is compromised)
let _PRIME: BigInt = BigInt(2).power(2281) - 1

// 13th Mersenne Prime is 2**521 - 1

func _eval_at(poly: [BigInt], x: Int, prime: BigInt) -> BigInt{
//        Evaluates polynomial (coefficient tuple) at x, used to generate a
//        shamir pool in make_random_shares below.
    var accum = BigInt(0)
    for coeff in poly.reversed() {
        accum *= BigInt(x)
        accum += coeff
        accum %= prime
    }
    return accum
}

func make_random_shares(secret: BigInt, minimum: Int = 3, shares: Int = 6, prime: BigInt=_PRIME) ->[(Int, BigInt)] {
    
    if minimum > shares {
        fatalError("ERROR: Pool secret would be irrecoverable.")
    }
    var poly: [BigInt] = [secret]
    for _ in 0..<(minimum - 1) {
        poly.append(BigInt(BigUInt.randomInteger(lessThan: BigUInt(_PRIME) - 1)))
    }
    
    var points = [(Int, BigInt)]()
    for i in 1..<(shares + 1) {
        points.append((i, _eval_at(poly: poly, x: i, prime: prime)))
    }
    
    return points
}

func _extended_gcd(_ num1: BigInt, _ num2: BigInt) -> (BigInt, BigInt) {
//    Division in integers modulus p means finding the inverse of the
//    denominator modulo p and then multiplying the numerator by this
//    inverse (Note: inverse of A is B such that A*B % p == 1) this can
//    be computed via extended Euclidean algorithm
//    http://en.wikipedia.org/wiki/Modular_multiplicative_inverse#Computation
    
    var a = num1, b = num2
    var x: BigInt = 0, y: BigInt = 1
    var last_x: BigInt = 1, last_y: BigInt = 0
    
    while (b != 0) {
        let quot = a / b
        var temp = a.modulus(b)
        a = b
        b = temp
        
        temp = last_x - quot * x
        last_x = x
        x = temp
        
        temp = last_y - quot * y
        last_y = y
        y = temp
        
    }
    
    return (last_x, last_y)
}

func _divmod(_ num: BigInt, _ den: Int, _ p: BigInt) -> BigInt {
//    Compute num / den modulo prime p
//
//    To explain what this means, the return value will be such that
//    the following is true: den * _divmod(num, den, p) % p == num
    
    let res = _extended_gcd(BigInt(den), p)
    let inv = res.0
    return num * inv
}

func _lagrange_interpolate(x: Int, x_s: [Int], y_s: [BigInt], p: BigInt) -> BigInt{
//    Find the y-value for the given x, given n (x, y) points;
//    k points will define a polynomial of up to kth order.
    
//    upper-case PI -- product of inputs
    func PI(vals: [Int]) -> Int{
        var accum = 1
        for v in vals {
            accum *= v
        }
        return accum
    }
    
    let k = x_s.count
    assert(k == Set(x_s).count, "Points must be distinct")
    
    var nums = [Int]() // avoid inexact division
    var dens = [Int]()
    
    for i in 0..<k {
        var others = x_s
        let cur = others.remove(at: i)
        
        var tempNums = [Int]()
        for o in others { tempNums.append(x - o) }
        var tempDens = [Int]()
        for o in others { tempDens.append(cur - o) }
        nums.append(PI(vals: tempNums))
        dens.append(PI(vals: tempDens))
    }
    let den = PI(vals: dens)
    var num = BigInt(0)
    for i in 0..<k {
        let tmpDiv = (BigInt(nums[i]) * BigInt(den) * y_s[i]).modulus(p)
        num += _divmod(tmpDiv, dens[i], p)
    }

    return (_divmod(num, den, p) + p).modulus(p)
    
}

func recover_secret(shares: [(Int, BigInt)], prime: BigInt = _PRIME) -> BigInt{
    if shares.count < 2 {
        fatalError("ERROR: need at least two shares")
    }
    var x_s: [Int] = []
    var y_s: [BigInt] = []
    
    for item in shares {
        x_s.append(item.0)
        y_s.append(item.1)
    }
    return _lagrange_interpolate(x: 0, x_s: x_s, y_s: y_s, p: prime)
}

func process(secret: BigInt, minimum: Int?, total: Int?, dumpFileName: String?, displayResult: Bool = true) {
    let secret = secret
    let minimumShares = minimum ?? 3
    let totalShares = total ?? 6
    
    let shares: [(Int, BigInt)] = make_random_shares(secret: secret, minimum: minimumShares, shares: totalShares)
    
    if displayResult {
        print("Secret: ", secret)
        
        print("Shares")
        for share in shares {
            print("\(share)\n")
        }
        
        print("Secret recovered from minimum subset of shares: ")
        print(recover_secret(shares: Array(shares[0..<minimumShares])))
        print("Secret recovered from a different minimum subset of shares: ")
        print(recover_secret(shares: Array(shares[(shares.count - minimumShares)...])))
    }

    
    if dumpFileName != nil {
        saveSharesToFile(shares, minimumShares, totalShares, fileName: dumpFileName!)
        print("\n-> Saved the shares to: \(dumpFileName!)")
    }
}


func saveSharesToFile(_ shares: [(Int, BigInt)], _ min: Int, _ total: Int, fileName: String) {
    var content: String = "\(total);\(min)\n"
    
    for share in shares {
        content += (share.1.description + "\n")
    }
//    debugPrint("Content:")
//    debugPrint(content)
    let currentDir = FileManager.default.currentDirectoryPath
    
    let fileURL = URL.init(fileURLWithPath: currentDir).appendingPathComponent(fileName)

    //writing
    do {
        try content.write(to: fileURL, atomically: false, encoding: .ascii)
    }
    catch {
        debugPrint("Error writing shares to fle: \(error)")
    }

}

func getSecretFromFile(filePath: String, displayResult: Bool = true) -> BigInt? {
    let fileURL = URL.init(fileURLWithPath: filePath)

    do {
        let content = try String(contentsOf: fileURL, encoding: .ascii)
        var arr = content.components(separatedBy: .newlines)
        arr = arr.filter{ $0 != "" }
//        print("arr text: ", arr)
        if (arr.count < 2) {
            fatalError("Format is not correct.")
        }
        let firstLine = arr[0].split(separator: ";")
        if firstLine.count == 2, firstLine[0] >= firstLine[1], Int(firstLine[0]) == arr.count - 1 {
            guard let total = Int(firstLine[0]) else { print("Cannot parse total!"); return nil}
            guard let min = Int(firstLine[1]) else { print("Cannot parse min!"); return nil}
            
            // Construct a shares-array
            var shares = [(Int, BigInt)]()
            for i in 1...total {
                guard let s = BigInt(arr[i]) else { print("Cannot parse share!"); return nil}
                shares.append((i, s))
            }
            
            if displayResult {
                print("Total shares: \(total)")
                print("Minimum shares to solve the secret: \(min)")
                print("Shares:")
                for share in shares {
                    print("\(share)\n")
                }
                print("Secret recovered from minimum subset of shares: ")
                print(recover_secret(shares: Array(shares[0..<min])))
                print("Secret recovered from a different minimum subset of shares: ")
                print(recover_secret(shares: Array(shares[(shares.count - min)...])))
            }

            let result = recover_secret(shares: Array(shares[0..<min]))
            return result
        }
        else {
            fatalError("Format is not correct.")
        }

    }
    catch {
        debugPrint("Error reading shares from file: \(error)")
    }

    return nil
}


private func convertUInt8ArrayToString(_ numbers: [UInt8]) -> String {
    var result = ""

    for num in numbers {
        let str = String(format:"%03d", Int(num))
        result += str
    }
    return result
}

private func convertStringToUInt8(_ string: String) -> [UInt8] {
    var result = [UInt8]()
    let strArr = string.components(withMaxLength: 3)
    
    for str in strArr {
        if let num = Int(str) {
            result.append(UInt8(num))
        }
        else {
            fatalError("Cannot convert string to Int")
        }
    }
//    print("0: \(result[0])")
//    print("2: \(result[2])")
    return result
}

@available(macOS 10.13, *)
func getShardFromECCKey(keyPath: String, minimum: Int?, total: Int?, dumpFileName: String?) {
    let keyURL = URL.init(fileURLWithPath: keyPath)
    
    do {
        let keyString = try String(contentsOf: keyURL)
        print("ECC Key: ")
        print(keyString)
        
        guard let keyStringData = (keyString.data(using: .utf8)) else {
            fatalError("Cannot convert string to data")
        }
        
        let uInt8String = convertUInt8ArrayToString([UInt8](keyStringData))
//        print("Numberr: ")
//        print(uInt8String)

        if let encryptNumber = BigInt(uInt8String) {
            print("\nNumber generated from the key: ")
            print(encryptNumber.description)
            
            process(secret: encryptNumber, minimum: minimum, total: total, dumpFileName: dumpFileName, displayResult: false)
        }

    }
    catch {
        debugPrint("Error reading ECC key: \(error)")
    }

}

func getECCKeyFromShard(shardPath: String, keyFileName: String?) {
    guard let secret = getSecretFromFile(filePath: shardPath, displayResult: false) else {
        print("Cannot get secret from \(shardPath)")
        return
    }
    // Preprocess - if secret has leading zero
    var secretString = secret.description
    while secretString.count % 3 != 0 {
        secretString.insert("0", at: secretString.startIndex)
    }
    print("Secret string")
    print(secretString)
    
    // From secret -> private key
    let uint8Data = convertStringToUInt8(secretString)
    let data = Data(uint8Data)
    let privateKeyString = String(data: data, encoding: .ascii)
    print("\nDeshard result: ")
    print(privateKeyString ?? "(Empty)")
    
    // Save private key to file
    if let keyFileName = keyFileName {
        let currentDir = FileManager.default.currentDirectoryPath
        let keyOutputURL = URL.init(fileURLWithPath: currentDir).appendingPathComponent(keyFileName)
        
        do {
            try privateKeyString?.write(to: keyOutputURL, atomically: false, encoding: .ascii)
            print("\n-> Saved the private ECC key to: \(keyFileName)")
        }
        catch {
            debugPrint("Error writing the private key to \(keyFileName): \(error)")
        }
    }
    
}

@available(macOS 10.13, *)
func encryptStringWithECC(_ string: String, keyOutputName: String, stringOutputname: String) {
    do {
        let privateKey = try ECPrivateKey.make(for: .prime256v1)
        let publicKey = try privateKey.extractPublicKey()
        
        let encryptedData = try string.encrypt(with: publicKey)
        
        let currentDir = FileManager.default.currentDirectoryPath
        
        // Save private key to file
        let keyOutputURL = URL.init(fileURLWithPath: currentDir).appendingPathComponent(keyOutputName)
        try privateKey.pemString.write(to: keyOutputURL, atomically: false, encoding: .ascii)
        print("\n-> Saved the private ECC key to: \(keyOutputName)")

        // Save encrypted string to file
        let stringOutputURL = URL.init(fileURLWithPath: currentDir).appendingPathComponent(stringOutputname)

        try encryptedData.base64EncodedString().write(to: stringOutputURL, atomically: false, encoding: .ascii)
        print("\n-> Saved the encrypted string to: \(stringOutputname)")
    }
    catch {
        debugPrint("Error creating ECC key pair: \(error)")
    }

}


@available(macOS 10.13, *)
func decryptStringWithECC(stringPath: String, keyPath: String) {
    let stringURL = URL.init(fileURLWithPath: stringPath, isDirectory: false)
    let keyURL = URL.init(fileURLWithPath: keyPath, isDirectory: false)
    
    do {
        // Get private key from file
        let privateKeyPEM = try String(contentsOf: keyURL)
        let privateKey = try ECPrivateKey(key: privateKeyPEM)

        // Get encrypted string from file
        let encryptedString = try String(contentsOf: stringURL, encoding: .ascii)
        print("\nEncrypted string: ")
        print(encryptedString)
        
        if let encryptedData = Data(base64Encoded: encryptedString) {
            let decryptedData = try encryptedData.decrypt(with: privateKey)
            print("\nDecrypted string: ")
            print(String(data: decryptedData, encoding: .ascii) ?? "(Empty).")
        }
        else {
            fatalError("Cannot load encrypted data.")
        }
    }
    catch {
        debugPrint("Error load private key from file: \(error)")
    }

    
}

@available(macOS 10.13, *)
struct ShamirsSecret: ParsableCommand {
    static let configuration = CommandConfiguration(subcommands: [Create.self, Solve.self, Encrypt.self, Decrypt.self, Shard.self, Deshard.self])
    
    init() { }
}


if #available(macOS 10.13, *) {
    ShamirsSecret.main()
} else {
    // Fallback on earlier versions
    print("Only support macOS >= 10.13")
}
