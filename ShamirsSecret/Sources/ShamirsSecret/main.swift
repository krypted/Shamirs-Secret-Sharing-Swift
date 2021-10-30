import ArgumentParser
import Foundation
import BigInt

// 12th Mersenne Prime
// (for this application we want a known prime number as close as
// possible to our security level; e.g.  desired security level of 128
// bits -- too large and all the ciphertext is large; too small and
// security is compromised)
let _PRIME: BigInt = BigInt(2).power(127) - 1

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

func make_random_shares(secret: Int, minimum: Int = 3, shares: Int = 6, prime: BigInt=_PRIME) ->[(Int, BigInt)] {
    
    if minimum > shares {
        fatalError("ERROR: Pool secret would be irrecoverable.")
    }
    var poly: [BigInt] = [BigInt(secret)]
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

func process(secret: Int, minimum: Int?, total: Int?, dumpFileName: String?) {
    let secret = secret
    let minimumShares = minimum ?? 3
    let totalShares = total ?? 6
    
    let shares: [(Int, BigInt)] = make_random_shares(secret: secret, minimum: minimumShares, shares: totalShares)
    
    print("Secret: ", secret)
    
    print("Shares")
    for share in shares {
        print("\(share)\n")
    }
    
    print("Secret recovered from minimum subset of shares: ")
    print(recover_secret(shares: Array(shares[0..<minimumShares])))
    print("Secret recovered from a different minimum subset of shares: ")
    print(recover_secret(shares: Array(shares[(shares.count - minimumShares)...])))
    
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

func getSecretFromFile(filePath: String) {
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
            guard let total = Int(firstLine[0]) else { print("Cannot parse total!"); return}
            guard let min = Int(firstLine[1]) else { print("Cannot parse min!"); return}
            
            // Construct a shares-array
            var shares = [(Int, BigInt)]()
            for i in 1...total {
                guard let s = BigInt(arr[i]) else { print("Cannot parse share!"); return}
                shares.append((i, s))
            }
            
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
        else {
            fatalError("Format is not correct.")
        }

    }
    catch {
        debugPrint("Error reading shares from file: \(error)")
    }

}

struct ShamirsSecret: ParsableCommand {
    static let configuration = CommandConfiguration(subcommands: [Create.self, Solve.self])
       
    init() { }
}

extension ShamirsSecret{

    struct Create: ParsableCommand {
        public static let configuration = CommandConfiguration(abstract: "Create shares from a given secret.")
        @Argument()
        var secret: Int
        
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
        }
        
        func run() throws {
            process(secret: secret, minimum: minimumShares, total: totalShares, dumpFileName: dumpURL)
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
}


ShamirsSecret.main()


