/*global BigInt*/
// 12th Mersenne Prime
// (for this application we want a known prime number as close as
// possible to our security level; e.g.  desired security level of 128
// bits -- too large and all the ciphertext is large; too small and
// security is compromised)
const _PRIME = BigInt(2n ** 127n - 1n);
// 13th Mersenne Prime is 2**521 - 1

// This funcion is needed in order to do Modulo operations, because the % operator
// doesn't work with negative numbers
const mod = (a, b) => ((a % b) + b) % b;

const _RINT = (max) => BigInt(Math.floor(Math.random() * Number(max) + 1));

const _eval_at = (poly, x, prime) => {
    /* Evaluates polynomial (coefficient array) at x, used to generate
    a shamir pool in make_random_shares below. */
    let accum = 0n;
    for (let coeff of [...poly].reverse()) {
        accum *= BigInt(x);
        accum += BigInt(coeff);
        accum = mod(accum, prime);
    }
    return accum;
};

const make_random_shares = (secret, minimum, shares, prime = _PRIME) => {
    /* Generates a random shamir pool for a given secret, returns share points. */
    if (minimum > shares)
        throw { error: "Pool secret would be irrecoverable." };

    const aux = [];
    for (let i = 0; i < minimum - 1; i++) aux.push(_RINT(prime - 1n));
    const poly = [secret, ...aux];

    const points = [];
    for (let i = 1; i <= shares; i++)
        points.push([i, _eval_at(poly, i, prime)]);
    return points;
};

const _extended_gcd = (a, b) => {
    /* Division in integers modulus p means finding the inverse of the
    denominator modulo p and then multiplying the numerator by this
    inverse (Note: inverse of A is B such that A*B % p == 1) this can
    be computed via extended Euclidean algorithm
    http://en.wikipedia.org/wiki/Modular_multiplicative_inverse#Computation */

    let x = 0n;
    let last_x = 1n;
    let y = 1n;
    let last_y = 0n;
    let quot, aux;
    while (b !== 0n) {
        quot = a / b;
        aux = a;
        a = b;
        b = mod(aux, a);
        aux = x;
        x = last_x - quot * x;
        last_x = aux;
        aux = y;
        y = last_y - quot * y;
        last_y = aux;
    }
    return [last_x, last_y];
};

const _divmod = (num, den, p) => {
    /* Compute num / den modulo prime p

    To explain what this means, the return value will be such that
    the following is true: den * _divmod(num, den, p) % p == num */

    const [inv, _] = _extended_gcd(den, p);
    return num * inv;
};

const _lagrange_interpolate = (x, x_s, y_s, p) => {
    /* Find the y-value for the given x, given n (x, y) points;
    k points will define a polynomial of up to kth order. */
    const k = x_s.length;
    if (k !== [...new Set(x_s)].length)
        throw { error: "points must be distinct" };
    const PI = (vals) => {
        // upper-case PI -- product of inputs
        let accum = 1n;
        for (let v of vals) accum *= v;
        return accum;
    };
    let nums = [];
    let dens = [];
    let others, cur, aux;
    for (let i = 0; i < k; i++) {
        others = [...x_s];
        cur = others.splice(i, 1);
        aux = [];
        for (let o of others) aux.push(BigInt(x) - BigInt(o));
        nums = [...nums, PI(aux)];
        aux = [];
        for (let o of others) aux.push(BigInt(cur) - BigInt(o));
        dens = [...dens, PI(aux)];
    }
    let den = PI(dens);
    aux = [];
    for (let i = 0; i < k; i++)
        aux.push(_divmod(mod(nums[i] * den * y_s[i], p), dens[i], p));
    let num = 0n;
    for (let a of aux) num += a;
    return mod(_divmod(num, den, p) + p, p);
};

const zip = (arr, ...arrs) => {
    /* This function replicates the behaviour of zip() in python */
    return arr.map((val, i) => arrs.reduce((a, arr) => [...a, arr[i]], [val]));
};

const recover_secret = (shares, prime = _PRIME) => {
    /* Recover the secret from share points
    (x, y points on the polynomial). */
    if (shares.length < 2) throw {};

    const [x_s, y_s] = zip(...shares);
    return _lagrange_interpolate(0, x_s, y_s, prime).toString();
};

const main = (secret) => {
    const shares = make_random_shares(secret, 3, 6);
    console.log("Secret: ", secret);
    if (shares)
        shares.forEach((share) => {
            console.log("  ", [share[0], share[1].toString()]);
        });
    console.log(
        "Secret recovered from minimum subset of shares:             ",
        recover_secret(shares.slice(0, 3))
    );
    console.log(
        "Secret recovered from a different minimum subset of shares: ",
        recover_secret(shares.slice(-3))
    );
    return shares.map((share) => [share[0], share[1].toString()]);
};

if (process.argv[2] === "local") main(process.argv[3]);
else {
    exports.handler = async (event) => {
        const shares = main(event.secret);
        const response = {
            statusCode: 200,
            body: JSON.stringify(shares),
        };
        return response;
    };
}
