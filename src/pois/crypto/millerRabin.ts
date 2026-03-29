/**
 * PA#13 — Miller-Rabin Primality Testing
 *
 * Implements:
 * - modpow: square-and-multiply modular exponentiation
 * - millerRabin: Miller-Rabin primality test with detailed traces
 * - fermatTest: simple Fermat test (for Carmichael number demo)
 * - randomBigInt: cryptographically random BigInt of given bit length
 * - genPrime: probable prime generation with candidate counting
 */

/* ------------------------------------------------------------------ */
/*  Modular exponentiation (square-and-multiply)                      */
/* ------------------------------------------------------------------ */

export function modpow(base: bigint, exp: bigint, mod: bigint): bigint {
  if (mod === 1n) return 0n
  let result = 1n
  base = ((base % mod) + mod) % mod
  while (exp > 0n) {
    if (exp & 1n) {
      result = (result * base) % mod
    }
    exp >>= 1n
    base = (base * base) % mod
  }
  return result
}

/* ------------------------------------------------------------------ */
/*  Random BigInt generation using crypto.getRandomValues             */
/* ------------------------------------------------------------------ */

export function randomBigInt(bits: number): bigint {
  if (bits <= 0) return 0n
  const byteLen = Math.ceil(bits / 8)
  const buf = new Uint8Array(byteLen)
  crypto.getRandomValues(buf)

  // Mask top byte so we have exactly `bits` bits, then set MSB
  const excessBits = byteLen * 8 - bits
  if (excessBits > 0) {
    buf[0] &= (1 << (8 - excessBits)) - 1
  }
  // Set the MSB to ensure correct bit length
  const msbBitInTopByte = (bits - 1) % 8
  buf[0] |= 1 << msbBitInTopByte

  let value = 0n
  for (let i = 0; i < byteLen; i++) {
    value = (value << 8n) | BigInt(buf[i])
  }
  return value
}

/* ------------------------------------------------------------------ */
/*  Random BigInt in range [lo, hi] inclusive                          */
/* ------------------------------------------------------------------ */

function randomBigIntInRange(lo: bigint, hi: bigint): bigint {
  const range = hi - lo + 1n
  if (range <= 0n) return lo

  // Determine bit length of range
  let bits = 0
  let tmp = range
  while (tmp > 0n) {
    bits++
    tmp >>= 1n
  }

  // Rejection sampling
  for (;;) {
    const byteLen = Math.ceil(bits / 8)
    const buf = new Uint8Array(byteLen)
    crypto.getRandomValues(buf)

    // Mask top byte
    const excessBits = byteLen * 8 - bits
    if (excessBits > 0) {
      buf[0] &= (1 << (8 - excessBits)) - 1
    }

    let value = 0n
    for (let i = 0; i < byteLen; i++) {
      value = (value << 8n) | BigInt(buf[i])
    }

    if (value < range) {
      return lo + value
    }
  }
}

/* ------------------------------------------------------------------ */
/*  Miller-Rabin types                                                */
/* ------------------------------------------------------------------ */

export type RoundTrace = {
  a: bigint
  xValues: bigint[]
  verdict: 'PROBABLY_PRIME' | 'COMPOSITE'
}

export type MillerRabinResult = {
  result: 'PROBABLY_PRIME' | 'COMPOSITE'
  witness?: bigint
  rounds: RoundTrace[]
  s: number
  d: bigint
}

/* ------------------------------------------------------------------ */
/*  Miller-Rabin primality test                                       */
/* ------------------------------------------------------------------ */

export function millerRabin(n: bigint, k: number): MillerRabinResult {
  // Factor out powers of 2: n - 1 = 2^s * d with d odd
  let s = 0
  let d = n - 1n
  while ((d & 1n) === 0n) {
    s++
    d >>= 1n
  }

  const rounds: RoundTrace[] = []

  for (let i = 0; i < k; i++) {
    const a = randomBigIntInRange(2n, n - 2n)
    let x = modpow(a, d, n)
    const xValues: bigint[] = [x]

    if (x === 1n || x === n - 1n) {
      rounds.push({ a, xValues, verdict: 'PROBABLY_PRIME' })
      continue
    }

    let foundMinus1 = false
    for (let r = 1; r < s; r++) {
      x = modpow(x, 2n, n)
      xValues.push(x)
      if (x === n - 1n) {
        foundMinus1 = true
        break
      }
    }

    if (!foundMinus1) {
      rounds.push({ a, xValues, verdict: 'COMPOSITE' })
      return { result: 'COMPOSITE', witness: a, rounds, s, d }
    }

    rounds.push({ a, xValues, verdict: 'PROBABLY_PRIME' })
  }

  return { result: 'PROBABLY_PRIME', rounds, s, d }
}

/* ------------------------------------------------------------------ */
/*  Fermat test (for Carmichael demo)                                 */
/* ------------------------------------------------------------------ */

export function fermatTest(n: bigint, a: bigint): boolean {
  return modpow(a, n - 1n, n) === 1n
}

/* ------------------------------------------------------------------ */
/*  Prime generation                                                  */
/* ------------------------------------------------------------------ */

export type GenPrimeResult = {
  prime: bigint
  candidatesTested: number
}

export function genPrime(bits: number, k = 40): GenPrimeResult {
  let candidatesTested = 0
  let candidate = randomBigInt(bits)
  // Ensure odd
  if ((candidate & 1n) === 0n) candidate += 1n

  for (;;) {
    candidatesTested++

    // Quick small-prime divisibility check
    const smallPrimes = [3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n]
    let skipCandidate = false
    for (const sp of smallPrimes) {
      if (candidate > sp && candidate % sp === 0n) {
        skipCandidate = true
        break
      }
    }

    if (!skipCandidate) {
      const mr = millerRabin(candidate, k)
      if (mr.result === 'PROBABLY_PRIME') {
        return { prime: candidate, candidatesTested }
      }
    }

    candidate += 2n
  }
}
