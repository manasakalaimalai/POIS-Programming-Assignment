/**
 * NIST SP 800-22 Statistical Randomness Tests.
 * Implements three tests: monobit frequency, block frequency, runs.
 * No external libraries used.
 */

import type { ByteArray } from '../types'

export interface StatTestResult {
  testName: string
  pValue: number
  pass: boolean       // p-value >= 0.01
  detail: string
  bitRatio?: number   // fraction of 1-bits (monobit only)
}

// ── Math helpers ──────────────────────────────────────────────────────────────

/**
 * erfc(x) — complementary error function.
 * Approximation from Abramowitz & Stegun 7.1.26, max error < 1.5e-7.
 */
function erfc(x: number): number {
  const sign = x < 0 ? -1 : 1
  x = Math.abs(x)
  const t = 1.0 / (1.0 + 0.3275911 * x)
  const poly =
    t * (0.254829592 +
    t * (-0.284496736 +
    t * (1.421413741 +
    t * (-1.453152027 +
    t * 1.061405429))))
  const result = poly * Math.exp(-x * x)
  return sign === 1 ? result : 2.0 - result
}

/**
 * Regularized upper incomplete gamma function: igamc(a, x) = 1 - P(a, x).
 * Used for chi-squared p-value in block frequency test.
 * Implemented via Lentz continued fraction (converges well for x >= a+1)
 * and series expansion (for x < a+1).
 */
function gammaln(z: number): number {
  // Lanczos approximation
  const g = 7
  const c = [
    0.99999999999980993, 676.5203681218851, -1259.1392167224028,
    771.32342877765313, -176.61502916214059, 12.507343278686905,
    -0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7,
  ]
  if (z < 0.5) {
    return Math.log(Math.PI / Math.sin(Math.PI * z)) - gammaln(1 - z)
  }
  z -= 1
  let x = c[0]
  for (let i = 1; i < g + 2; i++) x += c[i] / (z + i)
  const t = z + g + 0.5
  return 0.5 * Math.log(2 * Math.PI) + (z + 0.5) * Math.log(t) - t + Math.log(x)
}

function igamc(a: number, x: number): number {
  if (x < 0 || a <= 0) return 1.0
  if (x === 0) return 1.0

  // Use series for small x, continued fraction for large x
  if (x < a + 1) {
    // Lower incomplete gamma via series → igamc = 1 - P(a,x)
    let ap = a
    let sum = 1.0 / a
    let delta = sum
    for (let i = 0; i < 200; i++) {
      ap += 1
      delta *= x / ap
      sum += delta
      if (Math.abs(delta) < Math.abs(sum) * 1e-10) break
    }
    return 1.0 - sum * Math.exp(-x + a * Math.log(x) - gammaln(a))
  }

  // Upper incomplete gamma via continued fraction (Lentz's method)
  let b = x + 1 - a
  let c = 1e30
  let d = 1 / b
  let h = d
  for (let i = 1; i <= 200; i++) {
    const an = -i * (i - a)
    b += 2
    d = an * d + b
    if (Math.abs(d) < 1e-30) d = 1e-30
    c = b + an / c
    if (Math.abs(c) < 1e-30) c = 1e-30
    d = 1 / d
    const del = d * c
    h *= del
    if (Math.abs(del - 1) < 1e-10) break
  }
  return h * Math.exp(-x + a * Math.log(x) - gammaln(a))
}

// ── Bit extraction ─────────────────────────────────────────────────────────

/** Extract all bits from a ByteArray as an array of 0/1 values. */
function extractBits(bytes: ByteArray): number[] {
  const bits: number[] = []
  for (const byte of bytes) {
    for (let i = 7; i >= 0; i--) {
      bits.push((byte >> i) & 1)
    }
  }
  return bits
}

// ── Test 1: Monobit Frequency ──────────────────────────────────────────────

/**
 * NIST SP 800-22 Test 1: Frequency (Monobit) Test.
 * Checks that the number of 1s and 0s is approximately equal.
 * p = erfc(|sum| / sqrt(n) / sqrt(2))
 */
export function monobitFrequencyTest(bytes: ByteArray): StatTestResult {
  const bits = extractBits(bytes)
  const n = bits.length
  if (n < 8) {
    return { testName: 'Monobit Frequency', pValue: 0, pass: false, detail: 'Too few bits' }
  }

  // s = sum of +1/-1 representation (1→+1, 0→-1)
  let s = 0
  let ones = 0
  for (const b of bits) {
    s += b === 1 ? 1 : -1
    if (b === 1) ones++
  }

  const sObs = Math.abs(s) / Math.sqrt(n)
  const pValue = erfc(sObs / Math.sqrt(2))
  const bitRatio = ones / n

  return {
    testName: 'Monobit Frequency',
    pValue,
    pass: pValue >= 0.01,
    detail: `n=${n} bits, ones=${ones} (${(bitRatio * 100).toFixed(1)}%), S_obs=${sObs.toFixed(4)}`,
    bitRatio,
  }
}

// ── Test 2: Block Frequency ────────────────────────────────────────────────

/**
 * NIST SP 800-22 Test 2: Frequency Test within a Block.
 * Divides bit sequence into M-bit blocks, tests each block's proportion of 1s.
 * p = igamc(N/2, chi2/2) where chi2 = 4*M*sum((pi_i - 0.5)^2)
 */
export function blockFrequencyTest(bytes: ByteArray, M = 8): StatTestResult {
  const bits = extractBits(bytes)
  const n = bits.length
  const N = Math.floor(n / M)   // number of complete blocks

  if (N < 1) {
    return { testName: 'Block Frequency', pValue: 0, pass: false, detail: 'Too few bits for block size' }
  }

  let chi2 = 0
  for (let i = 0; i < N; i++) {
    let onesInBlock = 0
    for (let j = 0; j < M; j++) {
      onesInBlock += bits[i * M + j]
    }
    const pi = onesInBlock / M
    chi2 += (pi - 0.5) * (pi - 0.5)
  }
  chi2 *= 4 * M

  const pValue = igamc(N / 2, chi2 / 2)

  return {
    testName: 'Block Frequency',
    pValue,
    pass: pValue >= 0.01,
    detail: `N=${N} blocks of M=${M}, χ²=${chi2.toFixed(4)}`,
  }
}

// ── Test 3: Runs ───────────────────────────────────────────────────────────

/**
 * NIST SP 800-22 Test 3: Runs Test.
 * Tests the total number of runs (uninterrupted sequences of identical bits).
 * p = erfc(|V_obs - 2n*π*(1-π)| / (2*sqrt(2n)*π*(1-π)))
 */
export function runsTest(bytes: ByteArray): StatTestResult {
  const bits = extractBits(bytes)
  const n = bits.length

  if (n < 8) {
    return { testName: 'Runs', pValue: 0, pass: false, detail: 'Too few bits' }
  }

  const pi = bits.filter(b => b === 1).length / n

  // Pre-test: if proportion of 1s is too far from 0.5, auto-fail
  if (Math.abs(pi - 0.5) >= 2 / Math.sqrt(n)) {
    return {
      testName: 'Runs',
      pValue: 0,
      pass: false,
      detail: `Pre-test failed: π=${pi.toFixed(4)} too far from 0.5`,
    }
  }

  // Count runs: V_obs = 1 + number of positions where bit changes
  let vObs = 1
  for (let k = 1; k < n; k++) {
    if (bits[k] !== bits[k - 1]) vObs++
  }

  const expected = 2 * n * pi * (1 - pi)
  const denominator = 2 * Math.sqrt(2 * n) * pi * (1 - pi)
  const pValue = erfc(Math.abs(vObs - expected) / denominator)

  return {
    testName: 'Runs',
    pValue,
    pass: pValue >= 0.01,
    detail: `n=${n}, V_obs=${vObs}, expected=${expected.toFixed(2)}, π=${pi.toFixed(4)}`,
  }
}

// ── Run all tests ─────────────────────────────────────────────────────────

export function runAllStatTests(bytes: ByteArray): StatTestResult[] {
  return [
    monobitFrequencyTest(bytes),
    blockFrequencyTest(bytes),
    runsTest(bytes),
  ]
}
