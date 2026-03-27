/**
 * PA#4 — Modes of Operation: CBC, OFB, CTR
 *
 * Uses AES-128 as the underlying block cipher (from aes128.ts).
 * Implements:
 *   - CBC mode (encrypt/decrypt) with PKCS#7 padding
 *   - OFB mode (encrypt/decrypt) — stream cipher, no padding
 *   - CTR mode (randomized, encrypt/decrypt) — stream cipher, no padding
 *   - Unified encrypt/decrypt API
 *   - Attack demos: CBC IV-reuse, OFB keystream-reuse
 */

import { aesEncryptBlock, expandKey } from './aes128'
import type { ByteArray } from '../types'

const BLOCK_SIZE = 16

// ─── Inverse AES S-box (for AES decryption) ─────────────────────────────────

const INV_SBOX = new Uint8Array(256)
// Forward SBOX copied from aes128.ts to build inverse
const SBOX = new Uint8Array([
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
])
for (let i = 0; i < 256; i++) INV_SBOX[SBOX[i]] = i

// ─── GF(2^8) helpers ─────────────────────────────────────────────────────────

function gmul(a: number, b: number): number {
  let p = 0
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a
    const hi = a & 0x80
    a = (a << 1) & 0xff
    if (hi) a ^= 0x1b
    b >>= 1
  }
  return p
}

// ─── AES-128 block decryption (FIPS 197 inverse cipher) ──────────────────────

export function aesDecryptBlock(block: ByteArray, roundKeys: Uint8Array): ByteArray {
  const s = new Uint8Array(16)
  for (let i = 0; i < 16; i++) s[i] = block[i] ?? 0

  // AddRoundKey (round 10)
  for (let i = 0; i < 16; i++) s[i] ^= roundKeys[10 * 16 + i]

  for (let round = 9; round >= 0; round--) {
    // InvShiftRows
    // Row 1: shift right 1
    let t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t
    // Row 2: shift right 2
    t = s[2]; s[2] = s[10]; s[10] = t
    t = s[6]; s[6] = s[14]; s[14] = t
    // Row 3: shift right 3 (= shift left 1)
    t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t

    // InvSubBytes
    for (let i = 0; i < 16; i++) s[i] = INV_SBOX[s[i]]

    // AddRoundKey
    const rk = round * 16
    for (let i = 0; i < 16; i++) s[i] ^= roundKeys[rk + i]

    if (round > 0) {
      // InvMixColumns
      for (let c = 0; c < 4; c++) {
        const i = c * 4
        const s0 = s[i], s1 = s[i + 1], s2 = s[i + 2], s3 = s[i + 3]
        s[i]     = gmul(0x0e, s0) ^ gmul(0x0b, s1) ^ gmul(0x0d, s2) ^ gmul(0x09, s3)
        s[i + 1] = gmul(0x09, s0) ^ gmul(0x0e, s1) ^ gmul(0x0b, s2) ^ gmul(0x0d, s3)
        s[i + 2] = gmul(0x0d, s0) ^ gmul(0x09, s1) ^ gmul(0x0e, s2) ^ gmul(0x0b, s3)
        s[i + 3] = gmul(0x0b, s0) ^ gmul(0x0d, s1) ^ gmul(0x09, s2) ^ gmul(0x0e, s3)
      }
    }
  }

  return s
}

// ─── Utility helpers ─────────────────────────────────────────────────────────

function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const len = Math.min(a.length, b.length)
  const out = new Uint8Array(len)
  for (let i = 0; i < len; i++) out[i] = a[i] ^ b[i]
  return out
}

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n)
  crypto.getRandomValues(out)
  return out
}

/** Increment a 16-byte big-endian counter by delta */
function incrementCounter(ctr: Uint8Array, delta: number = 1): Uint8Array {
  const out = Uint8Array.from(ctr)
  let carry = delta
  for (let i = out.length - 1; i >= 0 && carry > 0; i--) {
    const sum = out[i] + carry
    out[i] = sum & 0xff
    carry = sum >> 8
  }
  return out
}

// ─── PKCS#7 Padding ──────────────────────────────────────────────────────────

export function pkcs7Pad(data: Uint8Array, blockSize: number = BLOCK_SIZE): Uint8Array {
  const padLen = blockSize - (data.length % blockSize)
  const out = new Uint8Array(data.length + padLen)
  out.set(data)
  out.fill(padLen, data.length)
  return out
}

export function pkcs7Unpad(data: Uint8Array): Uint8Array {
  if (data.length === 0 || data.length % BLOCK_SIZE !== 0) {
    throw new Error('Invalid padded data length')
  }
  const padLen = data[data.length - 1]
  if (padLen === 0 || padLen > BLOCK_SIZE) {
    throw new Error('Invalid PKCS#7 padding')
  }
  for (let i = data.length - padLen; i < data.length; i++) {
    if (data[i] !== padLen) throw new Error('Invalid PKCS#7 padding')
  }
  return data.slice(0, data.length - padLen)
}

// ─── CBC Mode ────────────────────────────────────────────────────────────────

export interface CbcBlockStep {
  blockIndex: number
  plainBlock: Uint8Array
  xorWithPrev: Uint8Array   // M_i XOR C_{i-1}
  cipherBlock: Uint8Array
}

export function cbcEncrypt(
  key: Uint8Array, iv: Uint8Array, message: Uint8Array
): { output: Uint8Array; steps: CbcBlockStep[] } {
  const roundKeys = expandKey(key)
  const padded = pkcs7Pad(message)
  const numBlocks = padded.length / BLOCK_SIZE
  const ciphertext = new Uint8Array(BLOCK_SIZE + padded.length) // IV || ciphertext
  ciphertext.set(iv, 0)

  let prev = iv
  const steps: CbcBlockStep[] = []

  for (let i = 0; i < numBlocks; i++) {
    const plainBlock = padded.slice(i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE)
    const xored = xorBytes(plainBlock, prev)
    const encrypted = aesEncryptBlock(xored, roundKeys)
    const cipherBlock = new Uint8Array(encrypted)
    ciphertext.set(cipherBlock, (i + 1) * BLOCK_SIZE)
    steps.push({ blockIndex: i, plainBlock, xorWithPrev: xored, cipherBlock })
    prev = cipherBlock
  }

  return { output: ciphertext, steps }
}

export function cbcDecrypt(
  key: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array
): { output: Uint8Array; steps: CbcBlockStep[] } {
  // ciphertext here is the raw ciphertext blocks (without IV prefix)
  const roundKeys = expandKey(key)
  const numBlocks = ciphertext.length / BLOCK_SIZE
  const paddedPlain = new Uint8Array(ciphertext.length)
  let prev = iv
  const steps: CbcBlockStep[] = []

  for (let i = 0; i < numBlocks; i++) {
    const cipherBlock = ciphertext.slice(i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE)
    const decrypted = aesDecryptBlock(cipherBlock, roundKeys)
    const plainBlock = xorBytes(new Uint8Array(decrypted), prev)
    paddedPlain.set(plainBlock, i * BLOCK_SIZE)
    steps.push({ blockIndex: i, plainBlock, xorWithPrev: new Uint8Array(decrypted), cipherBlock })
    prev = cipherBlock
  }

  return { output: pkcs7Unpad(paddedPlain), steps }
}

// ─── OFB Mode ────────────────────────────────────────────────────────────────

export interface OfbBlockStep {
  blockIndex: number
  keystreamBlock: Uint8Array
  inputBlock: Uint8Array
  outputBlock: Uint8Array
}

export function ofbEncrypt(
  key: Uint8Array, iv: Uint8Array, message: Uint8Array
): { output: Uint8Array; steps: OfbBlockStep[] } {
  const roundKeys = expandKey(key)
  const numBlocks = Math.ceil(message.length / BLOCK_SIZE)
  const result = new Uint8Array(BLOCK_SIZE + message.length) // IV || ciphertext
  result.set(iv, 0)

  let oi = iv
  const steps: OfbBlockStep[] = []

  for (let i = 0; i < numBlocks; i++) {
    const keystreamBlock = new Uint8Array(aesEncryptBlock(oi, roundKeys))
    const start = i * BLOCK_SIZE
    const end = Math.min(start + BLOCK_SIZE, message.length)
    const inputBlock = message.slice(start, end)
    const outputBlock = xorBytes(inputBlock, keystreamBlock.slice(0, inputBlock.length))
    result.set(outputBlock, BLOCK_SIZE + start)
    steps.push({ blockIndex: i, keystreamBlock, inputBlock, outputBlock })
    oi = keystreamBlock
  }

  return { output: result, steps }
}

export function ofbDecrypt(
  key: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array
): { output: Uint8Array; steps: OfbBlockStep[] } {
  // OFB decrypt is identical to encrypt (symmetric)
  return ofbEncrypt(key, iv, ciphertext)
}

// ─── CTR Mode (Randomized) ──────────────────────────────────────────────────

export interface CtrBlockStep {
  blockIndex: number
  counterValue: Uint8Array
  keystreamBlock: Uint8Array
  inputBlock: Uint8Array
  outputBlock: Uint8Array
}

export function ctrEncrypt(
  key: Uint8Array, message: Uint8Array
): { output: Uint8Array; nonce: Uint8Array; steps: CtrBlockStep[] } {
  const roundKeys = expandKey(key)
  const nonce = randomBytes(BLOCK_SIZE)
  const numBlocks = Math.ceil(message.length / BLOCK_SIZE)
  const result = new Uint8Array(BLOCK_SIZE + message.length) // nonce || ciphertext
  result.set(nonce, 0)

  const steps: CtrBlockStep[] = []

  for (let i = 0; i < numBlocks; i++) {
    const counterValue = incrementCounter(nonce, i)
    const keystreamBlock = new Uint8Array(aesEncryptBlock(counterValue, roundKeys))
    const start = i * BLOCK_SIZE
    const end = Math.min(start + BLOCK_SIZE, message.length)
    const inputBlock = message.slice(start, end)
    const outputBlock = xorBytes(inputBlock, keystreamBlock.slice(0, inputBlock.length))
    result.set(outputBlock, BLOCK_SIZE + start)
    steps.push({ blockIndex: i, counterValue, keystreamBlock, inputBlock, outputBlock })
  }

  return { output: result, nonce, steps }
}

export function ctrDecrypt(
  key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array
): { output: Uint8Array; steps: CtrBlockStep[] } {
  const roundKeys = expandKey(key)
  const numBlocks = Math.ceil(ciphertext.length / BLOCK_SIZE)
  const plaintext = new Uint8Array(ciphertext.length)

  const steps: CtrBlockStep[] = []

  for (let i = 0; i < numBlocks; i++) {
    const counterValue = incrementCounter(nonce, i)
    const keystreamBlock = new Uint8Array(aesEncryptBlock(counterValue, roundKeys))
    const start = i * BLOCK_SIZE
    const end = Math.min(start + BLOCK_SIZE, ciphertext.length)
    const inputBlock = ciphertext.slice(start, end)
    const outputBlock = xorBytes(inputBlock, keystreamBlock.slice(0, inputBlock.length))
    plaintext.set(outputBlock, start)
    steps.push({ blockIndex: i, counterValue, keystreamBlock, inputBlock, outputBlock })
  }

  return { output: plaintext, steps }
}

// ─── Unified API ─────────────────────────────────────────────────────────────

export type BlockMode = 'CBC' | 'OFB' | 'CTR'

export function encrypt(
  mode: BlockMode,
  key: Uint8Array,
  message: Uint8Array,
  iv?: Uint8Array
): Uint8Array {
  switch (mode) {
    case 'CBC': {
      const theIv = iv ?? randomBytes(BLOCK_SIZE)
      return cbcEncrypt(key, theIv, message).output
    }
    case 'OFB': {
      const theIv = iv ?? randomBytes(BLOCK_SIZE)
      return ofbEncrypt(key, theIv, message).output
    }
    case 'CTR':
      return ctrEncrypt(key, message).output
  }
}

export function decrypt(
  mode: BlockMode,
  key: Uint8Array,
  ciphertext: Uint8Array,
  iv?: Uint8Array
): Uint8Array {
  switch (mode) {
    case 'CBC': {
      // ciphertext = IV || encrypted blocks
      const theIv = iv ?? ciphertext.slice(0, BLOCK_SIZE)
      const ct = iv ? ciphertext : ciphertext.slice(BLOCK_SIZE)
      return cbcDecrypt(key, theIv, ct).output
    }
    case 'OFB': {
      const theIv = iv ?? ciphertext.slice(0, BLOCK_SIZE)
      const ct = iv ? ciphertext : ciphertext.slice(BLOCK_SIZE)
      return ofbDecrypt(key, theIv, ct).output
    }
    case 'CTR': {
      const nonce = iv ?? ciphertext.slice(0, BLOCK_SIZE)
      const ct = iv ? ciphertext : ciphertext.slice(BLOCK_SIZE)
      return ctrDecrypt(key, nonce, ct).output
    }
  }
}

// ─── Attack Demos ────────────────────────────────────────────────────────────

/**
 * CBC IV-Reuse Attack: encrypt two messages with same key and IV.
 * If M1[0] === M2[0] (first plaintext block equal), then C1[0] === C2[0].
 */
export function cbcIvReuseAttack(
  key: Uint8Array, iv: Uint8Array, m1: Uint8Array, m2: Uint8Array
): {
  c1: Uint8Array; c2: Uint8Array
  c1Block0Hex: string; c2Block0Hex: string
  firstBlocksMatch: boolean
  m1Block0Hex: string; m2Block0Hex: string
  plaintextFirstBlocksMatch: boolean
} {
  const enc1 = cbcEncrypt(key, iv, m1)
  const enc2 = cbcEncrypt(key, iv, m2)

  // First ciphertext block is at offset BLOCK_SIZE (after IV)
  const c1Block0 = enc1.output.slice(BLOCK_SIZE, 2 * BLOCK_SIZE)
  const c2Block0 = enc2.output.slice(BLOCK_SIZE, 2 * BLOCK_SIZE)

  const pad1 = pkcs7Pad(m1)
  const pad2 = pkcs7Pad(m2)
  const m1Block0 = pad1.slice(0, BLOCK_SIZE)
  const m2Block0 = pad2.slice(0, BLOCK_SIZE)

  const plaintextFirstBlocksMatch = m1Block0.every((b, i) => b === m2Block0[i])
  const firstBlocksMatch = c1Block0.every((b, i) => b === c2Block0[i])

  const toHex = (arr: Uint8Array) => Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('')

  return {
    c1: enc1.output, c2: enc2.output,
    c1Block0Hex: toHex(c1Block0), c2Block0Hex: toHex(c2Block0),
    firstBlocksMatch,
    m1Block0Hex: toHex(m1Block0), m2Block0Hex: toHex(m2Block0),
    plaintextFirstBlocksMatch,
  }
}

/**
 * OFB Keystream-Reuse Attack: encrypt two messages with same key+IV.
 * C1 XOR C2 = M1 XOR M2 (keystream cancels out).
 */
export function ofbKeystreamReuseAttack(
  key: Uint8Array, iv: Uint8Array, m1: Uint8Array, m2: Uint8Array
): {
  c1: Uint8Array; c2: Uint8Array
  c1Body: Uint8Array; c2Body: Uint8Array
  xorCiphertexts: Uint8Array
  xorPlaintexts: Uint8Array
  match: boolean
} {
  const enc1 = ofbEncrypt(key, iv, m1)
  const enc2 = ofbEncrypt(key, iv, m2)

  const c1Body = enc1.output.slice(BLOCK_SIZE)
  const c2Body = enc2.output.slice(BLOCK_SIZE)

  const minLen = Math.min(c1Body.length, c2Body.length)
  const xorCiphertexts = xorBytes(c1Body.slice(0, minLen), c2Body.slice(0, minLen))

  const minPtLen = Math.min(m1.length, m2.length)
  const xorPlaintexts = xorBytes(m1.slice(0, minPtLen), m2.slice(0, minPtLen))

  const match = minLen === minPtLen &&
    xorCiphertexts.every((b, i) => b === xorPlaintexts[i])

  return {
    c1: enc1.output, c2: enc2.output,
    c1Body, c2Body,
    xorCiphertexts, xorPlaintexts,
    match,
  }
}
