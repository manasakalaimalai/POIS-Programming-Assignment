/**
 * PA#17 — CCA-Secure PKC via Encrypt-then-Sign
 *
 * Combines PA#16 ElGamal encryption with PA#15 RSA digital signatures
 * to achieve CCA2-secure public-key cryptography.
 *
 * Lineage: PA#17 -> PA#15 + PA#16 -> PA#12 + PA#11 -> PA#13
 */

import {
  elgamalKeygen,
  elgamalEncrypt,
  elgamalDecrypt,
  type ElGamalKeyPair,
  type ElGamalCiphertext,
} from './elgamal'
import {
  sign,
  verify,
  rsaKeygen,
  type RSAPublicKey,
  type RSAPrivateKey,
  type RSAKeyPair,
} from './digitalSig'
import { DH_PARAMS } from './diffieHellman'
import { bigintToBytes, bytesToBigint } from './rsa'

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

export type CcaPkcEncKeys = {
  sk: bigint
  pk: ElGamalKeyPair['pk']
}

export type CcaPkcSigKeys = {
  sk: RSAPrivateKey
  pk: RSAPublicKey
}

export type CcaPkcKeyBundle = {
  encKeys: CcaPkcEncKeys
  sigKeys: CcaPkcSigKeys
}

export type CcaPkcCiphertext = {
  c1: bigint
  c2: bigint
  sigma: bigint
}

export type CcaMalleabilityBlockedResult = {
  originalM: bigint
  modifiedC2: bigint
  signatureValid: boolean
  decryptResult: null
}

export type PlainElGamalMalleabilityResult = {
  originalM: bigint
  decryptedModified: bigint
  attackSucceeded: boolean
}

/* ------------------------------------------------------------------ */
/*  Helper: bigint <-> fixed-length bytes                              */
/* ------------------------------------------------------------------ */

/**
 * Serialize a bigint to a fixed-length byte array.
 * Uses the byte length of the ElGamal prime p.
 */
export function bigintToFixedBytes(n: bigint, len: number): Uint8Array {
  return bigintToBytes(n, len)
}

/** Byte length needed to represent the ElGamal prime p. */
function elgamalByteLen(): number {
  return Math.ceil(DH_PARAMS.p.toString(2).length / 8)
}

/** Concatenate two Uint8Arrays. */
function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const result = new Uint8Array(a.length + b.length)
  result.set(a, 0)
  result.set(b, a.length)
  return result
}

/** Serialize (c1, c2) into a single byte array: c1_bytes || c2_bytes. */
function serializeCiphertext(c1: bigint, c2: bigint): Uint8Array {
  const len = elgamalByteLen()
  return concatBytes(bigintToFixedBytes(c1, len), bigintToFixedBytes(c2, len))
}

/* ------------------------------------------------------------------ */
/*  Key generation                                                     */
/* ------------------------------------------------------------------ */

/**
 * Generate keys for the Encrypt-then-Sign scheme.
 * - ElGamal keys for encryption
 * - RSA keys for signing
 */
export function ccaPkcKeygen(rsaBits: number): CcaPkcKeyBundle {
  const eg = elgamalKeygen()
  const rsa = rsaKeygen(rsaBits)

  return {
    encKeys: { sk: eg.sk, pk: eg.pk },
    sigKeys: {
      sk: { N: rsa.N, d: rsa.d },
      pk: { N: rsa.N, e: rsa.e },
    },
  }
}

/* ------------------------------------------------------------------ */
/*  Encrypt-then-Sign                                                  */
/* ------------------------------------------------------------------ */

/**
 * CCA-secure encryption via Encrypt-then-Sign.
 *
 * 1. Convert message bytes to bigint m
 * 2. ElGamal encrypt m -> (c1, c2)
 * 3. Serialize (c1, c2) to bytes
 * 4. Sign the serialized ciphertext with RSA
 * 5. Return { c1, c2, sigma }
 */
export function ccaPkcEncrypt(
  pkEnc: ElGamalKeyPair['pk'],
  skSign: RSAPrivateKey,
  message: Uint8Array,
): CcaPkcCiphertext {
  const m = bytesToBigint(message)
  if (m < 1n) {
    throw new Error('Message must encode to a positive integer')
  }
  const { c1, c2 } = elgamalEncrypt(pkEnc, m)
  const ctBytes = serializeCiphertext(c1, c2)
  const sigma = sign(skSign, ctBytes)
  return { c1, c2, sigma }
}

/**
 * CCA-secure decryption via Verify-then-Decrypt.
 *
 * 1. Serialize (c1, c2) to bytes
 * 2. Verify signature
 * 3. If invalid -> return null
 * 4. If valid -> ElGamal decrypt
 * 5. Return decrypted message as string
 */
export function ccaPkcDecrypt(
  skEnc: bigint,
  pkEnc: ElGamalKeyPair['pk'],
  pkVerify: RSAPublicKey,
  c1: bigint,
  c2: bigint,
  sigma: bigint,
): string | null {
  const ctBytes = serializeCiphertext(c1, c2)
  const valid = verify(pkVerify, ctBytes, sigma)
  if (!valid) {
    return null
  }
  const m = elgamalDecrypt(skEnc, pkEnc, c1, c2)
  // Convert bigint back to bytes then to string
  const byteLen = Math.max(1, Math.ceil(m.toString(16).length / 2))
  const mBytes = bigintToBytes(m, byteLen)
  return new TextDecoder().decode(mBytes)
}

/* ------------------------------------------------------------------ */
/*  Malleability attack — blocked by signature                         */
/* ------------------------------------------------------------------ */

/**
 * Demonstrate that Encrypt-then-Sign blocks the ElGamal malleability attack.
 *
 * 1. Encrypt-then-sign message m
 * 2. Modify ciphertext: (c1, 2*c2 mod p)
 * 3. Try to decrypt with modified ciphertext + original sigma
 * 4. Signature verification fails -> null returned
 */
export function ccaMalleabilityBlocked(
  encKeys: CcaPkcEncKeys,
  sigKeys: CcaPkcSigKeys,
  m: bigint,
): CcaMalleabilityBlockedResult {
  const { p } = encKeys.pk
  // Encode m as bytes
  const mByteLen = Math.max(1, Math.ceil(m.toString(16).length / 2))
  const mBytes = bigintToBytes(m, mByteLen)

  // Encrypt-then-sign
  const { c1, c2, sigma } = ccaPkcEncrypt(encKeys.pk, sigKeys.sk, mBytes)

  // Apply malleability: multiply c2 by 2
  const modifiedC2 = (2n * c2) % p

  // Try to decrypt the modified ciphertext with original sigma
  const decryptResult = ccaPkcDecrypt(
    encKeys.sk, encKeys.pk, sigKeys.pk,
    c1, modifiedC2, sigma,
  )

  // Check if the modified ciphertext passes signature verification
  const modifiedCtBytes = serializeCiphertext(c1, modifiedC2)
  const signatureValid = verify(sigKeys.pk, modifiedCtBytes, sigma)

  return {
    originalM: m,
    modifiedC2,
    signatureValid,
    decryptResult: decryptResult as null,
  }
}

/* ------------------------------------------------------------------ */
/*  Plain ElGamal malleability (no signature, attack succeeds)         */
/* ------------------------------------------------------------------ */

/**
 * Same malleability attack on plain ElGamal (no signature).
 * Decryption succeeds and returns 2m.
 */
export function plainElGamalMalleability(
  encKeys: CcaPkcEncKeys,
  m: bigint,
): PlainElGamalMalleabilityResult {
  const { p } = encKeys.pk
  const { c1, c2 } = elgamalEncrypt(encKeys.pk, m)
  const modifiedC2 = (2n * c2) % p
  const decryptedModified = elgamalDecrypt(encKeys.sk, encKeys.pk, c1, modifiedC2)
  const expected = (2n * m) % p
  return {
    originalM: m,
    decryptedModified,
    attackSucceeded: decryptedModified === expected,
  }
}

/* ------------------------------------------------------------------ */
/*  Re-exports for convenience                                         */
/* ------------------------------------------------------------------ */

export type { ElGamalKeyPair, ElGamalCiphertext, RSAPublicKey, RSAPrivateKey, RSAKeyPair }
