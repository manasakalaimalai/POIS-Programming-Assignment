import type { ByteArray, PrimitiveOracle } from './types'

function clampByte(n: number): number {
  return ((n % 256) + 256) % 256
}

export function toyTransform(material: ByteArray, salt: string, outLen = 16): ByteArray {
  const saltBytes = new TextEncoder().encode(salt)
  if (material.length === 0) {
    // Deterministic for empty input.
    const out = new Uint8Array(outLen)
    for (let i = 0; i < outLen; i++) out[i] = saltBytes[i % saltBytes.length] ?? 0
    return out
  }

  const out = new Uint8Array(outLen)
  for (let i = 0; i < outLen; i++) {
    const m = material[i % material.length]
    const s = saltBytes[i % saltBytes.length]
    out[i] = clampByte(m ^ s ^ (i * 31))
  }
  return out
}

export function makeToyOracle(kind: string, material: ByteArray): PrimitiveOracle {
  const mat = material.slice()
  const kindBytes = new TextEncoder().encode(kind)

  return {
    evaluate: (input: ByteArray) => {
      const inBytes = input.length === 0 ? new Uint8Array([0]) : input
      const outLen = 16
      const out = new Uint8Array(outLen)
      for (let i = 0; i < outLen; i++) {
        const k = kindBytes[i % kindBytes.length] ?? 0
        const m = mat[i % Math.max(1, mat.length)] ?? 0
        const x = inBytes[i % inBytes.length] ?? 0
        out[i] = clampByte((m + 17 * k + 29 * x + i * 13) ^ (m >> 1))
      }
      return out
    },
  }
}

export function seedToMaterial(seed: ByteArray): ByteArray {
  // Keep it deterministic and non-crypto; later PA#1/PA#2 will replace this.
  const out = new Uint8Array(16)
  if (seed.length === 0) return out
  for (let i = 0; i < out.length; i++) out[i] = (seed[i % seed.length] + i * 7) & 0xff
  return out
}

export function makeToyReductionInput(query: ByteArray, salt: string): ByteArray {
  // Reduction engines only need some deterministic bytes to “query” the oracle.
  return toyTransform(query, `reduction-input:${salt}`, 16)
}

