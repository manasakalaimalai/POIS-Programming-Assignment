import type { ByteArray } from '../types'

export function bytesToHex(bytes: ByteArray): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

export function hexToBytes(hex: string): ByteArray {
  const normalized = hex.replace(/^0x/i, '').trim()
  if (normalized.length === 0) return new Uint8Array()
  if (normalized.length % 2 !== 0) {
    // Be forgiving: treat odd-length as leading-nibble.
    return hexToBytes('0' + normalized)
  }
  if (!/^[0-9a-fA-F]+$/.test(normalized)) {
    throw new Error('Invalid hex string')
  }
  const out = new Uint8Array(normalized.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(normalized.slice(2 * i, 2 * i + 2), 16)
  }
  return out
}

export function parseFlexibleInputToBytes(s: string): ByteArray {
  const raw = s.trim()
  if (raw.length === 0) return new Uint8Array()

  if (/^0x[0-9a-fA-F]+$/i.test(raw) || /^[0-9a-fA-F]+$/.test(raw)) {
    try {
      return hexToBytes(raw)
    } catch {
      // fallthrough
    }
  }

  if (/^[01]+$/.test(raw)) {
    // Interpret as a bitstring; pack MSB-first within each byte.
    const bitLen = raw.length
    const byteLen = Math.ceil(bitLen / 8)
    const out = new Uint8Array(byteLen)
    for (let i = 0; i < bitLen; i++) {
      if (raw[bitLen - 1 - i] === '1') {
        out[Math.floor(i / 8)] |= 1 << (i % 8)
      }
    }
    return out
  }

  // Fallback: treat as UTF-8 text (non-crypto).
  return new TextEncoder().encode(raw)
}

export function abbreviateHex(hex: string, max = 24): string {
  const clean = hex.trim()
  if (clean.length <= max) return clean
  return `${clean.slice(0, Math.max(0, Math.floor(max / 2)))}…${clean.slice(-Math.floor(max / 2))}`
}

