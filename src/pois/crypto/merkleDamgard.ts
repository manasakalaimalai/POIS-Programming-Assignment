/**
 * PA#7 — Merkle-Damgard Transform
 *
 * Generic MD framework accepting any compression function,
 * MD-strengthening padding, toy XOR compression for testing,
 * and collision propagation demo.
 */

// ── MD-strengthening padding ────────────────────────────────────────────────

/**
 * Append 0x80, then zero bytes, then 8-byte big-endian bit-length.
 * Result length is a multiple of blockSize.
 */
export function mdPad(message: Uint8Array, blockSize: number): Uint8Array {
  const msgLen = message.length
  const bitLen = msgLen * 8

  // We need: msgLen + 1 (0x80) + zeroes + 8 (length) ≡ 0 (mod blockSize)
  // So: padding bytes after 0x80 (excluding length) = blockSize - ((msgLen + 1 + 8) % blockSize)
  // which may be blockSize itself if already aligned → mod it again
  let zeroBytes = blockSize - ((msgLen + 1 + 8) % blockSize)
  if (zeroBytes === blockSize) zeroBytes = 0

  const totalLen = msgLen + 1 + zeroBytes + 8
  const padded = new Uint8Array(totalLen)
  padded.set(message, 0)
  padded[msgLen] = 0x80

  // 8-byte big-endian bit length
  // JS bitwise ops are 32-bit, so handle upper and lower 32 bits separately
  const hi = Math.floor(bitLen / 0x100000000)
  const lo = bitLen >>> 0
  const lenOffset = totalLen - 8
  padded[lenOffset]     = (hi >>> 24) & 0xff
  padded[lenOffset + 1] = (hi >>> 16) & 0xff
  padded[lenOffset + 2] = (hi >>> 8)  & 0xff
  padded[lenOffset + 3] =  hi         & 0xff
  padded[lenOffset + 4] = (lo >>> 24) & 0xff
  padded[lenOffset + 5] = (lo >>> 16) & 0xff
  padded[lenOffset + 6] = (lo >>> 8)  & 0xff
  padded[lenOffset + 7] =  lo         & 0xff

  return padded
}

// ── Toy XOR compression ─────────────────────────────────────────────────────

/**
 * Block size = 8, output = 4 bytes.
 * toyCompress(cv, block) = cv XOR block[0..3] XOR block[4..7]
 */
export function toyCompress(chaining: Uint8Array, block: Uint8Array): Uint8Array {
  const out = new Uint8Array(4)
  for (let i = 0; i < 4; i++) {
    out[i] = chaining[i] ^ block[i] ^ block[i + 4]
  }
  return out
}

// ── Merkle-Damgard hash ─────────────────────────────────────────────────────

export type CompressFn = (chainingValue: Uint8Array, block: Uint8Array) => Uint8Array

export function merkleDamgardHash(
  message: Uint8Array,
  compressFn: CompressFn,
  iv: Uint8Array,
  blockSize: number,
): Uint8Array {
  const padded = mdPad(message, blockSize)
  let z = iv
  for (let i = 0; i < padded.length; i += blockSize) {
    const block = padded.slice(i, i + blockSize)
    z = compressFn(z, block)
  }
  return z
}

// ── With trace (for UI) ─────────────────────────────────────────────────────

export interface MdTrace {
  blocks: Uint8Array[]
  chainingValues: Uint8Array[]   // z_0 (IV), z_1, z_2, …, z_final
  digest: Uint8Array
  paddedMessage: Uint8Array
}

export function merkleDamgardWithTrace(
  message: Uint8Array,
  compressFn: CompressFn,
  iv: Uint8Array,
  blockSize: number,
): MdTrace {
  const padded = mdPad(message, blockSize)
  const blocks: Uint8Array[] = []
  const chainingValues: Uint8Array[] = [iv]

  let z = iv
  for (let i = 0; i < padded.length; i += blockSize) {
    const block = padded.slice(i, i + blockSize)
    blocks.push(block)
    z = compressFn(z, block)
    chainingValues.push(z)
  }

  return { blocks, chainingValues, digest: z, paddedMessage: padded }
}

// ── Collision propagation demo ──────────────────────────────────────────────

/**
 * Two messages that collide under the toy MD hash.
 * Since toyCompress XORs chaining with both halves of the block,
 * swapping the two 4-byte halves of any block produces the same output.
 */
export const COLLISION_MSG_A = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
export const COLLISION_MSG_B = new Uint8Array([0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04])

export const TOY_IV = new Uint8Array([0x00, 0x00, 0x00, 0x00])
export const TOY_BLOCK_SIZE = 8

export function collisionDemo() {
  const traceA = merkleDamgardWithTrace(COLLISION_MSG_A, toyCompress, TOY_IV, TOY_BLOCK_SIZE)
  const traceB = merkleDamgardWithTrace(COLLISION_MSG_B, toyCompress, TOY_IV, TOY_BLOCK_SIZE)
  return { traceA, traceB }
}
