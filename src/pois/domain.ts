export type PrimitiveKind =
  | 'OWF'
  | 'PRG'
  | 'PRF'
  | 'PRP'
  | 'MAC'
  | 'CRHF'
  | 'HMAC'

export type FoundationKind = 'AES_128' | 'DLP'

export const PRIMITIVE_ORDER: PrimitiveKind[] = [
  'OWF',
  'PRG',
  'PRF',
  'PRP',
  'MAC',
  'CRHF',
  'HMAC',
]

export const PrimitiveMeta: Record<
  PrimitiveKind,
  { label: string; duePa: number; description: string }
> = {
  OWF: {
    label: 'OWF',
    duePa: 1,
    description: 'One-Way Function',
  },
  PRG: {
    label: 'PRG',
    duePa: 1,
    description: 'Pseudorandom Generator',
  },
  PRF: {
    label: 'PRF',
    duePa: 2,
    description: 'Pseudorandom Function',
  },
  PRP: {
    label: 'PRP',
    duePa: 2,
    description: 'Pseudorandom Permutation',
  },
  MAC: {
    label: 'MAC',
    duePa: 5,
    description: 'Message Authentication Code',
  },
  CRHF: {
    label: 'CRHF',
    duePa: 8,
    description: 'Collision-Resistant Hash Function',
  },
  HMAC: {
    label: 'HMAC',
    duePa: 10,
    description: 'Hash-based MAC',
  },
}

export const FoundationMeta: Record<
  FoundationKind,
  {
    label: string
    // Toy mapping for leg-1 start node in the clique graph.
    startKind: PrimitiveKind
    duePa: number
  }
> = {
  AES_128: {
    label: 'AES-128 (PRP)',
    startKind: 'PRP',
    duePa: 2,
  },
  DLP: {
    label: 'DLP (gx mod p)',
    startKind: 'OWF',
    duePa: 1,
  },
}

