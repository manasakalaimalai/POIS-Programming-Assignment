export type ByteArray = Uint8Array

export type ReductionMode = 'forward' | 'backward'

export type StepStatus =
  | { kind: 'implemented' }
  | { kind: 'not_implemented'; duePa: number }

export type TraceStep = {
  id: string
  functionApplied: string
  inputHex?: string
  outputHex?: string
  status: StepStatus
  shortNote?: string
}

// A black-box oracle passed from Column 1 to Column 2.
export interface PrimitiveOracle {
  evaluate: (input: ByteArray) => ByteArray
}

export type PrimitiveInstanceBuild = {
  oracle: PrimitiveOracle
  trace: TraceStep[]
  // Internal (leg-1 only): lets us display intermediate “material” bytes deterministically.
  material?: ByteArray
}

export type CliqueRouteStep = {
  fromKind: import('./domain').PrimitiveKind
  toKind: import('./domain').PrimitiveKind
  theorem: string
  duePa: number
  mode: ReductionMode
  // Toy-only: how leg-1 derives “instance material” bytes from the previous material.
  materialSalt: string
  // Toy-only: how leg-2 derives the input it feeds to the black-box oracle for this edge.
  reductionInputSalt: string
}

