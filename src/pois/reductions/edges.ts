import type { CliqueRouteStep, ReductionMode } from '../types'
import { PrimitiveMeta, type PrimitiveKind } from '../domain'

function edge(
  mode: ReductionMode,
  fromKind: PrimitiveKind,
  toKind: PrimitiveKind,
  theorem: string,
  materialSalt: string,
  reductionInputSalt: string
): CliqueRouteStep {
  return {
    fromKind,
    toKind,
    theorem,
    // For UI placeholders, tie “due PA” to the implementation required for the target primitive.
    duePa: PrimitiveMeta[toKind].duePa,
    mode,
    materialSalt,
    reductionInputSalt,
  }
}

// Edges in the “Forward (A -> B)” direction (the reduction chain in the clique).
export const FORWARD_EDGES: CliqueRouteStep[] = [
  edge(
    'forward',
    'OWF',
    'PRG',
    'HILL hard-core-bit construction',
    'HILL',
    'HILL'
  ),
  edge(
    'forward',
    'PRG',
    'PRF',
    'GGM tree construction',
    'GGM',
    'GGM'
  ),
  edge(
    'forward',
    'PRF',
    'PRP',
    'Luby-Rackoff 3-round Feistel',
    'LUBY-RACKOFF',
    'LUBY-RACKOFF'
  ),
  edge(
    'forward',
    'PRF',
    'MAC',
    'Mack(m) = Fk(m)',
    'MACK',
    'MACK'
  ),
  edge(
    'forward',
    'PRP',
    'MAC',
    'PRP/PRF switching lemma, then MAC',
    'PRP->MAC',
    'PRP->MAC'
  ),
  edge(
    'forward',
    'CRHF',
    'HMAC',
    'HMAC construction (via PRF-secure compression)',
    'CRHF->HMAC',
    'CRHF->HMAC'
  ),
  edge(
    'forward',
    'HMAC',
    'MAC',
    'Direct: HMAC is a MAC',
    'HMAC->MAC',
    'HMAC->MAC'
  ),
]

// Edges in the “Backward (B -> A)” direction for adjacent clique pairs.
export const BACKWARD_EDGES: CliqueRouteStep[] = [
  edge(
    'backward',
    'PRG',
    'OWF',
    'Any PRG is immediately a OWF',
    'PRG->OWF',
    'PRG->OWF'
  ),
  edge(
    'backward',
    'PRF',
    'PRG',
    'Define G(s)=Fs(0^n)||Fs(1^n)',
    'PRF->PRG',
    'PRF->PRG'
  ),
  edge(
    'backward',
    'PRP',
    'PRF',
    'PRP indistinguishable from PRF (switching lemma)',
    'PRP->PRF',
    'PRP->PRF'
  ),
  edge(
    'backward',
    'MAC',
    'PRF',
    'EUF-CMA MAC => PRF oracle (distinguishing game)',
    'MAC->PRF',
    'MAC->PRF'
  ),
  edge(
    'backward',
    'MAC',
    'PRP',
    'MAC => PRF then PRF => PRP (Luby-Rackoff)',
    'MAC->PRP',
    'MAC->PRP'
  ),
  edge(
    'backward',
    'HMAC',
    'CRHF',
    'HMAC => CRHF (keyed compression used in Merkle-Damgard)',
    'HMAC->CRHF',
    'HMAC->CRHF'
  ),
  edge(
    'backward',
    'MAC',
    'HMAC',
    'MAC => HMAC (treat MAC as inner compression step)',
    'MAC->HMAC',
    'MAC->HMAC'
  ),
]

export const ALL_EDGES_FOR_LEG1: CliqueRouteStep[] = [...FORWARD_EDGES, ...BACKWARD_EDGES]

