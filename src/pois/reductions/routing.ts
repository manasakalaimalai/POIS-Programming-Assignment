import type { CliqueRouteStep, ReductionMode } from '../types'
import type { FoundationKind, PrimitiveKind } from '../domain'
import { BACKWARD_EDGES, FORWARD_EDGES, ALL_EDGES_FOR_LEG1 } from './edges'

export type ReductionResult =
  | { ok: true; steps: CliqueRouteStep[] }
  | { ok: false; error: string; suggestion?: string }

function bfsRoute(fromKind: PrimitiveKind, toKind: PrimitiveKind, edges: CliqueRouteStep[]) {
  if (fromKind === toKind) return [] as CliqueRouteStep[]

  const outgoing = new Map<PrimitiveKind, CliqueRouteStep[]>()
  for (const e of edges) {
    const list = outgoing.get(e.fromKind) ?? []
    list.push(e)
    outgoing.set(e.fromKind, list)
  }

  const queue: PrimitiveKind[] = [fromKind]
  const visited = new Set<PrimitiveKind>([fromKind])

  const prev = new Map<PrimitiveKind, { node: PrimitiveKind; edge: CliqueRouteStep }>()

  while (queue.length > 0) {
    const cur = queue.shift()!
    const nextEdges = outgoing.get(cur) ?? []
    for (const e of nextEdges) {
      const nxt = e.toKind
      if (visited.has(nxt)) continue
      visited.add(nxt)
      prev.set(nxt, { node: cur, edge: e })
      if (nxt === toKind) {
        // Reconstruct route.
        const rev: CliqueRouteStep[] = []
        let x: PrimitiveKind = toKind
        while (x !== fromKind) {
          const p = prev.get(x)
          if (!p) break
          rev.push(p.edge)
          x = p.node
        }
        return rev.reverse()
      }
      queue.push(nxt)
    }
  }

  return null
}

// Used for PA#0: Column 2 reductions must obey directionality.
export function reduce(
  fromKind: PrimitiveKind,
  toKind: PrimitiveKind,
  _foundation: FoundationKind,
  mode: ReductionMode
): ReductionResult {
  const edges = mode === 'forward' ? FORWARD_EDGES : BACKWARD_EDGES
  const route = bfsRoute(fromKind, toKind, edges)
  if (!route) {
    return {
      ok: false,
      error: `No directed reduction path exists from ${fromKind} to ${toKind} in this direction.`,
      suggestion: 'Try switching the bidirectional toggle (swapping A/B and using the reverse direction reductions).',
    }
  }
  return { ok: true, steps: route }
}

// Used for PA#0 leg-1: the foundation->A chain is under-the-hood, so we allow both directions.
export function findLeg1Route(fromKind: PrimitiveKind, toKind: PrimitiveKind): CliqueRouteStep[] | null {
  return bfsRoute(fromKind, toKind, ALL_EDGES_FOR_LEG1)
}


