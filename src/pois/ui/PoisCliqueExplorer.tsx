import { useMemo, useState } from 'react'
import type { PrimitiveKind, FoundationKind } from '../domain'
import { FoundationMeta, PrimitiveMeta, PRIMITIVE_ORDER } from '../domain'
import { buildLeg1 } from '../engine/leg1'
import { reduceLeg2 } from '../engine/leg2'
import type { TraceStep } from '../types'
import { abbreviateHex, bytesToHex } from '../utils/hex'
import './poisCliqueExplorer.css'

function TraceSteps({ steps }: { steps: TraceStep[] }) {
  return (
    <div className="traceList">
      {steps.map((s) => {
        const notImpl = s.status.kind === 'not_implemented'
        return (
          <div key={s.id} className={`traceStep ${notImpl ? 'traceStepNotImpl' : ''}`}>
            <div className="traceHeader">
              <div className="traceFn">{s.functionApplied}</div>
              {s.status.kind === 'not_implemented' ? (
                <div className="traceBadge">Not implemented (due: PA#{s.status.duePa})</div>
              ) : (
                <div className="traceBadge traceBadgeOk">Implemented</div>
              )}
            </div>

            {s.inputHex !== undefined && (
              <div className="traceKV">
                <span className="traceKey">in</span>
                <span className="traceVal mono" title={s.inputHex}>
                  {abbreviateHex(s.inputHex)}
                </span>
              </div>
            )}

            {s.outputHex !== undefined && (
              <div className="traceKV">
                <span className="traceKey">out</span>
                <span className="traceVal mono" title={s.outputHex}>
                  {abbreviateHex(s.outputHex)}
                </span>
              </div>
            )}

            {s.shortNote ? <div className="traceNote">{s.shortNote}</div> : null}
          </div>
        )
      })}
    </div>
  )
}

function LabeledSelect(props: {
  label: string
  value: PrimitiveKind
  onChange: (v: PrimitiveKind) => void
}) {
  return (
    <label className="field">
      <div className="fieldLabel">{props.label}</div>
      <select
        className="select"
        value={props.value}
        onChange={(e) => props.onChange(e.target.value as PrimitiveKind)}
      >
        {PRIMITIVE_ORDER.map((k) => (
          <option key={k} value={k}>
            {PrimitiveMeta[k].label}
          </option>
        ))}
      </select>
    </label>
  )
}

function LabeledInput(props: {
  label: string
  value: string
  onChange: (v: string) => void
  placeholder?: string
}) {
  return (
    <label className="field">
      <div className="fieldLabel">{props.label}</div>
      <input
        className="input"
        value={props.value}
        placeholder={props.placeholder}
        onChange={(e) => props.onChange(e.target.value)}
      />
    </label>
  )
}

function ProofSummaryPanel(props: {
  foundationKind: FoundationKind
  leftKind: PrimitiveKind
  rightKind: PrimitiveKind
  leg1Trace: TraceStep[]
  leg2Plan: { theorem: string; duePa: number }[] | null
  leg2Mode: 'forward' | 'backward'
  leg2Error?: string
}) {
  return (
    <details className="proofPanel" open>
      <summary className="proofSummary">
        Reduction proof summary: {props.leftKind} {'->'} {props.rightKind}
      </summary>

      <div className="proofBody">
        <div className="proofLine">
          <span className="proofDim">Foundation:</span> {FoundationMeta[props.foundationKind].label}
        </div>

        <div className="proofSectionTitle">
          Leg 1 (Foundation {'->'} {props.leftKind})
        </div>
        {props.leg1Trace.map((t) => {
          const due = t.status.kind === 'not_implemented' ? t.status.duePa : undefined
          return (
            <div key={t.id} className="proofStep">
              <div className="proofStepMain">{t.functionApplied}</div>
              <div className="proofStepSub">
                Advantage: eps&apos; {'>='} eps/q (standard reduction loss).
              </div>
              {due !== undefined ? (
                <div className="proofStepSub">Implements in: PA#{due}</div>
              ) : null}
            </div>
          )
        })}

        <div className="proofSectionTitle">
          Leg 2 ({props.leg2Mode} reductions: {props.leftKind} {'->'} {props.rightKind})
        </div>
        {props.leg2Error ? (
          <div className="proofError">{props.leg2Error}</div>
        ) : props.leg2Plan && props.leg2Plan.length > 0 ? (
          props.leg2Plan.map((p, idx) => (
            <div key={`${p.theorem}:${idx}`} className="proofStep">
              <div className="proofStepMain">{p.theorem}</div>
              <div className="proofStepSub">
                Advantage: eps&apos; {'>='} eps/q (standard reduction loss).
              </div>
              <div className="proofStepSub">Implements in: PA#{p.duePa}</div>
            </div>
          ))
        ) : (
          <div className="proofDim">No directed reduction chain available.</div>
        )}
      </div>
    </details>
  )
}

export default function PoisCliqueExplorer() {
  const [foundationKind, setFoundationKind] = useState<FoundationKind>('AES_128')
  // Forward mode: user’s A (left) reduces to B (right).
  // Backward mode: columns swap visually and we use reverse reductions for leg-2.
  const [isBackwardMode, setIsBackwardMode] = useState(false)

  const [primitiveA, setPrimitiveA] = useState<PrimitiveKind>('PRG')
  const [primitiveB, setPrimitiveB] = useState<PrimitiveKind>('PRF')

  const [keySeedHex, setKeySeedHex] = useState('a3f2b4c1d0e9')
  const [queryStr, setQueryStr] = useState('1011')

  const leftKind = isBackwardMode ? primitiveB : primitiveA
  const rightKind = isBackwardMode ? primitiveA : primitiveB

  const leg1 = useMemo(
    () => buildLeg1(foundationKind, keySeedHex, leftKind),
    [foundationKind, keySeedHex, leftKind]
  )

  const leg2 = useMemo(() => {
    return reduceLeg2({
      source: { oracle: leg1.oracle, kind: leftKind },
      targetKind: rightKind,
      query: queryStr,
      mode: isBackwardMode ? 'backward' : 'forward',
      foundationKind,
    })
  }, [leg1, leftKind, rightKind, queryStr, isBackwardMode, foundationKind])

  const leg2Ok = leg2.ok
  const leg2Trace = leg2Ok ? leg2.trace : []
  const leg2Plan = leg2Ok
    ? leg2.plan.map((p) => ({ theorem: p.theorem, duePa: p.duePa }))
    : null

  return (
    <div className="poisApp">
      <div className="topBar">
        <div className="topBarLeft">
          <div className="topTitle">
            <div className="topTitleMain">Minicrypt Clique Web Explorer</div>
            <div className="topTitleSub">CS8.401 Principles of Information Security Spring 2026 • PA#0</div>
          </div>
        </div>

        <div className="topBarRight">
          <label className="field inline">
            <div className="fieldLabel">Foundation</div>
            <select
              className="select"
              value={foundationKind}
              onChange={(e) => setFoundationKind(e.target.value as FoundationKind)}
            >
              <option value="AES_128">{FoundationMeta.AES_128.label}</option>
              <option value="DLP">{FoundationMeta.DLP.label}</option>
            </select>
          </label>

          <div className="modeToggle">
            <button
              className={`modeBtn ${!isBackwardMode ? 'modeBtnActive' : ''}`}
              onClick={() => setIsBackwardMode(false)}
              type="button"
            >
              Forward (A {'->'} B)
            </button>
            <button
              className={`modeBtn ${isBackwardMode ? 'modeBtnActive' : ''}`}
              onClick={() => setIsBackwardMode(true)}
              type="button"
            >
              Backward (B {'->'} A)
            </button>
          </div>

          <details className="infoMenu">
            <summary className="infoSummary">
              Project info
              <span className="infoCaret" aria-hidden="true">
                ▾
              </span>
            </summary>
            <div className="infoBody">
              <div className="infoRow">
                <div className="infoLabel">Course</div>
                <div className="infoValue">CS8.401 Principles of Information Security Spring 2026</div>
              </div>

              <div className="infoRow">
                <div className="infoLabel">Teammates</div>
                <ul className="infoList">
                  <li className="infoChip">Manasa Kalaimalai</li>
                  <li className="infoChip">Kevin Thakkar</li>
                  <li className="infoChip">Sparsh</li>
                  <li className="infoChip">Neel Amrutia</li>
                  <li className="infoChip">Abhinav</li>
                </ul>
              </div>
            </div>
          </details>
        </div>
      </div>

      <div className="mainArea">
        <div className="panel">
          <div className="panelTitle">Build panel (Leg 1: Foundation {'->'} Source A)</div>

          <LabeledSelect
            label="Source primitive A"
            value={leftKind}
            onChange={(v) => {
              if (isBackwardMode) setPrimitiveB(v)
              else setPrimitiveA(v)
            }}
          />

          <LabeledInput
            label="Input seed / key (hex)"
            value={keySeedHex}
            placeholder="e.g. a3f2b4c1d0e9"
            onChange={setKeySeedHex}
          />

          <div className="traceBlockHeader">
            Trace: Foundation {'->'} {leftKind}
          </div>
          <TraceSteps steps={leg1.trace} />
        </div>

        <div className="panel">
          <div className="panelTitle">Reduce panel (Leg 2: Source A {'->'} Target B)</div>

          <LabeledSelect
            label="Target primitive B"
            value={rightKind}
            onChange={(v) => {
              if (isBackwardMode) setPrimitiveA(v)
              else setPrimitiveB(v)
            }}
          />

          <LabeledInput
            label="Message / query"
            value={queryStr}
            placeholder="hex or bitstring (e.g. 1011)"
            onChange={setQueryStr}
          />

          <div className="traceBlockHeader">
            Trace: {leftKind} {'->'} {rightKind}
          </div>

          {leg2.ok ? (
            <>
              <TraceSteps steps={leg2Trace} />
              <div className="outputBox">
                Output ({rightKind}):{' '}
                <span className="mono">{bytesToHex(leg2.output)}</span>
              </div>
            </>
          ) : (
            <div className="leg2ErrorWrap">
              <div className="leg2Error">{leg2.error}</div>
              <div className="leg2Suggestion">{leg2.suggestion}</div>
              <div className="outputBox outputBoxNotImpl">
                Output placeholder (due: PA#{PrimitiveMeta[rightKind].duePa})
              </div>
              <TraceSteps
                steps={[
                  {
                    id: 'leg2:unsupported',
                    functionApplied: 'Reduction path unavailable in this direction',
                    inputHex: undefined,
                    outputHex: undefined,
                    status: { kind: 'not_implemented', duePa: PrimitiveMeta[rightKind].duePa },
                    shortNote: `Not implemented yet (due: PA#${PrimitiveMeta[rightKind].duePa})`,
                  },
                ]}
              />
            </div>
          )}
        </div>
      </div>

      <ProofSummaryPanel
        foundationKind={foundationKind}
        leftKind={leftKind}
        rightKind={rightKind}
        leg1Trace={leg1.trace}
        leg2Plan={leg2Ok && leg2Plan ? leg2Plan : null}
        leg2Mode={isBackwardMode ? 'backward' : 'forward'}
        leg2Error={leg2Ok ? undefined : leg2.error}
      />
    </div>
  )
}

