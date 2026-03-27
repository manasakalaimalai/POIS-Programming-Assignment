/**
 * PA#13 — Miller-Rabin Primality Testing Demo
 *
 * Left panel:  Primality tester with detailed per-round traces
 * Right panel: Prime generation with PNT comparison
 * Bottom:      Proof panel with theory explanation
 */

import { useState } from 'react'
import {
  millerRabin,
  fermatTest,
  genPrime,
  type MillerRabinResult,
  type GenPrimeResult,
} from '../crypto/millerRabin'
import './poisCliqueExplorer.css'

/* ------------------------------------------------------------------ */
/*  Pre-loaded examples                                               */
/* ------------------------------------------------------------------ */

const EXAMPLES: { label: string; value: string }[] = [
  { label: '561 (Carmichael)', value: '561' },
  { label: '104729 (prime)', value: '104729' },
  { label: '1000000007 (prime)', value: '1000000007' },
  { label: '123456789 (composite)', value: '123456789' },
]

/* ------------------------------------------------------------------ */
/*  Helper: format BigInt for display (abbreviate if very long)       */
/* ------------------------------------------------------------------ */

function fmtBig(n: bigint, max = 60): string {
  const s = n.toString()
  if (s.length <= max) return s
  return s.slice(0, 25) + '...' + s.slice(-25) + ` (${s.length} digits)`
}

/* ------------------------------------------------------------------ */
/*  Component                                                         */
/* ------------------------------------------------------------------ */

export default function Pa13MillerRabinDemo() {
  /* -- Primality tester state -- */
  const [numberInput, setNumberInput] = useState('561')
  const [rounds, setRounds] = useState(10)
  const [mrResult, setMrResult] = useState<MillerRabinResult | null>(null)
  const [fermatInfo, setFermatInfo] = useState<{
    isCarmichael: boolean
    witnesses: { a: bigint; passed: boolean }[]
  } | null>(null)
  const [testError, setTestError] = useState('')

  /* -- Prime generation state -- */
  const [genBits, setGenBits] = useState(64)
  const [genResult, setGenResult] = useState<GenPrimeResult | null>(null)
  const [genTime, setGenTime] = useState<number | null>(null)
  const [genRunning, setGenRunning] = useState(false)

  /* ---- Primality test handler ---- */
  function handleTest() {
    setTestError('')
    setMrResult(null)
    setFermatInfo(null)

    let n: bigint
    try {
      n = BigInt(numberInput.trim())
    } catch {
      setTestError('Invalid number. Enter a positive integer.')
      return
    }

    if (n < 3n || n % 2n === 0n) {
      setTestError('Enter an odd integer greater than 2.')
      return
    }

    const result = millerRabin(n, rounds)
    setMrResult(result)

    // If this is 561, also run Fermat test to show it is deceptive
    if (n === 561n) {
      const witnesses = [2n, 3n, 5n, 7n, 11n].map((a) => ({
        a,
        passed: fermatTest(561n, a),
      }))
      const allPass = witnesses.every((w) => w.passed)
      setFermatInfo({ isCarmichael: allPass, witnesses })
    }
  }

  /* ---- Prime generation handler ---- */
  function handleGenerate() {
    setGenRunning(true)
    setGenResult(null)
    setGenTime(null)
    // Use setTimeout so the UI can show "running" state
    setTimeout(() => {
      const t0 = performance.now()
      const result = genPrime(genBits)
      const elapsed = performance.now() - t0
      setGenResult(result)
      setGenTime(elapsed)
      setGenRunning(false)
    }, 10)
  }

  /* ---- Expected candidates from PNT ---- */
  const expectedCandidates = (0.693 * genBits).toFixed(1)

  return (
    <div className="poisApp">
      {/* Header */}
      <div className="topBar">
        <div className="topTitle">
          <span className="topTitleMain">PA#13 — Miller-Rabin Primality Testing</span>
          <span className="topTitleSub">
            Probabilistic primality, Carmichael numbers, prime generation
          </span>
        </div>
      </div>

      <div className="mainArea">
        {/* ============ LEFT PANEL: Primality Tester ============ */}
        <div className="panel">
          <div className="panelTitle">Primality Tester</div>

          {/* Number input */}
          <label className="field">
            <div className="fieldLabel">Number to test (supports large integers)</div>
            <input
              className="input"
              type="text"
              value={numberInput}
              onChange={(e) => setNumberInput(e.target.value)}
              placeholder="Enter an odd integer > 2"
            />
          </label>

          {/* Rounds slider */}
          <label className="field">
            <div className="fieldLabel">Rounds k = {rounds} (error &le; 4^(-{rounds}))</div>
            <input
              type="range"
              min={1}
              max={40}
              value={rounds}
              onChange={(e) => setRounds(Number(e.target.value))}
              style={{ width: '100%' }}
            />
          </label>

          {/* Example buttons */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 12 }}>
            {EXAMPLES.map((ex) => (
              <button
                key={ex.value}
                className="input"
                style={{
                  width: 'auto',
                  cursor: 'pointer',
                  fontSize: 12,
                  padding: '6px 10px',
                  background: 'var(--surface-2)',
                }}
                onClick={() => setNumberInput(ex.value)}
              >
                {ex.label}
              </button>
            ))}
          </div>

          {/* Test button */}
          <button
            className="input"
            style={{
              cursor: 'pointer',
              fontWeight: 700,
              background: 'var(--accent-bg)',
              marginBottom: 12,
            }}
            onClick={handleTest}
          >
            Test Primality
          </button>

          {/* Error */}
          {testError && (
            <div style={{ color: '#ef4444', fontWeight: 600, marginBottom: 8 }}>{testError}</div>
          )}

          {/* Result */}
          {mrResult && (
            <div className="outputBox">
              <div
                style={{
                  fontWeight: 700,
                  fontSize: 15,
                  color: mrResult.result === 'PROBABLY_PRIME' ? '#22c55e' : '#ef4444',
                  marginBottom: 8,
                }}
              >
                {mrResult.result === 'PROBABLY_PRIME' ? 'PROBABLY PRIME' : 'COMPOSITE'}
                {mrResult.witness !== undefined && (
                  <span style={{ fontWeight: 400, fontSize: 13, marginLeft: 8 }}>
                    witness a = {fmtBig(mrResult.witness)}
                  </span>
                )}
              </div>

              <div style={{ fontSize: 12, opacity: 0.8, marginBottom: 6 }}>
                n - 1 = 2^{mrResult.s} * {fmtBig(mrResult.d, 40)}
              </div>

              {/* Fermat comparison for 561 */}
              {fermatInfo && (
                <div
                  className="traceStep"
                  style={{ marginBottom: 10, border: '1px solid #f59e0b' }}
                >
                  <div className="traceHeader">
                    <span className="traceFn">Carmichael Number 561 — Fermat vs Miller-Rabin</span>
                  </div>
                  <div style={{ fontSize: 12, marginTop: 4 }}>
                    {fermatInfo.witnesses.map((w) => (
                      <div key={w.a.toString()} className="traceKV">
                        <span className="traceKey" style={{ width: 'auto' }}>
                          Fermat(a={w.a.toString()}):
                        </span>
                        <span
                          className="mono"
                          style={{ color: w.passed ? '#22c55e' : '#ef4444' }}
                        >
                          {w.passed ? 'PASS (deceptive!)' : 'FAIL'}
                        </span>
                      </div>
                    ))}
                    <div style={{ marginTop: 6, fontWeight: 600, color: '#f59e0b' }}>
                      Fermat says "prime" but Miller-Rabin catches it as COMPOSITE
                    </div>
                  </div>
                </div>
              )}

              {/* Per-round trace */}
              <div className="traceBlockHeader">Round-by-round trace</div>
              <div className="traceList">
                {mrResult.rounds.map((round, i) => (
                  <div className="traceStep" key={i}>
                    <div className="traceHeader">
                      <span className="traceFn">Round {i + 1}</span>
                      <span
                        className={
                          round.verdict === 'PROBABLY_PRIME'
                            ? 'traceBadge traceBadgeOk'
                            : 'traceBadge'
                        }
                        style={{
                          color:
                            round.verdict === 'PROBABLY_PRIME' ? '#22c55e' : '#ef4444',
                        }}
                      >
                        {round.verdict}
                      </span>
                    </div>
                    <div className="traceKV">
                      <span className="traceKey" style={{ width: 'auto' }}>
                        a =
                      </span>
                      <span className="traceVal mono">{fmtBig(round.a, 50)}</span>
                    </div>
                    <div className="traceKV">
                      <span className="traceKey" style={{ width: 'auto' }}>
                        x[] =
                      </span>
                      <span className="traceVal mono">
                        [{round.xValues.map((v) => fmtBig(v, 30)).join(', ')}]
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* ============ RIGHT PANEL: Prime Generation ============ */}
        <div className="panel">
          <div className="panelTitle">Prime Generation</div>

          {/* Bit length slider */}
          <label className="field">
            <div className="fieldLabel">Bit length: {genBits} bits</div>
            <input
              type="range"
              min={32}
              max={512}
              value={genBits}
              onChange={(e) => setGenBits(Number(e.target.value))}
              style={{ width: '100%' }}
            />
          </label>

          {/* Generate button */}
          <button
            className="input"
            style={{
              cursor: 'pointer',
              fontWeight: 700,
              background: 'var(--accent-bg)',
              marginBottom: 12,
            }}
            onClick={handleGenerate}
            disabled={genRunning}
          >
            {genRunning ? 'Generating...' : 'Generate Prime'}
          </button>

          {genResult && genTime !== null && (
            <div className="outputBox">
              <div className="traceBlockHeader">Generated Prime</div>
              <div className="mono" style={{ wordBreak: 'break-all', marginBottom: 10 }}>
                {genResult.prime.toString()}
              </div>

              <div className="traceList">
                <div className="traceStep">
                  <div className="traceKV">
                    <span className="traceKey" style={{ width: 'auto' }}>
                      Candidates tested:
                    </span>
                    <span className="traceVal mono">{genResult.candidatesTested}</span>
                  </div>
                  <div className="traceKV">
                    <span className="traceKey" style={{ width: 'auto' }}>
                      Time:
                    </span>
                    <span className="traceVal mono">{genTime.toFixed(1)} ms</span>
                  </div>
                </div>

                <div className="traceStep">
                  <div className="traceHeader">
                    <span className="traceFn">Prime Number Theorem comparison</span>
                  </div>
                  <div className="traceKV">
                    <span className="traceKey" style={{ width: 'auto' }}>
                      Expected candidates:
                    </span>
                    <span className="traceVal mono">
                      ~{expectedCandidates} (ln(2^{genBits}) = 0.693 * {genBits})
                    </span>
                  </div>
                  <div className="traceKV">
                    <span className="traceKey" style={{ width: 'auto' }}>
                      Actual:
                    </span>
                    <span className="traceVal mono">{genResult.candidatesTested}</span>
                  </div>
                  <div className="traceNote">
                    PNT says the density of primes near N is ~1/ln(N). For a {genBits}-bit
                    number, we expect to test ~{expectedCandidates} odd candidates on average.
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ============ BOTTOM: Proof Panel ============ */}
      <details className="proofPanel">
        <summary className="proofSummary">Theory: Miller-Rabin, Carmichael Numbers, PNT</summary>
        <div className="proofBody">
          <div className="proofStep">
            <div className="proofStepMain">Miller-Rabin Error Probability</div>
            <div className="proofStepSub">
              For each round, at most 1/4 of bases a in [2, n-2] are "strong liars" (non-witnesses).
              After k independent rounds, the probability that a composite passes all rounds is at
              most (1/4)^k = 4^(-k). With k=10, this is less than 10^(-6). With k=40, it is
              roughly 2^(-80) — negligible.
            </div>
          </div>

          <div className="proofStep">
            <div className="proofStepMain">Carmichael Numbers</div>
            <div className="proofStepSub">
              A Carmichael number n is a composite that satisfies a^(n-1) = 1 (mod n) for all a
              coprime to n. This means the Fermat test always says "probably prime" for these
              numbers. The smallest is 561 = 3 * 11 * 17. Miller-Rabin catches these because it
              checks the square-root structure: not only must a^(n-1) = 1, but the sequence
              a^d, a^(2d), ..., a^(2^s * d) must contain 1 preceded by -1 (or start at 1).
              Carmichael numbers fail this stronger condition.
            </div>
          </div>

          <div className="proofStep">
            <div className="proofStepMain">Prime Number Theorem</div>
            <div className="proofStepSub">
              The Prime Number Theorem states that the number of primes up to N is approximately
              N / ln(N). Equivalently, the density of primes near N is ~1/ln(N). For a random
              b-bit number, N ~ 2^b, so ln(N) ~ b * ln(2) ~ 0.693 * b. We therefore expect to
              test about 0.693 * b odd candidates before finding a prime. For 64-bit numbers, this
              is about 44 candidates; for 512-bit, about 355.
            </div>
          </div>
        </div>
      </details>
    </div>
  )
}
