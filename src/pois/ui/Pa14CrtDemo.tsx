/**
 * PA#14 — CRT, RSA-CRT, and Hastad's Broadcast Attack Demo
 *
 * Left panel:  CRT solver + RSA-CRT benchmark
 * Right panel: Hastad's broadcast attack demo
 * Bottom:      Proof panel with theory
 */

import { useState } from 'react'
import {
  crt,
  benchmarkCrt,
  hastadDemo,
  hastadWithPadding,
  type BenchmarkResult,
  type HastadDemoResult,
  type HastadPaddingResult,
} from '../crypto/crt'
import { rsaKeygen, type RSAKeyPair } from '../crypto/rsa'
import './poisCliqueExplorer.css'

/* ------------------------------------------------------------------ */
/*  Helper: format BigInt for display                                  */
/* ------------------------------------------------------------------ */

function fmtBig(n: bigint, max = 60): string {
  const s = n.toString()
  if (s.length <= max) return s
  return s.slice(0, 25) + '...' + s.slice(-25) + ` (${s.length} digits)`
}

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */

export default function Pa14CrtDemo() {
  /* -- CRT solver state -- */
  const [crtResidues, setCrtResidues] = useState('2, 3, 2')
  const [crtModuli, setCrtModuli] = useState('3, 5, 7')
  const [crtResult, setCrtResult] = useState<bigint | null>(null)
  const [crtError, setCrtError] = useState('')

  /* -- Benchmark state -- */
  const [benchKeys, setBenchKeys] = useState<RSAKeyPair | null>(null)
  const [benchResult, setBenchResult] = useState<BenchmarkResult | null>(null)
  const [benchRunning, setBenchRunning] = useState(false)
  const [benchBits, setBenchBits] = useState(512)

  /* -- Hastad attack state -- */
  const [hastadMessage, setHastadMessage] = useState('42')
  const [hastadBits, setHastadBits] = useState(256)
  const [hastadResult, setHastadResult] = useState<HastadDemoResult | null>(null)
  const [hastadRunning, setHastadRunning] = useState(false)
  const [hastadError, setHastadError] = useState('')

  /* -- Padding demo state -- */
  const [paddingResult, setPaddingResult] = useState<HastadPaddingResult | null>(null)
  const [paddingRunning, setPaddingRunning] = useState(false)

  /* -- Proof panel toggle -- */
  const [showProof, setShowProof] = useState(false)

  /* ---- CRT solver handler ---- */
  function handleCrtSolve() {
    setCrtError('')
    setCrtResult(null)
    try {
      const residues = crtResidues.split(',').map(s => BigInt(s.trim()))
      const moduli = crtModuli.split(',').map(s => BigInt(s.trim()))
      const result = crt(residues, moduli)
      setCrtResult(result)
    } catch (e: unknown) {
      setCrtError(e instanceof Error ? e.message : 'Invalid input')
    }
  }

  /* ---- Benchmark handler ---- */
  function handleBenchmark() {
    setBenchRunning(true)
    setBenchResult(null)
    setTimeout(() => {
      try {
        const keys = rsaKeygen(benchBits)
        setBenchKeys(keys)
        const result = benchmarkCrt(keys, 100)
        setBenchResult(result)
      } catch (e: unknown) {
        console.error(e)
      }
      setBenchRunning(false)
    }, 50)
  }

  /* ---- Hastad attack handler ---- */
  function handleHastadAttack() {
    setHastadError('')
    setHastadResult(null)
    setHastadRunning(true)
    setTimeout(() => {
      try {
        const m = BigInt(hastadMessage.trim())
        const result = hastadDemo(m, hastadBits)
        setHastadResult(result)
      } catch (e: unknown) {
        setHastadError(e instanceof Error ? e.message : 'Error')
      }
      setHastadRunning(false)
    }, 50)
  }

  /* ---- Padding demo handler ---- */
  function handlePaddingDemo() {
    setPaddingResult(null)
    setPaddingRunning(true)
    setTimeout(() => {
      try {
        const msgBytes = new TextEncoder().encode(hastadMessage.trim().slice(0, 4))
        const result = hastadWithPadding(msgBytes, hastadBits)
        setPaddingResult(result)
      } catch (e: unknown) {
        console.error(e)
      }
      setPaddingRunning(false)
    }, 50)
  }

  /* ---------------------------------------------------------------- */
  /*  Render                                                           */
  /* ---------------------------------------------------------------- */

  return (
    <div style={{ padding: 24, maxWidth: 1300, margin: '0 auto' }}>
      <h2 style={{ marginBottom: 4, color: 'var(--text-h)' }}>
        PA#14 — Chinese Remainder Theorem &amp; Hastad&apos;s Broadcast Attack
      </h2>
      <p style={{ color: 'var(--text-m)', marginBottom: 20, fontSize: 14 }}>
        CRT solver, Garner&apos;s RSA-CRT decryption, and Hastad&apos;s broadcast attack on textbook RSA.
      </p>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24 }}>
        {/* ===================== LEFT PANEL ===================== */}
        <div>
          {/* -- CRT Solver -- */}
          <div className="pois-card" style={{ marginBottom: 20 }}>
            <h3 style={{ margin: '0 0 12px', color: 'var(--text-h)' }}>CRT Solver</h3>
            <label style={{ fontSize: 13, color: 'var(--text-m)' }}>
              Residues (comma-separated):
            </label>
            <input
              value={crtResidues}
              onChange={e => setCrtResidues(e.target.value)}
              style={{ width: '100%', marginBottom: 8, padding: '6px 8px', fontFamily: 'monospace' }}
            />
            <label style={{ fontSize: 13, color: 'var(--text-m)' }}>
              Moduli (comma-separated, pairwise coprime):
            </label>
            <input
              value={crtModuli}
              onChange={e => setCrtModuli(e.target.value)}
              style={{ width: '100%', marginBottom: 8, padding: '6px 8px', fontFamily: 'monospace' }}
            />
            <button onClick={handleCrtSolve} style={{ marginTop: 4 }}>
              Solve CRT
            </button>
            {crtError && (
              <div style={{ color: '#e74c3c', marginTop: 8, fontSize: 13 }}>{crtError}</div>
            )}
            {crtResult !== null && (
              <div style={{ marginTop: 12, padding: 10, background: 'var(--surface)', borderRadius: 6 }}>
                <strong>x = {crtResult.toString()}</strong>
                <div style={{ fontSize: 12, color: 'var(--text-m)', marginTop: 4 }}>
                  x mod N = {crtResult.toString()} where N = product of moduli
                </div>
              </div>
            )}
          </div>

          {/* -- RSA-CRT Benchmark -- */}
          <div className="pois-card">
            <h3 style={{ margin: '0 0 12px', color: 'var(--text-h)' }}>
              RSA-CRT Benchmark
            </h3>
            <label style={{ fontSize: 13, color: 'var(--text-m)' }}>Key size (bits):</label>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8 }}>
              <input
                type="number"
                value={benchBits}
                onChange={e => setBenchBits(Number(e.target.value))}
                min={128}
                max={2048}
                step={128}
                style={{ width: 100, padding: '6px 8px', fontFamily: 'monospace' }}
              />
              <button onClick={handleBenchmark} disabled={benchRunning}>
                {benchRunning ? 'Running...' : 'Run Benchmark (100 trials)'}
              </button>
            </div>
            {benchResult && (
              <div style={{ marginTop: 8, padding: 10, background: 'var(--surface)', borderRadius: 6 }}>
                <div style={{ fontSize: 13 }}>
                  <strong>Standard RSA:</strong> {benchResult.standardMs.toFixed(2)} ms
                </div>
                <div style={{ fontSize: 13 }}>
                  <strong>CRT RSA:</strong> {benchResult.crtMs.toFixed(2)} ms
                </div>
                <div style={{ fontSize: 14, marginTop: 6, fontWeight: 700, color: 'var(--accent)' }}>
                  Speedup: {benchResult.speedup.toFixed(2)}x
                </div>
                {benchKeys && (
                  <div style={{ fontSize: 11, color: 'var(--text-m)', marginTop: 4 }}>
                    N = {fmtBig(benchKeys.N, 50)}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* ===================== RIGHT PANEL ===================== */}
        <div>
          {/* -- Hastad's Broadcast Attack -- */}
          <div className="pois-card" style={{ marginBottom: 20 }}>
            <h3 style={{ margin: '0 0 12px', color: 'var(--text-h)' }}>
              Hastad&apos;s Broadcast Attack (e=3)
            </h3>
            <label style={{ fontSize: 13, color: 'var(--text-m)' }}>
              Message (small integer):
            </label>
            <input
              value={hastadMessage}
              onChange={e => setHastadMessage(e.target.value)}
              style={{ width: '100%', marginBottom: 8, padding: '6px 8px', fontFamily: 'monospace' }}
            />
            <label style={{ fontSize: 13, color: 'var(--text-m)' }}>Key size (bits):</label>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8 }}>
              <input
                type="number"
                value={hastadBits}
                onChange={e => setHastadBits(Number(e.target.value))}
                min={128}
                max={1024}
                step={64}
                style={{ width: 100, padding: '6px 8px', fontFamily: 'monospace' }}
              />
            </div>
            <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
              <button onClick={handleHastadAttack} disabled={hastadRunning}>
                {hastadRunning ? 'Generating keys...' : 'Generate 3 Recipients & Attack'}
              </button>
              <button onClick={handlePaddingDemo} disabled={paddingRunning}>
                {paddingRunning ? 'Running...' : 'Try with PKCS Padding'}
              </button>
            </div>
            {hastadError && (
              <div style={{ color: '#e74c3c', marginTop: 8, fontSize: 13 }}>{hastadError}</div>
            )}

            {/* Hastad result (no padding) */}
            {hastadResult && (
              <div style={{ marginTop: 12, padding: 10, background: 'var(--surface)', borderRadius: 6 }}>
                <div style={{ fontSize: 13, marginBottom: 8, fontWeight: 600 }}>
                  Textbook RSA (no padding):
                </div>
                {hastadResult.keys.map((pk, i) => (
                  <div key={i} style={{ fontSize: 12, marginBottom: 4, color: 'var(--text-m)' }}>
                    <strong>N{i + 1}:</strong> {fmtBig(pk.N, 40)}<br />
                    <strong>c{i + 1}:</strong> {fmtBig(hastadResult.ciphertexts[i], 40)}
                  </div>
                ))}
                <div style={{ marginTop: 8, fontSize: 13 }}>
                  <strong>CRT result (m^3):</strong>{' '}
                  <span style={{ fontFamily: 'monospace' }}>{fmtBig(hastadResult.crtResult, 50)}</span>
                </div>
                <div style={{ marginTop: 4, fontSize: 13 }}>
                  <strong>Cube root (recovered m):</strong>{' '}
                  <span style={{ fontFamily: 'monospace' }}>{hastadResult.recoveredMessage.toString()}</span>
                </div>
                <div style={{
                  marginTop: 8,
                  padding: '6px 10px',
                  borderRadius: 4,
                  fontSize: 13,
                  fontWeight: 700,
                  background: hastadResult.attackSucceeded ? '#e8f5e9' : '#ffebee',
                  color: hastadResult.attackSucceeded ? '#2e7d32' : '#c62828',
                }}>
                  {hastadResult.attackSucceeded
                    ? 'Attack SUCCEEDED: recovered m = ' + hastadResult.recoveredMessage.toString()
                    : 'Attack failed'}
                </div>
              </div>
            )}

            {/* Padding result */}
            {paddingResult && (
              <div style={{ marginTop: 12, padding: 10, background: 'var(--surface)', borderRadius: 6 }}>
                <div style={{ fontSize: 13, marginBottom: 8, fontWeight: 600 }}>
                  PKCS#1 v1.5 Padded RSA:
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-m)', marginBottom: 4 }}>
                  Each padded value is different due to random padding bytes:
                </div>
                {paddingResult.paddedValues.map((pv, i) => (
                  <div key={i} style={{ fontSize: 11, marginBottom: 2, color: 'var(--text-m)' }}>
                    <strong>pad{i + 1}:</strong> {fmtBig(pv, 40)}
                  </div>
                ))}
                <div style={{ marginTop: 4, fontSize: 13 }}>
                  <strong>CRT + cube root:</strong>{' '}
                  <span style={{ fontFamily: 'monospace' }}>{fmtBig(paddingResult.recoveredValue, 50)}</span>
                </div>
                <div style={{
                  marginTop: 8,
                  padding: '6px 10px',
                  borderRadius: 4,
                  fontSize: 13,
                  fontWeight: 700,
                  background: paddingResult.attackSucceeded ? '#e8f5e9' : '#ffebee',
                  color: paddingResult.attackSucceeded ? '#2e7d32' : '#c62828',
                }}>
                  {paddingResult.attackSucceeded
                    ? 'Attack succeeded (unexpected!)'
                    : 'Attack FAILED: padding defeats Hastad\'s attack'}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ===================== PROOF PANEL ===================== */}
      <div className="pois-card" style={{ marginTop: 20 }}>
        <button
          onClick={() => setShowProof(!showProof)}
          style={{
            background: 'none',
            border: 'none',
            cursor: 'pointer',
            fontWeight: 700,
            fontSize: 15,
            color: 'var(--text-h)',
            padding: 0,
          }}
        >
          {showProof ? '\u25BC' : '\u25B6'} Theory &amp; Proofs
        </button>
        {showProof && (
          <div style={{ marginTop: 12, fontSize: 13, lineHeight: 1.7, color: 'var(--text-m)' }}>
            <h4 style={{ color: 'var(--text-h)' }}>Chinese Remainder Theorem</h4>
            <p>
              <strong>Theorem:</strong> Let n_1, n_2, ..., n_k be pairwise coprime positive integers
              and let a_1, a_2, ..., a_k be arbitrary integers. Then the system of congruences
              x ≡ a_i (mod n_i) for i = 1, ..., k has a unique solution modulo N = n_1 * n_2 * ... * n_k.
            </p>
            <p>
              <strong>Construction:</strong> Let N_i = N / n_i. Since gcd(N_i, n_i) = 1, the modular
              inverse y_i = N_i^(-1) mod n_i exists. Then x = sum(a_i * N_i * y_i) mod N.
            </p>

            <h4 style={{ color: 'var(--text-h)', marginTop: 16 }}>Garner&apos;s Algorithm (RSA-CRT)</h4>
            <p>
              RSA-CRT uses CRT to speed up decryption by working modulo the smaller primes p and q
              instead of the full modulus N = pq:
            </p>
            <ul>
              <li>m_p = c^(d mod (p-1)) mod p</li>
              <li>m_q = c^(d mod (q-1)) mod q</li>
              <li>h = q^(-1) * (m_p - m_q) mod p</li>
              <li>m = m_q + h * q</li>
            </ul>
            <p>
              This is ~4x faster because modular exponentiation with an n-bit exponent and n-bit
              modulus costs O(n^3). With CRT, we do two exponentiations with (n/2)-bit values,
              each costing O((n/2)^3) = O(n^3/8), totaling ~n^3/4 vs n^3.
            </p>

            <h4 style={{ color: 'var(--text-h)', marginTop: 16 }}>Hastad&apos;s Broadcast Attack</h4>
            <p>
              <strong>Setup:</strong> Suppose the same message m is encrypted with e=3 under three
              different RSA public keys (N_1, 3), (N_2, 3), (N_3, 3). The attacker sees:
            </p>
            <ul>
              <li>c_1 = m^3 mod N_1</li>
              <li>c_2 = m^3 mod N_2</li>
              <li>c_3 = m^3 mod N_3</li>
            </ul>
            <p>
              <strong>Attack:</strong> By CRT, compute x such that x ≡ c_i (mod N_i) for i=1,2,3.
              Since m &lt; each N_i, we have m^3 &lt; N_1*N_2*N_3, so x = m^3 as an integer (not reduced).
              Then m = floor(x^(1/3)).
            </p>

            <h4 style={{ color: 'var(--text-h)', marginTop: 16 }}>Why Padding Defeats Hastad&apos;s Attack</h4>
            <p>
              PKCS#1 v1.5 padding prepends random bytes to the message before encryption. Even though
              the same plaintext message is sent, each recipient sees a different padded value:
              pad_1(m) ≠ pad_2(m) ≠ pad_3(m). Since the CRT system is c_i = pad_i(m)^3 mod N_i with
              different base values, the cube root of the CRT result does not yield the original message.
            </p>
          </div>
        )}
      </div>
    </div>
  )
}
