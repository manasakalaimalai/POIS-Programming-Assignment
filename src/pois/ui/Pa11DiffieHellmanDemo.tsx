/**
 * PA#11 — Diffie-Hellman Key Exchange Demo
 *
 * Two-panel layout (Alice | Bob) with MITM attack and CDH hardness demo.
 */

import { useState } from 'react'
import {
  DH_PARAMS,
  dhAliceStep1,
  dhBobStep1,
  dhAliceStep2,
  dhBobStep2,
  mitmAttack,
  cdhBruteForce,
  bigintToHex,
  type DHStep1,
  type MITMResult,
  type CDHBruteResult,
} from '../crypto/diffieHellman'
import './poisCliqueExplorer.css'

/* ------------------------------------------------------------------ */
/*  Inline styles                                                      */
/* ------------------------------------------------------------------ */

const panelStyle: React.CSSProperties = {
  flex: 1,
  padding: 16,
  border: '1px solid var(--border, #444)',
  borderRadius: 8,
  background: 'var(--surface, #1e1e1e)',
}

const btnStyle: React.CSSProperties = {
  appearance: 'none',
  border: '1px solid var(--border, #555)',
  background: 'var(--accent-bg, #2a2a3a)',
  color: 'var(--text-h, #eee)',
  fontFamily: 'inherit',
  fontSize: 13,
  fontWeight: 600,
  padding: '6px 14px',
  borderRadius: 6,
  cursor: 'pointer',
}

const monoStyle: React.CSSProperties = {
  fontFamily: '"Fira Mono", "Cascadia Code", monospace',
  fontSize: 13,
  wordBreak: 'break-all',
}

const labelStyle: React.CSSProperties = {
  fontSize: 12,
  fontWeight: 600,
  textTransform: 'uppercase' as const,
  letterSpacing: '0.05em',
  color: 'var(--text-dim, #888)',
  marginBottom: 4,
}

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */

export default function Pa11DiffieHellmanDemo() {
  // Alice and Bob key pairs
  const [alice, setAlice] = useState<DHStep1 | null>(null)
  const [bob, setBob] = useState<DHStep1 | null>(null)

  // Shared secrets after exchange
  const [kAlice, setKAlice] = useState<bigint | null>(null)
  const [kBob, setKBob] = useState<bigint | null>(null)

  // Reveal toggles
  const [revealAlice, setRevealAlice] = useState(false)
  const [revealBob, setRevealBob] = useState(false)

  // MITM
  const [eveEnabled, setEveEnabled] = useState(false)
  const [eveResult, setEveResult] = useState<MITMResult | null>(null)
  const [kAliceEveVerify, setKAliceEveVerify] = useState<bigint | null>(null)
  const [kBobEveVerify, setKBobEveVerify] = useState<bigint | null>(null)

  // CDH brute force
  const [cdhResult, setCdhResult] = useState<CDHBruteResult | null>(null)
  const [cdhRunning, setCdhRunning] = useState(false)

  // Exchanged flag
  const [exchanged, setExchanged] = useState(false)

  const handleRandomizeAlice = () => {
    const a = dhAliceStep1()
    setAlice(a)
    setKAlice(null)
    setKBob(null)
    setExchanged(false)
    setEveResult(null)
    setKAliceEveVerify(null)
    setKBobEveVerify(null)
    setCdhResult(null)
  }

  const handleRandomizeBob = () => {
    const b = dhBobStep1()
    setBob(b)
    setKAlice(null)
    setKBob(null)
    setExchanged(false)
    setEveResult(null)
    setKAliceEveVerify(null)
    setKBobEveVerify(null)
    setCdhResult(null)
  }

  const handleExchange = () => {
    if (!alice || !bob) return

    if (eveEnabled) {
      // MITM: Eve intercepts
      const eve = mitmAttack(alice.public, bob.public)
      setEveResult(eve)
      // Alice receives Eve's bPrime, Bob receives Eve's aPrime
      const kA = dhAliceStep2(alice.secret, eve.bPrime)
      const kB = dhBobStep2(bob.secret, eve.aPrime)
      setKAlice(kA)
      setKBob(kB)
      // Verify Eve's keys match
      setKAliceEveVerify(eve.kAliceEve)
      setKBobEveVerify(eve.kBobEve)
    } else {
      // Normal exchange
      const kA = dhAliceStep2(alice.secret, bob.public)
      const kB = dhBobStep2(bob.secret, alice.public)
      setKAlice(kA)
      setKBob(kB)
      setEveResult(null)
      setKAliceEveVerify(null)
      setKBobEveVerify(null)
    }
    setExchanged(true)
  }

  const handleCdhBrute = () => {
    if (!alice || !bob) return
    setCdhRunning(true)
    setCdhResult(null)
    // Use setTimeout so UI updates before blocking computation
    setTimeout(() => {
      const result = cdhBruteForce(alice.public, bob.public)
      setCdhResult(result)
      setCdhRunning(false)
    }, 50)
  }

  const keysMatch = kAlice !== null && kBob !== null && kAlice === kBob
  const eveMitmActive = eveEnabled && eveResult !== null

  return (
    <div style={{ padding: '24px 28px', maxWidth: 1100, margin: '0 auto' }}>
      <h2 style={{ margin: '0 0 4px', fontSize: 22, color: 'var(--text-h, #fff)' }}>
        PA#11 -- Diffie-Hellman Key Exchange
      </h2>
      <p style={{ margin: '0 0 18px', fontSize: 14, color: 'var(--text-dim, #999)' }}>
        Interactive demo: DH protocol, MITM attack, and CDH hardness over a toy safe prime group.
      </p>

      {/* Group parameters */}
      <div style={{
        marginBottom: 18,
        padding: '10px 14px',
        borderRadius: 6,
        background: 'var(--accent-bg, #1a1a2e)',
        fontSize: 13,
        ...monoStyle,
      }}>
        <span style={{ color: 'var(--text-dim, #888)' }}>Group: </span>
        p = {DH_PARAMS.p.toString()} &nbsp;|&nbsp; g = {DH_PARAMS.g.toString()} &nbsp;|&nbsp; q = (p-1)/2 = {DH_PARAMS.q.toString()}
      </div>

      {/* Alice and Bob panels */}
      <div style={{ display: 'flex', gap: 16, marginBottom: 18 }}>
        {/* Alice */}
        <div style={panelStyle}>
          <h3 style={{ margin: '0 0 10px', fontSize: 16, color: '#6ec6ff' }}>Alice</h3>
          <button style={btnStyle} onClick={handleRandomizeAlice}>Randomize a</button>
          {alice && (
            <div style={{ marginTop: 12 }}>
              <div style={labelStyle}>Private exponent a</div>
              <div style={monoStyle}>
                {revealAlice ? alice.secret.toString() : '********'}
                <button
                  style={{ ...btnStyle, marginLeft: 8, padding: '2px 8px', fontSize: 11 }}
                  onClick={() => setRevealAlice(!revealAlice)}
                >
                  {revealAlice ? 'hide' : 'reveal'}
                </button>
              </div>
              <div style={{ ...labelStyle, marginTop: 10 }}>Public value A = g^a mod p</div>
              <div style={monoStyle}>{bigintToHex(alice.public)}</div>
              <div style={{ ...monoStyle, color: 'var(--text-dim, #777)', fontSize: 12 }}>
                = {alice.public.toString()}
              </div>
            </div>
          )}
          {kAlice !== null && (
            <div style={{ marginTop: 14 }}>
              <div style={labelStyle}>
                Shared secret K{eveMitmActive ? ' (with Eve!)' : ''}
              </div>
              <div style={{
                ...monoStyle,
                padding: '6px 10px',
                borderRadius: 4,
                background: eveMitmActive
                  ? 'rgba(255,60,60,0.12)'
                  : keysMatch ? 'rgba(60,200,80,0.12)' : 'rgba(255,200,0,0.12)',
                border: eveMitmActive
                  ? '1px solid rgba(255,60,60,0.3)'
                  : keysMatch ? '1px solid rgba(60,200,80,0.3)' : '1px solid rgba(255,200,0,0.3)',
              }}>
                {bigintToHex(kAlice)}
              </div>
            </div>
          )}
        </div>

        {/* Bob */}
        <div style={panelStyle}>
          <h3 style={{ margin: '0 0 10px', fontSize: 16, color: '#ffa94d' }}>Bob</h3>
          <button style={btnStyle} onClick={handleRandomizeBob}>Randomize b</button>
          {bob && (
            <div style={{ marginTop: 12 }}>
              <div style={labelStyle}>Private exponent b</div>
              <div style={monoStyle}>
                {revealBob ? bob.secret.toString() : '********'}
                <button
                  style={{ ...btnStyle, marginLeft: 8, padding: '2px 8px', fontSize: 11 }}
                  onClick={() => setRevealBob(!revealBob)}
                >
                  {revealBob ? 'hide' : 'reveal'}
                </button>
              </div>
              <div style={{ ...labelStyle, marginTop: 10 }}>Public value B = g^b mod p</div>
              <div style={monoStyle}>{bigintToHex(bob.public)}</div>
              <div style={{ ...monoStyle, color: 'var(--text-dim, #777)', fontSize: 12 }}>
                = {bob.public.toString()}
              </div>
            </div>
          )}
          {kBob !== null && (
            <div style={{ marginTop: 14 }}>
              <div style={labelStyle}>
                Shared secret K{eveMitmActive ? ' (with Eve!)' : ''}
              </div>
              <div style={{
                ...monoStyle,
                padding: '6px 10px',
                borderRadius: 4,
                background: eveMitmActive
                  ? 'rgba(255,60,60,0.12)'
                  : keysMatch ? 'rgba(60,200,80,0.12)' : 'rgba(255,200,0,0.12)',
                border: eveMitmActive
                  ? '1px solid rgba(255,60,60,0.3)'
                  : keysMatch ? '1px solid rgba(60,200,80,0.3)' : '1px solid rgba(255,200,0,0.3)',
              }}>
                {bigintToHex(kBob)}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Exchange controls */}
      <div style={{ textAlign: 'center', marginBottom: 18 }}>
        <button
          style={{ ...btnStyle, fontSize: 15, padding: '10px 28px' }}
          onClick={handleExchange}
          disabled={!alice || !bob}
        >
          Exchange
        </button>
        {exchanged && !eveMitmActive && keysMatch && (
          <div style={{ marginTop: 8, color: '#4caf50', fontWeight: 600, fontSize: 14 }}>
            K_Alice === K_Bob -- Shared secret established!
          </div>
        )}
        {exchanged && !eveMitmActive && !keysMatch && kAlice !== null && (
          <div style={{ marginTop: 8, color: '#ff9800', fontWeight: 600, fontSize: 14 }}>
            K_Alice !== K_Bob -- Something went wrong.
          </div>
        )}
      </div>

      {/* MITM section */}
      <div style={{
        marginBottom: 18,
        padding: '14px 16px',
        borderRadius: 8,
        border: '1px solid var(--border, #444)',
        background: eveEnabled ? 'rgba(255,40,40,0.04)' : 'var(--surface, #1e1e1e)',
      }}>
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', marginBottom: eveEnabled ? 12 : 0 }}>
          <input
            type="checkbox"
            checked={eveEnabled}
            onChange={() => {
              setEveEnabled(!eveEnabled)
              setEveResult(null)
              setKAlice(null)
              setKBob(null)
              setExchanged(false)
              setKAliceEveVerify(null)
              setKBobEveVerify(null)
            }}
          />
          <span style={{ fontWeight: 600, fontSize: 14, color: '#ff5252' }}>Enable Eve (MITM attacker)</span>
        </label>

        {eveEnabled && eveResult && (
          <div>
            <h4 style={{ margin: '0 0 8px', color: '#ff5252' }}>Eve (Man-in-the-Middle)</h4>
            <div style={{ display: 'flex', gap: 16 }}>
              <div style={{ flex: 1 }}>
                <div style={labelStyle}>Eve's secret e</div>
                <div style={monoStyle}>{eveResult.e.toString()}</div>
                <div style={{ ...labelStyle, marginTop: 8 }}>A' sent to Bob (g^e mod p)</div>
                <div style={monoStyle}>{bigintToHex(eveResult.aPrime)}</div>
                <div style={{ ...labelStyle, marginTop: 8 }}>B' sent to Alice (g^e mod p)</div>
                <div style={monoStyle}>{bigintToHex(eveResult.bPrime)}</div>
              </div>
              <div style={{ flex: 1 }}>
                <div style={labelStyle}>K_AliceEve = A^e mod p</div>
                <div style={monoStyle}>{bigintToHex(eveResult.kAliceEve)}</div>
                {kAliceEveVerify !== null && (
                  <div style={{ fontSize: 12, color: kAlice === kAliceEveVerify ? '#4caf50' : '#ff5252' }}>
                    {kAlice === kAliceEveVerify
                      ? 'Matches Alice\'s K'
                      : 'Mismatch with Alice\'s K'}
                  </div>
                )}
                <div style={{ ...labelStyle, marginTop: 8 }}>K_BobEve = B^e mod p</div>
                <div style={monoStyle}>{bigintToHex(eveResult.kBobEve)}</div>
                {kBobEveVerify !== null && (
                  <div style={{ fontSize: 12, color: kBob === kBobEveVerify ? '#4caf50' : '#ff5252' }}>
                    {kBob === kBobEveVerify
                      ? 'Matches Bob\'s K'
                      : 'Mismatch with Bob\'s K'}
                  </div>
                )}
              </div>
            </div>
            <div style={{
              marginTop: 12,
              padding: '8px 12px',
              borderRadius: 4,
              background: 'rgba(255,40,40,0.1)',
              border: '1px solid rgba(255,40,40,0.25)',
              color: '#ff5252',
              fontWeight: 600,
              fontSize: 13,
            }}>
              Eve knows both secrets -- all traffic is compromised.
              Alice and Bob each think they share a secret with the other,
              but they actually share separate secrets with Eve.
            </div>
          </div>
        )}
      </div>

      {/* CDH brute-force demo */}
      <div style={{
        marginBottom: 18,
        padding: '14px 16px',
        borderRadius: 8,
        border: '1px solid var(--border, #444)',
        background: 'var(--surface, #1e1e1e)',
      }}>
        <h4 style={{ margin: '0 0 8px', fontSize: 15, color: 'var(--text-h, #fff)' }}>
          CDH Brute-Force Demo
        </h4>
        <p style={{ margin: '0 0 10px', fontSize: 13, color: 'var(--text-dim, #999)' }}>
          Given g^a and g^b, brute-force search for a to compute g^(ab). Demonstrates computational hardness.
        </p>
        <button
          style={btnStyle}
          onClick={handleCdhBrute}
          disabled={!alice || !bob || cdhRunning}
        >
          {cdhRunning ? 'Searching...' : 'Run CDH brute-force'}
        </button>
        {cdhResult && (
          <div style={{ marginTop: 10, ...monoStyle }}>
            <div>g^(ab) mod p = {bigintToHex(cdhResult.gab)}</div>
            <div style={{ color: 'var(--text-dim, #999)' }}>
              Attempts: {cdhResult.attempts.toLocaleString()} &nbsp;|&nbsp; Time: {cdhResult.timeMs.toFixed(1)} ms
            </div>
            {kAlice !== null && (
              <div style={{ fontSize: 12, color: cdhResult.gab === kAlice ? '#4caf50' : '#ff5252', marginTop: 4 }}>
                {cdhResult.gab === kAlice
                  ? 'Matches the actual shared secret K.'
                  : 'Does not match K (MITM active, different keys).'}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Proof / explanation panel */}
      <div style={{
        padding: '16px 18px',
        borderRadius: 8,
        border: '1px solid var(--border, #444)',
        background: 'var(--surface, #1e1e1e)',
        fontSize: 13,
        lineHeight: 1.7,
        color: 'var(--text, #ccc)',
      }}>
        <h4 style={{ margin: '0 0 8px', fontSize: 15, color: 'var(--text-h, #fff)' }}>
          Theory and Security
        </h4>
        <p style={{ margin: '0 0 8px' }}>
          <strong>CDH assumption:</strong> Given g^a mod p and g^b mod p, computing g^(ab) mod p
          is believed to be computationally hard for large primes (without knowing a or b).
          The brute-force demo above shows that for our toy 30-bit prime, it takes up to ~500M
          operations. For 2048-bit primes used in practice, this is infeasible.
        </p>
        <p style={{ margin: '0 0 8px' }}>
          <strong>MITM attack:</strong> Unauthenticated Diffie-Hellman is vulnerable to
          man-in-the-middle attacks. Eve can intercept the public values and substitute her own,
          establishing separate shared secrets with Alice and Bob. She can then decrypt, read,
          and re-encrypt all traffic. This is why DH must be combined with digital signatures
          (PA#15) or certificates for authentication.
        </p>
        <p style={{ margin: 0 }}>
          <strong>Group parameters:</strong> p = {DH_PARAMS.p.toString()} (safe prime),
          g = {DH_PARAMS.g.toString()}, subgroup order q = {DH_PARAMS.q.toString()}.
          In practice, groups of 2048+ bits (or elliptic curves of 256+ bits) are used.
        </p>
      </div>
    </div>
  )
}
