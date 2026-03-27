/**
 * PA#12 — Textbook RSA and PKCS#1 v1.5 Demo
 *
 * Left panel:  RSA Encrypt/Decrypt with key generation
 * Right panel: Attack demos (determinism + padding oracle)
 * Bottom:      Proof panel with theory
 */

import { useState } from 'react'
import {
  rsaKeygen,
  rsaEncrypt,
  rsaDecrypt,
  pkcs15Encrypt,
  pkcs15Decrypt,
  determinismAttack,
  paddingOracle,
  bleichenbacherDemo,
  bytesToBigint,
  type RSAKeyPair,
  type DeterminismResult,
  type BleichenbacherDemoResult,
} from '../crypto/rsa'
import './poisCliqueExplorer.css'

/* ------------------------------------------------------------------ */
/*  Helper: format BigInt for display                                  */
/* ------------------------------------------------------------------ */

function fmtBig(n: bigint, max = 60): string {
  const s = n.toString()
  if (s.length <= max) return s
  return s.slice(0, 25) + '...' + s.slice(-25) + ` (${s.length} digits)`
}

function textToBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text)
}

function bytesToText(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes)
}

function textToBigint(text: string): bigint {
  const bytes = textToBytes(text)
  return bytesToBigint(bytes)
}

function bigintToText(n: bigint): string {
  const hexStr = n.toString(16)
  const padded = hexStr.length % 2 === 1 ? '0' + hexStr : hexStr
  const bytes = new Uint8Array(padded.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(padded.slice(i * 2, i * 2 + 2), 16)
  }
  return bytesToText(bytes)
}

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */

export default function Pa12RsaDemo() {
  /* -- Key generation state -- */
  const [bitLen, setBitLen] = useState(256)
  const [keys, setKeys] = useState<RSAKeyPair | null>(null)
  const [showPrivate, setShowPrivate] = useState(false)
  const [keyGenTime, setKeyGenTime] = useState<number | null>(null)
  const [keyGenRunning, setKeyGenRunning] = useState(false)

  /* -- Encrypt/Decrypt state -- */
  const [message, setMessage] = useState('Hello RSA!')
  const [usePkcs, setUsePkcs] = useState(false)
  const [ciphertext, setCiphertext] = useState<bigint | null>(null)
  const [decrypted, setDecrypted] = useState<string | null>(null)
  const [encError, setEncError] = useState('')

  /* -- Determinism attack state -- */
  const [detResult, setDetResult] = useState<DeterminismResult | null>(null)

  /* -- Bleichenbacher state -- */
  const [bleichResult, setBleichResult] = useState<BleichenbacherDemoResult | null>(null)
  const [oracleValidResult, setOracleValidResult] = useState<boolean | null>(null)
  const [oracleTamperedResult, setOracleTamperedResult] = useState<boolean | null>(null)
  const [validC, setValidC] = useState<bigint | null>(null)
  const [tamperedC, setTamperedC] = useState<bigint | null>(null)

  /* ---------------------------------------------------------------- */
  /*  Handlers                                                         */
  /* ---------------------------------------------------------------- */

  function handleGenKeys() {
    setKeyGenRunning(true)
    setKeys(null)
    setCiphertext(null)
    setDecrypted(null)
    setDetResult(null)
    setBleichResult(null)
    setOracleValidResult(null)
    setOracleTamperedResult(null)
    setValidC(null)
    setTamperedC(null)
    setTimeout(() => {
      const t0 = performance.now()
      const kp = rsaKeygen(bitLen)
      const elapsed = performance.now() - t0
      setKeys(kp)
      setKeyGenTime(elapsed)
      setKeyGenRunning(false)
    }, 10)
  }

  function handleEncrypt() {
    if (!keys) return
    setEncError('')
    try {
      const pk = { N: keys.N, e: keys.e }
      const sk = { N: keys.N, d: keys.d }
      const keyBytes = Math.ceil(keys.N.toString(2).length / 8)

      if (usePkcs) {
        const msgBytes = textToBytes(message)
        const c = pkcs15Encrypt(pk, msgBytes)
        setCiphertext(c)
        const dec = pkcs15Decrypt(sk, c, keyBytes)
        setDecrypted(dec ? bytesToText(dec) : '[decryption failed]')
      } else {
        const m = textToBigint(message)
        if (m >= keys.N) {
          setEncError('Message value must be less than N')
          return
        }
        const c = rsaEncrypt(pk, m)
        setCiphertext(c)
        const d = rsaDecrypt(sk, c)
        setDecrypted(bigintToText(d))
      }
    } catch (e: unknown) {
      setEncError(e instanceof Error ? e.message : String(e))
    }
  }

  function handleDeterminism() {
    if (!keys) return
    const pk = { N: keys.N, e: keys.e }
    const m = textToBigint(message)
    setDetResult(determinismAttack(pk, m))
  }

  function handleBleichenbacher() {
    if (!keys) return
    const pk = { N: keys.N, e: keys.e }
    const sk = { N: keys.N, d: keys.d }
    const keyBytes = Math.ceil(keys.N.toString(2).length / 8)

    // Create a valid PKCS#1 v1.5 ciphertext
    const msgBytes = textToBytes(message)
    const c = pkcs15Encrypt(pk, msgBytes)
    setValidC(c)

    // Create a tampered ciphertext (just a random value)
    const tampered = (c + 42n) % pk.N
    setTamperedC(tampered)

    setOracleValidResult(null)
    setOracleTamperedResult(null)
    setBleichResult(bleichenbacherDemo(pk, sk, c, keyBytes))
  }

  function handleOracleQuery(valid: boolean) {
    if (!keys) return
    const sk = { N: keys.N, d: keys.d }
    const keyBytes = Math.ceil(keys.N.toString(2).length / 8)
    if (valid && validC !== null) {
      setOracleValidResult(paddingOracle(sk, validC, keyBytes))
    } else if (!valid && tamperedC !== null) {
      setOracleTamperedResult(paddingOracle(sk, tamperedC, keyBytes))
    }
  }

  /* ---------------------------------------------------------------- */
  /*  Styles                                                           */
  /* ---------------------------------------------------------------- */

  const card: React.CSSProperties = {
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: 12,
    padding: 20,
    marginBottom: 16,
  }
  const label: React.CSSProperties = { fontWeight: 600, marginBottom: 4, fontSize: 13, color: 'var(--text-h)' }
  const mono: React.CSSProperties = {
    fontFamily: 'var(--mono)',
    fontSize: 12,
    wordBreak: 'break-all',
    background: 'var(--accent-bg)',
    padding: '6px 10px',
    borderRadius: 6,
    marginTop: 4,
  }
  const btn: React.CSSProperties = {
    appearance: 'none',
    border: '1px solid var(--accent)',
    background: 'var(--accent-bg)',
    color: 'var(--accent)',
    fontFamily: 'inherit',
    fontWeight: 600,
    fontSize: 13,
    padding: '6px 16px',
    borderRadius: 6,
    cursor: 'pointer',
  }
  const banner = (ok: boolean): React.CSSProperties => ({
    padding: '8px 14px',
    borderRadius: 8,
    fontWeight: 600,
    fontSize: 13,
    marginTop: 8,
    background: ok ? '#e6f9e6' : '#fde8e8',
    color: ok ? '#1a7a1a' : '#b91c1c',
    border: `1px solid ${ok ? '#a3d9a3' : '#f5a3a3'}`,
  })

  /* ---------------------------------------------------------------- */
  /*  Render                                                           */
  /* ---------------------------------------------------------------- */

  return (
    <div style={{ padding: '24px 28px', maxWidth: 1200, margin: '0 auto' }}>
      <h2 style={{ margin: '0 0 4px', color: 'var(--text-h)' }}>PA#12 — Textbook RSA &amp; PKCS#1 v1.5</h2>
      <p style={{ margin: '0 0 20px', color: 'var(--text-m)', fontSize: 14 }}>
        RSA key generation, textbook encrypt/decrypt, PKCS#1 v1.5 padding, and attack demonstrations.
      </p>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
        {/* ========== LEFT PANEL ========== */}
        <div>
          {/* Key Generation */}
          <div style={card}>
            <div style={label}>Key Generation</div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginTop: 8 }}>
              <select
                value={bitLen}
                onChange={(e) => setBitLen(Number(e.target.value))}
                style={{ padding: '4px 8px', borderRadius: 4, fontFamily: 'inherit' }}
              >
                <option value={256}>256 bits</option>
                <option value={512}>512 bits</option>
              </select>
              <button style={btn} onClick={handleGenKeys} disabled={keyGenRunning}>
                {keyGenRunning ? 'Generating...' : 'Generate Keys'}
              </button>
              {keyGenTime !== null && (
                <span style={{ fontSize: 12, color: 'var(--text-m)' }}>
                  {keyGenTime.toFixed(0)} ms
                </span>
              )}
            </div>

            {keys && (
              <div style={{ marginTop: 12 }}>
                <div style={label}>Public Key (N, e)</div>
                <div style={mono}>N = {fmtBig(keys.N, 80)}</div>
                <div style={mono}>e = {keys.e.toString()}</div>

                <div style={{ ...label, marginTop: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
                  Private Key (d)
                  <button
                    style={{ ...btn, fontSize: 11, padding: '2px 8px' }}
                    onClick={() => setShowPrivate(!showPrivate)}
                  >
                    {showPrivate ? 'Hide' : 'Reveal'}
                  </button>
                </div>
                {showPrivate && <div style={mono}>d = {fmtBig(keys.d, 80)}</div>}

                <div style={{ ...label, marginTop: 12 }}>CRT Components</div>
                {showPrivate && (
                  <>
                    <div style={mono}>dp = {fmtBig(keys.dp, 60)}</div>
                    <div style={mono}>dq = {fmtBig(keys.dq, 60)}</div>
                    <div style={mono}>qinv = {fmtBig(keys.qinv, 60)}</div>
                  </>
                )}
                {!showPrivate && (
                  <div style={{ fontSize: 12, color: 'var(--text-m)', marginTop: 4 }}>
                    Click "Reveal" to show private key and CRT components
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Encrypt / Decrypt */}
          <div style={card}>
            <div style={label}>Encrypt / Decrypt</div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginTop: 8 }}>
              <input
                type="text"
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                placeholder="Enter short message"
                style={{
                  flex: 1,
                  padding: '6px 10px',
                  borderRadius: 6,
                  border: '1px solid var(--border)',
                  fontFamily: 'var(--mono)',
                  fontSize: 13,
                }}
              />
            </div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginTop: 8 }}>
              <label style={{ fontSize: 12, display: 'flex', alignItems: 'center', gap: 4 }}>
                <input
                  type="checkbox"
                  checked={usePkcs}
                  onChange={(e) => setUsePkcs(e.target.checked)}
                />
                PKCS#1 v1.5 padding
              </label>
              <button style={btn} onClick={handleEncrypt} disabled={!keys}>
                Encrypt &amp; Decrypt
              </button>
            </div>

            {encError && <div style={banner(false)}>{encError}</div>}

            {ciphertext !== null && (
              <div style={{ marginTop: 12 }}>
                <div style={label}>Ciphertext (C)</div>
                <div style={mono}>{fmtBig(ciphertext, 80)}</div>
                <div style={{ ...label, marginTop: 8 }}>Decrypted</div>
                <div style={mono}>{decrypted}</div>
              </div>
            )}
          </div>
        </div>

        {/* ========== RIGHT PANEL ========== */}
        <div>
          {/* Determinism Attack */}
          <div style={card}>
            <div style={label}>Attack: Deterministic Encryption</div>
            <p style={{ fontSize: 12, color: 'var(--text-m)', margin: '4px 0 8px' }}>
              Encrypt the same message twice. Textbook RSA produces identical ciphertexts;
              PKCS#1 v1.5 uses random padding to produce different ciphertexts.
            </p>
            <button style={btn} onClick={handleDeterminism} disabled={!keys}>
              Encrypt Twice
            </button>

            {detResult && (
              <div style={{ marginTop: 12 }}>
                <div style={label}>Textbook RSA</div>
                <div style={mono}>C1 = {fmtBig(detResult.textbookC1, 50)}</div>
                <div style={mono}>C2 = {fmtBig(detResult.textbookC2, 50)}</div>
                <div style={banner(!detResult.textbookMatch)}>
                  {detResult.textbookMatch
                    ? 'INSECURE: Identical ciphertexts -- deterministic encryption leaks equality'
                    : 'Different ciphertexts'}
                </div>

                <div style={{ ...label, marginTop: 12 }}>PKCS#1 v1.5</div>
                <div style={mono}>C1 = {fmtBig(detResult.pkcs15C1, 50)}</div>
                <div style={mono}>C2 = {fmtBig(detResult.pkcs15C2, 50)}</div>
                <div style={banner(!detResult.pkcs15Match)}>
                  {detResult.pkcs15Match
                    ? 'Identical ciphertexts (unexpected)'
                    : 'SECURE: Different ciphertexts -- random padding prevents equality leakage'}
                </div>
              </div>
            )}
          </div>

          {/* Bleichenbacher Padding Oracle */}
          <div style={card}>
            <div style={label}>Attack: Padding Oracle (Bleichenbacher)</div>
            <p style={{ fontSize: 12, color: 'var(--text-m)', margin: '4px 0 8px' }}>
              A padding oracle reveals whether decryption yields valid PKCS#1 v1.5 format.
              An attacker can exploit RSA's multiplicative homomorphism to query the oracle
              with tampered ciphertexts and learn information about the plaintext.
            </p>
            <button style={btn} onClick={handleBleichenbacher} disabled={!keys}>
              Run Oracle Demo
            </button>

            {bleichResult && (
              <div style={{ marginTop: 12 }}>
                <div style={label}>Padding Oracle Queries</div>

                <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 4 }}>Valid Ciphertext</div>
                    <div style={{ ...mono, fontSize: 11 }}>{validC !== null ? fmtBig(validC, 30) : '...'}</div>
                    <button
                      style={{ ...btn, marginTop: 6, fontSize: 11 }}
                      onClick={() => handleOracleQuery(true)}
                      disabled={validC === null}
                    >
                      Query Oracle
                    </button>
                    {oracleValidResult !== null && (
                      <div style={banner(oracleValidResult)}>
                        {oracleValidResult ? 'Valid padding' : 'Invalid padding'}
                      </div>
                    )}
                  </div>

                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 4 }}>Tampered Ciphertext</div>
                    <div style={{ ...mono, fontSize: 11 }}>{tamperedC !== null ? fmtBig(tamperedC, 30) : '...'}</div>
                    <button
                      style={{ ...btn, marginTop: 6, fontSize: 11 }}
                      onClick={() => handleOracleQuery(false)}
                      disabled={tamperedC === null}
                    >
                      Query Oracle
                    </button>
                    {oracleTamperedResult !== null && (
                      <div style={banner(!oracleTamperedResult)}>
                        {oracleTamperedResult ? 'Valid padding' : 'Invalid padding'}
                      </div>
                    )}
                  </div>
                </div>

                <div style={{ ...label, marginTop: 12 }}>Homomorphic Tampering (10 random multipliers)</div>
                <div style={{ maxHeight: 160, overflow: 'auto', marginTop: 4 }}>
                  {bleichResult.tamperedCiphertexts.map((t, i) => (
                    <div key={i} style={{ ...mono, fontSize: 11, marginTop: 2 }}>
                      s={fmtBig(t.s, 20)} {' -> '} oracle={t.oracleResult ? 'VALID' : 'INVALID'}
                    </div>
                  ))}
                </div>
                <div style={banner(!bleichResult.infoLeaked)}>
                  {bleichResult.infoLeaked
                    ? 'INSECURE: Oracle responses vary -- attacker learns information about plaintext'
                    : 'Oracle responses were uniform (try again with different parameters)'}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ========== BOTTOM: PROOF PANEL ========== */}
      <div style={{ ...card, marginTop: 8 }}>
        <div style={label}>Theory and Proofs</div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginTop: 12, fontSize: 13 }}>
          <div>
            <div style={{ fontWeight: 600, marginBottom: 4 }}>RSA Correctness</div>
            <div style={mono}>
              {'D(E(m)) = (m^e)^d = m^(ed) mod N\n'}
              {'Since ed = 1 + k*phi(N), by Euler\'s theorem:\n'}
              {'m^(ed) = m * (m^phi(N))^k = m * 1^k = m mod N'}
            </div>
          </div>
          <div>
            <div style={{ fontWeight: 600, marginBottom: 4 }}>Why Textbook RSA is Insecure</div>
            <ul style={{ margin: '4px 0', paddingLeft: 18, fontSize: 12, color: 'var(--text-m)' }}>
              <li><strong>Deterministic:</strong> Same message always produces the same ciphertext, enabling equality tests.</li>
              <li><strong>Malleable:</strong> Given E(m1) and E(m2), attacker can compute E(m1*m2) = E(m1)*E(m2) mod N.</li>
              <li><strong>No IND-CPA security:</strong> An adversary can win the CPA game with probability 1.</li>
            </ul>
          </div>
          <div>
            <div style={{ fontWeight: 600, marginBottom: 4 }}>PKCS#1 v1.5 Padding</div>
            <div style={mono}>
              {'EM = 0x00 || 0x02 || PS || 0x00 || M\n'}
              {'PS: random nonzero bytes, |PS| >= 8\n'}
              {'Adds randomness -> IND-CPA secure (heuristically)'}
            </div>
          </div>
          <div>
            <div style={{ fontWeight: 600, marginBottom: 4 }}>Bleichenbacher Attack (1998)</div>
            <ul style={{ margin: '4px 0', paddingLeft: 18, fontSize: 12, color: 'var(--text-m)' }}>
              <li>Exploits PKCS#1 v1.5 padding oracle: server reveals if padding is valid.</li>
              <li>RSA homomorphism: c' = c * s^e decrypts to m*s. Query oracle on c' to learn if m*s has valid padding.</li>
              <li>Iteratively narrow plaintext range using ~2^20 oracle queries.</li>
              <li>Key generation lineage: PA#13 Miller-Rabin generates primes for RSA.</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  )
}
