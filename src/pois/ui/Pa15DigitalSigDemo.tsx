/**
 * PA#15 — RSA Digital Signatures Demo
 *
 * Left panel:  Sign & Verify (hash-then-sign)
 * Right panel: Forgery demos (raw RSA vs hash-then-sign)
 * Bottom:      Proof panel with theory
 */

import { useState } from 'react'
import {
  rsaKeygen,
  sign,
  verify,
  hashToBigint,
  textToBytes,
  multiplicativeForgery,
  hashThenSignDefeatsForgery,
  eufCmaGame,
  type RSAKeyPair,
  type MultiplicativeForgeryResult,
  type HashForgeryResult,
  type EufCmaResult,
} from '../crypto/digitalSig'
import { modpow } from '../crypto/millerRabin'
import './poisCliqueExplorer.css'

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

function fmtBig(n: bigint, max = 60): string {
  const s = n.toString(16)
  if (s.length <= max) return '0x' + s
  return '0x' + s.slice(0, 20) + '...' + s.slice(-20) + ` (${s.length} hex digits)`
}

function fmtDec(n: bigint, max = 40): string {
  const s = n.toString()
  if (s.length <= max) return s
  return s.slice(0, 15) + '...' + s.slice(-15) + ` (${s.length} digits)`
}

/* ------------------------------------------------------------------ */
/*  Styles                                                             */
/* ------------------------------------------------------------------ */

const cardStyle: React.CSSProperties = {
  background: 'var(--surface, #1e1e2e)',
  borderRadius: 12,
  padding: 20,
  border: '1px solid var(--border, #333)',
}

const btnStyle: React.CSSProperties = {
  appearance: 'none',
  border: 'none',
  borderRadius: 8,
  padding: '8px 18px',
  fontWeight: 600,
  fontSize: 14,
  cursor: 'pointer',
  fontFamily: 'inherit',
  background: 'var(--accent, #7c3aed)',
  color: '#fff',
}

const monoStyle: React.CSSProperties = {
  fontFamily: 'monospace',
  fontSize: 13,
  wordBreak: 'break-all',
  background: 'var(--bg, #0d0d14)',
  padding: '6px 10px',
  borderRadius: 6,
  margin: '4px 0',
  lineHeight: 1.5,
}

const labelStyle: React.CSSProperties = {
  fontWeight: 600,
  fontSize: 13,
  color: 'var(--text-dim, #888)',
  marginBottom: 2,
}

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */

export default function Pa15DigitalSigDemo() {
  /* -- Key state -- */
  const [keys, setKeys] = useState<RSAKeyPair | null>(null)
  const [keyGenRunning, setKeyGenRunning] = useState(false)

  /* -- Sign/Verify state -- */
  const [message, setMessage] = useState('Hello Digital Signatures!')
  const [sigma, setSigma] = useState<bigint | null>(null)
  const [verifyResult, setVerifyResult] = useState<{
    valid: boolean
    sigmaE: bigint
    hm: bigint
  } | null>(null)
  const [tampered, setTampered] = useState(false)

  /* -- Forgery state -- */
  const [rawForgery, setRawForgery] = useState<MultiplicativeForgeryResult | null>(null)
  const [hashForgery, setHashForgery] = useState<HashForgeryResult | null>(null)
  const [eufCma, setEufCma] = useState<EufCmaResult | null>(null)
  const [forgeryRunning, setForgeryRunning] = useState(false)

  /* -- Handlers -- */
  const handleKeygen = () => {
    setKeyGenRunning(true)
    setSigma(null)
    setVerifyResult(null)
    setTampered(false)
    setRawForgery(null)
    setHashForgery(null)
    setEufCma(null)
    setTimeout(() => {
      const kp = rsaKeygen(256)
      setKeys(kp)
      setKeyGenRunning(false)
    }, 50)
  }

  const handleSign = () => {
    if (!keys) return
    const sk = { N: keys.N, d: keys.d }
    const msgBytes = textToBytes(message)
    const sig = sign(sk, msgBytes)
    setSigma(sig)
    setVerifyResult(null)
    setTampered(false)
  }

  const handleVerify = () => {
    if (!keys || sigma === null) return
    const pk = { N: keys.N, e: keys.e }
    const msgToVerify = tampered ? message + '!' : message
    const msgBytes = textToBytes(msgToVerify)
    const hm = hashToBigint(msgBytes)
    const sigmaE = modpow(sigma, pk.e, pk.N)
    const valid = verify(pk, msgBytes, sigma)
    setVerifyResult({ valid, sigmaE, hm })
  }

  const handleTamper = () => {
    setTampered(true)
    setVerifyResult(null)
  }

  const handleForgeryDemos = () => {
    if (!keys) return
    setForgeryRunning(true)
    setTimeout(() => {
      const pk = { N: keys.N, e: keys.e }
      const sk = { N: keys.N, d: keys.d }
      setRawForgery(multiplicativeForgery(pk, sk))
      setHashForgery(hashThenSignDefeatsForgery(pk, sk))
      setEufCma(eufCmaGame(pk, sk, 50))
      setForgeryRunning(false)
    }, 50)
  }

  return (
    <div style={{ padding: '28px 32px', maxWidth: 1300, margin: '0 auto' }}>
      <h2 style={{ marginBottom: 4 }}>PA#15 — RSA Digital Signatures</h2>
      <p style={{ color: 'var(--text-dim, #888)', marginTop: 0, marginBottom: 24 }}>
        Hash-then-sign using PA#12 RSA + PA#8 DLP hash. Multiplicative forgery on raw RSA, defeated by hashing.
      </p>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24 }}>
        {/* ============================================================ */}
        {/* LEFT PANEL: Sign & Verify                                     */}
        {/* ============================================================ */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={cardStyle}>
            <h3 style={{ marginTop: 0 }}>Key Generation</h3>
            <button style={btnStyle} onClick={handleKeygen} disabled={keyGenRunning}>
              {keyGenRunning ? 'Generating...' : 'Generate Keys (256-bit)'}
            </button>
            {keys && (
              <div style={{ marginTop: 12 }}>
                <div style={labelStyle}>Public Key (N, e)</div>
                <div style={monoStyle}>
                  N = {fmtBig(keys.N)}<br />
                  e = {keys.e.toString()}
                </div>
                <div style={labelStyle}>Private Key (d)</div>
                <div style={monoStyle}>
                  d = {fmtBig(keys.d)}
                </div>
              </div>
            )}
          </div>

          <div style={cardStyle}>
            <h3 style={{ marginTop: 0 }}>Sign & Verify</h3>
            <div style={labelStyle}>Message</div>
            <input
              type="text"
              value={message}
              onChange={e => { setMessage(e.target.value); setSigma(null); setVerifyResult(null); setTampered(false) }}
              style={{
                width: '100%',
                padding: '8px 12px',
                borderRadius: 6,
                border: '1px solid var(--border, #333)',
                background: 'var(--bg, #0d0d14)',
                color: 'var(--text-h, #eee)',
                fontFamily: 'monospace',
                fontSize: 14,
                boxSizing: 'border-box',
              }}
            />

            <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
              <button style={btnStyle} onClick={handleSign} disabled={!keys}>
                Sign
              </button>
              <button style={btnStyle} onClick={handleVerify} disabled={!keys || sigma === null}>
                Verify{tampered ? ' (tampered)' : ''}
              </button>
              <button
                style={{ ...btnStyle, background: '#b91c1c' }}
                onClick={handleTamper}
                disabled={!keys || sigma === null}
              >
                Tamper Message
              </button>
            </div>

            {sigma !== null && (
              <div style={{ marginTop: 12 }}>
                <div style={labelStyle}>Signature (sigma)</div>
                <div style={monoStyle}>{fmtBig(sigma)}</div>
                {tampered && (
                  <div style={{ color: '#f59e0b', fontSize: 13, marginTop: 4 }}>
                    Message tampered: appended "!" to the message
                  </div>
                )}
              </div>
            )}

            {verifyResult && (
              <div style={{ marginTop: 12 }}>
                <div style={labelStyle}>Verification</div>
                <div style={monoStyle}>
                  sigma^e mod N = {fmtBig(verifyResult.sigmaE)}<br />
                  H(m)&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;= {fmtBig(verifyResult.hm)}
                </div>
                <div style={{
                  marginTop: 8,
                  padding: '8px 14px',
                  borderRadius: 8,
                  fontWeight: 700,
                  fontSize: 14,
                  background: verifyResult.valid ? '#166534' : '#7f1d1d',
                  color: '#fff',
                  display: 'inline-block',
                }}>
                  {verifyResult.valid ? 'Signature VALID' : 'Signature INVALID'}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* ============================================================ */}
        {/* RIGHT PANEL: Forgery Demos                                    */}
        {/* ============================================================ */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={cardStyle}>
            <h3 style={{ marginTop: 0 }}>Forgery Demos</h3>
            <button
              style={btnStyle}
              onClick={handleForgeryDemos}
              disabled={!keys || forgeryRunning}
            >
              {forgeryRunning ? 'Running...' : 'Run All Forgery Demos'}
            </button>
          </div>

          {/* Raw RSA Forgery */}
          {rawForgery && (
            <div style={cardStyle}>
              <h4 style={{ marginTop: 0, color: '#f59e0b' }}>Raw RSA Multiplicative Forgery</h4>
              <div style={monoStyle}>
                m1 = {rawForgery.m1.toString()}<br />
                m2 = {rawForgery.m2.toString()}<br />
                sigma1 = signRaw(m1) = {fmtBig(rawForgery.sigma1)}<br />
                sigma2 = signRaw(m2) = {fmtBig(rawForgery.sigma2)}<br />
                <br />
                m_forged = m1 * m2 mod N = {fmtDec(rawForgery.mForged)}<br />
                sigma_forged = sigma1 * sigma2 mod N = {fmtBig(rawForgery.sigmaForged)}
              </div>
              <div style={{
                marginTop: 8,
                padding: '8px 14px',
                borderRadius: 8,
                fontWeight: 700,
                fontSize: 14,
                background: rawForgery.forgerySucceeded ? '#166534' : '#7f1d1d',
                color: '#fff',
                display: 'inline-block',
              }}>
                {rawForgery.forgerySucceeded
                  ? 'Forgery succeeded! Raw RSA is insecure.'
                  : 'Forgery failed'}
              </div>
            </div>
          )}

          {/* Hash-then-sign defeats forgery */}
          {hashForgery && (
            <div style={cardStyle}>
              <h4 style={{ marginTop: 0, color: '#3b82f6' }}>Hash-then-Sign Defeats Forgery</h4>
              <div style={monoStyle}>
                H(m1) = {fmtBig(hashForgery.hm1)}<br />
                H(m2) = {fmtBig(hashForgery.hm2)}<br />
                H(m1)*H(m2) mod N = {fmtBig(hashForgery.hProductOfInputs)}<br />
                H(m1*m2 mod N)&nbsp;&nbsp;&nbsp;= {fmtBig(hashForgery.hProduct)}<br />
                <br />
                H(m1)*H(m2) != H(m1*m2) -- hash is NOT multiplicative
              </div>
              <div style={{
                marginTop: 8,
                padding: '8px 14px',
                borderRadius: 8,
                fontWeight: 700,
                fontSize: 14,
                background: hashForgery.forgerySucceeded ? '#166534' : '#7f1d1d',
                color: '#fff',
                display: 'inline-block',
              }}>
                {hashForgery.forgerySucceeded
                  ? 'Forgery succeeded!'
                  : 'Forgery failed -- H is not multiplicative'}
              </div>
            </div>
          )}

          {/* EUF-CMA game */}
          {eufCma && (
            <div style={cardStyle}>
              <h4 style={{ marginTop: 0, color: '#a78bfa' }}>EUF-CMA Security Game</h4>
              <div style={{ fontSize: 13, marginBottom: 8, color: 'var(--text-dim, #888)' }}>
                Adversary made {eufCma.queries.length} signing oracle queries,
                then attempted {eufCma.forgeryAttempts.length} forgeries on new messages.
              </div>
              <div style={monoStyle}>
                Oracle queries: {eufCma.queries.length}<br />
                Forgery attempts: {eufCma.forgeryAttempts.length}<br />
                Successful forgeries: {eufCma.forgeryAttempts.filter(a => a.valid).length}
              </div>
              <div style={{
                marginTop: 8,
                padding: '8px 14px',
                borderRadius: 8,
                fontWeight: 700,
                fontSize: 14,
                background: eufCma.adversaryWon ? '#7f1d1d' : '#166534',
                color: '#fff',
                display: 'inline-block',
              }}>
                {eufCma.adversaryWon
                  ? 'Adversary won!'
                  : `Adversary failed: ${eufCma.queries.length} queries, 0 forgeries`}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ============================================================ */}
      {/* BOTTOM: Proof Panel                                           */}
      {/* ============================================================ */}
      <div style={{ ...cardStyle, marginTop: 24 }}>
        <h3 style={{ marginTop: 0, color: 'var(--accent, #7c3aed)' }}>Theory: RSA Digital Signatures</h3>
        <div style={{ fontSize: 14, lineHeight: 1.7, color: 'var(--text-h, #ddd)' }}>
          <p>
            <strong>RSA Signatures</strong> use the private key to sign and the public key to verify.
            Given key pair (N, e, d), signing a message m produces sigma = m^d mod N, and
            verification checks sigma^e mod N = m.
          </p>
          <p>
            <strong>Why hashing is essential:</strong> Raw RSA signatures are
            <em> multiplicatively homomorphic</em>: given sigma1 = m1^d and sigma2 = m2^d,
            an adversary can compute sigma1 * sigma2 mod N = (m1*m2)^d mod N, which is a
            valid signature on m1*m2 without knowing d. Hash-then-sign defeats this because
            H(m1*m2) != H(m1)*H(m2) for any collision-resistant hash function H.
          </p>
          <p>
            <strong>EUF-CMA security:</strong> A signature scheme is EUF-CMA secure if no
            efficient adversary, even with access to a signing oracle on chosen messages, can
            forge a valid signature on any new message. RSA hash-then-sign with a
            collision-resistant hash achieves this under the RSA assumption.
          </p>
          <p style={{ color: 'var(--text-dim, #888)', fontSize: 13, marginBottom: 0 }}>
            <strong>Lineage:</strong> PA#15 (Digital Signatures) depends on PA#12 (RSA) + PA#8 (DLP Hash),
            which in turn depend on PA#13 (Miller-Rabin Primality) + PA#7 (Merkle-Damgard).
          </p>
        </div>
      </div>
    </div>
  )
}
