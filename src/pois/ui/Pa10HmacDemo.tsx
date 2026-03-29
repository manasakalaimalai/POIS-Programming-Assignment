/**
 * PA#10 --- HMAC and Length-Extension Attack Demo
 */
import { useState, useCallback } from 'react'
import {
  hmac,
  naiveMac,
  lengthExtensionAttack,
  hmacEufCmaGame,
  macToCrhf,
  ethEncrypt,
  ethDecrypt,
  type EufCmaResult,
} from '../crypto/hmac'
import { bytesToHex, hexToBytes } from '../utils/hex'
import './poisCliqueExplorer.css'

const enc = new TextEncoder()

export default function Pa10HmacDemo() {
  // Shared inputs
  const [keyHex, setKeyHex] = useState('deadbeef')
  const [message, setMessage] = useState('Hello, HMAC!')
  const [suffix, setSuffix] = useState('evil')

  // EUF-CMA result
  const [eufResult, setEufResult] = useState<EufCmaResult | null>(null)
  const [eufRunning, setEufRunning] = useState(false)

  // EtH state
  const [ethMsg, setEthMsg] = useState('Secret message')
  const [ethResult, setEthResult] = useState<{
    r: string; ct: string; tag: string; decrypted: string; tamperResult: string
  } | null>(null)

  // Compute key bytes
  let keyBytes: Uint8Array
  try {
    keyBytes = hexToBytes(keyHex)
  } catch {
    keyBytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef])
  }

  const msgBytes = enc.encode(message)
  const suffixBytes = enc.encode(suffix)

  // Naive MAC
  const naiveTag = naiveMac(keyBytes, msgBytes)
  const naiveTagHex = bytesToHex(naiveTag)

  // HMAC
  const hmacTag = hmac(keyBytes, msgBytes)
  const hmacTagHex = bytesToHex(hmacTag)

  // Length-extension attack
  const attackResult = lengthExtensionAttack(keyBytes, msgBytes, suffixBytes)

  // EUF-CMA game
  const runEufCma = useCallback(() => {
    setEufRunning(true)
    setEufResult(null)
    setTimeout(() => {
      const result = hmacEufCmaGame(50)
      setEufResult(result)
      setEufRunning(false)
    }, 50)
  }, [])

  // Encrypt-then-HMAC demo
  const runEth = useCallback(() => {
    const kE = new Uint8Array(4)
    const kM = new Uint8Array(4)
    crypto.getRandomValues(kE)
    crypto.getRandomValues(kM)
    const plain = enc.encode(ethMsg)
    const { r, ciphertext, tag } = ethEncrypt(kE, kM, plain)

    // Decrypt correctly
    const dec = ethDecrypt(kE, kM, r, ciphertext, tag)
    const decrypted = dec ? new TextDecoder().decode(dec) : '(failed)'

    // Tamper with ciphertext
    const tampered = new Uint8Array(ciphertext)
    tampered[0] ^= 0xff
    const tamperDec = ethDecrypt(kE, kM, r, tampered, tag)
    const tamperResult = tamperDec === null ? 'Rejected (null) -- CCA secure!' : new TextDecoder().decode(tamperDec)

    setEthResult({
      r: bytesToHex(r),
      ct: bytesToHex(ciphertext),
      tag: bytesToHex(tag),
      decrypted,
      tamperResult,
    })
  }, [ethMsg])

  // MAC => CRHF demo
  const macCrhfHash = (() => {
    const { hash } = macToCrhf(
      (k, m) => hmac(k, m),
      keyBytes,
    )
    return bytesToHex(hash(msgBytes))
  })()

  return (
    <div className="poisApp">
      <div className="topBar">
        <div className="topTitle">
          <span className="topTitleMain">PA#10 HMAC</span>
          <span className="topTitleSub">
            HMAC_k(m) = H((k &oplus; opad) || H((k &oplus; ipad) || m)) &nbsp;|&nbsp;
            Length-Extension Attack &nbsp;|&nbsp; Encrypt-then-HMAC
          </span>
        </div>
      </div>

      <div className="mainArea">
        {/* ---- Left panel: Length-Extension Attack (Broken H(k||m)) ---- */}
        <div className="panel" style={{ flex: 1 }}>
          <div className="panelTitle">Naive MAC: H(k || m) -- Length Extension</div>

          <div className="field">
            <label className="fieldLabel">Key (hex)</label>
            <input
              className="input"
              value={keyHex}
              onChange={(e) => setKeyHex(e.target.value)}
              placeholder="deadbeef"
            />
          </div>

          <div className="field">
            <label className="fieldLabel">Message (text)</label>
            <input
              className="input"
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              placeholder="Hello, HMAC!"
            />
          </div>

          <div className="field">
            <label className="fieldLabel">Naive tag: H(k || m)</label>
            <div className="outputBox mono">{naiveTagHex}</div>
          </div>

          <div className="field">
            <label className="fieldLabel">Suffix to extend (text)</label>
            <input
              className="input"
              value={suffix}
              onChange={(e) => setSuffix(e.target.value)}
              placeholder="evil"
            />
          </div>

          <div className="field">
            <label className="fieldLabel">Attack result</label>
            <div className="traceStep">
              <span className="traceKey">MD padding inserted</span>
              <span className="traceVal mono">{bytesToHex(attackResult.paddingBytes)}</span>
            </div>
            <div className="traceStep">
              <span className="traceKey">Forged tag (no key)</span>
              <span className="traceVal mono">{bytesToHex(attackResult.forgedTag)}</span>
            </div>
            <div className="traceStep">
              <span className="traceKey">Actual tag H(k||m||pad||suffix)</span>
              <span className="traceVal mono">{bytesToHex(attackResult.actualTag)}</span>
            </div>
          </div>

          <div className="traceStep">
            {attackResult.naiveAttackSucceeds ? (
              <span className="traceBadge traceBadgeOk" style={{ background: '#22c55e', color: '#fff', padding: '6px 14px', borderRadius: 6, fontWeight: 700 }}>
                Forgery succeeded on H(k||m)!
              </span>
            ) : (
              <span className="traceBadge" style={{ background: '#ef4444', color: '#fff', padding: '6px 14px', borderRadius: 6, fontWeight: 700 }}>
                Forgery failed (unexpected)
              </span>
            )}
          </div>
        </div>

        {/* ---- Right panel: HMAC (Secure) ---- */}
        <div className="panel" style={{ flex: 1 }}>
          <div className="panelTitle">HMAC (Secure)</div>

          <div className="field">
            <label className="fieldLabel">HMAC_k(m)</label>
            <div className="outputBox mono">{hmacTagHex}</div>
          </div>

          <div className="field">
            <label className="fieldLabel">Same length-extension attempt</label>
            <div className="traceStep">
              <span className="traceKey">HMAC tag on original message</span>
              <span className="traceVal mono">{bytesToHex(attackResult.hmacOriginalTag)}</span>
            </div>
            <div className="traceStep">
              {attackResult.hmacAttackSucceeds ? (
                <span className="traceBadge traceBadgeOk" style={{ background: '#22c55e', color: '#fff', padding: '6px 14px', borderRadius: 6, fontWeight: 700 }}>
                  Forgery succeeded (unexpected!)
                </span>
              ) : (
                <span className="traceBadge" style={{ background: '#ef4444', color: '#fff', padding: '6px 14px', borderRadius: 6, fontWeight: 700 }}>
                  Forgery failed -- HMAC blocks length extension
                </span>
              )}
            </div>
          </div>

          {/* EUF-CMA Game */}
          <div className="field" style={{ marginTop: 16 }}>
            <label className="fieldLabel">EUF-CMA Forgery Game (50 queries)</label>
            <button
              className="input"
              onClick={runEufCma}
              disabled={eufRunning}
              style={{ cursor: eufRunning ? 'wait' : 'pointer', fontWeight: 600, textAlign: 'center' }}
            >
              {eufRunning ? 'Running...' : 'Run EUF-CMA Game'}
            </button>
            {eufResult && (
              <div style={{ marginTop: 8 }}>
                <div className="traceStep">
                  <span className="traceKey">Signing queries</span>
                  <span className="traceVal">{eufResult.queries}</span>
                </div>
                <div className="traceStep">
                  <span className="traceKey">Forgery attempts</span>
                  <span className="traceVal">{eufResult.forgeryAttempts}</span>
                </div>
                <div className="traceStep">
                  <span className="traceKey">Forgery succeeded?</span>
                  <span className="traceVal" style={{ color: eufResult.forgerySucceeded ? '#22c55e' : '#ef4444', fontWeight: 700 }}>
                    {eufResult.forgerySucceeded ? 'Yes (unexpected!)' : 'No -- HMAC is EUF-CMA secure'}
                  </span>
                </div>
              </div>
            )}
          </div>

          {/* MAC => CRHF */}
          <div className="field" style={{ marginTop: 16 }}>
            <label className="fieldLabel">MAC to CRHF (backward reduction)</label>
            <div className="traceStep">
              <span className="traceKey">h&apos;(cv, block) = HMAC_k(cv || block)</span>
              <span className="traceVal mono">{macCrhfHash}</span>
            </div>
          </div>

          {/* Encrypt-then-HMAC */}
          <div className="field" style={{ marginTop: 16 }}>
            <label className="fieldLabel">Encrypt-then-HMAC (CCA-secure)</label>
            <input
              className="input"
              value={ethMsg}
              onChange={(e) => setEthMsg(e.target.value)}
              placeholder="Secret message"
            />
            <button
              className="input"
              onClick={runEth}
              style={{ cursor: 'pointer', fontWeight: 600, textAlign: 'center', marginTop: 6 }}
            >
              Encrypt &amp; Decrypt
            </button>
            {ethResult && (
              <div style={{ marginTop: 8 }}>
                <div className="traceStep">
                  <span className="traceKey">r (nonce)</span>
                  <span className="traceVal mono">{ethResult.r}</span>
                </div>
                <div className="traceStep">
                  <span className="traceKey">Ciphertext</span>
                  <span className="traceVal mono">{ethResult.ct}</span>
                </div>
                <div className="traceStep">
                  <span className="traceKey">HMAC tag</span>
                  <span className="traceVal mono">{ethResult.tag}</span>
                </div>
                <div className="traceStep">
                  <span className="traceKey">Decrypted</span>
                  <span className="traceVal">{ethResult.decrypted}</span>
                </div>
                <div className="traceStep">
                  <span className="traceKey">Tampered ciphertext</span>
                  <span className="traceVal" style={{ color: '#ef4444', fontWeight: 700 }}>
                    {ethResult.tamperResult}
                  </span>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ---- Bottom: Proof Panel ---- */}
      <div style={{ padding: '0 18px 18px' }}>
        <div className="proofPanel">
          <div className="proofSummary">HMAC Construction and Security</div>
          <div className="proofBody">
            <div className="proofStep">
              <div className="proofStepMain">Why H(k || m) is Broken</div>
              <div className="proofStepSub">
                Merkle-Damgard hashes process messages block by block. Given H(k || m) = tag,
                an attacker can continue hashing from tag as the chaining value:
                H(k || m || padding || m&apos;) = MD(m&apos;, cv = tag). The attacker does not need the key
                because the chaining value (= tag) is public. This is the <em>length-extension attack</em>.
              </div>
            </div>
            <div className="proofStep">
              <div className="proofStepMain">HMAC: Inner + Outer Hash</div>
              <div className="proofStepSub">
                HMAC_k(m) = H((k &oplus; opad) || H((k &oplus; ipad) || m)).
                The inner hash H((k &oplus; ipad) || m) produces an intermediate digest.
                The outer hash wraps this digest with (k &oplus; opad), so the attacker cannot
                extend the computation: extending the inner hash does not help because the outer
                hash re-keys the result. The two different pads (ipad = 0x36, opad = 0x5C) ensure
                the inner and outer keys are domain-separated.
              </div>
            </div>
            <div className="proofStep">
              <div className="proofStepMain">CRHF &rArr; MAC (Forward)</div>
              <div className="proofStepSub">
                If the underlying hash H is a collision-resistant PRF in both the inner and outer
                invocations, HMAC is EUF-CMA secure. An adversary making q signing queries has
                advantage at most q / 2<sup>n</sup> in forging a tag on a new message (where n is the
                output bit length). The demo runs 50 queries and 100 forgery attempts, all of which fail.
              </div>
            </div>
            <div className="proofStep">
              <div className="proofStepMain">MAC &rArr; CRHF (Backward)</div>
              <div className="proofStepSub">
                Given a secure MAC, define a compression function h&apos;(cv, block) = MAC_k(cv || block).
                Plug h&apos; into Merkle-Damgard to get a CRHF. If an adversary finds a collision
                (m, m&apos;) with H&apos;(m) = H&apos;(m&apos;), this yields two distinct inputs to h&apos; with the same
                output, which constitutes a MAC forgery (contradiction). This establishes the
                bidirectional relationship: CRHF &hArr; MAC.
              </div>
            </div>
            <div className="proofStep">
              <div className="proofStepMain">Encrypt-then-HMAC (CCA Security)</div>
              <div className="proofStepSub">
                The Encrypt-then-MAC paradigm: encrypt with key k<sub>E</sub>, then MAC the ciphertext
                (including nonce r) with key k<sub>M</sub>. On decryption, verify the MAC <em>first</em>;
                reject if invalid. This achieves CCA security because any tampering with the ciphertext
                invalidates the MAC tag, so the decryption oracle reveals nothing to the adversary.
                The demo shows that flipping a single bit in the ciphertext causes rejection.
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
