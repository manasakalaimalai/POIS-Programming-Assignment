import { useState } from 'react'
import PoisCliqueExplorer from './pois/ui/PoisCliqueExplorer'
import Pa1Demo from './pois/ui/Pa1Demo'
import Pa2GgmVisualizer from './pois/ui/Pa2GgmVisualizer'
import Pa3CpaDemo from './pois/ui/Pa3CpaDemo'
import Pa4ModesDemo from './pois/ui/Pa4ModesDemo'
import Pa5MacDemo from './pois/ui/Pa5MacDemo'
import Pa6CcaDemo from './pois/ui/Pa6CcaDemo'
import Pa7MerkleDamgardDemo from './pois/ui/Pa7MerkleDamgardDemo'
import Pa8DlpHashDemo from './pois/ui/Pa8DlpHashDemo'
import Pa9BirthdayDemo from './pois/ui/Pa9BirthdayDemo'
import Pa10HmacDemo from './pois/ui/Pa10HmacDemo'
import Pa11DiffieHellmanDemo from './pois/ui/Pa11DiffieHellmanDemo'
import Pa12RsaDemo from './pois/ui/Pa12RsaDemo'
import Pa13MillerRabinDemo from './pois/ui/Pa13MillerRabinDemo'
import Pa14CrtDemo from './pois/ui/Pa14CrtDemo'
import Pa15DigitalSigDemo from './pois/ui/Pa15DigitalSigDemo'
import Pa16ElGamalDemo from './pois/ui/Pa16ElGamalDemo'
import Pa17CcaPkcDemo from './pois/ui/Pa17CcaPkcDemo'
import './App.css'

const TABS = [
  { id: 'clique', label: 'Clique Explorer' },
  { id: 'pa1',    label: 'PA1 — OWF/PRG' },
  { id: 'pa2',    label: 'PA2 — PRF/GGM' },
  { id: 'pa3',    label: 'PA3 — CPA-Enc' },
  { id: 'pa4',    label: 'PA4 — Modes' },
  { id: 'pa5',    label: 'PA5 — MAC' },
  { id: 'pa6',    label: 'PA6 — CCA-Enc' },
  { id: 'pa7',    label: 'PA7 — Merkle-Damgård' },
  { id: 'pa8',    label: 'PA8 — DLP Hash' },
  { id: 'pa9',    label: 'PA9 — Birthday' },
  { id: 'pa10',   label: 'PA10 — HMAC' },
  { id: 'pa11',   label: 'PA11 — Diffie-Hellman' },
  { id: 'pa12',   label: 'PA12 — RSA' },
  { id: 'pa13',   label: 'PA13 — Primality' },
  { id: 'pa14',   label: 'PA14 — CRT' },
  { id: 'pa15',   label: 'PA15 — Digital Sig' },
  { id: 'pa16',   label: 'PA16 — ElGamal' },
  { id: 'pa17',   label: 'PA17 — CCA PKC' },
] as const
type TabId = (typeof TABS)[number]['id']

export default function App() {
  const [tab, setTab] = useState<TabId>('clique')

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* Tab bar */}
      <div style={{
        display: 'flex',
        gap: 2,
        padding: '10px 18px 0',
        borderBottom: '1px solid var(--border)',
        background: 'var(--surface)',
      }}>
        {TABS.map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            style={{
              appearance: 'none',
              border: 'none',
              background: tab === t.id ? 'var(--accent-bg)' : 'transparent',
              color: 'var(--text-h)',
              fontFamily: 'inherit',
              fontWeight: tab === t.id ? 700 : 500,
              fontSize: 14,
              padding: '8px 16px',
              borderRadius: '8px 8px 0 0',
              cursor: 'pointer',
              borderBottom: tab === t.id ? '2px solid var(--accent)' : '2px solid transparent',
              transition: 'background 0.15s, border-color 0.15s',
              opacity: tab === t.id ? 1 : 0.72,
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div style={{ flex: 1 }}>
        {tab === 'clique' && <PoisCliqueExplorer />}
        {tab === 'pa1'    && <Pa1Demo />}
        {tab === 'pa2'    && <Pa2GgmVisualizer />}
        {tab === 'pa3'    && <Pa3CpaDemo />}
        {tab === 'pa4'    && <Pa4ModesDemo />}
        {tab === 'pa5'    && <Pa5MacDemo />}
        {tab === 'pa6'    && <Pa6CcaDemo />}
        {tab === 'pa7'    && <Pa7MerkleDamgardDemo />}
        {tab === 'pa8'    && <Pa8DlpHashDemo />}
        {tab === 'pa9'    && <Pa9BirthdayDemo />}
        {tab === 'pa10'   && <Pa10HmacDemo />}
        {tab === 'pa11'   && <Pa11DiffieHellmanDemo />}
        {tab === 'pa12'   && <Pa12RsaDemo />}
        {tab === 'pa13'   && <Pa13MillerRabinDemo />}
        {tab === 'pa14'   && <Pa14CrtDemo />}
        {tab === 'pa15'   && <Pa15DigitalSigDemo />}
        {tab === 'pa16'   && <Pa16ElGamalDemo />}
        {tab === 'pa17'   && <Pa17CcaPkcDemo />}
      </div>
    </div>
  )
}
