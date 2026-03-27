# POIS Programming Assignment

Interactive visualizer for the cryptographic reduction chain **OWF → PRG → PRF → PRP**, built for CS 8.401 Principles of Information Security.

## What's inside

| Tab | What it does |
|-----|-------------|
| **Clique Explorer** | Step through the full reduction graph — pick a foundation (AES-128 or DLP), source primitive, and target primitive to see the live reduction trace |
| **PA1 — OWF/PRG** | AES Davies-Meyer OWF and DLP OWF (`f(x) = g^x mod p`), HILL PRG construction, NIST SP 800-22 randomness tests |
| **PA2 — PRF/GGM** | GGM PRF binary tree visualizer, AES plug-in PRF, χ² distinguishing game |

## Prerequisites

- **Node.js** v18+ (project uses v22)
- **npm** v9+

## Getting started

```bash
# 1. Clone
git clone https://github.com/manasakalaimalai/POIS-Programming-Assignment.git
cd POIS-Programming-Assignment

# 2. Install dependencies
npm install

# 3. Start dev server
npm run dev
```

Open **http://localhost:5173** in your browser.

## Other commands

```bash
npm run build      # type-check + production build → dist/
npm run preview    # preview the production build locally
```

## Project structure

```
src/
├── App.tsx                        # Tab bar — routes between the three views
└── pois/
    ├── crypto/
    │   ├── aes128.ts              # AES-128 scratch implementation (FIPS 197)
    │   ├── dlp.ts                 # DLP OWF: f(x) = g^x mod p
    │   ├── owf.ts                 # OWF oracle factories (AES Davies-Meyer, DLP)
    │   ├── prg.ts                 # HILL PRG, fast AES split PRG for GGM
    │   └── prf.ts                 # GGM PRF, AES PRF, distinguishing game
    ├── stats/
    │   └── randomness.ts          # NIST SP 800-22: monobit, block freq, runs
    ├── engine/
    │   ├── leg1.ts                # Builds primitive instances along the clique
    │   └── leg2.ts                # Applies reductions between primitives
    ├── foundation/
    │   └── foundation.ts          # Wires AES / DLP into the oracle abstraction
    ├── reductions/
    │   ├── edges.ts               # Forward + backward reduction edges
    │   └── routing.ts             # BFS route finder across the clique graph
    └── ui/
        ├── PoisCliqueExplorer.tsx  # PA0 — clique explorer UI
        ├── Pa1Demo.tsx             # PA1 — OWF/PRG playground
        └── Pa2GgmVisualizer.tsx    # PA2 — GGM tree + distinguishing game
```

## Contributing

1. Create a branch: `git checkout -b pa3-your-name`
2. Make your changes
3. `npm run build` must pass with zero errors before opening a PR
4. Open a pull request against `main`

Higher PA stubs (MAC, CRHF, HMAC) are marked `not_implemented` with `duePa` annotations in `src/pois/reductions/edges.ts` — that's the starting point for PA3+.
