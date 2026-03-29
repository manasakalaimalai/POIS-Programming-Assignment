# POIS Programming Assignment

Interactive visualizer for the **full cryptographic reduction chain** from One-Way Functions to Secure Multi-Party Computation, built for **CS 8.401 Principles of Information Security**.

The app implements all 21 programming assignments (PA#0 through PA#20) as a single React web application with a tab per PA. Every cryptographic primitive is built from scratch — no external crypto libraries. Each PA includes an interactive demo with live hex values, attack demonstrations, and security proof summaries.

## The Cryptographic Stack

```
                        OWF (PA#1)
                       /          \
                    PRG (PA#1)    OWP
                      |
                    PRF (PA#2)
                   /    |    \
               PRP    MAC (PA#5)    CPA-Enc (PA#3)
             (PA#4)     |              |
              |      CRHF (PA#7-8)  CCA-Enc (PA#6)
              |         |
             CBC/     HMAC (PA#10)
            OFB/CTR     |
                     Birthday (PA#9)

          PKC: DH (PA#11), RSA (PA#12), ElGamal (PA#16)
          Math: Miller-Rabin (PA#13), CRT (PA#14)
          Signatures (PA#15) → CCA-PKC (PA#17)

          OT (PA#18) → Secure AND (PA#19) → Full MPC (PA#20)
```

## All 21 Tabs

| Tab | PA# | Topic | Key Features |
|-----|-----|-------|-------------|
| Clique Explorer | #0 | Minicrypt Clique | Two-column reduction viewer, foundation toggle (AES/DLP), proof summaries |
| OWF/PRG | #1 | One-Way Functions & PRG | AES Davies-Meyer OWF, DLP OWF, HILL PRG, NIST SP 800-22 tests |
| PRF/GGM | #2 | Pseudorandom Functions | GGM tree visualizer, AES plug-in PRF, chi-squared distinguishing game |
| CPA-Enc | #3 | CPA-Secure Encryption | C = (r, F_k(r) XOR m), IND-CPA game, nonce reuse attack |
| Modes | #4 | Block Cipher Modes | CBC, OFB, CTR with AES-128, IV-reuse and keystream-reuse attacks |
| MAC | #5 | Message Authentication | PRF-MAC, CBC-MAC, EUF-CMA forgery game |
| CCA-Enc | #6 | CCA-Secure Encryption | Encrypt-then-MAC, malleability attack blocked by MAC |
| Merkle-Damgard | #7 | Hash Transform | Generic MD framework, MD-strengthening padding, collision propagation |
| DLP Hash | #8 | Collision-Resistant Hash | h(x,y) = g^x * h^y mod p, birthday collision demo |
| Birthday | #9 | Birthday Attack | Naive sort-based + Floyd's cycle detection, empirical curve |
| HMAC | #10 | HMAC & CCA Encryption | Length-extension attack on H(k\|\|m), HMAC defeats it, Encrypt-then-HMAC |
| Diffie-Hellman | #11 | Key Exchange | DH protocol, MITM attack demo, CDH brute-force |
| RSA | #12 | Textbook RSA | Keygen, PKCS#1 v1.5, determinism attack, Bleichenbacher oracle |
| Primality | #13 | Miller-Rabin | Carmichael number 561 demo, prime generation, PNT benchmarking |
| CRT | #14 | Chinese Remainder Theorem | CRT solver, Garner's RSA-CRT (~4x speedup), Hastad broadcast attack |
| Digital Sig | #15 | RSA Signatures | Hash-then-sign, multiplicative forgery on raw RSA, EUF-CMA game |
| ElGamal | #16 | ElGamal PKC | Probabilistic encryption, malleability (c1, 2c2) -> 2m, IND-CPA game |
| CCA PKC | #17 | CCA-Secure PKC | Encrypt-then-Sign (ElGamal + RSA Sig), malleability blocked |
| OT | #18 | Oblivious Transfer | Bellare-Micali 1-out-of-2 OT, receiver/sender privacy demos |
| Secure Gates | #19 | Secure AND/XOR/NOT | AND via OT, XOR via secret sharing (free), truth table verification |
| MPC | #20 | 2-Party Computation | Boolean circuit evaluator, Millionaire's Problem, Equality, Addition |

## No External Crypto Libraries

Every cryptographic primitive is implemented from scratch. The only permitted external functions are:
- `crypto.getRandomValues()` for OS-level randomness
- JavaScript `BigInt` for arbitrary-precision arithmetic

The dependency chain is fully traceable:
```
PA#20 (MPC) → PA#19 (Secure AND) → PA#18 (OT) → PA#16 (ElGamal) → PA#11 (DH) → PA#13 (Miller-Rabin)
```

## Prerequisites

- **Node.js** v20+ (project tested with v22 and v25)
- **npm** v9+

## Getting Started

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

## Other Commands

```bash
npm run build      # type-check + production build -> dist/
npm run preview    # preview the production build locally
```

## Project Structure

```
src/
├── App.tsx                             # Tab bar — routes between all 21 views
├── main.tsx                            # React entry point
└── pois/
    ├── crypto/                         # All cryptographic implementations
    │   ├── aes128.ts                   # AES-128 from scratch (FIPS 197)
    │   ├── dlp.ts                      # DLP OWF: f(x) = g^x mod p
    │   ├── owf.ts                      # OWF oracle factories
    │   ├── prg.ts                      # HILL PRG + fast AES split PRG
    │   ├── prf.ts                      # GGM PRF + AES plug-in + distinguishing game
    │   ├── cpaEnc.ts                   # PA#3: CPA-secure encryption
    │   ├── blockModes.ts               # PA#4: CBC, OFB, CTR modes + AES decrypt
    │   ├── mac.ts                      # PA#5: PRF-MAC, CBC-MAC, EUF-CMA
    │   ├── ccaEnc.ts                   # PA#6: Encrypt-then-MAC
    │   ├── merkleDamgard.ts            # PA#7: Merkle-Damgard transform
    │   ├── dlpHash.ts                  # PA#8: DLP-based CRHF
    │   ├── birthdayAttack.ts           # PA#9: Naive + Floyd's birthday attack
    │   ├── hmac.ts                     # PA#10: HMAC + length-extension
    │   ├── diffieHellman.ts            # PA#11: DH key exchange + MITM
    │   ├── rsa.ts                      # PA#12: RSA + PKCS#1 v1.5
    │   ├── millerRabin.ts              # PA#13: Miller-Rabin primality
    │   ├── crt.ts                      # PA#14: CRT + Hastad attack
    │   ├── digitalSig.ts              # PA#15: RSA signatures
    │   ├── elgamal.ts                  # PA#16: ElGamal PKC
    │   ├── ccaPkc.ts                   # PA#17: Encrypt-then-Sign
    │   ├── obliviousTransfer.ts        # PA#18: Bellare-Micali OT
    │   ├── secureGates.ts              # PA#19: Secure AND/XOR/NOT
    │   └── mpc.ts                      # PA#20: Boolean circuit evaluator
    ├── stats/
    │   └── randomness.ts               # NIST SP 800-22 statistical tests
    ├── engine/
    │   ├── leg1.ts                     # Foundation -> Primitive builder
    │   └── leg2.ts                     # Primitive -> Primitive reducer
    ├── foundation/
    │   └── foundation.ts               # AES / DLP foundation abstraction
    ├── reductions/
    │   ├── edges.ts                    # Forward + backward clique edges
    │   └── routing.ts                  # BFS route finder
    ├── utils/
    │   └── hex.ts                      # Hex/byte/bitstring utilities
    ├── domain.ts                       # Primitive & foundation type metadata
    ├── types.ts                        # Core interfaces
    └── ui/                             # All interactive demo components
        ├── PoisCliqueExplorer.tsx       # PA#0: Clique explorer
        ├── Pa1Demo.tsx                 # PA#1: OWF/PRG playground
        ├── Pa2GgmVisualizer.tsx        # PA#2: GGM tree visualizer
        ├── Pa3CpaDemo.tsx              # PA#3: IND-CPA game
        ├── Pa4ModesDemo.tsx            # PA#4: Block cipher mode animator
        ├── Pa5MacDemo.tsx              # PA#5: MAC forge attempt
        ├── Pa6CcaDemo.tsx              # PA#6: Malleability attack panel
        ├── Pa7MerkleDamgardDemo.tsx     # PA#7: MD chain viewer
        ├── Pa8DlpHashDemo.tsx          # PA#8: DLP hash + collision hunt
        ├── Pa9BirthdayDemo.tsx         # PA#9: Live birthday attack
        ├── Pa10HmacDemo.tsx            # PA#10: Length-extension demo
        ├── Pa11DiffieHellmanDemo.tsx    # PA#11: DH exchange + MITM
        ├── Pa12RsaDemo.tsx             # PA#12: RSA determinism attack
        ├── Pa13MillerRabinDemo.tsx      # PA#13: Primality tester
        ├── Pa14CrtDemo.tsx             # PA#14: Hastad broadcast visualizer
        ├── Pa15DigitalSigDemo.tsx       # PA#15: Sign & verify + forgery
        ├── Pa16ElGamalDemo.tsx          # PA#16: ElGamal malleability
        ├── Pa17CcaPkcDemo.tsx           # PA#17: CCA malleability blocked
        ├── Pa18OtDemo.tsx              # PA#18: OT protocol stepper
        ├── Pa19SecureAndDemo.tsx        # PA#19: Secure AND step-by-step
        ├── Pa20MpcDemo.tsx             # PA#20: Millionaire's problem
        └── poisCliqueExplorer.css      # Shared UI styles
```

## Implementation Details by Part

### Part I: Symmetric Cryptography & Minicrypt (PA#1-6)

- **PA#1-2**: AES-128 from scratch (FIPS 197), DLP OWF (g^x mod p with ~30-bit safe prime), HILL hard-core-bit PRG, GGM tree PRF construction
- **PA#3**: CPA-secure encryption C = (r, F_k(r) XOR m) with counter-mode multi-block and PKCS#7 padding
- **PA#4**: Full AES inverse cipher (InvSubBytes, InvShiftRows, InvMixColumns) for CBC decrypt; OFB and CTR stream modes
- **PA#5**: PRF-MAC and CBC-MAC with EUF-CMA security game
- **PA#6**: Encrypt-then-MAC CCA2 construction with constant-time tag comparison

### Part II: Hashing & Data Integrity (PA#7-10)

- **PA#7**: Generic Merkle-Damgard framework with MD-strengthening padding (0x80 || zeros || 64-bit length)
- **PA#8**: DLP compression function h(x,y) = g^x * h^y mod p plugged into MD framework
- **PA#9**: Naive O(k log k) and Floyd's O(1)-space birthday attacks; empirical confirmation of O(2^(n/2)) bound
- **PA#10**: HMAC construction, length-extension attack on naive H(k||m), CRHF/MAC bidirectional reductions

### Part III: Public-Key Cryptography (PA#11-17)

- **PA#11**: Diffie-Hellman over safe prime group, MITM attack demonstration
- **PA#12**: RSA with extended Euclidean algorithm, PKCS#1 v1.5 padding, Bleichenbacher padding oracle
- **PA#13**: Miller-Rabin with per-round witness traces, Carmichael number 561 demo, PNT benchmarking
- **PA#14**: CRT solver, Garner's RSA-CRT decryption (~4x speedup), Hastad's broadcast attack (e=3)
- **PA#15**: RSA hash-then-sign signatures, multiplicative forgery on raw RSA defeated by hashing
- **PA#16**: ElGamal encryption (DDH-based), malleability attack (c1, 2c2) -> 2m
- **PA#17**: Encrypt-then-Sign combining ElGamal + RSA signatures for CCA2-secure PKC

### Part IV: Secure Multi-Party Computation (PA#18-20)

- **PA#18**: Bellare-Micali 1-out-of-2 OT using ElGamal, 3-step API
- **PA#19**: Secure AND via OT (Alice sends (0,a), Bob chooses b, gets a AND b), Secure XOR via additive secret sharing (free), NOT (local flip)
- **PA#20**: Boolean circuit evaluator (DAG of AND/XOR/NOT gates), three mandatory circuits: Millionaire's Problem (x > y), Secure Equality (x = y), Secure Addition (x + y mod 2^n)

## Toy Parameters

All demos use small parameters for instant in-browser computation:
- DLP: safe prime p ~ 2^30, generator g = 2
- RSA: 256-512 bit modulus
- ElGamal/DH: same DLP group
- Birthday attack: 8-16 bit truncated hashes
- MPC circuits: n = 4 bits (16 possible values)

## Security Notions Demonstrated

| Security Notion | PA | Demo |
|----------------|-----|------|
| One-wayness | #1 | Random inversion fails |
| Pseudorandomness | #1, #2 | NIST SP 800-22 tests pass |
| IND-CPA | #3, #16 | Advantage ~ 0 with fresh nonces |
| IND-CCA2 | #6, #17 | MAC/signature blocks malleability |
| EUF-CMA | #5, #15 | 0 forgeries in 50 queries |
| Collision resistance | #8, #9 | Birthday bound O(2^(n/2)) confirmed |
| MITM vulnerability | #11 | Unauthenticated DH broken |
| Determinism attack | #12 | Textbook RSA leaks plaintext equality |
| Malleability | #16 | ElGamal (c1, 2c2) decrypts to 2m |
| Length-extension | #10 | H(k||m) forgeable, HMAC immune |
| Hastad broadcast | #14 | CRT + cube root recovers plaintext |
| OT privacy | #18 | Sender/receiver learn nothing extra |
| MPC privacy | #20 | Neither party learns other's input |

## Team

- Manasa Kalaimalai
- Kevin Thakkar
- Sparsh
- Neel
- Abhinav

## Contributing

1. Create a branch: `git checkout -b feature-name`
2. Make your changes
3. `tsc -b` must pass with zero errors
4. Open a pull request against `main`
