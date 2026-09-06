# Incoterms Escrow

> **Status: v0.1, not production-ready.** This is an early-stage reference implementation — no
> external security audit, and several hardening items (see [Current scope](#current-scope) and
> [Security notes](#security-notes)) are still open. Do not move real funds with it yet.

`@ublp/incoterms-escrow` is a Midnight Network smart-contract escrow system for settling
international trade deals under [Incoterms 2020](https://iccwbo.org/business-solutions/incoterms-rules/)
rules. It supports all 11 Incoterms 2020 rules — EXW, FCA, CPT, CIP, DAP, DPU, DDP, FAS, FOB,
CFR, and CIF — through one shared escrow state machine: every rule ultimately reduces to "one
agreed party attests that a milestone happened, then the seller gets paid, with a timeout
safety net if that attestation never comes." What differs between the 11 rules is *which*
real-world milestone that is and *who* plays the attesting role — that's captured per rule in
`src/policies/`, not by branching the contract itself. See [How a deal works](#how-a-deal-works)
for the mechanism and [Choosing an Incoterm rule](#choosing-an-incoterm-rule) for what each rule
actually means here.

Funds and deal terms move through a Compact smart contract on Midnight, so amounts and payout
addresses are never written to the chain in plaintext — only zero-knowledge commitments are.
Everything else (who is negotiating with whom, the actual deal terms) is exchanged directly
between the counterparties' own agents, encrypted, with no UBLP-operated server anywhere in
the path.

## How a deal works

A deal has three parties and moves through four states:

```
Empty -> Proposed -> Locked -> Released
```

- **Seller** creates the offer (`propose`), fixing the terms — amount, deadline, the chosen
  Incoterm rule, and the identity of the party who will confirm that rule's milestone.
- **Buyer** reviews the offer and locks funds into the contract (`lockEscrow`). Locking is a
  precondition for shipping to start, not a step that happens afterward.
- **"C"** — the role the code and panel label `port-authority`, whoever that actually is for
  this deal — confirms the milestone happened (`attestLoadingConfirmed`). This call proves only
  the caller's own identity — it never touches financial data, by design. The circuit name is a
  holdover from FOB (the first rule implemented) but the check itself is generic: it just
  verifies the caller's key against whichever DID was nominated as "C" at proposal time, so the
  same call works whether "C" is a maritime terminal (FOB/FAS/CFR/CIF), a carrier (FCA/CPT/CIP),
  or a destination-side warehouse (DAP/DPU/DDP). See
  [Choosing an Incoterm rule](#choosing-an-incoterm-rule) for who that should be per rule.
- Once that milestone is confirmed, anyone can trigger `claimPayout` to release funds to the
  seller (in practice the seller's own agent does this automatically).
- If "C" never attests, `releaseOnTimeout` acts as a safety net once the deadline passes, paying
  out to whichever party was designated at proposal time — this call is deliberately
  unauthenticated, since a stuck deal must always be resolvable by someone.

Two independent commitment patterns keep the deal private on-chain: fund custody is shielded
(the coin amount is never in plaintext on the ledger — only a commitment hash is), and payout
addresses are likewise never written directly, only committed to and checked at release time.

## Choosing an Incoterm rule

The panel's "New deal" form lets the seller pick any of the 11 rules; whichever one is chosen
is signed into the deal's terms and shown as-is everywhere the deal appears (pending queue,
incoming offers, deal status). The contract's behavior is identical no matter which rule is
picked — what actually changes per rule is which real-world event counts as the milestone, and
who should realistically be trusted to attest it:

| Rule | Milestone (risk transfer point) | Typical "C" |
|---|---|---|
| EXW | Goods placed at buyer's disposal at seller's premises | The buyer's own nominated carrier — see the note below |
| FCA | Goods handed to the carrier nominated by the buyer | That carrier, or a terminal at the named place |
| CPT | Same as FCA (seller additionally pays carriage to destination) | Same as FCA |
| CIP | Same as FCA (seller additionally pays carriage + insurance) | Same as FCA |
| DAP | Goods arrive, ready for unloading, at the named destination | A destination-side terminal or warehouse |
| DPU | Goods are unloaded at the named destination | A destination-side terminal or warehouse |
| DDP | Goods delivered, import duty paid, at the named destination | See the note below |
| FAS | Goods placed alongside the vessel at the port of shipment | A loading-port terminal/quay operator |
| FOB | Goods loaded on board the vessel at the port of shipment | A loading-port terminal operator |
| CFR | Same as FOB (seller additionally pays freight to destination) | Same as FOB |
| CIF | Same as FOB (seller additionally pays freight + insurance) | Same as FOB |

Two rules are worth a second look before using them:

- **EXW** has no natural independent third party at the transfer point — unlike the others, the
  realistic attester is aligned with the buyer (their own nominated carrier), not neutral.
  Choose who plays "C" deliberately for an EXW deal.
- **DDP** technically involves an import customs clearance, which is its own well-defined domain
  (UBLP's separate `zk-customs` module handles exactly that). This escrow's DDP support is
  deliberately simplified to the same single-attestation model as every other rule — it does
  **not** require or integrate with `zk-customs` — so DDP works standalone rather than depending
  on a separate module's maturity. A tighter integration is a possible future direction, not a
  current dependency.

This escrow does not model cost allocation (who pays freight/insurance) or customs
responsibility at all — it only custodies a single agreed amount and releases it on one
attested milestone. The rules that only differ from another rule by cost allocation (CPT/CIP
vs. FCA, CFR/CIF vs. FOB) are therefore mechanically identical here; the distinction matters for
the parties' own commercial agreement, not for what this contract enforces.

## Architecture

Each company runs its **own** settlement-agent (backend) and connects to it with the **panel**
(a React frontend). There is no shared or UBLP-operated backend — a buyer, a seller, and a port
authority are three genuinely separate deployments, each with its own wallet, identity, and
data store.

```
company's browser  --(wallet-signature session)-->  their own settlement-agent  --> Midnight
       |                                                      |
       +-- panel (React, Vite) ------------------------------+
```

- **Contract** (`contracts/Escrow.compact`) — the escrow state machine described above, compiled
  to a ZK circuit set with the Compact compiler.
- **Settlement agent** (`src/server`) — a Fastify HTTP server, one per company/role. Wraps the
  contract calls, manages that company's own Midnight wallet, and exposes a small approval
  queue so a human signs off before any financial commitment (`propose`/`lockEscrow`) is
  submitted.
- **Panel** (`panel/`) — a browser UI that authenticates against a settlement agent via a
  wallet-signature challenge/response (no passwords), shows pending approvals and deal status,
  and can manage more than one agent instance in the same browser session (useful when one
  company acts as both buyer and seller across different deals).
- **Agent-to-agent delivery** — once a seller approves an offer, it is delivered automatically
  and directly to the buyer's own agent, encrypted end-to-end so that even a compromised
  transport never exposes the deal terms. There is no relay or intermediary between the two
  agents.

### Reaching a counterparty

An agent is identified purely by its base URL — there is no fixed IP requirement and no
directory service to register with. In practice this means an operator can expose their
settlement agent behind their own real domain name (e.g. `https://escrow.acme-export.com`,
reverse-proxied per the [Security notes](#security-notes) below) and simply hand that domain to
a counterparty, the same way you'd hand out a company email address. The panel's instance
switcher and the agent-to-agent delivery endpoint both work off this base URL alone.

## Repository layout

```
contracts/            Compact source (Escrow.compact) and compiled output
src/
  contract/            witnesses, memo encryption, contract-address helpers
  deploy/               network config, wallet construction, provider wiring
  policies/             per-Incoterm-rule policy logic — one file per rule, all 11 covered
  server/               HTTP routes, auth, identity, db, deal watcher
scripts/
  devnet/               local devnet helpers: deploy, fund wallets, full lifecycle runs
panel/                 React frontend (Vite)
tests/                 unit and integration tests (Vitest)
```

## Prerequisites

- Node.js and npm (workspace-managed — run commands from the repository root or this package
  with `-w @ublp/incoterms-escrow`)
- The [Compact compiler](https://docs.midnight.network/relnotes/compact) on your `PATH`, for
  `npm run compile:contract`
- A running Midnight devnet (e.g. via `midnight-local-dev`) and a local proof server for local
  development — see `src/deploy/networks.ts` for the exact endpoints expected

## Getting started (local devnet)

0. **Start a local Midnight devnet.** This repository doesn't bundle one — pull the official
   [`midnight-local-dev`](https://github.com/midnightntwrk/midnight-local-dev) tool separately
   and bring up its three containers (node, indexer, proof server):
   ```bash
   git clone https://github.com/midnightntwrk/midnight-local-dev.git
   cd midnight-local-dev
   npm install
   docker compose -f standalone.yml up -d
   docker compose -f standalone.yml ps   # wait until all three report healthy
   ```
   This exposes `localhost:9944` (node), `localhost:8088` (indexer), and `localhost:6300`
   (proof server) — exactly what `src/deploy/networks.ts` expects, no extra configuration
   needed. Leave it running in the background; everything below assumes it's up.
1. Compile the contract:
   ```bash
   npm run compile:contract -w @ublp/incoterms-escrow
   ```
2. Generate local test wallets and fund them:
   ```bash
   npx tsx scripts/devnet/generate-test-accounts.ts
   npx tsx scripts/devnet/fund-agent-role.ts buyer
   npx tsx scripts/devnet/fund-agent-role.ts seller
   npx tsx scripts/devnet/fund-agent-role.ts port-authority
   ```
   `generate-test-accounts.ts` always creates all three roles' wallets in one run — encrypted
   copies land in `.devnet-secrets/{buyer,seller,port-authority}.json` (AES-256-GCM, decryptable
   only with the same `DEVNET_WALLET_PASSPHRASE` the script was run with), but it **also** writes
   `.devnet-secrets/accounts.json` in plaintext, containing every role's mnemonic words. That
   plaintext copy exists so it can be fed straight into `midnight-local-dev`'s own `--fund-config`
   option — it's the simplest way to read a generated mnemonic back if you need it (e.g. to import
   into a wallet extension). This is only ever done for throwaway local-devnet test money; never
   do this for a real deployment's secrets. Both files stay out of git (`.gitignore` excludes all
   of `.devnet-secrets/`).
3. Start a settlement agent per role (each needs its own terminal, port, and — for more than
   one role on one machine — its own `SETTLEMENT_SECRETS_DIR`/`SETTLEMENT_DATA_DIR`):
   ```bash
   SETTLEMENT_ROLE=seller SETTLEMENT_DID=did:ublp:seller:acme-export \
     SETTLEMENT_PORT=4100 SETTLEMENT_PASSPHRASE=devnet-only \
     npm run start:settlement-agent -w @ublp/incoterms-escrow
   ```
   `devnet-only` above is just a placeholder — the *first* time an agent runs for a given
   `SETTLEMENT_SECRETS_DIR`, whatever value you pass becomes that role's real passphrase, since
   it's used right then to encrypt a freshly-generated wallet/identity. **If that directory
   already has secrets in it from an earlier run** (yours or someone else's), you must supply
   the exact same passphrase used back then, not this README's example — a mismatch fails loudly
   at startup with a decryption error (`Unsupported state or unable to authenticate data`), it
   does not silently create a new identity. There's no way to recover a forgotten passphrase
   short of deleting the secrets directory and starting over with a fresh identity/wallet.
4. Start the panel:
   ```bash
   npm run dev -w @ublp/incoterms-escrow-panel
   ```
   Point it at an agent with `VITE_AGENT_BASE_URL` (default `http://127.0.0.1:4100`), then use
   the instance switcher in the UI to add and switch between roles.

For a scripted, non-interactive run through the whole lifecycle (useful for verifying a fresh
setup), see `scripts/devnet/full-lifecycle.ts`.

### Wallet funding requirements

Each agent's wallet needs **two distinct kinds of funding**, and mixing them up is a common
mistake:

- **Shielded NIGHT**, to actually fund the escrowed amount. The contract only ever moves coins
  through Midnight's shielded (Zswap) pool — an escrow can only be locked with shielded funds.
  A faucet only ever pays into an **unshielded** address, so unshielded NIGHT has to be
  converted to shielded NIGHT before it can be used here (`fund-agent-role.ts` does this by
  transferring shielded-to-shielded from an already-shielded source, since a direct
  unshielded→shielded conversion is not yet reliable at the SDK level this project uses).
- **Unshielded NIGHT, registered for DUST generation**, to pay transaction fees. DUST — the
  resource that actually pays for a transaction — is only generated from unshielded NIGHT UTXOs
  that have been explicitly registered for it; shielded NIGHT never generates DUST no matter
  the amount.

`scripts/devnet/fund-agent-role.ts <buyer|seller|port-authority>` funds a role's wallet with
both in one step.

## Running more than one role from the same company

It's a common setup for one company to act as both buyer and seller across different deals
(and, for local testing, to also run the port authority role itself, even though in a real deal
that's a genuinely separate neutral party). Each role still needs to be its own isolated process
with its own wallet, identity, and data store — the settlement agent enforces this by having
every role write to the same default directories unless told otherwise, so co-located roles
**must** be given distinct `SETTLEMENT_SECRETS_DIR`/`SETTLEMENT_DATA_DIR` values or they'll
collide on the same files.

Assuming the local devnet from [Getting started](#getting-started-local-devnet) is already up
and steps 1–2 (compile, generate + fund all three wallets) are done, open three terminals:

```bash
# Terminal 1 — seller
SETTLEMENT_ROLE=seller \
SETTLEMENT_DID=did:ublp:seller:your-company \
SETTLEMENT_PORT=4100 \
SETTLEMENT_PASSPHRASE=change-me \
SETTLEMENT_SECRETS_DIR=.settlement-secrets-seller \
SETTLEMENT_DATA_DIR=data-seller \
npm run start:settlement-agent -w @ublp/incoterms-escrow
```

```bash
# Terminal 2 — buyer
SETTLEMENT_ROLE=buyer \
SETTLEMENT_DID=did:ublp:buyer:your-company \
SETTLEMENT_PORT=4200 \
SETTLEMENT_PASSPHRASE=change-me \
SETTLEMENT_SECRETS_DIR=.settlement-secrets-buyer \
SETTLEMENT_DATA_DIR=data-buyer \
npm run start:settlement-agent -w @ublp/incoterms-escrow
```

```bash
# Terminal 3 — port authority (a real deployment would have a separate company run this)
SETTLEMENT_ROLE=port-authority \
SETTLEMENT_DID=did:ublp:port-authority:test-authority \
SETTLEMENT_PORT=4300 \
SETTLEMENT_PASSPHRASE=change-me \
SETTLEMENT_SECRETS_DIR=.settlement-secrets-portauth \
SETTLEMENT_DATA_DIR=data-portauth \
npm run start:settlement-agent -w @ublp/incoterms-escrow
```

Then start the panel (`VITE_NETWORK_ID=undeployed npm run dev -w @ublp/incoterms-escrow-panel`)
and, in its instance switcher, add all three base URLs (`http://127.0.0.1:4100`, `:4200`,
`:4300`) with distinct labels. Log into each with your wallet extension (set to the `undeployed`
network) before using it.

A full deal exercises every role in turn:

1. **Seller** → "New deal", fill in the terms, approve — the offer is delivered automatically
   and encrypted to the buyer's agent.
2. **Buyer** → "Incoming offers", "Accept & Lock", approve (generates a real ZK proof, ~30–60s).
3. **Port authority** → "Open deal", paste the contract address, "Confirm loading completed".
4. **Seller**'s agent claims the payout automatically once the attestation lands — no manual step
   needed; the deal's status moves to "Released".

## Configuration

Settlement-agent environment variables (`scripts/start-settlement-agent.ts`):

| Variable | Required | Description |
|---|---|---|
| `SETTLEMENT_ROLE` | yes | `buyer`, `seller`, or `port-authority` |
| `SETTLEMENT_DID` | yes | This company's own `did:ublp:...` identifier |
| `SETTLEMENT_PORT` | no (default `4100`) | HTTP port for this agent |
| `SETTLEMENT_PASSPHRASE` | yes | Decrypts this agent's wallet and identity secrets. Must match whatever value was used the *first* time this `SETTLEMENT_SECRETS_DIR` was populated — see the note in [Getting started](#getting-started-local-devnet). In production this should come from a secrets manager, not a plain environment variable |
| `SETTLEMENT_SECRETS_DIR` | no | Override for where wallet/identity secrets live — required when running more than one role from the same checkout |
| `SETTLEMENT_DATA_DIR` | no | Override for where this agent's local SQLite stores live |
| `SETTLEMENT_INCOMING_RATE_LIMIT_MAX` | no (default `20`) | Max requests per window to the public `/deals/incoming` endpoint |
| `SETTLEMENT_INCOMING_RATE_LIMIT_WINDOW` | no (default `1 minute`) | Rate-limit window, in `@fastify/rate-limit` format |

Panel build-time variable:

| Variable | Description |
|---|---|
| `VITE_AGENT_BASE_URL` | Default agent base URL seeded into the instance switcher on first load |
| `VITE_NETWORK_ID` | Network hint passed to the wallet connector — must match whatever network the browser's Midnight wallet extension is actually set to, or the connection is rejected |

## Testing

```bash
npm test -w @ublp/incoterms-escrow
```

Covers the contract's core logic, witness behavior, all 11 Incoterm rule policies,
encrypted-memo round-tripping, and the settlement agent's server-side pieces (auth, db, deal
policy, identity).

## Cryptography

What's protected, and how:

- **Escrowed fund amounts** move through Midnight's shielded (Zswap) pool. On-chain, the ledger
  only ever stores a `persistentCommit` hash of the coin's nonce/color/value — never the amount
  itself. A commitment is opened later only by supplying the real value as a witness and
  checking it against the stored hash.
- **Payout addresses** (both the seller's and the buyer's) are handled the same way: never
  written to the ledger directly — only committed to, at proposal/lock time. This is what makes
  `releaseOnTimeout` safe to leave callable by anyone: since the real address is never public,
  there's nothing for an unauthenticated caller to redirect.
- **Deal terms in transit and in the on-chain memo** are encrypted with static-static
  **X25519 ECDH** (HKDF-derived key) and **ChaCha20-Poly1305 AEAD** — a dual-recipient scheme
  where either party (the author or the counterparty) can decrypt the same ciphertext with only
  their own private key and the other side's public key. This one scheme covers both:
  1. the on-chain encrypted memo fields (so the deal's coin data and payout address survive on
     the ledger without ever being legible to anyone but the two parties), and
  2. the agent-to-agent HTTP delivery of a signed offer — the exact same encryption is reused
     there, so a compromised or logged transport (a proxy, a misconfigured log line) still never
     exposes the plaintext terms.
- **Panel login** is a wallet-signature challenge/response — the agent issues a one-time
  challenge, the wallet signs it, and the agent verifies the signature. No password is ever
  stored or transmitted.

**Strengths of this design:** amounts and payout destinations are never plaintext on a public
ledger; the same encryption protects the data whether it's sitting on-chain or moving over
HTTP, so there's only one scheme to reason about; and because the memo is symmetric between
author and counterparty, no separate key-exchange or side channel is needed to hand off private
data — it rides along with the transaction itself.

## Security notes

- **Every deployment is self-hosted, per company.** A buyer, a seller, and a port authority are
  three independent processes with independent wallets and independent secrets — there is no
  shared operator and no relay between them. If you run more than one role's agent from a
  shared, un-hardened host, a compromise of that host compromises every role on it at once.
- **Authentication** to a settlement agent's panel is a wallet-signature challenge/response, not
  a password. If you disable or bypass this (e.g. exposing the API without going through the
  panel's auth flow), anyone who can reach the agent's port can drive its approval queue.
- **Two endpoints are intentionally public** on each agent: the identity lookups a counterparty
  needs before any session exists, and `POST /deals/incoming` (the agent-to-agent proposal
  delivery endpoint), which is rate-limited per the table above precisely because it accepts
  unauthenticated writes from the public internet. If you raise or disable that rate limit, this
  endpoint becomes a straightforward spam/DoS target — every request costs real CPU on signature
  verification and can persist attacker-controlled data.
- **Put a reverse proxy in front of your public agent.** Every settlement agent is self-hosted
  and exposes at least one unauthenticated write endpoint. If you expose an agent directly to
  the public internet without a reverse proxy or CDN/WAF (Cloudflare or an equivalent) in front
  of it, you lose TLS termination and the DDoS/abuse protection that layer would otherwise
  absorb — the application itself has no way to provide either. This is an operator-level
  deployment decision the code can't enforce, so it's documented here instead: always put one
  in front before going live.
- **Secrets** (wallet mnemonic, identity keys) are encrypted at rest with `SETTLEMENT_PASSPHRASE`.
  Treat that passphrase the same way you would treat the keys themselves — if it leaks (a plain
  environment variable in a process listing, a CI log, a shell history file), everything it
  protects leaks with it. A real deployment should source it from a secrets manager, not a
  plain environment variable.

## Current scope

v0.1 supports all 11 Incoterms 2020 rules, but only against a local devnet — it has not been
run against a public Midnight network or audited, and this escrow deliberately doesn't model
cost allocation (freight/insurance) or customs responsibility (see
[Choosing an Incoterm rule](#choosing-an-incoterm-rule)). Treat this repository as a reference
implementation to build on, not as something to point at real trade flows yet.
