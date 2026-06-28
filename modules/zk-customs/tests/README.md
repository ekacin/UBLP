# UBLP Test Suite

Comprehensive test suite for the UBLP ZK Customs Clearance module.

## Test Structure

```
tests/
├── README.md                  # This file
├── setup.ts                   # Global test setup & teardown
├── vitest.config.ts           # Vitest configuration (at module root)
├── fixtures/
│   ├── sample-documents.ts    # Standardized test documents
│   └── keys.ts                # Pre-generated P-256 keypairs
├── unit/
│   ├── mockCrypto.test.ts     # ECDSA, hashing, ZK proof unit tests
│   ├── blsCrypto.test.ts      # BLS12-381 threshold signature tests
│   ├── sp1Client.test.ts      # SP1 client utilities
│   └── vc.test.ts             # VC/VP type structure tests
├── integration/
│   ├── ministry.test.ts       # Ministry HTTP API integration tests
│   ├── agent.test.ts          # UBLP Agent HTTP API integration tests
│   ├── l2-verifier.test.ts    # L2 Verifier HTTP API integration tests
│   └── e2e.test.ts            # Full end-to-end flow test
└── negative/
    └── negative.test.ts       # Attack vectors & edge case tests
```

## Running Tests

### Prerequisites
```bash
cd modules/zk-customs
npm install
```

### All tests
```bash
npm test
```

### By category
```bash
npm run test:unit          # Unit tests only
npm run test:integration   # Integration tests only
npm run test:negative      # Negative/security tests only
npm run test:e2e           # End-to-end flow test
npm run test:coverage      # All tests with coverage report
```

### Watch mode
```bash
npm run test:watch
```

### Test coverage
Coverage reports are generated in `coverage/` directory:
- `coverage/lcov-report/index.html` — HTML report
- `coverage/lcov.info` — LCOV format (for CI)

## Test Categories

### Unit Tests (`tests/unit/`)
Test individual cryptographic primitives in isolation:
- **mockCrypto**: `canonicalJson`, `sha256Hash`, `sha256HashDocument`, `combinedSignatureHash`, `holderProofHash`, `generateKeyPair`, `signDocument`, `verifySignature`, `verifySignatureOverHash`, `generateMockZKProof`
- **blsCrypto**: `blsGenerateKeyPair`, `blsSign/Verify`, `blsAggregateSignatures`, `blsAggregatePublicKeys`, `blsGroupKeyHash`, `blsVerifyThreshold`
- **sp1Client**: `pubKeyPemToRaw`, `sp1Available`
- **vc**: VC/VP type structural invariants

### Integration Tests (`tests/integration/`)
Test each service's HTTP API with an in-memory Fastify server:
- **Ministry**: key retrieval, VC issuance, signature verification, input validation
- **Agent**: VC processing, ZK proof generation, VP construction, holder privacy
- **L2 Verifier**: settlement, replay protection, key authorization, revocation, raw document rejection

### End-to-End Test (`tests/integration/e2e.test.ts`)
Test the complete flow:
1. Broker creates document → Ministry signs → VC received
2. Agent processes VC → ZK proof → Committee BLS → VP constructed  
3. L2 verifies and settles
4. Replay protection enforcement
5. BLS attestation independent verification
6. Holder identity privacy (raw key never leaves agent)

### Negative Tests (`tests/negative/`)
Test attack vectors and edge cases:
- **Signature attacks**: document tampering, key substitution, wrong documentIdHash, combined hash mismatch
- **ZK proof attacks**: invalid ministry sig, missing holder auth, wrong holder key, DID binding
- **BLS attacks**: wrong pubkey, wrong message, insufficient signers, attacker pubkey injection
- **Hash attacks**: domain separation bypass (cross-protocol collision), MitM via DID spoofing
- **Edge cases**: malformed signatures, empty keys, key uniqueness

## Coverage Goals

| Component | Target Coverage | Current |
|-----------|----------------|---------|
| `shared/src/crypto/mockCrypto.ts` | 95%+ | — |
| `shared/src/crypto/blsCrypto.ts` | 95%+ | — |
| `shared/src/crypto/sp1Client.ts` | 80%+ | — |
| `shared/src/types/vc.ts` | 100% | — |
| `ministry/src/index.ts` | 70%+ | — |
| `committee/src/index.ts` | 70%+ | — |
| `ublp-agent/src/index.ts` | 70%+ | — |
| `l2-verifier-mock/src/index.ts` | 70%+ | — |

## CI/CD

The test suite runs automatically via GitHub Actions (see `.github/workflows/ci.yml`):

1. **lint-and-typecheck** — TypeScript compilation check
2. **unit-tests** — Unit tests + coverage upload
3. **integration-tests** — Integration tests
4. **negative-tests** — Security/negative tests
5. **sp1-circuit** — Rust compilation check (conditional)
6. **e2e-tests** — Full end-to-end tests
7. **full-flow** — Live service startup + broker demo execution

## Adding Tests

1. Add test file in the appropriate `tests/` subdirectory
2. Name with `.test.ts` suffix
3. Use Vitest API (`describe`, `it`, `expect`)
4. For HTTP tests, use Fastify's in-memory server (port 0 for dynamic allocation)
5. Import from `@ublp/shared` (or relative path for internal tests)

Example:
```typescript
import { describe, it, expect } from 'vitest';
import { sha256Hash } from '../../shared/src/crypto/mockCrypto';

describe('sha256Hash', () => {
  it('produces 64-char hex', () => {
    expect(sha256Hash('test')).toHaveLength(64);
  });
});
```
