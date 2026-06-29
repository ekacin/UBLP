# Test Fixtures

Shared test data for UBLP test suite.

## Files

- `sample-documents.ts` — Standardized customs document fixtures for reproducible tests
- `keys.ts` — Pre-generated P-256 keypairs for ministry, agent, and unauthorized actors

## Usage

```typescript
import { SAMPLE_CUSTOMS_DOCUMENT } from '../fixtures/sample-documents';
import { TEST_MINISTRY_KEYS } from '../fixtures/keys';
```
