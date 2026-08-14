import { describe, it, expect } from 'vitest';
import { evaluatePolicy } from '@ublp/shared';
import type { Attestation, UBLPDid, ShipmentId } from '@ublp/shared';
import { fobPolicy, LOADING_CONFIRMED_CLAIM } from '../src/policies/fob.js';

const SHIPMENT_ID: ShipmentId = 'shp:test-fob-1';
const PORT_AUTHORITY: UBLPDid = 'did:ublp:port-authority:pendik-roro';
const OTHER_ISSUER: UBLPDid = 'did:ublp:port-authority:someone-else';

function loadingAttestation(issuerSet: UBLPDid[]): Attestation {
  return {
    subjectId: SHIPMENT_ID,
    claimType: LOADING_CONFIRMED_CLAIM,
    proofRef: 'mock-proof',
    issuerSet,
    threshold: issuerSet.length,
    timestamp: Date.now(),
  };
}

describe('FOB AttestationPolicy', () => {
  it('is satisfied when the designated port authority (C) attests and the attestation verifies', async () => {
    const policy = fobPolicy(PORT_AUTHORITY);
    const bundle = [loadingAttestation([PORT_AUTHORITY])];

    const result = await evaluatePolicy(policy, bundle, async () => true);

    expect(result.satisfied).toBe(true);
  });

  it('is NOT satisfied when a different party (not the escrow-scoped C) attests', async () => {
    const policy = fobPolicy(PORT_AUTHORITY);
    const bundle = [loadingAttestation([OTHER_ISSUER])];

    const result = await evaluatePolicy(policy, bundle, async () => true);

    expect(result.satisfied).toBe(false);
    expect(result.reasons.length).toBeGreaterThan(0);
  });

  it('is NOT satisfied when the bundle has no matching claim', async () => {
    const policy = fobPolicy(PORT_AUTHORITY);

    const result = await evaluatePolicy(policy, [], async () => true);

    expect(result.satisfied).toBe(false);
  });

  it('is NOT satisfied when the cryptographic verification fails even for the right issuer', async () => {
    const policy = fobPolicy(PORT_AUTHORITY);
    const bundle = [loadingAttestation([PORT_AUTHORITY])];

    const result = await evaluatePolicy(policy, bundle, async () => false);

    expect(result.satisfied).toBe(false);
  });
});
