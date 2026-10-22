/**
 * UBLP's generic DID scheme — where Attestation/AttestationPolicy (see ../attestation)
 * answers "who". Not module-specific: zk-customs, incoterms-escrow, and every future
 * module share the same actor/role types.
 */

/** UBLP DID format: did:ublp:<role>:<identifier> — e.g. did:ublp:carrier:pendik-roro-001 */
export type UBLPDid = `did:ublp:${string}`;

export const UBLP_ROLES = [
  'shipper',
  'carrier',
  'buyer',
  'seller',
  'committee-member',
  'port-authority',
  'arbiter',
] as const;

export type UBLPRole = (typeof UBLP_ROLES)[number];

export interface UBLPActor {
  did: UBLPDid;
  role: UBLPRole;
  /** P-256 SPKI PEM or BLS hex — depends on the cryptographic scheme, decided by agent-core. */
  publicKey: string;
}

/** Shipment ID scheme: shp:<shipment-uuid> — shared reference across all modules (zk-customs, incoterms-escrow). */
export type ShipmentId = `shp:${string}`;

export function isUBLPDid(value: string): value is UBLPDid {
  return value.startsWith('did:ublp:');
}

export function parseUBLPDid(did: UBLPDid): { role: string; identifier: string } {
  const parts = did.split(':');
  if (parts.length < 4 || parts[0] !== 'did' || parts[1] !== 'ublp') {
    throw new Error(`Invalid UBLP DID: ${did}`);
  }
  return { role: parts[2], identifier: parts.slice(3).join(':') };
}

/**
 * W3C `did:web` method (incoterms-escrow's port-authority identity — see AGENTS.md 5.35):
 * `did:web:<domain>[%3A<port>][:<path-segment>...]`. Chosen over `did:ublp:...` for this one
 * role specifically because it's independently, cryptographically resolvable over HTTPS by
 * anyone (buyer included) — a `did:ublp:...` label is just a string neither party can verify
 * against anything. See ./didWeb.ts for the actual resolution algorithm.
 */
export type DidWeb = `did:web:${string}`;

export function isDidWeb(value: string): value is DidWeb {
  return value.startsWith('did:web:');
}
