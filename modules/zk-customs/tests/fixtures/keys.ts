import { generateKeyPair } from '../../../../shared/src/crypto/documentCrypto';

const ministryKeys = generateKeyPair();
const agentKeys = generateKeyPair();
const altAgentKeys = generateKeyPair();

export const TEST_MINISTRY_KEYS = ministryKeys;
export const TEST_AGENT_KEYS = agentKeys;
export const TEST_ALT_AGENT_KEYS = altAgentKeys;
export const TEST_UNAUTHORIZED_KEYS = generateKeyPair();
