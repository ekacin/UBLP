/**
 * `did:web` resolution (W3C did:web method — AGENTS.md 5.35). Two responsibilities:
 *   1. `didWebToUrl`: the pure domain->URL mapping the spec defines (no path -> .well-known;
 *      path present -> direct /did.json, not .well-known).
 *   2. `fetchDidWebDocument`: actually fetch it.
 *
 * Hand-rolled rather than pulling in `did-resolver`/`web-did-resolver`: those target the full,
 * generic multi-method DID-resolution pipeline (verification relationships, service
 * endpoints, ...); we only need this one narrow mapping for one role (port authority), so a
 * real dependency would be pure overhead — consistent with this project's minimal-dependency
 * style.
 *
 * Host normalization uses Node's built-in `domainToASCII` (WHATWG URL / UTS-46), NOT the
 * deprecated `punycode` module. Confirmed by direct testing (2026-10-22): this already
 * case-folds (`LIMAN.com` and `liman.com` both -> `liman.com`), so no separate
 * `.toLowerCase()` step is needed. It does NOT conflate visually-similar-but-distinct
 * characters (e.g. Turkish dotted `İ` vs plain `i` produce different punycode) — that's
 * correct, not a bug: those really are different domains, and the resulting punycode form is
 * exactly what should be shown to a human when flagging a suspicious-looking lookup (the
 * homograph-attack defense), rather than a pretty-rendered Unicode form that could visually
 * fool someone.
 */

import { domainToASCII } from 'node:url';
import type { DidWeb } from './did.js';

export interface ParsedDidWeb {
  /** Host, including port if present (e.g. "example.com" or "example.com:3000"); already
   * IDNA/punycode-normalized. */
  host: string;
  path: string[];
}

export function parseDidWeb(did: DidWeb): ParsedDidWeb {
  const rest = did.slice('did:web:'.length);
  if (!rest) throw new Error(`Invalid did:web — empty identifier: ${did}`);

  const [hostAndPort, ...path] = rest.split(':');
  const decoded = hostAndPort.replace(/%3A/gi, ':');
  const [rawHost, port] = decoded.split(':');
  if (!rawHost) throw new Error(`Invalid did:web — empty host: ${did}`);

  const asciiHost = domainToASCII(rawHost);
  if (!asciiHost) throw new Error(`Invalid did:web — host failed IDNA conversion: ${did}`);

  return { host: port ? `${asciiHost}:${port}` : asciiHost, path };
}

/** Per the did:web spec: no path segments -> /.well-known/did.json; path segments present
 * -> /<path>/did.json directly (NOT under .well-known). `localhost`/`127.0.0.1` are the one
 * spec-sanctioned exception to "always https" — without it, every local-devnet port-authority
 * agent (plain HTTP, no TLS — see server/index.ts) would be unresolvable in test scripts. */
export function didWebToUrl(did: DidWeb): string {
  const { host, path } = parseDidWeb(did);
  const hostname = host.split(':')[0];
  const scheme = hostname === 'localhost' || hostname === '127.0.0.1' ? 'http' : 'https';
  if (path.length === 0) return `${scheme}://${host}/.well-known/did.json`;
  return `${scheme}://${host}/${path.join('/')}/did.json`;
}

/**
 * Fetches and JSON-parses whatever document lives at the did:web URL. Deliberately returns
 * `unknown` — this module only knows the generic did:web transport, not the incoterms-escrow-
 * specific document shape (`{ portAuthorityKeyHashHex, did }`); the caller validates that.
 *
 * NOTE (ZK/witness integrity limit — AGENTS.md 5.35): this fetch is ordinary HTTPS, verified
 * only by TLS, same as any browser request. A circuit witness cannot prove this request
 * wasn't tampered with in transit or that the remote server itself is honest — it can only
 * prove the *result* the buyer got matches what the seller separately committed to on-chain.
 * If the real source is compromised, no on-chain mechanism can detect it; this is the same
 * category of limit as the project's own pre-existing "oracle problem" (Module 3 discussion).
 */
export async function fetchDidWebDocument(did: DidWeb, timeoutMs = 10_000): Promise<unknown> {
  const url = didWebToUrl(did);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: controller.signal });
    if (!res.ok) throw new Error(`did:web fetch failed: ${url} -> HTTP ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}
