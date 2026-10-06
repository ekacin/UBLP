"""Thin HTTP client for a company's own UBLP settlement-agent REST API.

No business logic lives here — one method per route, same pattern Odoo's own official
payment_stripe module uses for calling Stripe's REST API from a model method (requests ships
as a core Odoo dependency already).

Login is the one non-obvious part: the agent's `/auth/*` routes expect a real Midnight
wallet-signature challenge-response (see src/server/auth.ts), which this server-side Python
process cannot produce itself (no wallet extension). Instead, a companion Node.js script
(`scripts/odoo-auth-helper.ts`, in the UBLP repo this agent is part of) holds its own dedicated
signing key and performs just the signing step — see that script's header comment for the full
trust-model explanation. This client shells out to it.
"""
import json
import logging
import subprocess
import time

import requests

_logger = logging.getLogger(__name__)

REQUEST_TIMEOUT_SECONDS = 30


class EscrowApiError(Exception):
    """Raised for any non-2xx response from the settlement-agent, or a transport failure."""


class EscrowClient:
    """Stateless aside from the session token the caller passes in/gets back — this class holds
    no Odoo ORM state itself, so it's safe to construct fresh per call from escrow_deal.py."""

    def __init__(self, base_url, session_token=None):
        self.base_url = base_url.rstrip('/')
        self.session_token = session_token

    def _headers(self, has_body):
        headers = {}
        if has_body:
            headers['Content-Type'] = 'application/json'
        if self.session_token:
            headers['Authorization'] = f'Bearer {self.session_token}'
        return headers

    def _request(self, method, path, json_body=None, expect_codes=(200,)):
        """json_body=None means "no request body" (e.g. /auth/challenge) — Content-Type:
        application/json is only sent when there's an actual JSON body, since Fastify's global
        JSON parser rejects that header on a genuinely empty body (FST_ERR_CTP_EMPTY_JSON_BODY)."""
        url = f'{self.base_url}{path}'
        try:
            resp = requests.request(
                method, url, json=json_body, headers=self._headers(json_body is not None),
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
        except requests.RequestException as exc:
            raise EscrowApiError(f'Could not reach settlement-agent at {url}: {exc}') from exc

        if resp.status_code not in expect_codes:
            raise EscrowApiError(f'{method} {path} -> HTTP {resp.status_code}: {resp.text}')
        return resp.json() if resp.content else {}

    # ---- Auth -----------------------------------------------------------------------------

    def issue_challenge(self):
        return self._request('POST', '/auth/challenge')

    def verify_challenge(self, challenge_id, signature, signed_data_hex, verifying_key):
        return self._request(
            'POST',
            '/auth/verify',
            {
                'challengeId': challenge_id,
                'signature': signature,
                'signedDataHex': signed_data_hex,
                'verifyingKey': verifying_key,
            },
            expect_codes=(200, 401),
        )

    def sign_challenge_via_helper(self, repo_path, secrets_dir, role, passphrase, nonce_hex):
        """Shells out to odoo-auth-helper.ts. Raises EscrowApiError on any failure — a failed
        sign means login cannot proceed, there is no fallback.

        The passphrase is piped via stdin (`input=`), never argv — a process's command line is
        visible to any other local user via `ps aux`/`/proc/<pid>/cmdline` for as long as it
        runs; stdin isn't."""
        try:
            result = subprocess.run(
                ['npx', 'tsx', 'scripts/odoo-auth-helper.ts', secrets_dir, role, nonce_hex],
                cwd=repo_path,
                input=passphrase,
                capture_output=True,
                text=True,
                timeout=REQUEST_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise EscrowApiError(f'Could not run odoo-auth-helper.ts (is Node.js installed?): {exc}') from exc

        if result.returncode != 0:
            raise EscrowApiError(f'odoo-auth-helper.ts failed: {result.stderr.strip()}')
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise EscrowApiError(f'odoo-auth-helper.ts produced non-JSON output: {result.stdout!r}') from exc

    def login(self, repo_path, secrets_dir, role, passphrase):
        """Full challenge -> sign -> verify round trip. Returns {'sessionToken', 'expiresAt'}."""
        challenge = self.issue_challenge()
        signed = self.sign_challenge_via_helper(
            repo_path, secrets_dir, role, passphrase, challenge['nonceHex']
        )
        result = self.verify_challenge(
            challenge['challengeId'], signed['signature'], signed['signedDataHex'], signed['verifyingKey']
        )
        if 'sessionToken' not in result:
            raise EscrowApiError('Login rejected by settlement-agent (invalid/expired challenge or wrong key).')
        self.session_token = result['sessionToken']
        return result

    # ---- Deals ------------------------------------------------------------------------------

    def propose_deal(self, params):
        """Queues a propose action (202) — does NOT submit on-chain yet, see approve_pending."""
        return self._request('POST', '/deals/propose', params, expect_codes=(202,))

    def lock_deal(self, params):
        """Queues a lockEscrow action (202) — see approve_pending."""
        return self._request('POST', '/deals/lock', params, expect_codes=(202,))

    def list_pending(self, deal_ref=None):
        path = '/deals/pending'
        if deal_ref:
            path += f'?dealRef={deal_ref}'
        return self._request('GET', path)

    def approve_pending(self, pending_id):
        """Actually submits the queued propose/lockEscrow transaction on-chain."""
        return self._request('POST', f'/deals/pending/{pending_id}/approve')

    def reject_pending(self, pending_id):
        return self._request('POST', f'/deals/pending/{pending_id}/reject')

    def attest_deal(self, contract_address):
        """Immediate, single-call — no approval queue, unlike propose/lock."""
        return self._request('POST', f'/deals/{contract_address}/attest')

    def claim_deal(self, contract_address):
        return self._request('POST', f'/deals/{contract_address}/claim')

    def release_timeout_deal(self, contract_address):
        """Only the buyer-refund direction is implemented agent-side as of this module's
        writing — see actions.ts's own v0.1 scope note. Don't expose a seller-payout button
        in the UI; the call would simply fail if that branch is attempted."""
        return self._request('POST', f'/deals/{contract_address}/release-timeout')

    def get_status(self, contract_address):
        """Explicitly a convenience passthrough per the agent's own routes.ts comment, not the
        source of truth — fine for this integration's purposes."""
        return self._request('GET', f'/deals/{contract_address}/status')

    def list_incoming(self):
        return self._request('GET', '/deals/incoming')

    def whoami(self):
        """Returns {'role', 'did', 'network'} for whichever identity this agent is actually
        running as — lets the caller catch a Settings > Our role mismatch early."""
        return self._request('GET', '/identity/whoami')

    def dismiss_incoming_offer(self, offer_id):
        return self._request('POST', f'/deals/incoming/{offer_id}/dismiss')


def get_client(env):
    """Builds a ready-to-use, logged-in EscrowClient from this Odoo instance's config
    (ir.config_parameter), re-using a cached session token if it's still valid and logging in
    fresh otherwise. This is the one place escrow_deal.py / the wizards should go through,
    rather than constructing EscrowClient directly and managing the token themselves."""
    get_param = env['ir.config_parameter'].sudo().get_param
    base_url = get_param('ublp_incoterms_escrow.agent_base_url')
    if not base_url:
        raise EscrowApiError('UBLP settlement-agent URL is not configured (Settings > UBLP Incoterms Escrow).')

    token = get_param('ublp_incoterms_escrow.session_token')
    expires_at = get_param('ublp_incoterms_escrow.session_expires_at')
    now_ms = int(time.time() * 1000)

    client = EscrowClient(base_url, session_token=token or None)
    if token and expires_at and int(expires_at) > now_ms:
        return client

    repo_path = get_param('ublp_incoterms_escrow.repo_path')
    secrets_dir = get_param('ublp_incoterms_escrow.secrets_dir')
    role = get_param('ublp_incoterms_escrow.role')
    passphrase = get_param('ublp_incoterms_escrow.login_passphrase')
    if not all([repo_path, secrets_dir, role, passphrase]):
        raise EscrowApiError('UBLP connection is not fully configured (Settings > UBLP Incoterms Escrow).')

    result = client.login(repo_path, secrets_dir, role, passphrase)
    set_param = env['ir.config_parameter'].sudo().set_param
    set_param('ublp_incoterms_escrow.session_token', result['sessionToken'])
    set_param('ublp_incoterms_escrow.session_expires_at', str(result['expiresAt']))
    return client
