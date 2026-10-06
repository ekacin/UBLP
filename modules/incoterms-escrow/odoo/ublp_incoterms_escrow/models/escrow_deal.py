"""A deal tracked by this Odoo instance's one UBLP role.

Status representation is deliberately NOT a rigid 1:1 mirror of the on-chain EscrowState enum
(Empty/Proposed/Locked/Released) — see the plan this module was built from
([[project_ublp_escrow_architectural_gaps]]): a real dispute-resolution mechanism is a known,
not-yet-designed gap in the underlying contract, and when it lands it will likely add a new
state that doesn't exist on-chain today. `status` is computed from the raw on-chain state plus
`milestone_confirmed`/deadline in ONE place (`_compute_status`) specifically so that adding a
real "disputed" branch later is a logic change here, not a schema migration. Selection fields in
Odoo tolerate new values being added later without invalidating existing stored rows.
"""
import time

from odoo import api, fields, models
from odoo.exceptions import UserError, ValidationError

from .escrow_client import get_client, EscrowApiError

INCOTERM_SELECTION = [
    ('EXW', 'EXW — Ex Works'),
    ('FCA', 'FCA — Free Carrier'),
    ('CPT', 'CPT — Carriage Paid To'),
    ('CIP', 'CIP — Carriage and Insurance Paid To'),
    ('DAP', 'DAP — Delivered at Place'),
    ('DPU', 'DPU — Delivered at Place Unloaded'),
    ('DDP', 'DDP — Delivered Duty Paid'),
    ('FAS', 'FAS — Free Alongside Ship'),
    ('FOB', 'FOB — Free on Board'),
    ('CFR', 'CFR — Cost and Freight'),
    ('CIF', 'CIF — Cost, Insurance and Freight'),
]

TIMEOUT_DIRECTION_SELECTION = [('buyer', 'Buyer (refund)'), ('seller', 'Seller')]

# Extensible on purpose — see module docstring. Only the first four exist on-chain today.
STATUS_SELECTION = [
    ('empty', 'Empty'),
    ('proposed', 'Proposed'),
    ('locked', 'Locked'),
    ('released', 'Released'),
]

_ONCHAIN_STATE_TO_STATUS = {0: 'empty', 1: 'proposed', 2: 'locked', 3: 'released'}


class EscrowDeal(models.Model):
    _name = 'ublp.escrow.deal'
    _description = 'UBLP Incoterms Escrow Deal'
    _rec_name = 'shipment_id'

    shipment_id = fields.Char(required=True)
    contract_address = fields.Char(
        index=True, readonly=True,
        help='Set automatically once action_approve_pending submits the deal on-chain and the '
             'agent returns a real address — never typed in manually.',
    )

    # readonly=True on every field below: all of these are set ONCE, at creation, from whatever
    # was actually submitted to the agent (propose/lock) — editing them afterward through the
    # generic form wouldn't change the real on-chain deal at all, only desync this local record
    # from reality. The wizards' own sudo().create() calls are unaffected (readonly is a UI-only
    # hint, not an ORM/write() restriction) — see contract_address's identical pattern above.
    seller_did = fields.Char(string='Seller DID', readonly=True)
    buyer_did = fields.Char(string='Buyer DID', readonly=True)
    port_authority_did = fields.Char(string='Port Authority DID', readonly=True)
    port_authority_key_hash = fields.Char(string='Port Authority key hash', readonly=True)
    buyer_memo_public_key = fields.Char(string="Buyer's memo public key (hex)", readonly=True)

    incoterm = fields.Selection(INCOTERM_SELECTION, required=True, default='FOB', readonly=True)
    agreed_amount = fields.Char(
        required=True, readonly=True,
        help='Integer string, smallest unit — matches the wire format exactly (BigInt on the '
             'agent side), not a float, to avoid any rounding mismatch with the on-chain commitment.',
    )
    duration_seconds = fields.Integer(default=7 * 24 * 60 * 60, help='Default: 7 days.', readonly=True)
    timeout_direction = fields.Selection(TIMEOUT_DIRECTION_SELECTION, default='buyer', readonly=True)

    onchain_state = fields.Integer(string='Raw on-chain state', readonly=True)
    milestone_confirmed = fields.Boolean(readonly=True)
    deadline_timestamp = fields.Integer(readonly=True)
    status = fields.Selection(STATUS_SELECTION, default='empty', readonly=True, store=True)

    pending_action_id = fields.Integer(
        string='Pending action ID',
        readonly=True,
        help='Set while a propose/lock call is queued awaiting approval on the agent side.',
    )

    # Every action below (approve/attest/claim/release-timeout) makes a REAL on-chain call —
    # a ZK proof + a chain submission, empirically over a minute, sometimes 2+ (see
    # CHAIN_OPERATION_TIMEOUT_SECONDS in escrow_client.py). Odoo's own button click gives no
    # visual feedback once the request is in flight beyond a brief spin that's easy to miss —
    # found the hard way: a user who saw no feedback for a slow-but-successful Approve clicked
    # Reject instead, assuming it had failed. Without this flag the Reject click would silently
    # succeed against an action the agent had *already confirmed on-chain*, permanently losing
    # the only local record of a real contractAddress — see the matching fix in routes.ts's
    # /deals/pending/:id/reject (status guard) for the other half of that bug. This flag is
    # written and `env.cr.commit()`-ed BEFORE the slow call starts specifically so it's visible
    # immediately (the view swaps the button for a "please wait" banner), not only after the
    # slow call eventually returns.
    is_submitting = fields.Boolean(
        default=False, readonly=True,
        help='True while a propose/lock approval, attest, claim, or timeout-release call is in '
             'flight against the settlement-agent. Prevents a second click on the same action '
             'and on Reject while the first is still running.',
    )

    @api.constrains('agreed_amount')
    def _check_agreed_amount(self):
        for deal in self:
            if not deal.agreed_amount.isdigit() or int(deal.agreed_amount) <= 0:
                raise ValidationError(
                    'Agreed Amount must be a positive whole number (smallest unit, no letters, '
                    'no decimals) — e.g. 1000000.'
                )

    @api.constrains('seller_did', 'buyer_did', 'port_authority_did')
    def _check_did_prefix(self):
        for deal in self:
            for field_name in ('seller_did', 'buyer_did', 'port_authority_did'):
                value = deal[field_name]
                if value and not value.startswith('did:ublp:'):
                    raise ValidationError(f'{field_name} must start with "did:ublp:".')

    @api.model
    def _status_from_onchain(self, onchain_state):
        return _ONCHAIN_STATE_TO_STATUS.get(onchain_state, 'empty')

    def _run_chain_operation(self, call):
        """Shared wrapper for every button that makes a real on-chain call (approve/attest/
        claim/release-timeout) — see is_submitting's own docstring for why this exists. `call`
        is a zero-arg callable doing the actual EscrowApiError-raising work; this only handles
        the in-progress flag around it. Commits straight away so the flag is visible to anyone
        re-reading this record (e.g. a page refresh) the instant the click registers, not only
        once the slow call eventually finishes."""
        self.ensure_one()
        if self.is_submitting:
            raise UserError(
                'An on-chain operation is already in progress for this deal — please wait for '
                'it to finish (this can take a minute or two) before trying again.'
            )
        self.is_submitting = True
        self.env.cr.commit()
        try:
            call()
        except Exception:
            self.is_submitting = False
            self.env.cr.commit()
            raise
        self.is_submitting = False

    def action_refresh_status(self):
        """Pulls GET /deals/:contractAddress/status and updates this record. A no-op (with a
        warning) for deals that have no contract_address yet (not yet proposed/approved)."""
        for deal in self:
            if not deal.contract_address:
                continue
            try:
                client = get_client(self.env)
                result = client.get_status(deal.contract_address)
            except EscrowApiError as exc:
                raise UserError(str(exc)) from exc
            deal.write({
                'onchain_state': result['state'],
                'milestone_confirmed': result['milestoneConfirmed'],
                'deadline_timestamp': result['deadlineTimestamp'],
                'timeout_direction': result['timeoutDirection'],
                'status': deal._status_from_onchain(result['state']),
            })

    def action_approve_pending(self):
        """Second step of the propose/lock two-step flow — actually submits the queued action
        on-chain. Separate from action_submit on the wizards on purpose: queueing and approving
        are deliberately distinct human steps on the agent side (a real review gate), not a
        single call this module should collapse into one button."""
        self.ensure_one()
        if not self.pending_action_id:
            raise UserError('This deal has no pending action to approve.')

        result = {}

        def call():
            try:
                client = get_client(self.env)
                result['value'] = client.approve_pending(self.pending_action_id)
            except EscrowApiError as exc:
                raise UserError(str(exc)) from exc

        self._run_chain_operation(call)
        contract_address = result['value'].get('contractAddress') or result['value'].get('contract_address')
        self.write({
            'contract_address': contract_address or self.contract_address,
            'pending_action_id': False,
        })
        if self.contract_address:
            self.action_refresh_status()

    def action_reject_pending(self):
        self.ensure_one()
        if not self.pending_action_id:
            raise UserError('This deal has no pending action to reject.')
        if self.is_submitting:
            # Mirrors routes.ts's own status guard on /deals/pending/:id/reject: once an
            # approval is in flight it may already be confirmed on-chain by the time this
            # click lands — rejecting it then would just desync this local record from a deal
            # that actually went through, with the real contractAddress lost. See
            # is_submitting's docstring for the real incident this fixes.
            raise UserError(
                'An approval is currently in progress for this deal — please wait for it to '
                'finish (or fail) before rejecting.'
            )

        def call():
            try:
                client = get_client(self.env)
                client.reject_pending(self.pending_action_id)
            except EscrowApiError as exc:
                raise UserError(str(exc)) from exc

        self._run_chain_operation(call)
        self.write({'pending_action_id': False})

    def action_attest(self):
        """Port-authority only, in practice — the agent itself will reject this call if our
        role isn't port-authority; no client-side role gate is duplicated here."""
        self.ensure_one()

        def call():
            try:
                client = get_client(self.env)
                client.attest_deal(self.contract_address)
            except EscrowApiError as exc:
                raise UserError(str(exc)) from exc

        self._run_chain_operation(call)
        self.action_refresh_status()

    def action_claim(self):
        self.ensure_one()

        def call():
            try:
                client = get_client(self.env)
                client.claim_deal(self.contract_address)
            except EscrowApiError as exc:
                raise UserError(str(exc)) from exc

        self._run_chain_operation(call)
        self.action_refresh_status()

    def action_release_timeout(self):
        """Only the buyer-refund direction is implemented agent-side today — see
        escrow_client.py's release_timeout_deal docstring. The view only shows this button when
        timeout_direction == 'buyer', matching that real limitation."""
        self.ensure_one()

        def call():
            try:
                client = get_client(self.env)
                client.release_timeout_deal(self.contract_address)
            except EscrowApiError as exc:
                raise UserError(str(exc)) from exc

        self._run_chain_operation(call)
        self.action_refresh_status()
