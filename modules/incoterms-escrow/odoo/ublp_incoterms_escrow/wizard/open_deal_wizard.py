"""Ported from the React panel's own OpenDeal.tsx + DealStatus.tsx (AGENTS.md 5.21) — the
pattern that already solves "a port-authority was never the one who proposed/locked this deal,
so it has no local record of it" cleanly: don't create one. A deal is identified purely by its
on-chain contract_address; this wizard loads its LIVE status (GET /deals/:contractAddress/status)
on demand and shows role-gated action buttons, with no persistent ublp.escrow.deal row at all.

Privacy note (verified against the real route, not assumed): the status read returns only
state/milestoneConfirmed/deadlineTimestamp/timeoutDirection/ownRecord — never the amount or
either party's DID. ownRecord (the only place an amount appears) is populated purely from this
agent's OWN local transaction log, filtered by this exact contractAddress — a party who never
proposed/locked/claimed this deal (e.g. a real port-authority) gets an empty ownRecord and never
learns the amount at all, same as the panel.
"""
import time

from odoo import api, fields, models
from odoo.exceptions import UserError

from ..models.escrow_client import get_client, EscrowApiError
from ..models.escrow_deal import TIMEOUT_DIRECTION_SELECTION

_ONCHAIN_STATE_LABELS = {0: 'Empty', 1: 'Proposed', 2: 'Locked', 3: 'Released'}


class OpenDealWizard(models.TransientModel):
    _name = 'ublp.escrow.open.wizard'
    _description = 'Open a UBLP Incoterms Escrow deal by contract address (no local record kept)'

    contract_address = fields.Char(required=True, help="Paste the address the other party shared with you.")
    loaded = fields.Boolean(default=False, readonly=True)

    role = fields.Char(readonly=True)
    raw_state = fields.Integer(readonly=True)
    status_label = fields.Char(readonly=True)
    milestone_confirmed = fields.Boolean(readonly=True)
    deadline_timestamp = fields.Integer(readonly=True)
    timeout_direction = fields.Selection(TIMEOUT_DIRECTION_SELECTION, readonly=True)
    is_expired = fields.Boolean(readonly=True)
    own_record_summary = fields.Text(
        readonly=True,
        help="This agent's own bookkeeping for this deal, if any — never written to the chain, "
             "and empty unless this install itself proposed/locked/claimed this exact deal.",
    )

    def _reopen(self):
        """A target='new' wizard dialog closes by default when a button method returns nothing
        — every action below needs the dialog to stay open showing the refreshed status, so
        each explicitly re-opens itself instead of returning None."""
        return {
            'type': 'ir.actions.act_window',
            'res_model': self._name,
            'res_id': self.id,
            'view_mode': 'form',
            'target': 'new',
        }

    def action_load_status(self):
        self.ensure_one()
        try:
            client = get_client(self.env)
            whoami = client.whoami()
            status = client.get_status(self.contract_address)
        except EscrowApiError as exc:
            raise UserError(str(exc)) from exc

        own_record = status.get('ownRecord') or []
        summary = '\n'.join(
            f"{entry['action']}: {entry.get('amount', '—')} {entry.get('currency', '')}"
            for entry in own_record
        ) or '(none — this install never proposed/locked/claimed this deal itself)'

        self.write({
            'loaded': True,
            'role': whoami.get('role'),
            'raw_state': status['state'],
            'status_label': _ONCHAIN_STATE_LABELS.get(status['state'], str(status['state'])),
            'milestone_confirmed': status['milestoneConfirmed'],
            'deadline_timestamp': status['deadlineTimestamp'],
            'timeout_direction': status['timeoutDirection'],
            'is_expired': bool(status['deadlineTimestamp']) and time.time() > status['deadlineTimestamp'],
            'own_record_summary': summary,
        })
        return self._reopen()

    def action_attest(self):
        self.ensure_one()
        try:
            get_client(self.env).attest_deal(self.contract_address)
        except EscrowApiError as exc:
            raise UserError(str(exc)) from exc
        self.action_load_status()
        return self._reopen()

    def action_claim(self):
        self.ensure_one()
        try:
            get_client(self.env).claim_deal(self.contract_address)
        except EscrowApiError as exc:
            raise UserError(str(exc)) from exc
        self.action_load_status()
        return self._reopen()

    def action_release_timeout(self):
        """Buyer-refund direction only — see escrow_deal.py's matching method; the
        seller-payout branch isn't implemented agent-side yet, so this view never offers it."""
        self.ensure_one()
        try:
            get_client(self.env).release_timeout_deal(self.contract_address)
        except EscrowApiError as exc:
            raise UserError(str(exc)) from exc
        self.action_load_status()
        return self._reopen()
