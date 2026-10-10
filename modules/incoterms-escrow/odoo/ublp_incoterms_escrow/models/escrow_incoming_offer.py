"""A local, refreshable mirror of the settlement-agent's /deals/incoming inbox — ported from
the React panel's own IncomingOffers.tsx, which already solved this exact problem (auto-polling,
Accept & Lock, Dismiss). Before this model existed, the Odoo module only had the raw API client
method (list_incoming) with nothing calling it — see data/ir_cron.xml for the periodic sync.

Records here are a CACHE, not the source of truth — the agent's own inbox is. action_sync_incoming
upserts by external_id so repeated syncs never duplicate a row.
"""
import json
from datetime import datetime, timedelta

from odoo import api, fields, models
from odoo.exceptions import UserError

from .escrow_client import get_client, EscrowApiError
from .escrow_deal import INCOTERM_SELECTION, TIMEOUT_DIRECTION_SELECTION

STATUS_SELECTION = [('pending', 'Pending'), ('dismissed', 'Dismissed'), ('used', 'Used')]


class EscrowIncomingOffer(models.Model):
    _name = 'ublp.escrow.incoming.offer'
    _description = 'UBLP Incoterms Escrow — incoming offer (from the settlement-agent inbox)'
    _rec_name = 'shipment_id'
    _order = 'received_at desc'

    external_id = fields.Integer(
        required=True, index=True,
        help="This offer's id on the settlement-agent itself — not an Odoo id.",
    )
    contract_address = fields.Char(required=True)
    seller_did = fields.Char()
    shipment_id = fields.Char()
    incoterm = fields.Selection(INCOTERM_SELECTION)
    agreed_amount = fields.Char()
    duration_seconds = fields.Integer()
    timeout_direction = fields.Selection(TIMEOUT_DIRECTION_SELECTION)
    port_authority_did = fields.Char()
    proposal_json = fields.Text(
        required=True,
        help='The full signed proposal blob exactly as the agent sent it — needed verbatim to '
             'call /deals/lock. Opaque to this module, never parsed beyond what the terms above '
             'already show.',
    )
    status = fields.Selection(STATUS_SELECTION, default='pending', required=True)
    received_at = fields.Datetime()

    _external_id_unique = models.Constraint(
        'unique(external_id)',
        'Each incoming offer is synced at most once.',
    )

    @api.model
    def action_sync_incoming(self):
        """Pulls the agent's current inbox and upserts local rows. Safe to call from a cron
        before Settings is configured — logs nothing alarming, just skips."""
        try:
            client = get_client(self.env)
            offers = client.list_incoming()
        except EscrowApiError:
            return

        for offer in offers:
            terms = offer['proposal']['terms']
            values = {
                'contract_address': offer['contractAddress'],
                'seller_did': terms.get('sellerDid'),
                'shipment_id': terms.get('shipmentId'),
                'incoterm': terms.get('incoterm'),
                'agreed_amount': terms.get('amount'),
                'duration_seconds': terms.get('durationSeconds'),
                'timeout_direction': terms.get('timeoutDirection', 'buyer'),
                'port_authority_did': terms.get('portAuthorityDid'),
                'proposal_json': json.dumps(offer['proposal']),
                'status': offer['status'],
                'received_at': datetime(1970, 1, 1) + timedelta(milliseconds=offer['receivedAt']),
            }
            existing = self.search([('external_id', '=', offer['id'])], limit=1)
            if existing:
                existing.write(values)
            else:
                # sudo(): perm_create=0 on purpose (no manual Import should fabricate a fake
                # incoming offer) — this sync method (cron, or the "Sync now" action) is the
                # only trusted creation path, same pattern as ublp.escrow.deal.
                self.sudo().create({**values, 'external_id': offer['id']})

    def action_accept(self):
        """Mirrors the panel's "Accept & Lock" — queues a lockEscrow pending-action (still
        needs a separate Approve from the Deals list, same as the manual-paste flow)."""
        self.ensure_one()
        proposal = json.loads(self.proposal_json)
        try:
            client = get_client(self.env)
            result = client.lock_deal({
                'contractAddress': self.contract_address,
                'proposal': proposal,
                'incomingOfferId': self.external_id,
            })
        except EscrowApiError as exc:
            raise UserError(str(exc)) from exc

        terms = proposal['terms']
        # sudo(): see propose_deal_wizard.py's matching comment — perm_create=0 on purpose.
        self.env['ublp.escrow.deal'].sudo().create({
            'shipment_id': terms.get('shipmentId', self.contract_address),
            'created_as_role': 'buyer',
            'contract_address': self.contract_address,
            'seller_did': terms.get('sellerDid'),
            'port_authority_did': terms.get('portAuthorityDid'),
            'incoterm': terms.get('incoterm'),
            'agreed_amount': terms.get('amount'),
            'duration_seconds': terms.get('durationSeconds'),
            'timeout_direction': terms.get('timeoutDirection', 'buyer'),
            'pending_action_id': result.get('id'),
            'status': 'proposed',
        })
        self.status = 'used'
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': 'UBLP Incoterms Escrow',
                'message': 'Lock queued — approve it from the Deals list to actually submit '
                            'it on-chain.',
                'type': 'success',
            },
        }

    def action_dismiss(self):
        self.ensure_one()
        try:
            client = get_client(self.env)
            client.dismiss_incoming_offer(self.external_id)
        except EscrowApiError as exc:
            raise UserError(str(exc)) from exc
        self.status = 'dismissed'
