"""Buyer's "accept and lock" action — pastes the signed offer JSON the seller handed over
out-of-band (or copied from the agent's /deals/incoming list), matching the panel's own
LockForm (NewDeal.tsx) exactly: contract address + the raw EscrowProposal JSON blob. Signature
verification happens agent-side (acceptEscrow) — this wizard only does a shallow shape check
before sending, same as the panel's own parseEscrowProposal helper.
"""
import json

from odoo import fields, models
from odoo.exceptions import UserError

from ..models.escrow_client import get_client, EscrowApiError


class LockDealWizard(models.TransientModel):
    _name = 'ublp.escrow.lock.wizard'
    _description = 'Accept and lock a UBLP Incoterms Escrow deal'

    contract_address = fields.Char(required=True)
    signed_offer_json = fields.Text(
        required=True,
        string='Signed offer (JSON)',
        help='{"terms": {...}, "sellerSignature": "...", "sellerPublicKey": "..."}',
    )

    def _parse_proposal(self):
        try:
            proposal = json.loads(self.signed_offer_json)
        except json.JSONDecodeError as exc:
            raise UserError(f'That does not look like valid JSON: {exc}') from exc
        if not all(k in proposal for k in ('terms', 'sellerSignature', 'sellerPublicKey')):
            raise UserError(
                'This does not look like a signed EscrowTerms proposal '
                '(missing terms/sellerSignature/sellerPublicKey).'
            )
        return proposal

    def action_submit(self):
        self.ensure_one()
        # lockEscrow() is buyer-only on the agent side — same class of mistake as
        # propose_deal_wizard.py's matching guard: without this, submitting here while Odoo is
        # configured as seller/port-authority queues a pending action that can only ever fail at
        # approve time, with no way back. Caught here, before any agent call.
        role = self.env['ir.config_parameter'].sudo().get_param('ublp_incoterms_escrow.role')
        if role != 'buyer':
            raise UserError(
                f'This Odoo install is configured as "{role}", not buyer. Only the buyer can '
                'lock a deal — switch the role in Settings first.'
            )
        proposal = self._parse_proposal()
        try:
            client = get_client(self.env)
            result = client.lock_deal({'contractAddress': self.contract_address, 'proposal': proposal})
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

        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': 'UBLP Incoterms Escrow',
                'message': 'Lock queued — approve it from the Deals list to actually submit '
                            'it on-chain.',
                'type': 'success',
                # See propose_deal_wizard.py's matching comment — same double-submit risk.
                'next': {'type': 'ir.actions.act_window_close'},
            },
        }
