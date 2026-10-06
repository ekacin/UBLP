"""Seller's "propose a new deal" action — a wizard because this is a one-shot submission, not
a persisted draft the way escrow_deal.py's main record is once a contract_address exists.

propose is two-step on the agent side (queue, then a separate approve call) — this wizard only
does the queueing half; approving is a deliberate separate action (see escrow_deal's pending
queue view), matching the real human-review gate the agent itself enforces.
"""
from odoo import api, fields, models
from odoo.exceptions import UserError, ValidationError

from ..models.escrow_client import get_client, EscrowApiError
from ..models.escrow_deal import INCOTERM_SELECTION, TIMEOUT_DIRECTION_SELECTION


class ProposeDealWizard(models.TransientModel):
    _name = 'ublp.escrow.propose.wizard'
    _description = 'Propose a new UBLP Incoterms Escrow deal'

    shipment_id = fields.Char(required=True)
    buyer_partner_id = fields.Many2one(
        'res.partner', string='Buyer',
        help='Pick a Contact with UBLP details already filled in (Contacts > UBLP Incoterms '
             'Escrow tab) to auto-fill the fields below — or leave blank and fill them in by hand.',
    )
    buyer_did = fields.Char(required=True, help='e.g. did:ublp:buyer:acme-import')
    buyer_memo_public_key = fields.Char(required=True, string="Buyer's memo public key (hex)")
    port_authority_partner_id = fields.Many2one('res.partner', string='Port Authority')
    port_authority_did = fields.Char(required=True, help='e.g. did:ublp:port-authority:...')
    port_authority_key_hash = fields.Char(required=True)
    incoterm = fields.Selection(INCOTERM_SELECTION, required=True, default='FOB')
    agreed_amount = fields.Char(required=True, help='Integer string, smallest unit, e.g. 1000000')
    duration_seconds = fields.Integer(default=7 * 24 * 60 * 60, help='Default: 7 days.')
    timeout_direction = fields.Selection(TIMEOUT_DIRECTION_SELECTION, default='buyer')
    buyer_agent_url = fields.Char(
        string="Buyer's agent URL (optional)",
        help='If set, the proposal is pushed directly to the buyer\'s own agent once approved. '
             'Otherwise hand it to them out-of-band.',
    )

    @api.onchange('buyer_partner_id')
    def _onchange_buyer_partner_id(self):
        if self.buyer_partner_id:
            self.buyer_did = self.buyer_partner_id.ublp_did
            self.buyer_memo_public_key = self.buyer_partner_id.ublp_memo_public_key
            self.buyer_agent_url = self.buyer_partner_id.ublp_agent_url

    @api.onchange('port_authority_partner_id')
    def _onchange_port_authority_partner_id(self):
        if self.port_authority_partner_id:
            self.port_authority_did = self.port_authority_partner_id.ublp_did
            self.port_authority_key_hash = self.port_authority_partner_id.ublp_port_authority_key_hash

    @api.constrains('agreed_amount')
    def _check_agreed_amount(self):
        for wizard in self:
            if not wizard.agreed_amount.isdigit() or int(wizard.agreed_amount) <= 0:
                raise ValidationError(
                    'Agreed Amount must be a positive whole number (smallest unit, no letters, '
                    'no decimals) — e.g. 1000000.'
                )

    @api.constrains('buyer_did', 'port_authority_did')
    def _check_did_prefix(self):
        for wizard in self:
            for field_name in ('buyer_did', 'port_authority_did'):
                value = wizard[field_name]
                if value and not value.startswith('did:ublp:'):
                    raise ValidationError(f'{field_name} must start with "did:ublp:".')

    def action_submit(self):
        self.ensure_one()
        params = {
            'shipmentId': self.shipment_id,
            'buyerDid': self.buyer_did,
            'buyerMemoPublicKeyHex': self.buyer_memo_public_key,
            'portAuthorityDid': self.port_authority_did,
            'portAuthorityKeyHashHex': self.port_authority_key_hash,
            'incoterm': self.incoterm,
            'agreedAmount': self.agreed_amount,
            'durationSeconds': self.duration_seconds,
            'timeoutDirection': self.timeout_direction,
        }
        if self.buyer_agent_url:
            params['buyerAgentUrl'] = self.buyer_agent_url

        try:
            client = get_client(self.env)
            result = client.propose_deal(params)
        except EscrowApiError as exc:
            raise UserError(str(exc)) from exc

        # sudo(): ublp.escrow.deal has perm_create=0 for regular users on purpose (no manual
        # "New" / CSV Import should ever fabricate a deal record, e.g. a fake contract_address)
        # — this wizard's own successful agent call above is the only trusted creation path.
        self.env['ublp.escrow.deal'].sudo().create({
            'shipment_id': self.shipment_id,
            'buyer_did': self.buyer_did,
            'buyer_memo_public_key': self.buyer_memo_public_key,
            'port_authority_did': self.port_authority_did,
            'port_authority_key_hash': self.port_authority_key_hash,
            'incoterm': self.incoterm,
            'agreed_amount': self.agreed_amount,
            'duration_seconds': self.duration_seconds,
            'timeout_direction': self.timeout_direction,
            'pending_action_id': result.get('id'),
            'status': 'empty',
        })

        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': 'UBLP Incoterms Escrow',
                'message': 'Proposal queued — approve it from the Deals list to actually '
                            'submit it on-chain.',
                'type': 'success',
                # Closes this wizard dialog right after the toast — without it the form stayed
                # open and "Propose" could be clicked again, queueing a second, fully duplicate
                # propose for the same terms.
                'next': {'type': 'ir.actions.act_window_close'},
            },
        }
