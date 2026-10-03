"""Lets a buyer/port-authority be registered ONCE as a normal Odoo Contact and then picked from
a dropdown in the Propose wizard, instead of retyping their DID/memo key/agent URL by hand on
every deal — the technical fields a real ERP user shouldn't have to remember or copy-paste.
"""
from odoo import fields, models


class ResPartner(models.Model):
    _inherit = 'res.partner'

    ublp_did = fields.Char(string='UBLP DID', help='e.g. did:ublp:buyer:acme-import')
    ublp_memo_public_key = fields.Char(
        string='UBLP Memo Public Key (hex)',
        help="This partner's long-term X25519 memo public key — used by buyers and sellers.",
    )
    ublp_port_authority_key_hash = fields.Char(
        string='UBLP Port-Authority Key Hash (hex)',
        help='Only relevant if this partner acts as an independent attester (C).',
    )
    ublp_agent_url = fields.Char(
        string='UBLP Agent URL',
        help="This partner's own settlement-agent base URL, if known — lets a proposal be "
             'pushed to them directly once approved.',
    )
