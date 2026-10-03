{
    'name': 'UBLP Incoterms Escrow',
    'version': '19.0.1.0.0',
    'summary': 'Privacy-preserving Incoterms 2020 escrow on Midnight Network',
    'description': """
UBLP Incoterms Escrow
======================

Connects this Odoo instance to a company's own, self-hosted UBLP settlement-agent (see
modules/incoterms-escrow in the UBLP monorepo) over its existing REST API. No new backend code
is introduced by this module — it is a thin client.

This Odoo install always represents exactly ONE role (buyer, seller, or port-authority),
matching UBLP's "genuinely separate companies" model: there is no central UBLP server, and this
module never talks to another company's Odoo directly, only to this company's own agent.

Requires Node.js (to run the companion `odoo-auth-helper.ts` script, used to sign this
integration's own login challenge — see that script's header comment for why a human wallet
popup isn't used here) reachable from wherever this Odoo server process runs.
""",
    'author': 'UBLP',
    'license': 'AGPL-3',
    'category': 'Operations/Inventory',
    'depends': ['base'],
    'external_dependencies': {'python': ['requests']},
    'data': [
        'security/ir.model.access.csv',
        'data/ir_cron.xml',
        'views/res_partner_views.xml',
        'views/escrow_config_views.xml',
        'views/escrow_deal_views.xml',
        'views/escrow_incoming_offer_views.xml',
        'wizard/propose_deal_wizard_views.xml',
        'wizard/lock_deal_wizard_views.xml',
    ],
    'installable': True,
    'application': True,
}
