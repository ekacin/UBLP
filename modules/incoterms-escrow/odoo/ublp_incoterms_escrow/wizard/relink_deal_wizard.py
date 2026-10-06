"""Admin-only recovery path for a deal record whose local state has desynced from the real
on-chain/agent-side truth — e.g. a slow approve whose response Odoo never got to process (see
escrow_deal.py's is_submitting / action_reject_pending docstrings for the real incident this
exists to recover from). contract_address stays auto-set/read-only for the normal propose/lock
flow (see escrow_deal.py's own field docstring) — this is deliberately a separate, explicit,
admin-gated action, not a loosening of that rule. Restricted to base.group_system in
ir.model.access.csv, same group as deal deletion.
"""
from odoo import fields, models
from odoo.exceptions import UserError

from ..models.escrow_client import get_client, EscrowApiError


class RelinkDealWizard(models.TransientModel):
    _name = 'ublp.escrow.relink.wizard'
    _description = 'Manually relink a UBLP Incoterms Escrow deal to its real on-chain contract'

    deal_id = fields.Many2one('ublp.escrow.deal', required=True, readonly=True)
    contract_address = fields.Char(
        required=True,
        help='The real, already-deployed contract address for this deal — e.g. recovered from '
             'the settlement-agent\'s own pending-actions log or transaction history after a '
             'desync. Typing an address that was never actually deployed will simply make '
             '"Refresh status" fail below; nothing on-chain is created or changed by this action.',
    )
    clear_pending_action = fields.Boolean(
        default=True,
        help='Also clear the stuck "Pending action ID" — almost always what you want: a deal '
             'being relinked here already has a real on-chain outcome, so there is nothing left '
             'to approve/reject locally.',
    )

    def action_submit(self):
        self.ensure_one()
        values = {'contract_address': self.contract_address, 'is_submitting': False}
        if self.clear_pending_action:
            values['pending_action_id'] = False
        self.deal_id.sudo().write(values)
        try:
            self.deal_id.action_refresh_status()
        except (UserError, EscrowApiError):
            # Saving the address is the important part — a failed refresh (e.g. this role's
            # agent isn't configured/reachable right now) shouldn't block that; the user can
            # retry "Refresh status" from the deal form once it is.
            pass
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': 'UBLP Incoterms Escrow',
                'message': 'Relinked. Use "Refresh status" on the deal if its on-chain status '
                            "doesn't look right yet.",
                'type': 'success',
            },
        }
