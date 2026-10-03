"""Connection settings for this Odoo instance's one UBLP role.

v0.1 simplification, flagged rather than hidden: the login passphrase is stored via
ir.config_parameter (Odoo's own settings store), same trust level as any other Odoo system
parameter — not a dedicated secrets vault. A real production deployment should source it from
an environment variable or Odoo's own credential-management tooling instead.
"""
from odoo import api, fields, models
from odoo.exceptions import UserError

from .escrow_client import get_client, EscrowApiError


class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    ublp_agent_base_url = fields.Char(
        string='Settlement-agent URL',
        config_parameter='ublp_incoterms_escrow.agent_base_url',
        help='This company\'s own settlement-agent, e.g. http://localhost:4100',
    )
    ublp_role = fields.Selection(
        [('buyer', 'Buyer'), ('seller', 'Seller'), ('port-authority', 'Port Authority')],
        string='Our role',
        config_parameter='ublp_incoterms_escrow.role',
    )
    ublp_repo_path = fields.Char(
        string='UBLP repo path',
        config_parameter='ublp_incoterms_escrow.repo_path',
        help='Absolute path to the UBLP monorepo checkout on this server, e.g. '
             '/opt/UBLP/modules/incoterms-escrow — needed to invoke odoo-auth-helper.ts.',
    )
    ublp_secrets_dir = fields.Char(
        string='Login key storage directory',
        config_parameter='ublp_incoterms_escrow.secrets_dir',
        help='Where this Odoo install\'s own dedicated login signing key is encrypted at rest. '
             'Must be writable by the Odoo server process.',
    )
    ublp_login_passphrase = fields.Char(
        string='Login key passphrase',
        config_parameter='ublp_incoterms_escrow.login_passphrase',
    )

    def ublp_test_connection(self):
        """Button handler — saves the form's current values first (so get_client reads what's
        on screen, not stale config), then runs a real login round trip."""
        self.ensure_one()
        self.execute()  # persist the fields' config_parameter values before testing them
        try:
            client = get_client(self.env)
            whoami = client.whoami()
        except EscrowApiError as exc:
            raise UserError(str(exc)) from exc

        if whoami.get('role') != self.ublp_role:
            message = (
                f'Connected, but this agent is actually running as "{whoami.get("role")}", '
                f'not "{self.ublp_role}" — fix "Our role" above or you may be talking to the '
                'wrong agent.'
            )
            notif_type = 'warning'
        else:
            message = 'Connected and logged in successfully.'
            notif_type = 'success'

        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': 'UBLP Incoterms Escrow',
                'message': message,
                'type': notif_type,
            },
        }
