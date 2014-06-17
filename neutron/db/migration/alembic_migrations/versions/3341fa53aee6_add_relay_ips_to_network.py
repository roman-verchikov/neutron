# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2014 OpenStack Foundation
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

"""Add relay IPs to Network

Revision ID: 3341fa53aee6
Revises: havana
Create Date: 2014-03-10 07:29:01.918712

"""

# revision identifiers, used by Alembic.
revision = '3341fa53aee6'
down_revision = '2db5203cb7a9'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = ['*']

from alembic import op
import sqlalchemy as sa

from neutron.db import migration


DHCP_RELAY_IP = 'dhcp_relay_ip'
DNS_RELAY_IP = 'dns_relay_ip'


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.add_column(
        'networks',
        sa.Column(DHCP_RELAY_IP, sa.String(length=64), nullable=True)
    )
    op.add_column(
        'networks',
        sa.Column(DNS_RELAY_IP, sa.String(length=64), nullable=True)
    )


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_column('networks', DHCP_RELAY_IP)
    op.drop_column('networks', DNS_RELAY_IP)
