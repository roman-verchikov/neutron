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

"""create infobloxnetviewmembers table

Revision ID: 45284803ad19
Revises: 2f1983f0efc6
Create Date: 2014-03-29 21:26:25.194109

"""

# revision identifiers, used by Alembic.
revision = '45284803ad19'
down_revision = '2f1983f0efc6'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = ['*']

from alembic import op
import sqlalchemy as sa


from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.create_table(
        'infobloxnetviewmembers',
        sa.Column('member_name', sa.String(255), nullable=False),
        sa.Column('netview_name', sa.String(255), nullable=False),
        sa.PrimaryKeyConstraint('member_name'))


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_table('infobloxnetviewmembers')
