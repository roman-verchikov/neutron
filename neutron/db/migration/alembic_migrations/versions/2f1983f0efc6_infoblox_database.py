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

"""Infoblox Database

Revision ID: 2f1983f0efc6
Revises: 3341fa53aee6
Create Date: 2014-03-10 15:10:56.848382

"""

# revision identifiers, used by Alembic.
revision = '2f1983f0efc6'
down_revision = '3341fa53aee6'

# Change to ['*'] if this migration applies to all plugins

migration_for_plugins = ['*']

from alembic import op
import sqlalchemy as sa


from neutron.db import migration


def upgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.create_table(
        'infobloxtenantmembers',
        sa.Column('member_name', sa.String(255), nullable=False),
        sa.Column('tenant_id', sa.String(36), nullable=False),
        sa.PrimaryKeyConstraint('member_name'))

    op.create_table(
        'infobloxnetworkmembers',
        sa.Column('member_name', sa.String(255), nullable=False),
        sa.Column('network_id', sa.String(36), nullable=False),
        sa.PrimaryKeyConstraint('member_name'))


def downgrade(active_plugins=None, options=None):
    if not migration.should_run(active_plugins, migration_for_plugins):
        return

    op.drop_table('infobloxtenantmembers')
    op.drop_table('infobloxnetworkmembers')
