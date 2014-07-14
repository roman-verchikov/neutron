# Copyright 2014 OpenStack LLC.
# All Rights Reserved.
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

from oslo.config import cfg
import sqlalchemy as sa
from sqlalchemy.orm import exc

from neutron.db import external_net_db
from neutron.db import model_base
from neutron.db import models_v2
from neutron.openstack.common import log as logging
from neutron.plugins.ml2 import db as ml2_db
from neutron.plugins.openvswitch import ovs_db_v2

LOG = logging.getLogger(__name__)


DHCP_MEMBER_TYPE = 'dhcp'
DNS_MEMBER_TYPE = 'dns'


class InfobloxMemberMap(model_base.BASEV2):
    """Maps Neutron object to Infoblox member.

    map_id may point to Network ID, Tenant ID or Infoblox network view name
    depending on configuration. Infoblox member names are unique."""

    member_name = sa.Column(sa.String(255), nullable=False, primary_key=True)
    map_id = sa.Column(sa.String(255), nullable=False)
    member_type = sa.Column(sa.Enum(DHCP_MEMBER_TYPE, DNS_MEMBER_TYPE))


def get_used_members(context, member_type):
    """Returns used names of members."""
    query = context.session.query(InfobloxMemberMap.member_name)
    members = query.filter_by(member_type=member_type).distinct()
    return [m.member_name for m in members]


def get_member(context, map_id, member_type):
    """Returns names of members used by currently used mapping (tenant id,
    network id or Infoblox netview name)."""
    q = context.session.query(InfobloxMemberMap)

    member = q.filter_by(map_id=map_id, member_type=member_type).first()

    if member:
        return member.member_name

    return None


def attach_member(context, map_id, member_name, member_type):
    context.session.add(InfobloxMemberMap(map_id=map_id,
                                          member_name=member_name,
                                          member_type=member_type))


def delete_members(context, map_id):
    with context.session.begin(subtransactions=True):
        context.session.query(InfobloxMemberMap).filter_by(map_id=map_id).\
            delete()


def is_last_subnet(context, subnet_id):
    q = context.session.query(models_v2.Subnet)
    return q.filter(models_v2.Subnet.id != subnet_id).count() == 0


def is_network_external(context, network_id):
    try:
        context.session.query(external_net_db.ExternalNetwork).filter_by(
            network_id=network_id).one()
        return True
    except exc.NoResultFound:
        return False


def delete_ip_allocation(context, network_id, subnet, ip_address):
    # Delete the IP address from the IPAllocate table
    subnet_id = subnet['id']
    LOG.debug(_("Delete allocated IP %(ip_address)s "
                "(%(network_id)s/%(subnet_id)s)"), locals())
    alloc_qry = context.session.query(
        models_v2.IPAllocation).with_lockmode('update')
    alloc_qry.filter_by(network_id=network_id,
                        ip_address=ip_address,
                        subnet_id=subnet_id).delete()


def get_subnets_by_network(context, network_id):
    subnet_qry = context.session.query(models_v2.Subnet)
    return subnet_qry.filter_by(network_id=network_id).all()


def get_network_name(context, subnet):
    q = context.session.query(models_v2.Network)
    net_name = q.join(models_v2.Subnet).filter(
        models_v2.Subnet.id == subnet['id']).first()

    if net_name:
        return net_name.name


def get_device_id_by_port(context, port_id):
    try:
        query = context.session.query(models_v2.Port)
        port = query.filter(models_v2.Port.id == port_id).one()
    except exc.NoResultFound:
        return None

    if port:
        return port.device_id

    return None


def get_subnet_dhcp_port_address(context, subnet_id):
    dhcp_port = (context.session.query(models_v2.IPAllocation).
                 filter_by(subnet_id=subnet_id).
                 join(models_v2.Port).
                 filter_by(device_owner='network:dhcp')
                 .first())
    if dhcp_port:
        return dhcp_port.ip_address
    return None


class NetworkL2InfoProvider(object):
    def __init__(self, plugin=None):
        """plugin - OpenStack core plugin
        This class is nessesary for providing information
        about network_type, physical_network and segmentation_id
        for each core plugin
        """
        if not plugin:
            self.plugin = cfg.CONF.core_plugin
        else:
            self.plugin = plugin

    def _get_behavior_class(self):
        if self.plugin == 'neutron.plugins.ml2.plugin.Ml2Plugin':
            return Ml2NetworkL2InfoProvider()
        if self.plugin == 'neutron.plugins.openvswitch.' \
                          'ovs_neutron_plugin.OVSNeutronPluginV2':
            return OVSNetworkL2InfoProvider()

    def get_network_l2_info(self, session, network_id):
        behavior_class = self._get_behavior_class()
        return behavior_class.get_network_l2_info(session, network_id)


class Ml2NetworkL2InfoProvider(object):
    def get_network_l2_info(self, session, network_id):
        network_segments = ml2_db.get_network_segments(session, network_id)
        result = dict()
        if network_segments:
            for name, value in network_segments[0].iteritems():
                result[name] = value
            return result
        else:
            return {'network_type': None,
                    'segmentation_id': None,
                    'physical_network': None}


class OVSNetworkL2InfoProvider(object):
    def get_network_l2_info(self, session, network_id):
        network_binding = ovs_db_v2.get_network_binding(session, network_id)
        result = dict()
        if network_binding:
            for name, value in network_binding.iteritems():
                result[name] = value
            return result
        else:
            return {'network_type': None,
                    'segmentation_id': None,
                    'physical_network': None}
