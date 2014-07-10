# Copyright 2014 OpenStack LLC.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
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

from neutron.db import models_v2, db_base_plugin_v2
from neutron.ipam.drivers.infoblox import exceptions
from neutron.ipam.drivers.infoblox import connector
from neutron.openstack.common import uuidutils
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class InfobloxEaManager(object):
    OPENSTACK_OBJECT_FLAG = 'is_openstack_object'

    def __init__(self, infoblox_db):
        # Passing this thru constructor to avoid cyclic imports
        self.db = infoblox_db
        self._network_l2_info_provider = self.db.NetworkL2InfoProvider()

    def get_extattrs_for_network(self, context, subnet, network):
        if hasattr(subnet, 'id'):
            os_subnet_id = subnet['id']
        else:
            subnet['id'] = uuidutils.generate_uuid()
            os_subnet_id = subnet['id']

        os_network_id = network['id']
        os_network_is_shared = network['shared']
        os_network_l2_info = self._network_l2_info_provider. \
            get_network_l2_info(context.session, os_network_id)
        os_network_type = os_network_l2_info['network_type']
        os_segmentation_id = os_network_l2_info['segmentation_id']
        os_physical_network = os_network_l2_info['physical_network']
        os_tenant_id = context.tenant_id
        os_user_id = context.user_id

        attributes = dict(
            os_subnet_id=os_subnet_id,
            os_network_id=os_network_id,
            os_network_is_shared=os_network_is_shared,
            os_network_type=os_network_type,
            os_segmentation_id=os_segmentation_id,
            os_physical_network=os_physical_network,
            os_tenant_id=os_tenant_id,
            os_user_id=os_user_id,
        )
        # Do not add subnet name if it's empty.
        os_subnet_name = subnet['name']
        if os_subnet_name:
            attributes['os_subnet_name'] = os_subnet_name

        return self._build_extattrs(attributes)

    def get_extattrs_for_ip(self, context, port):
        os_tenant_id = port.get('tenant_id')
        os_user_id = context.user_id

        network_is_external = self.db.is_network_external(
            context, port['network_id'])
        if network_is_external:
            os_instance_id = self.db.get_device_id_by_port(
                context, port['device_id'])
        else:
            os_instance_id = port['device_id']

        attributes = {
            'os_tenant_id': os_tenant_id,
            'os_user_id': os_user_id,
            'os_port_id': port['id']
        }
        if os_instance_id:
            # DHCP port has long device_id, so cut it.
            attributes['os_instance_id'] = os_instance_id[:36]

        return self._build_extattrs(attributes)

    def _to_str_or_none(self, value):
        retval = None
        if not isinstance(value, basestring):
            if value is not None:
                retval = str(value)
        else:
            retval = value
        return retval

    def _build_extattrs(self, attributes):
        extattrs = {}
        for name, value in attributes.iteritems():
            str_val = self._to_str_or_none(value)
            if str_val:
                extattrs[name] = {'value': str_val}

        self.add_openstack_extattrs_marker(extattrs)
        return extattrs

    @classmethod
    def add_openstack_extattrs_marker(cls, extattrs):
        extattrs[cls.OPENSTACK_OBJECT_FLAG] = {'value': 'True'}


def _construct_extattrs(filters):
    extattrs = {}
    for name, filter_value_list in filters.items():
        # Filters in Neutron look like a dict
        # {
        #   'filter1_name': ['filter1_value'],
        #   'filter2_name': ['filter2_value']
        # }
        # So we take only the first item from user's input which is
        # filter_value_list here.
        # Also not Infoblox filters must be removed from filters.
        # Infoblox filters must be as following:
        # neutron <command> --infoblox_ea:<EA_name> <EA_value>
        infoblox_prefix = 'infoblox_ea:'
        if name.startswith(infoblox_prefix) and filter_value_list:
            # "infoblox-ea:" removed from filter name
            prefix_len = len(infoblox_prefix)
            attr_name = name[prefix_len:]
            extattrs[attr_name] = {'value': filter_value_list[0]}
    return extattrs


def _extattrs_result_filter_hook(query, filters, db_model,
                                 os_object, ib_objtype, mapping_id):
    """Result filter hook which filters Infoblox objects by
     Extensible Attributes (EAs) and returns Query object containing
     OpenStack objects which are equal to Infoblox ones.
    """
    infoblox = connector.Infoblox()
    infoblox_objects_ids = []
    extattrs = _construct_extattrs(filters)

    if extattrs:
        InfobloxEaManager.add_openstack_extattrs_marker(extattrs)
        infoblox_objects = infoblox.get_object(
            ib_objtype, return_fields=['extattrs'],
            extattrs=extattrs)
        if infoblox_objects:
            for infoblox_object in infoblox_objects:
                try:
                    obj_id = infoblox_object['extattrs'][mapping_id]['value']
                except KeyError:
                    raise exceptions.NoAttributeInInfobloxObject(
                        os_object=os_object, ib_object=ib_objtype,
                        attribute=mapping_id)
                infoblox_objects_ids.append(obj_id)
        query = query.filter(db_model.id.in_(infoblox_objects_ids))
    return query


def subnet_extattrs_result_filter_hook(query, filters):
    return _extattrs_result_filter_hook(
        query, filters, models_v2.Subnet, 'subnet', 'network', 'os_subnet_id')


def network_extattrs_result_filter_hook(query, filters):
    return _extattrs_result_filter_hook(
        query, filters, models_v2.Network, 'subnet', 'network',
        'os_network_id')


def port_extattrs_result_filter_hook(query, filters):
    if cfg.CONF.use_host_records_for_ip_allocation:
        ib_objtype = 'record:host'
    else:
        ib_objtype = 'record:a'
    return _extattrs_result_filter_hook(
        query, filters, models_v2.Port, 'port', ib_objtype, 'os_port_id')


if (cfg.CONF.use_ipam and cfg.CONF.ipam_driver ==
    'neutron.ipam.drivers.infoblox.infoblox_ipam.InfobloxIPAM'):

    db_base_plugin_v2.NeutronDbPluginV2.register_model_query_hook(
        models_v2.Port, 'port_extattrs', None, None,
        port_extattrs_result_filter_hook)

    db_base_plugin_v2.NeutronDbPluginV2.register_model_query_hook(
        models_v2.Network, 'network_extattrs', None, None,
        network_extattrs_result_filter_hook)

    db_base_plugin_v2.NeutronDbPluginV2.register_model_query_hook(
        models_v2.Subnet, 'subnet_extattrs', None, None,
        subnet_extattrs_result_filter_hook)
