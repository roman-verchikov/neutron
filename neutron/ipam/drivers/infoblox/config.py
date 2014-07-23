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

import json
import io
from operator import attrgetter

from oslo.config import cfg as neutron_conf

from neutron.ipam.drivers.infoblox import exceptions
from neutron.ipam.drivers.infoblox import objects
from neutron.db.infoblox import infoblox_db as ib_db

OPTS = [
    neutron_conf.StrOpt('conditional_config', default=None,
                        help=_("Infoblox conditional config path")),
    neutron_conf.StrOpt('infoblox_members_config', default=None,
                        help=_("Path to infoblox members config file."))
]

neutron_conf.CONF.register_opts(OPTS)


class ConfigFinder(object):
    VALID_CONDITIONS = ['global', 'tenant', 'tenant_id:', 'subnet_range:']

    def __init__(self, stream=None, member_manager=None):
        """Reads config from `io.IOBase`:stream:. Config is JSON format."""
        if not member_manager:
            member_manager = MemberManager()
        if not stream:
            config_file = neutron_conf.CONF.conditional_config
            if not config_file:
                raise exceptions.ConfigNotFound(object='conditional config')
            stream = io.FileIO(config_file)

        self.member_manager = member_manager

        with stream:
            try:
                self.conf = json.loads(stream.read())
                self._validate_conditions()
            except ValueError as e:
                raise exceptions.InfobloxInvalidConditionalConfig(msg=e)

    def find_config_for_subnet(self, context, net_or_subnet):
        """
        Returns first configuration which matches the object being created.
        :param context:
        :param net_or_subnet:
        :return: :raise exceptions.InfobloxNoConfigFoundForSubnet:
        """
        for cfg in self.conf:
            cfg = Config(cfg, context, net_or_subnet, self.member_manager)
            if self._condition_matches(context, cfg, net_or_subnet):
                return cfg

        raise exceptions.InfobloxNoConfigFoundForSubnet(subnet=net_or_subnet)

    find_config_for_network = find_config_for_subnet

    @staticmethod
    def _variable_condition_match(condition, var, expected):
        return (condition.startswith(var) and
                condition.split(':')[1] == expected)

    def _condition_matches(self, context, config, net_or_subnet):
        net_id = net_or_subnet.get('network_id', net_or_subnet.get('id'))
        cidr = net_or_subnet.get('cidr')
        tenant_id = net_or_subnet['tenant_id']

        is_external = ib_db.is_network_external(context, net_id)
        cond = config.condition
        condition_matches = (
            cond == 'global' or cond == 'tenant' or
            self._variable_condition_match(cond, 'tenant_id', tenant_id) or
            self._variable_condition_match(cond, 'subnet_range', cidr))

        return config.is_external == is_external and condition_matches

    def _validate_conditions(self):
        for conf in self.conf:
            if not any([conf['condition'].startswith(valid)
                        for valid in self.VALID_CONDITIONS]):
                msg = 'Invalid condition specified: {}'.format(
                    conf['condition'])
                raise exceptions.InfobloxInvalidConditionalConfig(msg=msg)


class PatternBuilder(object):
    def __init__(self, *pattern):
        self.pattern = '.'.join([el.strip('.')
                                 for el in pattern if el is not None])

    def build(self, context, subnet, port=None, ip_addr=None):
        """
        Builds string by passing supplied values into pattern
        :raise exceptions.InvalidPattern:
        """
        self._validate_pattern()

        subnet_name = subnet['name'] if subnet['name'] else subnet['id']

        pattern_dict = {
            'network_id': subnet['network_id'],
            'network_name': ib_db.get_network_name(context, subnet),
            'tenant_id': subnet['tenant_id'],
            'subnet_name': subnet_name,
            'subnet_id': subnet['id'],
            'user_id': context.user_id
        }

        if ip_addr:
            octets = ip_addr.split('.')
            pattern_dict['ip_address'] = ip_addr.replace('.', '-')
            for i in xrange(len(octets)):
                octet_key = 'ip_address_octet{i}'.format(i=(i + 1))
                pattern_dict[octet_key] = octets[i]

        if port:
            pattern_dict['port_id'] = port['id']
            pattern_dict['instance_id'] = port['device_id']

        try:
            fqdn = self.pattern.format(**pattern_dict)
        except (KeyError, IndexError) as e:
            raise exceptions.InvalidPattern(msg=e)

        return fqdn

    def _validate_pattern(self):
        invalid_values = ['..']
        for val in invalid_values:
            if val in self.pattern:
                error_message = "Invalid value {}".format(val)
                raise exceptions.InvalidPattern(msg=error_message)


class Config(object):
    NEXT_AVAILABLE_MEMBER = '<next-available-member>'
    NETWORK_VIEW_TEMPLATES = ['{tenant_id}',
                              '{network_name}',
                              '{network_id}']

    def __init__(self, config_dict, context, net_or_subnet,
                 member_manager=None):
        if not member_manager:
            member_manager = MemberManager()

        if 'condition' not in config_dict:
            raise exceptions.InfobloxInvalidConditionalConfig(
                msg="Missing mandatory 'condition' option")

        self.condition = config_dict['condition']
        self.is_external = config_dict.get('is_external', False)

        self._cached_network_view = None

        self._net_view = config_dict.get('network_view', 'default')
        self._dns_view = config_dict.get('dns_view')

        self.require_dhcp_relay = config_dict.get('require_dhcp_relay', False)

        self._dhcp_members = config_dict.get('dhcp_members',
                                             self.NEXT_AVAILABLE_MEMBER)
        self._dns_members = config_dict.get('dns_members')

        self.domain_suffix_pattern = config_dict.get(
            'domain_suffix_pattern', 'global.com')
        self.hostname_pattern = config_dict.get(
            'hostname_pattern', 'host-{ip_address}.{subnet_name}')

        self.network_template = config_dict.get('network_template')
        self.ns_group = config_dict.get('ns_group')

        self.context = context
        self.net_or_subnet = net_or_subnet
        self.member_manager = member_manager

    @property
    def network_view(self):
        if self._cached_network_view is not None:
            # do all the heavy stuff once
            return self._cached_network_view

        if (self._net_view.startswith('{') and
                self._net_view not in self.NETWORK_VIEW_TEMPLATES):
            raise exceptions.InfobloxInvalidConditionalConfig(
                msg="Invalid value for 'network_view'")

        if self._net_view == '{tenant_id}':
            self._cached_network_view = self.net_or_subnet['tenant_id']
        elif self._net_view == '{network_name}':
            is_subnet = self.net_or_subnet.get('network_id') is not None
            if is_subnet:
                self._cached_network_view = ib_db.get_network_name(
                    self.context, self.net_or_subnet)
            else:
                # network
                self._cached_network_view = self.net_or_subnet['name']
        elif self._net_view == '{network_id}':
            self._cached_network_view = self.net_or_subnet.get(
                'network_id', self.net_or_subnet['id'])
        else:
            self._cached_network_view = self._net_view

        return self._cached_network_view

    @property
    def dns_view(self):
        if self._dns_view:
            return self._dns_view

        if self.network_view and self.network_view != 'default':
            return '.'.join(['default', self.network_view])
        return 'default'

    @property
    def dhcp_member(self):
        return self._get_member(ib_db.DHCP_MEMBER_TYPE)

    @property
    def dns_member(self):
        return self._get_member(ib_db.DNS_MEMBER_TYPE)

    @property
    def is_global_config(self):
        return self.condition == 'global'

    def reserve_dns_member(self):
        reserved_member = self._reserve_member(self._dns_members,
                                               self.ns_group,
                                               ib_db.DNS_MEMBER_TYPE)
        return reserved_member

    def reserve_dhcp_member(self):
        reserved_member = self._reserve_member(self._dhcp_members,
                                               self.network_template,
                                               ib_db.DHCP_MEMBER_TYPE)
        # use DHCP member for DNS if DNS is not set
        if self._dns_members is None:
            self._reserve_member(reserved_member.name,
                                 self.network_template,
                                 ib_db.DNS_MEMBER_TYPE)
        return reserved_member

    def requires_net_view(self):
        return not self.is_external

    def _get_member(self, member_type):
        member = self.member_manager.find_member(
            self.context, self.network_view, member_type)

        if member is not None:
            return member

        msg = ("Looks like you're trying to call config.{member_type}_member "
               "without reserving one. You should call "
               "reserve_{member_type}_member() "
               "first!".format(member_type=member_type))
        raise RuntimeError(msg)

    def _reserve_member(self, members, template, member_type):
        member = self.member_manager.find_member(self.context,
                                                 self.network_view,
                                                 member_type)

        if member:
            return member

        if template:
            member = self._get_member_from_template(members,
                                                    template)
            self.member_manager.reserve_member(self.context,
                                               self.network_view,
                                               member.name,
                                               member_type)
            return member

        member_explicitly_set = not (
            members == self.NEXT_AVAILABLE_MEMBER or
            isinstance(members, list)
        )

        if member_explicitly_set:
            member = self.member_manager.get_member(members)
            self.member_manager.reserve_member(self.context,
                                               self.network_view,
                                               member.name,
                                               member_type)
            return member

        member = self.member_manager.next_available(self.context,
                                                    members,
                                                    member_type)
        self.member_manager.reserve_member(self.context,
                                           self.network_view,
                                           member.name,
                                           member_type)
        return member

    def _get_member_from_template(self, members, template):
        member_defined = (members != self.NEXT_AVAILABLE_MEMBER and
                          isinstance(members, basestring))
        if template and not member_defined:
            msg = 'Member MUST be configured for {template}'.format(
                template=template)
            raise exceptions.InfobloxInvalidConditionalConfig(msg=msg)
        return self.member_manager.get_member(members)


class MemberManager(object):
    def __init__(self, member_config_stream=None):
        if not member_config_stream:
            config_file = neutron_conf.CONF.infoblox_members_config
            if not config_file:
                raise exceptions.ConfigNotFound(object='Infoblox members')

            member_config_stream = io.FileIO(config_file)
        with member_config_stream:
            all_members = json.loads(member_config_stream.read())

            try:
                self.available_members = map(
                    lambda m: objects.Member(name=m['name'], ip=m['ipv4addr']),
                    filter(lambda m: m.get('is_available', True), all_members))
            except KeyError as key:
                raise exceptions.InvalidMemberConfig(key=key)

    def next_available(self, context,
                       members_to_choose_from=Config.NEXT_AVAILABLE_MEMBER,
                       member_type=ib_db.DHCP_MEMBER_TYPE):
        if members_to_choose_from == Config.NEXT_AVAILABLE_MEMBER:
            members_to_choose_from = map(attrgetter('name'),
                                         self.available_members)

        already_reserved = ib_db.get_used_members(context, member_type)
        for member in members_to_choose_from:
            if member not in already_reserved:
                return self.get_member(member)
        raise exceptions.NoInfobloxMemberAvailable()

    def reserve_member(self, context, mapping, member_name, member_type):
        ib_db.attach_member(context, mapping, member_name, member_type)

    def find_member(self, context, mapping, member_type):
        member_name = ib_db.get_member(context, mapping, member_type)
        if member_name:
            for member in self.available_members:
                if member.name == member_name:
                    return member
            else:
                raise exceptions.ReservedMemberNotAvailableInConfig(
                    member_name=member_name,
                    config=neutron_conf.CONF.infoblox_members_config)
        return None

    def release_member(self, context, mapping):
        ib_db.delete_members(context, mapping)

    def get_member(self, member_name):
        for member in self.available_members:
            if member.name == member_name:
                return member
        raise exceptions.NoInfobloxMemberAvailable()
