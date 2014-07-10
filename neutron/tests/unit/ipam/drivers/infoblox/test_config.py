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

import io
import json
import mock

from testtools import matchers

from neutron.tests import base
from neutron.ipam.drivers.infoblox import config
from neutron.ipam.drivers.infoblox import exceptions
from neutron.ipam.drivers.infoblox import objects
from neutron.db.infoblox import infoblox_db


class ConfigFinderTestCase(base.BaseTestCase):
    def test_config_reads_data_from_json(self):
        valid_config = """
            [
                {
                    "condition": "tenant",
                    "is_external": false,
                    "network_view": "{tenant_id}",
                    "dhcp_members":  "next-available-member",
                    "require_dhcp_relay":  true,
                    "domain_suffix_pattern": "local.test.com",
                    "hostname_pattern": "%{instance_id}"
                },
                {
                    "condition": "global",
                    "is_external": true,
                    "dhcp_members":  "member1.infoblox.com",
                    "domain_suffix_pattern": "test.com",
                    "hostname_pattern": "%{instance_id}"
                }
            ]
        """

        subnet = {
            'network_id': 'some-net-id',
            'cidr': '192.168.1.0/24',
            'tenant_id': 'some-tenant-id'
        }
        context = mock.MagicMock()

        cfg = config.ConfigFinder(stream=io.BytesIO(valid_config),
                                  member_manager=mock.Mock())
        subnet_config = cfg.find_config_for_subnet(context, subnet)

        self.assertIsNotNone(subnet_config)
        self.assertIsInstance(subnet_config, config.Config)

    def test_throws_error_on_invalid_configuration(self):
        invalid_config = """
            [
                {
                    "condition": "tenant",
                    "is_external": false,
                    "network_view": "{tenant_id}",
                    "dhcp_members":  "next-available-member",
                    "require_dhcp_relay":  True,
                    "domain_suffix_pattern": "local.test.com",
                    "hostname_pattern": "{instance_id}"
                },
                {
                    "condition": "global"
                    "is_external": true,
                    "dhcp_members":  "member1.infoblox.com",
                    "domain_suffix_pattern": "test.com",
                    "hostname_pattern": "{instance_id}"
                }
            ]
        """

        # configuration is considered invalid if JSON parser has failed
        self.assertRaises(exceptions.InfobloxInvalidConditionalConfig,
                          config.ConfigFinder,
                          stream=io.BytesIO(invalid_config),
                          member_manager=mock.Mock())

    @mock.patch('neutron.db.infoblox.infoblox_db.is_network_external')
    def test_external_network_matches_first_external_config(self, is_external):
        expected_condition = 'global'
        external_config = """
            [
                {{
                    "condition": "tenant",
                    "is_external": false,
                    "network_view": "{{tenant_id}}",
                    "dhcp_members":  "next-available-member",
                    "require_dhcp_relay":  true,
                    "domain_suffix_pattern": "local.test.com",
                    "hostname_pattern": "{{instance_id}}"
                }},
                {{
                    "condition": "{expected_condition:s}",
                    "is_external": true,
                    "dhcp_members":  "member1.infoblox.com",
                    "domain_suffix_pattern": "test.com",
                    "hostname_pattern": "{{instance_id}}"
                }},
                {{
                    "condition": "tenant",
                    "is_external": true,
                    "dhcp_members":  "member1.infoblox.com",
                    "domain_suffix_pattern": "test.com",
                    "hostname_pattern": "{{instance_id}}"
                }}
            ]
        """.format(**locals())
        context = mock.Mock()
        subnet = {
            'network_id': 'some-net-id',
            'cidr': '192.168.1.0/24',
            'tenant_id': 'some-tenant-id'
        }
        is_external.return_value = True
        cfg = config.ConfigFinder(stream=io.BytesIO(external_config),
                                  member_manager=mock.Mock())
        config_for_subnet = cfg.find_config_for_subnet(context, subnet)

        self.assertThat(config_for_subnet.condition,
                        matchers.Equals(expected_condition))

    @mock.patch('neutron.db.infoblox.infoblox_db.is_network_external')
    def test_subnet_range_condition_matches(self, is_external):
        expected_cidr = '10.0.0.0/24'
        expected_condition = 'subnet_range:{}'.format(expected_cidr)
        external_config = """
            [
                {{
                    "condition": "{expected_condition:s}",
                    "is_external": false,
                    "dhcp_members":  "member1.infoblox.com",
                    "domain_suffix_pattern": "test.com",
                    "hostname_pattern": "{{instance_id}}"
                }},
                {{
                    "condition": "tenant",
                    "is_external": false,
                    "network_view": "{{tenant_id}}",
                    "dhcp_members":  "next-available-member",
                    "require_dhcp_relay":  true,
                    "domain_suffix_pattern": "local.test.com",
                    "hostname_pattern": "{{instance_id}}"
                }},
                {{
                    "condition": "tenant",
                    "is_external": true,
                    "dhcp_members":  "member1.infoblox.com",
                    "domain_suffix_pattern": "test.com",
                    "hostname_pattern": "{{instance_id}}"
                }}
            ]
        """.format(**locals())
        context = mock.Mock()
        subnet = {
            'network_id': 'some-net-id',
            'cidr': expected_cidr,
            'tenant_id': 'some-tenant-id'
        }
        is_external.return_value = False
        cfg = config.ConfigFinder(stream=io.BytesIO(external_config),
                                  member_manager=mock.Mock())
        config_for_subnet = cfg.find_config_for_subnet(context, subnet)

        self.assertThat(config_for_subnet.condition,
                        matchers.Equals(expected_condition))

    @mock.patch('neutron.db.infoblox.infoblox_db.is_network_external')
    def test_tenant_id_condition_matches(self, is_external_mock):
        expected_tenant_id = 'some-tenant-id'
        expected_condition = 'tenant_id:{}'.format(expected_tenant_id)
        tenant_id_conf = """
            [
                {{
                    "condition": "{expected_condition:s}",
                    "is_external": false,
                    "dhcp_members":  "member1.infoblox.com",
                    "domain_suffix_pattern": "test.com",
                    "hostname_pattern": "{{instance_id}}"
                }},
                {{
                    "condition": "global",
                    "is_external": false,
                    "network_view": "{{tenant_id}}",
                    "dhcp_members":  "next-available-member",
                    "require_dhcp_relay":  true,
                    "domain_suffix_pattern": "local.test.com",
                    "hostname_pattern": "{{instance_id}}"
                }},
                {{
                    "condition": "tenant",
                    "is_external": true,
                    "dhcp_members":  "member1.infoblox.com",
                    "domain_suffix_pattern": "test.com",
                    "hostname_pattern": "{{instance_id}}"
                }}
            ]
        """.format(**locals())
        context = mock.Mock()
        subnet = {
            'network_id': 'some-net-id',
            'cidr': '10.0.0.0/24',
            'tenant_id': expected_tenant_id
        }
        is_external_mock.return_value = False
        cfg = config.ConfigFinder(stream=io.BytesIO(tenant_id_conf),
                                  member_manager=mock.Mock())
        config_for_subnet = cfg.find_config_for_subnet(context, subnet)

        self.assertThat(config_for_subnet.condition,
                        matchers.Equals(expected_condition))

    def test_raises_on_invalid_condition(self):
        config_template = """
            [
                {{
                    "condition": "{condition}",
                    "is_external": false,
                    "dhcp_members":  "member1.infoblox.com",
                    "domain_suffix_pattern": "test.com",
                    "hostname_pattern": "{{instance_id}}"
                }}
            ]
        """

        member_manager = mock.Mock()
        for valid in config.ConfigFinder.VALID_CONDITIONS:
            valid_conf = config_template.format(condition=valid)
            try:
                config.ConfigFinder(io.BytesIO(valid_conf), member_manager)
            except exceptions.InfobloxInvalidConditionalConfig as e:
                msg = 'Unexpected {error_type} for {config}'.format(
                    error_type=type(e), config=valid_conf)
                self.fail(msg)

        invalid_cof = config_template.format(condition='invalid-condition')
        self.assertRaises(exceptions.InfobloxInvalidConditionalConfig,
                          config.ConfigFinder, io.BytesIO(invalid_cof),
                          member_manager)

    def test_raises_if_no_suitable_config_found(self):
        cfg = """
            [
                {
                    "condition": "tenant_id:wrong-id",
                    "is_external": false
                }
            ]
        """
        context = mock.MagicMock()
        subnet = mock.MagicMock()

        cf = config.ConfigFinder(io.BytesIO(cfg), member_manager=mock.Mock())
        self.assertRaises(exceptions.InfobloxNoConfigFoundForSubnet,
                          cf.find_config_for_subnet, context, subnet)


class ConfigTestCase(base.BaseTestCase):
    def test_exception_raised_on_missing_condition(self):
        context = mock.Mock()
        subnet = mock.Mock()

        self.assertRaises(exceptions.InfobloxInvalidConditionalConfig,
                          config.Config, {}, context, subnet,
                          member_manager=mock.Mock())

    def test_default_values_are_set(self):
        context = mock.Mock()
        subnet = mock.Mock()

        cfg = config.Config({'condition': 'global'}, context, subnet,
                            member_manager=mock.Mock())

        self.assertFalse(cfg.is_external)
        self.assertFalse(cfg.require_dhcp_relay)
        self.assertEqual(cfg.network_view, 'default')
        self.assertEqual(cfg.dns_view, 'default')
        self.assertIsNone(cfg.network_template)
        self.assertIsNone(cfg.ns_group)
        self.assertEqual(cfg.hostname_pattern,
                         'host-{ip_address}.{subnet_name}')
        self.assertEqual(cfg.domain_suffix_pattern, 'global.com')

    def test_dhcp_member_is_returned_as_is_if_explicitly_set(self):
        context = mock.Mock()
        subnet = mock.Mock()

        expected_member_name = 'some-dhcp-member.com'
        expected_dhcp_member = objects.Member(name=expected_member_name,
                                              ip='some-ip')

        conf_dict = {
            'condition': 'global',
            'dhcp_members': expected_member_name
        }

        member_manager = mock.Mock()
        member_manager.find_member.return_value = expected_dhcp_member
        cfg = config.Config(conf_dict, context, subnet, member_manager)

        self.assertEqual(cfg.dhcp_member, expected_dhcp_member)
        assert member_manager.find_member.called
        assert not member_manager.next_available.called
        assert not member_manager.reserve_member.called

    def test_dhcp_member_is_taken_from_member_config_if_next_available(self):
        context = mock.Mock()
        subnet = mock.Mock()

        expected_member = objects.Member('some-member-ip', 'some-member-name')

        member_manager = mock.Mock()
        member_manager.find_member.return_value = None
        member_manager.next_available.return_value = expected_member

        conf_dict = {
            'condition': 'global',
            'dhcp_members': config.Config.NEXT_AVAILABLE_MEMBER
        }

        cfg = config.Config(conf_dict, context, subnet, member_manager)
        member = cfg.reserve_dhcp_member()
        self.assertEqual(member, expected_member)
        assert member_manager.find_member.called_once
        assert member_manager.next_available.called_once
        assert member_manager.reserve_meber.called_once

    def test_dns_view_joins_net_view_with_default_if_not_default(self):
        context = mock.Mock()
        subnet = mock.Mock()
        member_manager = mock.Mock()

        expected_net_view = 'non-default-net-view'
        conf_dict = {
            'condition': 'global',
            'network_view': expected_net_view,
        }

        cfg = config.Config(conf_dict, context, subnet, member_manager)

        self.assertTrue(cfg.dns_view.startswith('default'))
        self.assertTrue(cfg.dns_view.endswith(expected_net_view))

    def test_dns_view_is_default_if_netview_is_default(self):
        context = mock.Mock()
        subnet = mock.Mock()
        member_manager = mock.Mock()

        conf_dict = {
            'condition': 'global',
            'network_view': 'default',
        }

        cfg = config.Config(conf_dict, context, subnet, member_manager)

        self.assertThat(cfg.dns_view, matchers.Equals(cfg.network_view))


class MemberManagerTestCase(base.BaseTestCase):
    def test_raises_error_if_no_config_file(self):
        self.assertRaises(exceptions.ConfigNotFound, config.MemberManager)

    def test_returns_next_unused_member(self):
        context = mock.MagicMock()
        member_config = [{"name": "member%d" % i,
                          "ipv4addr": "192.168.1.%d" % i}
                         for i in xrange(1, 5)]

        used_members = [member_config[i]['name'] for i in xrange(3)]
        unused_members = [member_config[i]
                          for i in xrange(3, len(member_config))]

        mm = config.MemberManager(io.BytesIO(json.dumps(member_config)))

        with mock.patch.object(infoblox_db, 'get_used_members',
                               mock.Mock(return_value=used_members)):
            available_member = mm.next_available(context)

            self.assertIn({"name": available_member.name,
                           "ipv4addr": available_member.ip}, unused_members)

    def test_raises_no_member_available_if_all_members_used(self):
        context = mock.MagicMock()
        member_config = [{"name": "member%d" % i,
                          "ipv4addr": "192.168.1.%d" % i}
                         for i in xrange(1, 5)]

        used_members = [member_config[i]['name']
                        for i in xrange(len(member_config))]

        mm = config.MemberManager(io.BytesIO(json.dumps(member_config)))

        with mock.patch.object(infoblox_db, 'get_used_members',
                               mock.Mock(return_value=used_members)):
            self.assertRaises(exceptions.NoInfobloxMemberAvailable,
                              mm.next_available, context)

    def test_reserve_member_stores_member_in_db(self):
        context = mock.Mock()
        mapping = 'some-mapping-value'
        member_name = 'member1'

        mm = config.MemberManager(io.BytesIO("{}"))

        with mock.patch.object(infoblox_db, 'attach_member') as attach_mock:
            mm.reserve_member(context, mapping, member_name,
                              infoblox_db.DHCP_MEMBER_TYPE)

            attach_mock.assert_called_once_with(
                context, mapping, member_name, infoblox_db.DHCP_MEMBER_TYPE)

    def test_finds_member_for_mapping(self):
        context = mock.Mock()
        mapping = 'some-mapping-value'
        expected_member = 'member1'
        expected_ip = '10.0.0.1'

        mm = config.MemberManager(
            io.BytesIO(json.dumps([{'name': expected_member,
                                    'ipv4addr': expected_ip}])))

        with mock.patch.object(infoblox_db, 'get_member') as get_mock:
            get_mock.return_value = expected_member
            member = mm.find_member(context, mapping,
                                    infoblox_db.DHCP_MEMBER_TYPE)

            self.assertEqual(expected_ip, member.ip)
            self.assertEqual(expected_member, member.name)

    def test_builds_member_from_config(self):
        ip = 'some-ip'
        name = 'some-name'

        mm = config.MemberManager(
            io.BytesIO(json.dumps([{'name': name,
                                    'ipv4addr': ip}])))

        m = mm.get_member(name)

        self.assertEqual(m.name, name)
        self.assertEqual(m.ip, ip)

    def test_raises_member_not_available_if_member_is_not_in_config(self):
        ip = 'some-ip'
        actual_name = 'some-name'
        search_for_name = 'some-other-name'

        mm = config.MemberManager(
            io.BytesIO(json.dumps([{'name': actual_name,
                                    'ipv4addr': ip}])))

        self.assertRaises(exceptions.NoInfobloxMemberAvailable, mm.get_member,
                          search_for_name)
