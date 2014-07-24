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

import mock

import taskflow.engines

from neutron.db.infoblox import infoblox_db as infoblox_db
from neutron.ipam.drivers.infoblox import exceptions as ib_exceptions
from neutron.ipam.drivers.infoblox import infoblox_ipam
from neutron.ipam.drivers.infoblox import ipam_controller
from neutron.ipam.drivers.infoblox import objects
from neutron.tests import base


class SubstringMatcher(object):
    def __init__(self, expected):
        self.expected = expected

    def __eq__(self, actual):
        return self.expected in actual

    def __repr__(self):
        return "Expected substring: '{}'".format(self.expected)


class CreateSubnetTestCases(base.BaseTestCase):
    def setUp(self):
        super(CreateSubnetTestCases, self).setUp()

        self.expected_net_view_name = 'some-tenant-id'
        self.cidr = 'some-cidr'
        self.first_ip = '192.168.0.1'
        self.last_ip = '192.168.0.254'
        self.subnet = {
            'cidr': self.cidr,
            'tenant_id': self.expected_net_view_name,
            'allocation_pools': [{
                'start': self.first_ip,
                'end': self.last_ip
            }],
            'name': 'some-name',
            'ip_version': 'ipv4',
            'enable_dhcp': True,
            'network_id': 'some-net-id',
            'gateway_ip': 'some-ip'
        }
        self.object_manipulator = mock.Mock()
        ip_allocator = mock.Mock()
        config_finder = mock.Mock()
        context = infoblox_ipam.FlowContext(mock.MagicMock(),
                                            'create-subnet')

        b = ipam_controller.InfobloxIPAMController(self.object_manipulator,
                                                   config_finder,
                                                   ip_allocator)
        b.ea_manager = mock.Mock()
        b.create_subnet(context, self.subnet)
        taskflow.engines.run(context.parent_flow, store=context.store)

    def test_network_view_is_created_on_subnet_creation(self):
        assert self.object_manipulator.create_network_view.called_once

    def test_dns_view_is_created_on_subnet_creation(self):
        assert self.object_manipulator.create_dns_view.called_once

    def test_infoblox_network_is_created_on_subnet_create(self):
        assert self.object_manipulator.create_network.called_once

    def test_ip_range_is_created_on_subnet_create(self):
        assert self.object_manipulator.create_ip_range.called_once


class UpdateSubnetTestCase(base.BaseTestCase):
    def setUp(self):
        super(UpdateSubnetTestCase, self).setUp()
        self.object_manipulator = mock.Mock()
        self.context = mock.Mock()
        ip_allocator = mock.Mock()
        config_finder = mock.Mock()
        self.ipam = ipam_controller.InfobloxIPAMController(
            self.object_manipulator, config_finder, ip_allocator)

        self.sub_id = 'fake-id'
        self.new_nameservers = ['new_serv1', 'new_serv2']
        self.sub = dict(
            id=self.sub_id,
            cidr='test-cidr',
            dns_nameservers=self.new_nameservers
        )
        self.ib_net = objects.Network()
        self.object_manipulator.get_network.return_value = self.ib_net

    @mock.patch.object(infoblox_db, 'get_subnet_dhcp_port_address',
                       mock.Mock(return_value=None))
    def test_update_subnet_dns_no_primary_ip(self):
        self.ipam.update_subnet(self.context, self.sub_id, self.sub)

        self.assertEqual(self.new_nameservers, self.ib_net.dns_nameservers)
        self.object_manipulator.update_network_options.assert_called_once_with(
            self.ib_net
        )

    @mock.patch.object(infoblox_db, 'get_subnet_dhcp_port_address',
                       mock.Mock(return_value=None))
    def test_update_subnet_dns_primary_is_member_ip(self):
        self.ib_net.member_ip_addr = 'member-ip'
        self.ib_net.dns_nameservers = ['member-ip', 'old_serv1', 'old_serv']

        self.ipam.update_subnet(self.context, self.sub_id, self.sub)

        self.assertEqual(['member-ip'] + self.new_nameservers,
                         self.ib_net.dns_nameservers)
        self.object_manipulator.update_network_options.assert_called_once_with(
            self.ib_net
        )

    @mock.patch.object(infoblox_db, 'get_subnet_dhcp_port_address',
                       mock.Mock())
    def test_update_subnet_dns_primary_is_relay_ip(self):
        self.ib_net.member_ip_addr = 'fake_ip'
        self.ib_net.dns_nameservers = ['relay_ip', '1.1.1.1', '2.2.2.2']

        infoblox_db.get_subnet_dhcp_port_address.return_value = 'relay-ip'

        self.ipam.update_subnet(self.context, self.sub_id, self.sub)

        self.assertEqual(['relay-ip'] + self.new_nameservers,
                         self.ib_net.dns_nameservers)
        self.object_manipulator.update_network_options.assert_called_once_with(
            self.ib_net
        )


class AllocateIPTestCase(base.BaseTestCase):
    def test_host_record_created_on_allocate_ip(self):
        infoblox = mock.Mock()
        member_config = mock.Mock()
        ip_allocator = mock.Mock()
        context = mock.Mock()

        hostname = 'hostname'
        subnet = {'tenant_id': 'some-id'}
        mac = 'aa:bb:cc:dd:ee:ff'
        host = {'name': hostname,
                'mac_address': mac}
        ip = '192.168.1.1'

        b = ipam_controller.InfobloxIPAMController(infoblox,
                                                   member_config,
                                                   ip_allocator)
        b.pattern_builder = mock.Mock()

        b.allocate_ip(context, subnet, host, ip)

        ip_allocator.allocate_given_ip.assert_called_once_with(
            mock.ANY, mock.ANY, mock.ANY, hostname, mac, ip)

    def test_host_record_from_range_created_on_allocate_ip(self):
        infoblox = mock.Mock()
        member_config = mock.Mock()
        ip_allocator = mock.Mock()
        context = mock.Mock()

        hostname = 'hostname'
        first_ip = '192.168.1.1'
        last_ip = '192.168.1.132'
        subnet = {'allocation_pools': [{'first_ip': first_ip,
                                        'last_ip': last_ip}],
                  'tenant_id': 'some-id'}
        mac = 'aa:bb:cc:dd:ee:ff'
        host = {'name': hostname,
                'mac_address': mac}

        b = ipam_controller.InfobloxIPAMController(infoblox,
                                                   member_config,
                                                   ip_allocator)
        b.pattern_builder = mock.Mock()
        b.allocate_ip(context, subnet, host)

        assert not ip_allocator.allocate_given_ip.called
        ip_allocator.allocate_ip_from_range.assert_called_once_with(
            mock.ANY, mock.ANY, mock.ANY, hostname, mac, first_ip, last_ip)

    def test_cannot_allocate_ip_raised_if_empty_range(self):
        infoblox = mock.Mock()
        member_config = mock.Mock()
        context = mock.Mock()
        ip_allocator = mock.Mock()

        hostname = 'hostname'
        subnet = {'allocation_pools': [],
                  'tenant_id': 'some-id',
                  'cidr': '192.168.0.0/24'}
        mac = 'aa:bb:cc:dd:ee:ff'
        host = {'name': hostname,
                'mac_address': mac}

        b = ipam_controller.InfobloxIPAMController(infoblox,
                                                   member_config,
                                                   ip_allocator)
        b.pattern_builder = mock.Mock()

        assert not infoblox.create_host_record_range.called
        assert not infoblox.create_host_record_ip.called
        self.assertRaises(ib_exceptions.InfobloxCannotAllocateIpForSubnet,
                          b.allocate_ip, context, subnet, host)


class DeallocateIPTestCase(base.BaseTestCase):
    def setUp(self):
        super(DeallocateIPTestCase, self).setUp()

        self.infoblox = mock.Mock()
        config_finder = mock.Mock()
        context = mock.MagicMock()
        self.ip_allocator = mock.Mock()

        hostname = 'hostname'
        self.ip = '192.168.0.1'
        subnet = {'tenant_id': 'some-id',
                  'network_id': 'some-id',
                  'id': 'some-id'}
        mac = 'aa:bb:cc:dd:ee:ff'
        host = {'name': hostname,
                'mac_address': mac}

        b = ipam_controller.InfobloxIPAMController(self.infoblox,
                                                   config_finder,
                                                   self.ip_allocator)
        b.deallocate_ip(context, subnet, host, self.ip)

    def test_ip_is_deallocated(self):
        self.ip_allocator.deallocate_ip.assert_called_once_with(
            mock.ANY, mock.ANY, self.ip)

    def test_dns_and_dhcp_services_restarted(self):
        self.infoblox.restart_all_services.assert_called_once_with(mock.ANY)


class NetOptionsMatcher(object):
    def __init__(self, expected_ip):
        self.expected_ip = expected_ip

    def __eq__(self, actual_net):
        return self.expected_ip in actual_net.dns_nameservers

    def __repr__(self):
        return "{}".format(self.expected_ip)


class DnsNameserversTestCase(base.BaseTestCase):
    def test_network_is_updated_with_new_ip(self):
        infoblox = mock.Mock()
        ip_allocator = mock.Mock()
        member_config = mock.Mock()
        context = mock.MagicMock()

        expected_ip = '192.168.1.1'
        cidr = '192.168.1.0/24'
        port = {'fixed_ips': [{'subnet_id': 'some-id',
                               'ip_address': expected_ip}]}
        subnet = {'cidr': cidr,
                  'tenant_id': 'some-id'}

        network = objects.Network()
        network.members = ['member1']
        network.member_ip_addr = '192.168.1.2'
        network.dns_nameservers = [expected_ip]

        infoblox.get_network.return_value = network

        b = ipam_controller.InfobloxIPAMController(infoblox,
                                                   member_config,
                                                   ip_allocator)
        b._get_subnet = mock.Mock()
        b._get_subnet.return_value = subnet

        b.set_dns_nameservers(context, port)

        matcher = NetOptionsMatcher(expected_ip)
        infoblox.update_network_options.assert_called_once_with(matcher)

    def test_network_is_not_updated_if_network_has_no_members(self):
        infoblox = mock.Mock()
        member_config = mock.Mock()
        ip_allocator = mock.Mock()
        context = mock.MagicMock()

        expected_ip = '192.168.1.1'
        cidr = '192.168.1.0/24'
        port = {'fixed_ips': [{'subnet_id': 'some-id',
                               'ip_address': expected_ip}]}
        subnet = {'cidr': cidr,
                  'tenant_id': 'some-id'}

        infoblox.get_network.return_value = objects.Network()

        b = ipam_controller.InfobloxIPAMController(infoblox,
                                                   member_config,
                                                   ip_allocator)
        b._get_subnet = mock.Mock()
        b._get_subnet.return_value = subnet

        b.set_dns_nameservers(context, port)

        assert not infoblox.update_network_options.called

    def test_network_is_not_updated_if_network_has_no_dns_members(self):
        infoblox = mock.Mock()
        member_config = mock.Mock()
        ip_allocator = mock.Mock()
        context = mock.MagicMock()

        expected_ip = '192.168.1.1'
        cidr = '192.168.1.0/24'
        port = {'fixed_ips': [{'subnet_id': 'some-id',
                               'ip_address': expected_ip}]}
        subnet = {'cidr': cidr,
                  'tenant_id': 'some-id'}
        network = objects.Network()
        network.members = ['member1']

        infoblox.get_network.return_value = network

        b = ipam_controller.InfobloxIPAMController(infoblox,
                                                   member_config,
                                                   ip_allocator)
        b._get_subnet = mock.Mock()
        b._get_subnet.return_value = subnet

        b.set_dns_nameservers(context, port)

        assert not infoblox.update_network_options.called


class DeleteSubnetTestCase(base.BaseTestCase):
    def test_ib_network_deleted(self):
        infoblox = mock.Mock()
        member_conf = mock.Mock()
        ip_allocator = mock.Mock()
        context = mock.MagicMock()

        cidr = '192.168.0.0/24'
        subnet = {'cidr': cidr,
                  'tenant_id': 'some-id',
                  'enable_dhcp': False}

        b = ipam_controller.InfobloxIPAMController(infoblox,
                                                   member_conf,
                                                   ip_allocator)

        b.delete_subnet(context, subnet)

        infoblox.delete_network.assert_called_once_with(mock.ANY, cidr=cidr)

    def test_member_released(self):
        infoblox = mock.Mock()
        member_finder = mock.Mock()
        ip_allocator = mock.Mock()
        context = mock.MagicMock()

        cidr = '192.168.0.0/24'
        subnet = {'cidr': cidr,
                  'tenant_id': 'some-id',
                  'enable_dhcp': True}

        b = ipam_controller.InfobloxIPAMController(infoblox,
                                                   member_finder,
                                                   ip_allocator)
        b.delete_subnet(context, subnet)

        assert member_finder.member_manager.release_member.called_once


class CreateSubnetFlowTestCase(base.BaseTestCase):
    def setUp(self):
        super(CreateSubnetFlowTestCase, self).setUp()

        self.infoblox = mock.Mock()
        member_conf = mock.MagicMock()
        ip_allocator = mock.Mock()
        self.context = infoblox_ipam.FlowContext(mock.MagicMock(),
                                                 'create-subnet')
        self.subnet = {'cidr': '192.168.0.0/24',
                       'tenant_id': 'some-id',
                       'network_id': 'some-id',
                       'gateway_ip': '192.168.1.1',
                       'allocation_pools': [{'start': 'start',
                                             'end': 'end'}],
                       'ip_version': 'ipv4',
                       'name': 'some-name',
                       'enable_dhcp': True}

        self.infoblox.create_ip_range.side_effect = Exception()

        self.b = ipam_controller.InfobloxIPAMController(self.infoblox,
                                                        member_conf,
                                                        ip_allocator)
        self.b.pattern_builder = mock.Mock()
        self.b.ea_manager = mock.Mock()

    def test_flow_is_reverted_in_case_of_error(self):
        self.infoblox.has_networks.return_value = False
        self.b.create_subnet(self.context, self.subnet)
        self.assertRaises(Exception, taskflow.engines.run,
                          self.context.parent_flow, store=self.context.store)

        assert self.infoblox.delete_network.called
        assert not self.infoblox.delete_dns_view.called
        assert self.infoblox.delete_network_view.called

    def test_network_view_is_not_deleted_if_has_networks(self):
        self.infoblox.has_networks.return_value = True
        self.b.create_subnet(self.context, self.subnet)

        self.assertRaises(Exception, taskflow.engines.run,
                          self.context.parent_flow, store=self.context.store)

        assert self.infoblox.delete_network.called
        assert not self.infoblox.delete_dns_view.called
        assert not self.infoblox.delete_network_view.called


class DeleteNetworkTestCase(base.BaseTestCase):
    def test_deletes_all_subnets(self):
        infoblox = mock.Mock()
        ip_allocator = mock.Mock()
        member_conf = mock.Mock()
        context = mock.Mock()
        network = {'id': 'some-id'}
        num_subnets = 5

        b = ipam_controller.InfobloxIPAMController(infoblox,
                                                   member_conf,
                                                   ip_allocator)

        b.delete_subnet = mock.Mock()
        b.get_subnets_by_network = mock.Mock()
        b.get_subnets_by_network.return_value = [mock.Mock()
                                                 for _ in xrange(num_subnets)]

        b.delete_network(context, network)

        assert b.delete_subnet.called
        assert b.delete_subnet.call_count == num_subnets

    def test_network_view_deleted(self):
        infoblox = mock.Mock()
        ip_allocator = mock.Mock()
        member_conf = mock.Mock()
        context = mock.Mock()
        network = {'id': 'some-id'}

        b = ipam_controller.InfobloxIPAMController(infoblox,
                                                   member_conf,
                                                   ip_allocator)

        b.get_subnets_by_network = mock.MagicMock()
        b.delete_network(context, network)

        assert infoblox.delete_network_view.called_once