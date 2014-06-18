# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
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
from mock import patch
from neutron.ddi import base as ddi_base
from neutron.tests import base


SUBNET = {'tenant_id': 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee',
          'id': 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee',
          'name': 'network_name',
          'network_id': '00000000-0000-0000-0000-000000000001',
          'ip_version': 'IPv4',
          'cidr': '10.0.0.0/24',
          'enable_dhcp': True,
          'gateway_ip': '10.0.0.1',
          'shared': False}

NETWORK_ID = '00000000-0000-0000-0000-000000000001'
HOST = {'mac_address': '00:0a:95:9d:68:16',
        'host_name': 'name',
        'dns_aliases': []}
IP = {'ip_address': '10.0.0.3',
      'subnet_id': 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'}


class FakeContext(object):
    def __init__(self):
        self.is_admin = False
        self.user_id = 'fake_user'
        self.project_id = 'fake_project'

    def elevated(self):
        elevated = self.__class__()
        elevated.is_admin = True
        return elevated


class FakeDDI(ddi_base.DDI):
    def __init__(self):
        self.ipam_controller = mock.MagicMock()
        self.dns_controller = mock.MagicMock()
        self.dhcp_controller = mock.MagicMock()


class TestDDI(base.BaseTestCase):
    def setUp(self):
        super(TestDDI, self).setUp()
        self.context = FakeContext()
        self.ddi_driver = FakeDDI()

    def tearDown(self):
        super(TestDDI, self).tearDown()

    @patch.object(ddi_base.DDI, '_get_subnet_dns_params',
                  return_value='subnet_dns_params')
    @patch.object(ddi_base.DDI, '_get_subnet_dhcp_params',
                  return_value='subnet_dhcp_params')
    def test_create_subnet(self, subnet_dns_params, subnet_dhcp_params):
        with patch.object(self.ddi_driver.ipam_controller, 'create_subnet',
                          return_value=SUBNET) as mock_create_subnet:
            with patch.object(self.ddi_driver.dhcp_controller,
                              'configure_dhcp',
                              return_value=None) as mock_configure_dhcp:
                self.ddi_driver.create_subnet(self.context, SUBNET)
                mock_create_subnet.assert_called_with(
                    self.context, SUBNET)
                mock_configure_dhcp.assert_called_with(
                    self.context, SUBNET, 'subnet_dhcp_params')

    @patch.object(ddi_base.DDI, '_get_subnet_dns_params',
                  return_value='subnet_dns_params')
    @patch.object(ddi_base.DDI, '_get_subnet_dhcp_params',
                  return_value='subnet_dhcp_params')
    def test_update_subnet(self, subnet_dns_params, subnet_dhcp_params):
        with patch.object(self.ddi_driver.ipam_controller, 'update_subnet',
                          return_value=SUBNET) as mock_update_subnet:
            with patch.object(self.ddi_driver.dhcp_controller,
                              'reconfigure_dhcp',
                              return_value=None) as mock_reconfigure_dhcp:

                self.ddi_driver.update_subnet(self.context,
                                              SUBNET['id'], SUBNET)
                mock_update_subnet.assert_called_with(
                    self.context, SUBNET['id'], SUBNET)
                mock_reconfigure_dhcp.assert_called_with(
                    self.context, SUBNET, 'subnet_dhcp_params')

    def _delete_subnet_by_id(self):
        with patch.object(self.ddi_driver.ipam_controller, 'delete_subnet',
                          return_value=SUBNET['id']) as mock_delete_subnet:
            with patch.object(self.ddi_driver.ipam_controller,
                              'get_subnet_by_id',
                              return_value=SUBNET) as mock_get_subnet_by_id:
                with patch.object(self.ddi_driver.ipam_controller,
                                  'get_subnet_ports',
                                  return_value=[]) as mock_get_subnet_ports:
                    with patch.object(
                            self.ddi_driver.ipam_controller,
                            'force_off_ports',
                            return_value=None) as mock_force_off_ports:
                            with patch.object(
                                    self.ddi_driver.dhcp_controller,
                                    'disable_dhcp') as mock_disable_dhcp:
                                self.ddi_driver.delete_subnet(self.context,
                                                              SUBNET['id'])
                                mock_get_subnet_by_id.assert_called_with(
                                    self.context, SUBNET['id'])
                                mock_get_subnet_ports.assert_called_with(
                                    self.context, SUBNET)
                                mock_force_off_ports.assert_called_with(
                                    self.context, [])
                                mock_disable_dhcp.assert_called_with(
                                    self.context, SUBNET)
                                mock_delete_subnet.assert_called_with(
                                    self.context, SUBNET)

    def test_get_subnet_by_id(self):
        with patch.object(self.ddi_driver.ipam_controller,
                          'get_subnet_by_id') as mock_get_subnet_by_id:
            self.ddi_driver.get_subnet_by_id(self.context, SUBNET['id'])
            mock_get_subnet_by_id.assert_called_with(self.context,
                                                     SUBNET['id'])

    def test_allocate_ip(self):
        with patch.object(self.ddi_driver.ipam_controller, 'allocate_ip',
                          return_value='ip_object') as mock_allocate_ip:
            with patch.object(self.ddi_driver.ipam_controller,
                              'get_subnet_by_id',
                              return_value=SUBNET) as mock_get_subnet_by_id:
                with patch.object(self.ddi_driver.dhcp_controller, 'bind_mac',
                                  return_value=SUBNET) as mock_bind_mac:
                    self.ddi_driver.allocate_ip(self.context, HOST, IP)
                    mock_get_subnet_by_id.assert_called_with(self.context,
                                                             SUBNET['id'])
                    mock_allocate_ip.assert_called_with(
                        self.context, SUBNET, HOST, IP['ip_address'])
                    mock_bind_mac.assert_called_with(
                        self.context, SUBNET,
                        'ip_object', HOST['mac_address'])

    def test_deallocate_ip(self):
        with patch.object(self.ddi_driver.ipam_controller, 'deallocate_ip',
                          return_value='ip_object') as mock_deallocate_ip:
            with patch.object(self.ddi_driver.ipam_controller,
                              'get_subnet_by_id',
                              return_value=SUBNET) as mock_get_subnet_by_id:
                with patch.object(self.ddi_driver.dhcp_controller,
                                  'unbind_mac') as mock_unbind_mac:
                    self.ddi_driver.deallocate_ip(self.context, HOST, IP)
                    mock_get_subnet_by_id.assert_called_with(self.context,
                                                             SUBNET['id'])
                    mock_unbind_mac.assert_called_with(
                        self.context, SUBNET, IP['ip_address'])
                    mock_deallocate_ip.assert_called_with(
                        self.context, SUBNET, HOST, IP['ip_address'])

    def test_get_subnets_by_network(self):
        with patch.object(
                self.ddi_driver.ipam_controller,
                'get_subnets_by_network') as mock_get_subnets_by_network:
            self.ddi_driver.get_subnets_by_network(self.context, NETWORK_ID)
            mock_get_subnets_by_network.assert_called_with(self.context,
                                                           NETWORK_ID)

    def test_get_all_subnets(self):
        with patch.object(self.ddi_driver.ipam_controller,
                          'get_all_subnets') as mock_get_all_subnets:
            self.ddi_driver.get_all_subnets(self.context)
            mock_get_all_subnets.assert_called_with(self.context)

    def test_get_subnets(self):
        with patch.object(self.ddi_driver.ipam_controller,
                          'get_subnets') as mock_get_subnets:
            self.ddi_driver.get_subnets(self.context)
            mock_get_subnets.assert_called_with(self.context, None, None,
                                                None, None, None, False)

    def test_get_subnets_count(self):
        with patch.object(self.ddi_driver.ipam_controller,
                          'get_subnets_count') as mock_get_subnets_count:
            self.ddi_driver.get_subnets_count(self.context)
            mock_get_subnets_count.assert_called_with(self.context, None)

    def test_delete_network(self):
        with patch.object(self.ddi_driver.ipam_controller,
                          'delete_network') as mock_delete_network:
            self.ddi_driver.delete_network(self.context, NETWORK_ID)
            mock_delete_network.assert_called_with(self.context, NETWORK_ID)
