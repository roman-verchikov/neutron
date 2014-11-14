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

from neutron.ipam.drivers.infoblox import l2_driver
from neutron.tests import base


class L2InfoTestCase(base.BaseTestCase):
    def test_raises_exception_if_no_core_plugin(self):
        session = mock.Mock()
        network_id = mock.Mock()
        l2info = l2_driver.L2Info()
        self.assertRaises(ImportError, l2info.get_network_l2_info,
                          session, network_id)

    def test_get_driver(self):
        l2info = l2_driver.L2Info('ml2')
        self.assertEqual(None, l2info.driver)
        l2info._get_driver()
        self.assertEqual(
            'Driver', l2info.driver.__class__.__name__,
            'Verify driver variable is set after driver loading')

    def test_get_l2_info(self):
        session = mock.MagicMock()
        network_id = mock.MagicMock()
        l2info = l2_driver.L2Info('openvswitch')
        l2info.get_network_l2_info(session, network_id)


class L2DriverFactoryTestCase(base.BaseTestCase):
    def test_get_plugin_name_from_path(self):
        plugins = {
            'neutron.plugins.ml2.plugin:Ml2Plugin': 'ml2',
            'neutron.plugins.ml2.plugin.Ml2Plugin': 'ml2',
            'neutron.plugins.openvswitch.ovs_neutron_plugin': 'openvswitch',
            'my_plugin_name': 'my_plugin_name',
            'None': 'None',
            None: 'None',
        }

        l2factory = l2_driver.L2DriverFactory
        for path in plugins:
            self.assertEqual(l2factory.get_plugin_name(path), plugins[path])

    def test_load_ml2_driver(self):
        facade = l2_driver.L2DriverFactory.load('ml2')
        self.assertEqual('neutron.ipam.drivers.infoblox.l2_drivers.ml2',
                         facade.__module__)
        self.assertEqual('Driver', facade.__class__.__name__)

    def test_load_ovs_driver(self):
        facade = l2_driver.L2DriverFactory.load('openvswitch')
        self.assertEqual(
            'neutron.ipam.drivers.infoblox.l2_drivers.openvswitch',
            facade.__module__)
        self.assertEqual('Driver', facade.__class__.__name__)
