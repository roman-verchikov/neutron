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

import abc

from neutron.ipam.drivers import neutron_db
from neutron.openstack.common import log as logging

# Ports with the following 'device_owner' values will not prevent
# network deletion.  If delete_network() finds that all ports on a
# network have these owners, it will explicitly delete each port
# and allow network deletion to continue.  Similarly, if delete_subnet()
# finds out that all existing IP Allocations are associated with ports
# with these owners, it will allow subnet deletion to proceed with the
# IP allocations being cleaned up by cascade.
AUTO_DELETE_PORT_OWNERS = ['network:dhcp']

LOG = logging.getLogger(__name__)


class DHCPController(neutron_db.NeutronPluginController):
    __meta__ = abc.ABCMeta

    @abc.abstractmethod
    def configure_dhcp(self, context, backend_subnet, dhcp_params):
        """
        Make DHCP pools, save DHCP Gateway, save DHCP DNS names,
        save DHCP host routes.
        """
        pass

    @abc.abstractmethod
    def reconfigure_dhcp(self, context, backend_subnet, dhcp_params):
        """Update DHCP pools, DHCP gateway, DNS names, Host routes."""
        pass

    @abc.abstractmethod
    def disable_dhcp(self, context, backend_subnet):
        """Disable DHCP Service only."""
        pass

    @abc.abstractmethod
    def dhcp_is_enabled(self, context, backend_subnet):
        """Returns True if DHCP service is enabled for backend_subnet."""
        pass

    @abc.abstractmethod
    def get_dhcp_ranges(self, context, backend_subnet):
        pass

    @abc.abstractmethod
    def bind_mac(self, context, backend_subnet, ip_address, mac_address):
        pass

    @abc.abstractmethod
    def unbind_mac(self, context, backend_subnet, ip_address):
        pass


class DNSController(neutron_db.NeutronPluginController):
    __meta__ = abc.ABCMeta

    @abc.abstractmethod
    def bind_names(self, context, backend_port):
        pass

    @abc.abstractmethod
    def unbind_names(self, context, backend_port):
        pass

    @abc.abstractmethod
    def create_dns_zones(self, context, backend_subnet):
        pass

    @abc.abstractmethod
    def delete_dns_zones(self, context, backend_subnet):
        pass


class IPAMController(neutron_db.NeutronPluginController):
    __meta__ = abc.ABCMeta

    @abc.abstractmethod
    def create_subnet(self, context, subnet):
        """Create allocation pools and ip ranges.

        Don't store gateway address here.
        Don't store dns names here.
        Don't store host routes here.

        Store CIDR and Allocation pools only.

        subnet - validated subnet in user view (dict).

        Returns backend related subnet object.
        """
        pass

    @abc.abstractmethod
    def update_subnet(self, context, subnet_id, subnet):
        """Update subnet params such as name."""
        pass

    @abc.abstractmethod
    def delete_subnet(self, context, subnet):
        pass

    @abc.abstractmethod
    def delete_subnets_by_network(self, context, network_id):
        pass

    @abc.abstractmethod
    def get_subnets(self, context, filters=None, fields=None,
                    sorts=None, limit=None, marker=None,
                    page_reverse=False):
        pass

    @abc.abstractmethod
    def force_off_ports(self, context, ports):
        """Force Off ports on subnet delete event."""
        pass

    @abc.abstractmethod
    def get_subnet_by_id(self, context, subnet_id):
        pass

    @abc.abstractmethod
    def allocate_ip(self, context, backend_subnet, host, ip=None):
        pass

    @abc.abstractmethod
    def deallocate_ip(self, context, backend_subnet, host, ip):
        pass

    @abc.abstractmethod
    def create_network(self, context, network):
        pass

    @abc.abstractmethod
    def delete_network(self, context, network_id):
        pass


class IPAMManager(object):
    @abc.abstractmethod
    def create_subnet(self, context, subnet):
        pass

    @abc.abstractmethod
    def update_subnet(self, context, id, subnet):
        pass

    @abc.abstractmethod
    def delete_subnet(self, context, subnet_id):
        pass

    @abc.abstractmethod
    def delete_subnets_by_network(self, context, network_id):
        pass

    @abc.abstractmethod
    def get_subnet_by_id(self, context, subnet_id):
        pass

    @abc.abstractmethod
    def allocate_ip(self, context, host, ip):
        pass

    @abc.abstractmethod
    def deallocate_ip(self, context, host, ip):
        pass

    @abc.abstractmethod
    def get_subnets(self, context, filters=None, fields=None,
                    sorts=None, limit=None, marker=None,
                    page_reverse=False):
        pass

    @abc.abstractmethod
    def create_network(self, context, network):
        pass

    @abc.abstractmethod
    def delete_network(self, context, network_id):
        pass

    @abc.abstractmethod
    def create_port(self, context, port):
        pass

    @abc.abstractmethod
    def update_port(self, context, port):
        pass

    @abc.abstractmethod
    def delete_port(self, context, port):
        pass

    @abc.abstractmethod
    def configure_floatingip(self, context, floatingip, port):
        pass

    @abc.abstractmethod
    def get_additional_network_dict_params(self, ctx, network_id):
        pass
