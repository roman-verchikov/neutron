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
from sqlalchemy.orm import exc

from neutron.common import constants
from neutron.common import exceptions as q_exc
from neutron.db import db_base_plugin_v2
from neutron.db import models_v2
from neutron.openstack.common import log as logging


# NOTE(zasimov): copy-paste from db_base_plugin_v2
# Ports with the following 'device_owner' values will not prevent
# network deletion.  If delete_network() finds that all ports on a
# network have these owners, it will explicitly delete each port
# and allow network deletion to continue.  Similarly, if delete_subnet()
# finds out that all existing IP Allocations are associated with ports
# with these owners, it will allow subnet deletion to proceed with the
# IP allocations being cleaned up by cascade.
AUTO_DELETE_PORT_OWNERS = ['network:dhcp']

LOG = logging.getLogger(__name__)


class BackendController(db_base_plugin_v2.CommonDbMixin):

    def _get_network(self, context, net_id):
        # NOTE(zasimov): Copy-paste from db_base_plugin_v2
        try:
            network = self._get_by_id(context, models_v2.Network, net_id)
        except exc.NoResultFound:
            raise q_exc.NetworkNotFound(net_id=net_id)
        return network

    def _get_networks_by_tenant(self, context, tenant_id):
        net_qry = context.session.query(models_v2.Network)
        return net_qry.filter_by(tenant_id=tenant_id).all()

    def _get_subnet(self, context, subnet_id):
        try:
            subnet = self._get_by_id(context, models_v2.Subnet, subnet_id)
        except exc.NoResultFound:
            raise q_exc.SubnetNotFound(subnet_id=subnet_id)
        return subnet

    def check_network_subnet_pair(self, network, subnet):
        pass


class DHCPController(BackendController):
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


class DNSController(BackendController):
    __meta__ = abc.ABCMeta

    @abc.abstractmethod
    def bind_host_names(self, context, backend_port):
        pass

    @abc.abstractmethod
    def bind_dhcp_port_names(self, context, backend_port):
        pass

    @abc.abstractmethod
    def unbind_host_names(self, context, backend_port):
        pass

    @abc.abstractmethod
    def unbind_dhcp_port_names(self, context, backend_port):
        pass

    @abc.abstractmethod
    def get_names(self, context, backend_port):
        pass

    @abc.abstractmethod
    def create_dns_zones(self, context, backend_subnet):
        pass

    @abc.abstractmethod
    def delete_dns_zones(self, context, backend_subnet):
        pass

    @abc.abstractmethod
    def get_dns_zone(self, context, backend_subnet):
        pass


class IPAMController(BackendController):
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
    def get_subnets_by_network(self, context, network_id):
        pass

    @abc.abstractmethod
    def get_all_subnets(self, context):
        pass

    @abc.abstractmethod
    def get_subnet_ports(self, context, backend_subnet):
        pass

    @abc.abstractmethod
    def get_subnets(self, context, filters=None, fields=None,
                    sorts=None, limit=None, marker=None,
                    page_reverse=False):
        pass

    @abc.abstractmethod
    def get_subnets_count(self, context, filters=None):
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
    def delete_network(self, context, network_id):
        pass


class IPAM(BackendController):
    def _get_subnet_info(self, subnet):
        return subnet

    def _get_subnet_dns_params(self, subnet):
        return None

    def _get_subnet_dhcp_params(self, subnet):
        return subnet

    def create_subnet(self, context, subnet):
        # Allocate IP addresses. Create allocation pools only
        backend_subnet = self.ipam_controller.create_subnet(context, subnet)
        self.dns_controller.create_dns_zones(context, backend_subnet)
        # Configure DHCP
        dhcp_params = self._get_subnet_dhcp_params(subnet)
        self.dhcp_controller.configure_dhcp(context, backend_subnet,
                                            dhcp_params)
        return backend_subnet

    def update_subnet(self, context, subnet_id, subnet):
        #subnet_info = self._get_subnet_info(subnet)
        backend_subnet = self.ipam_controller.update_subnet(
            context, subnet_id, subnet)

        # Reconfigure DHCP for subnet
        dhcp_params = self._get_subnet_dhcp_params(subnet)
        dhcp_changes = self.dhcp_controller.reconfigure_dhcp(
            context, backend_subnet, dhcp_params)

        return backend_subnet, dhcp_changes

    def _is_auto_del_port(self, port):
        #return (not a.port_id or a.ports.device_owner in
        # AUTO_DELETE_PORT_OWNERS)
        return True

    def delete_subnet(self, context, subnet):
        self.dns_controller.delete_dns_zones(context, subnet)
        self.dhcp_controller.disable_dhcp(context, subnet)
        self.ipam_controller.delete_subnet(context, subnet)

    def delete_subnets_by_network(self, context, network_id):
        subnets = self.ipam_controller.get_subnets_by_network(
            context, network_id)
        for subnet in subnets:
            self.delete_subnet(context, subnet['id'])

    def get_subnet_by_id(self, context, subnet_id):
        return self.ipam_controller.get_subnet_by_id(context, subnet_id)

    def allocate_ip(self, context, host, ip):
        subnet_id = ip.get('subnet_id', None)
        if not subnet_id:
            LOG.debug(_("ip object must have %(subnet_id)s") % subnet_id)
            raise
        backend_subnet = self.ipam_controller.get_subnet_by_id(context,
                                                               subnet_id)
        ip_address = self.ipam_controller.allocate_ip(
            context,
            backend_subnet,
            host,
            ip.get('ip_address', None))
        LOG.debug('IPAM allocate IP: %s' % ip_address)
        mac_address = host['mac_address']
        self.dhcp_controller.bind_mac(
            context,
            backend_subnet,
            ip_address,
            mac_address)
        return ip_address

    def deallocate_ip(self, context, host, ip):
        subnet_id = ip['subnet_id']
        ip_address = ip['ip_address']
        backend_subnet = self.ipam_controller.get_subnet_by_id(
            context, subnet_id)
        self.dhcp_controller.unbind_mac(
            context,
            backend_subnet,
            ip_address)
        self.ipam_controller.deallocate_ip(
            context,
            backend_subnet,
            host,
            ip_address)

    def get_subnets_by_network(self, context, network_id):
        # TODO(zasimov): must be returns 'external' subnet objects
        return self.ipam_controller.get_subnets_by_network(context,
                                                           network_id)

    def get_all_subnets(self, context):
        # TODO(zasimov): must be returns 'external' subnet objects
        return self.ipam_controller.get_all_subnets(context)

    def get_subnets(self, context, filters=None, fields=None,
                    sorts=None, limit=None, marker=None,
                    page_reverse=False):
        # TODO(zasimov): must be returns 'external' subnet objects
        return self.ipam_controller.get_subnets(context, filters, fields,
                                                sorts, limit, marker,
                                                page_reverse)

    def get_subnets_count(self, context, filters=None):
        return self.ipam_controller.get_subnets_count(context, filters)

    def delete_network(self, context, network_id,
                       allowed_net_number_for_netview_delete=0):
        self.ipam_controller.delete_network(
            context, network_id)

    def create_port(self, context, port):
        if self._compute_or_floating_ip(port):
            self.dns_controller.bind_host_names(context, port)
        if 'dhcp' in port['device_owner']:
            self.ipam_controller.set_dns_nameservers(context, port)
            self.dns_controller.bind_dhcp_port_names(context, port)

    def delete_port(self, context, port):
        if self._compute_or_floating_ip(port):
            self.dns_controller.unbind_host_names(context, port)
        if 'dhcp' in port['device_owner']:
            self.dns_controller.unbind_dhcp_port_names(context, port)

    def update_floatingip(self, context, floatingip, port):
        associate = floatingip['floatingip'] is not None
        if associate:
            self.create_port(context, port)
        else:
            self.delete_port(context, port)

    @staticmethod
    def _compute_or_floating_ip(port):
        return any([p in port['device_owner']
                    for p in 'compute', constants.DEVICE_OWNER_FLOATINGIP])
