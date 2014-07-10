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

import itertools

import netaddr
from sqlalchemy import orm
from sqlalchemy.orm import exc

from neutron.api.v2 import attributes
from neutron.db import models_v2
from neutron.ipam import base
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class NeutronIPAMController(base.IPAMController):
    def _make_allocation_pools(self, context, backend_subnet, subnet):
        # Store information about allocation pools and ranges
        for pool in subnet['allocation_pools']:
            ip_pool = models_v2.IPAllocationPool(subnet=backend_subnet,
                                                 first_ip=pool['start'],
                                                 last_ip=pool['end'])
            context.session.add(ip_pool)
            ip_range = models_v2.IPAvailabilityRange(
                ipallocationpool=ip_pool,
                first_ip=pool['start'],
                last_ip=pool['end'])
            context.session.add(ip_range)

    def create_subnet(self, context, subnet):
        return subnet

    def get_subnet_by_id(self, context, subnet_id):
        return self._get_subnet(context, subnet_id)

    def update_subnet(self, context, subnet_id, subnet):
        backend_subnet = self.get_subnet_by_id(context, subnet_id)
        return backend_subnet

    def get_subnets_by_network(self, context, network_id):
        subnet_qry = context.session.query(models_v2.Subnet)
        return subnet_qry.filter_by(network_id=network_id).all()

    def get_all_subnets(self, context):
        return context.session.query(models_v2.Subnet).all()

    def get_subnet_ports(self, context, backend_subnet):
        # TODO(zasimov): get ports for current subnet
        # Check if any tenant owned ports are using this subnet
        ports_qry = context.session.query(models_v2.IPAllocation)
        ports_qry = ports_qry.options(orm.joinedload('ports'))
        ports = ports_qry.filter_by(subnet_id=backend_subnet.id)
        return ports

    def _make_subnet_dict(self, subnet, fields=None):
        res = {'id': subnet['id'],
               'name': subnet['name'],
               'tenant_id': subnet['tenant_id'],
               'network_id': subnet['network_id'],
               'ip_version': subnet['ip_version'],
               'cidr': subnet['cidr'],
               'allocation_pools': [{'start': pool['first_ip'],
                                     'end': pool['last_ip']}
                                    for pool in subnet['allocation_pools']],
               'gateway_ip': subnet['gateway_ip'],
               'enable_dhcp': subnet['enable_dhcp'],
               'dns_nameservers': [dns['address']
                                   for dns in subnet['dns_nameservers']],
               'host_routes': [{'destination': route['destination'],
                                'nexthop': route['nexthop']}
                               for route in subnet['routes']],
               'shared': subnet['shared']
               }
        return self._fields(res, fields)

    def get_subnets(self, context, filters=None, fields=None,
                    sorts=None, limit=None, marker=None,
                    page_reverse=False):
        marker_obj = self._get_marker_obj(context, 'subnet', limit, marker)
        return self._get_collection(context, models_v2.Subnet,
                                    self._make_subnet_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts,
                                    limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    def get_subnets_count(self, context, filters=None):
        return self._get_collection_count(context, models_v2.Subnet,
                                          filters=filters)

    def delete_subnet(self, context, backend_subnet):
        pass

    def force_off_ports(self, context, ports):
        """Force Off ports on subnet delete event."""
        ports.delete()

    @staticmethod
    def _generate_ip(context, backend_subnet):
        """Generate an IP address.

        The IP address will be generated from one of the subnets defined on
        the network.
        """
        range_qry = context.session.query(
            models_v2.IPAvailabilityRange).join(
                models_v2.IPAllocationPool).with_lockmode('update')
        range = range_qry.filter_by(subnet_id=backend_subnet.id).first()
        if not range:
            LOG.debug(_("All IPs from subnet %(subnet_id)s (%(cidr)s) "
                        "allocated"),
                      {'subnet_id': backend_subnet.id,
                       'cidr': backend_subnet.cidr})
            return None
        ip_address = range['first_ip']
        LOG.debug(_("Allocated IP - %(ip_address)s from %(first_ip)s "
                    "to %(last_ip)s"),
                  {'ip_address': ip_address,
                   'first_ip': range['first_ip'],
                   'last_ip': range['last_ip']})
        if range['first_ip'] == range['last_ip']:
            # No more free indices on subnet => delete
            LOG.debug(_("No more free IP's in slice. Deleting allocation "
                        "pool."))
            context.session.delete(range)
        else:
            # increment the first free
            range['first_ip'] = str(netaddr.IPAddress(ip_address) + 1)
        return ip_address

    @staticmethod
    def _allocate_specific_ip(context, backend_subnet, ip_address):
        """Allocate a specific IP address on the subnet."""
        ip = int(netaddr.IPAddress(ip_address))
        range_qry = context.session.query(
            models_v2.IPAvailabilityRange).join(
                models_v2.IPAllocationPool).with_lockmode('update')
        results = range_qry.filter_by(subnet_id=backend_subnet.id)
        for range in results:
            first = int(netaddr.IPAddress(range['first_ip']))
            last = int(netaddr.IPAddress(range['last_ip']))
            if first <= ip <= last:
                if first == last:
                    context.session.delete(range)
                    return
                elif first == ip:
                    range['first_ip'] = str(netaddr.IPAddress(ip_address) + 1)
                    return
                elif last == ip:
                    range['last_ip'] = str(netaddr.IPAddress(ip_address) - 1)
                    return
                else:
                    # Split into two ranges
                    new_first = str(netaddr.IPAddress(ip_address) + 1)
                    new_last = range['last_ip']
                    range['last_ip'] = str(netaddr.IPAddress(ip_address) - 1)
                    ip_range = models_v2.IPAvailabilityRange(
                        allocation_pool_id=range['allocation_pool_id'],
                        first_ip=new_first,
                        last_ip=new_last)
                    context.session.add(ip_range)
                    return ip_address
            return None

    def allocate_ip(self, context, backend_subnet, host, ip=None):
        if ip:
            return self._allocate_specific_ip(context, backend_subnet, ip)
        else:
            return self._generate_ip(context, backend_subnet)

    def _check_ip_in_allocation_pool(self, context, backend_subnet,
                                     ip_address):
        if backend_subnet.gateway_ip == ip_address:
            return False

        # Check if the requested IP is in a defined allocation pool
        pool_qry = context.session.query(models_v2.IPAllocationPool)
        allocation_pools = pool_qry.filter_by(subnet_id=backend_subnet.id)
        ip = netaddr.IPAddress(ip_address)
        for allocation_pool in allocation_pools:
            allocation_pool_range = netaddr.IPRange(
                allocation_pool['first_ip'],
                allocation_pool['last_ip'])
            if ip in allocation_pool_range:
                return True
        return False

    # FIXME(zasimov): kill network_id
    @staticmethod
    def _delete_ip_allocation(context, network_id, backend_subnet, ip_address):

        # Delete the IP address from the IPAllocate table
        LOG.debug(_("Delete allocated IP %(ip_address)s "
                    "(%(network_id)s/%(subnet_id)s)"),
                  {'ip_address': ip_address,
                   'network_id': network_id,
                   'subnet_id': backend_subnet.id})
        alloc_qry = context.session.query(
            models_v2.IPAllocation).with_lockmode('update')
        alloc_qry.filter_by(network_id=network_id,
                            ip_address=ip_address,
                            subnet_id=backend_subnet.id).delete()

    # FIXME(zasimov): kill network_id
    @staticmethod
    def _recycle_ip(context, network_id, backend_subnet, ip_address):
        """Return an IP address to the pool of free IP's on the network
        subnet.

        TODO(zasimov): check this function (ip range is lost?)
        """
        # FIXME(zasimov): maybe use normal join here?
        # Grab all allocation pools for the subnet
        allocation_pools = (context.session.query(
            models_v2.IPAllocationPool).filter_by(subnet_id=backend_subnet.id).
            options(orm.joinedload('available_ranges', innerjoin=True)).
            with_lockmode('update'))
        # If there are no available ranges the previous query will return no
        # results as it uses an inner join to avoid errors with the postgresql
        # backend (see lp bug 1215350). In this case IP allocation pools must
        # be loaded with a different query, which does not require lock for
        # update as the allocation pools for a subnet are immutable.
        # The 2nd query will be executed only if the first yields no results
        unlocked_allocation_pools = (context.session.query(
            models_v2.IPAllocationPool).filter_by(subnet_id=backend_subnet.id))

        # Find the allocation pool for the IP to recycle
        pool_id = None

        for allocation_pool in itertools.chain(allocation_pools,
                                               unlocked_allocation_pools):
            allocation_pool_range = netaddr.IPRange(
                allocation_pool['first_ip'], allocation_pool['last_ip'])
            if netaddr.IPAddress(ip_address) in allocation_pool_range:
                pool_id = allocation_pool['id']
                break
        if not pool_id:
            NeutronIPAMController._delete_ip_allocation(
                context, network_id, backend_subnet, ip_address)
            return
        # Two requests will be done on the database. The first will be to
        # search if an entry starts with ip_address + 1 (r1). The second
        # will be to see if an entry ends with ip_address -1 (r2).
        # If 1 of the above holds true then the specific entry will be
        # modified. If both hold true then the two ranges will be merged.
        # If there are no entries then a single entry will be added.
        range_qry = context.session.query(
            models_v2.IPAvailabilityRange).with_lockmode('update')
        ip_first = str(netaddr.IPAddress(ip_address) + 1)
        ip_last = str(netaddr.IPAddress(ip_address) - 1)
        LOG.debug(_("Recycle %s"), ip_address)
        try:
            r1 = range_qry.filter_by(allocation_pool_id=pool_id,
                                     first_ip=ip_first).one()
            LOG.debug(_("Recycle: first match for %(first_ip)s-%(last_ip)s"),
                      {'first_ip': r1['first_ip'], 'last_ip': r1['last_ip']})
        except exc.NoResultFound:
            r1 = []
        try:
            r2 = range_qry.filter_by(allocation_pool_id=pool_id,
                                     last_ip=ip_last).one()
            LOG.debug(_("Recycle: last match for %(first_ip)s-%(last_ip)s"),
                      {'first_ip': r2['first_ip'], 'last_ip': r2['last_ip']})
        except exc.NoResultFound:
            r2 = []

        if r1 and r2:
            # Merge the two ranges
            ip_range = models_v2.IPAvailabilityRange(
                allocation_pool_id=pool_id,
                first_ip=r2['first_ip'],
                last_ip=r1['last_ip'])
            context.session.add(ip_range)
            LOG.debug(_("Recycle: merged %(first_ip1)s-%(last_ip1)s and "
                        "%(first_ip2)s-%(last_ip2)s"),
                      {'first_ip1': r2['first_ip'], 'last_ip1': r2['last_ip'],
                       'first_ip2': r1['first_ip'], 'last_ip2': r1['last_ip']})
            context.session.delete(r1)
            context.session.delete(r2)
        elif r1:
            # Update the range with matched first IP
            r1['first_ip'] = ip_address
            LOG.debug(_("Recycle: updated first %(first_ip)s-%(last_ip)s"),
                      {'first_ip': r1['first_ip'], 'last_ip': r1['last_ip']})
        elif r2:
            # Update the range with matched last IP
            r2['last_ip'] = ip_address
            LOG.debug(_("Recycle: updated last %(first_ip)s-%(last_ip)s"),
                      {'first_ip': r2['first_ip'], 'last_ip': r2['last_ip']})
        else:
            # Create a new range
            ip_range = models_v2.IPAvailabilityRange(
                allocation_pool_id=pool_id,
                first_ip=ip_address,
                last_ip=ip_address)
            context.session.add(ip_range)
            LOG.debug(_("Recycle: created new %(first_ip)s-%(last_ip)s"),
                      {'first_ip': ip_address, 'last_ip': ip_address})
        NeutronIPAMController._delete_ip_allocation(
            context, network_id, backend_subnet, ip_address)

    def deallocate_ip(self, context, backend_subnet, host, ip_address):
        # TODO(zasimov): maybe remove this if self._check?
        if self._check_ip_in_allocation_pool(context, backend_subnet,
                                             ip_address):
            self._recycle_ip(context,
                             backend_subnet.network_id,
                             backend_subnet,
                             ip_address)
        else:
            # IPs out of allocation pool will not be recycled, but
            # we do need to delete the allocation from the DB
            self._delete_ip_allocation(
                context,
                backend_subnet.network_id,
                backend_subnet,
                ip_address)
            msg_dict = {'address': ip_address,
                        'subnet_id': backend_subnet.id}
            msg = _("%(address)s (%(subnet_id)s) is not "
                    "recycled") % msg_dict
            LOG.debug(msg)

    def delete_network(self, context, network_id):
        pass

    def set_dns_nameservers(self, context, port):
        pass


class NeutronDHCPController(base.DHCPController):
    def configure_dhcp(self, context, backend_subnet, dhcp_params):
        # Store information about DNS Servers
        if dhcp_params['dns_nameservers'] is not attributes.ATTR_NOT_SPECIFIED:
            for addr in dhcp_params['dns_nameservers']:
                ns = models_v2.DNSNameServer(address=addr,
                                             subnet_id=backend_subnet.id)
                context.session.add(ns)

        # Store host routes
        if dhcp_params['host_routes'] is not attributes.ATTR_NOT_SPECIFIED:
            for rt in dhcp_params['host_routes']:
                route = models_v2.SubnetRoute(
                    subnet_id=backend_subnet.id,
                    destination=rt['destination'],
                    nexthop=rt['nexthop'])
                context.session.add(route)

    def _get_dns_by_subnet(self, context, subnet_id):
        dns_qry = context.session.query(models_v2.DNSNameServer)
        return dns_qry.filter_by(subnet_id=subnet_id).all()

    def _get_route_by_subnet(self, context, subnet_id):
        route_qry = context.session.query(models_v2.SubnetRoute)
        return route_qry.filter_by(subnet_id=subnet_id).all()

    def reconfigure_dhcp(self, context, backend_subnet, dhcp_params):
        changed_dns = False
        new_dns = []
        if "dns_nameservers" in dhcp_params:
            changed_dns = True
            old_dns_list = self._get_dns_by_subnet(context, backend_subnet.id)
            new_dns_addr_set = set(dhcp_params["dns_nameservers"])
            old_dns_addr_set = set([dns['address']
                                    for dns in old_dns_list])

            new_dns = list(new_dns_addr_set)
            for dns_addr in old_dns_addr_set - new_dns_addr_set:
                for dns in old_dns_list:
                    if dns['address'] == dns_addr:
                        context.session.delete(dns)
            for dns_addr in new_dns_addr_set - old_dns_addr_set:
                dns = models_v2.DNSNameServer(
                    address=dns_addr,
                    subnet_id=backend_subnet.id)
                context.session.add(dns)

        def _combine(ht):
            return ht['destination'] + "_" + ht['nexthop']

        changed_host_routes = False
        new_routes = []
        if "host_routes" in dhcp_params:
            changed_host_routes = True
            old_route_list = self._get_route_by_subnet(
                context, backend_subnet.id)

            new_route_set = set([_combine(route)
                                 for route in dhcp_params['host_routes']])

            old_route_set = set([_combine(route)
                                 for route in old_route_list])

            for route_str in old_route_set - new_route_set:
                for route in old_route_list:
                    if _combine(route) == route_str:
                        context.session.delete(route)
            for route_str in new_route_set - old_route_set:
                route = models_v2.SubnetRoute(
                    destination=route_str.partition("_")[0],
                    nexthop=route_str.partition("_")[2],
                    subnet_id=backend_subnet.id)
                context.session.add(route)

            # Gather host routes for result
            for route_str in new_route_set:
                new_routes.append(
                    {'destination': route_str.partition("_")[0],
                     'nexthop': route_str.partition("_")[2]})

        # FIXME(zasimov): Is it here?
        subnet_related_info = {}
        if 'gateway_ip' in dhcp_params:
            subnet_related_info['gateway_ip'] = dhcp_params['gateway_ip']
        if 'enable_dhcp' in dhcp_params:
            subnet_related_info['enable_dhcp'] = dhcp_params['enable_dhcp']
        backend_subnet.update(subnet_related_info)

        result = {}
        if changed_dns:
            result['new_dns'] = new_dns
        if changed_host_routes:
            result['new_routes'] = new_routes
        return result

    def bind_mac(self, context, backend_subnet, ip_address, mac_address):
        pass

    def unbind_mac(self, context, backend_subnet, ip_address):
        pass

    def dhcp_is_enabled(self, context, backend_subnet):
        pass

    def disable_dhcp(self, context, backend_subnet):
        pass

    def get_dhcp_ranges(self, context, backend_subnet):
        pass


class NeutronDNSController(base.DNSController):
    def bind_host_names(self, context, backend_port):
        pass

    def bind_dhcp_port_names(self, context, backend_port):
        pass

    def unbind_host_names(self, context, backend_port):
        pass

    def unbind_dhcp_port_names(self, context, backend_port):
        pass

    def create_dns_zones(self, context, backend_subnet):
        pass

    def delete_dns_zones(self, context, backend_subnet):
        pass


class NeutronIPAM(base.IPAM):
    def __init__(self):
        self.ipam_controller = NeutronIPAMController()
        self.dhcp_controller = NeutronDHCPController()
        self.dns_controller = NeutronDNSController()

    def create_subnet(self, context, subnet):
        with context.session.begin(subtransactions=True):
            return super(NeutronIPAM, self).create_subnet(context, subnet)

    def update_subnet(self, context, subnet_id, subnet):
        with context.session.begin(subtransactions=True):
            return super(NeutronIPAM, self).update_subnet(context, subnet_id,
                                                          subnet)

    def get_subnets_by_network(self, context, network_id):
        with context.session.begin(subtransactions=True):
            return super(NeutronIPAM, self).get_subnets_by_network(context,
                                                                   network_id)

    def get_all_subnets(self, context):
        with context.session.begin(subtransactions=True):
            return super(NeutronIPAM, self).get_all_subnets(context)

    def get_subnets(self, context, filters=None, fields=None,
                    sorts=None, limit=None, marker=None,
                    page_reverse=False):
        with context.session.begin(subtransactions=True):
            return super(NeutronIPAM, self).get_subnets(context, filters,
                                                        fields, sorts, limit,
                                                        marker, page_reverse)

    def get_subnets_count(self, context, filters=None):
        with context.session.begin(subtransactions=True):
            return super(NeutronIPAM, self).get_subnets_count(context, filters)

    def get_subnet_by_id(self, context, subnet_id):
        with context.session.begin(subtransactions=True):
            return super(NeutronIPAM, self).get_subnet_by_id(context,
                                                             subnet_id)

    def allocate_ip(self, context, host, ip):
        with context.session.begin(subtransactions=True):
            return super(NeutronIPAM, self).allocate_ip(context, host, ip)

    def deallocate_ip(self, context, host, ip):
        with context.session.begin(subtransactions=True):
            return super(NeutronIPAM, self).deallocate_ip(context, host, ip)

    def delete_subnet(self, context, subnet_id):
        with context.session.begin(subtransactions=True):
            return super(NeutronIPAM, self).delete_subnet(context, subnet_id)

    def delete_subnets_by_network(self, context, network_id):
        with context.session.begin(subtransactions=True):
            return super(NeutronIPAM, self).delete_subnets_by_network(
                context, network_id)
