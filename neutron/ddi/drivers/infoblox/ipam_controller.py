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

from oslo.config import cfg as neutron_conf
from taskflow.patterns import linear_flow

from neutron.openstack.common import log as logging
from neutron.db.infoblox import infoblox_db
from neutron.ddi.drivers import neutron_ddi
from neutron.ddi.drivers.infoblox import config
from neutron.ddi.drivers.infoblox import dns_controller
from neutron.ddi.drivers.infoblox import exceptions
from neutron.ddi.drivers.infoblox import tasks
from neutron.ddi.drivers.infoblox import ea_manager


OPTS = [
    neutron_conf.BoolOpt('use_host_records_for_ip_allocation',
                         default=True,
                         help=_("Use host records for IP allocation. If False "
                                "then Fixed IP + A + PTR record are used."))
]

neutron_conf.CONF.register_opts(OPTS)
LOG = logging.getLogger(__name__)


class InfobloxIPAMController(neutron_ddi.NeutronIPAMController):
    def __init__(self, obj_manip=None, config_finder=None, ip_allocator=None):
        """IPAM backend implementation for Infoblox"""
        self.infoblox = obj_manip
        self.config_finder = config_finder
        self.ip_allocator = ip_allocator
        self.ea_manager = ea_manager.InfobloxEaManager(infoblox_db)
        self.pattern_builder = config.PatternBuilder

    def create_subnet(self, context, subnet):
        cfg = self.config_finder.find_config_for_subnet(context, subnet)
        dhcp_member = cfg.reserve_dhcp_member()
        dns_member = cfg.reserve_dns_member()

        create_subnet_flow = linear_flow.Flow('ib_create_subnet')

        # Neutron will sort this later so make sure infoblox copy is
        # sorted too.
        user_nameservers = sorted(dns_controller.get_nameservers(subnet))

        # For flat network we save member IP as a primary DNS server: to
        # the beginning of the list.
        # If this net is not flat, Member IP will later be replaced by
        # DNS relay IP.
        nameservers = [dhcp_member.ip] + user_nameservers

        network = self._get_network(context, subnet['network_id'])
        network_extattrs = self.ea_manager.get_extattrs_for_network(
            context, subnet, network)
        method_arguments = {'obj_manip': self.infoblox,
                            'net_view_name': cfg.network_view,
                            'dns_view_name': cfg.dns_view,
                            'cidr': subnet['cidr'],
                            'dhcp_member': dhcp_member,
                            'gateway_ip': subnet['gateway_ip'],
                            'disable': True,
                            'nameservers': nameservers,
                            'network_extattrs': network_extattrs}

        net = self._get_network(context, subnet['network_id'])
        if not cfg.is_external and cfg.require_dhcp_relay:
            net.update(dict(dns_relay_ip=dns_member.ip,
                            dhcp_relay_ip=dhcp_member.ip))

        if cfg.requires_net_view():
            create_subnet_flow.add(
                tasks.CreateNetViewTask())

        if cfg.network_template:
            method_arguments['template'] = cfg.network_template
            create_subnet_flow.add(tasks.CreateNetworkFromTemplateTask())
        else:
            create_subnet_flow.add(tasks.CreateNetworkTask())

        create_subnet_flow.add(tasks.CreateDNSViewTask())

        for ip_range in subnet['allocation_pools']:
            # context.store is a global dict of method arguments for tasks in
            # current flow, hence method arguments need to be rebound

            first = ip_range['start']
            last = ip_range['end']
            first_ip_arg = 'ip_range %s' % first
            last_ip_arg = 'ip_range %s' % last
            method_arguments[first_ip_arg] = first
            method_arguments[last_ip_arg] = last
            task_name = '-'.join([first, last])
            create_subnet_flow.add(
                tasks.CreateIPRange(name=task_name,
                                    rebind={'start_ip': first_ip_arg,
                                            'end_ip': last_ip_arg}))

        context.store.update(method_arguments)
        context.parent_flow.add(create_subnet_flow)

        return super(InfobloxIPAMController, self).create_subnet(
            context, subnet)

    def update_subnet(self, context, subnet_id, subnet):
        backend_subnet = self.get_subnet_by_id(context, subnet_id)

        cfg = self.config_finder.find_config_for_subnet(context,
                                                        backend_subnet)
        ib_network = self.infoblox.get_network(cfg.network_view,
                                               subnet['cidr'])

        user_nameservers = sorted(subnet['dns_nameservers'])
        updated_nameservers = user_nameservers
        if ib_network.member_ip_addr in ib_network.dns_nameservers:
            # Flat network, primary dns is member_ip
            primary_dns = ib_network.member_ip_addr
            updated_nameservers = [primary_dns] + user_nameservers
        else:
            # Network with relays, primary dns is relay_ip
            primary_dns = infoblox_db.get_subnet_dhcp_port_address(
                context, subnet['id'])
            if primary_dns:
                updated_nameservers = [primary_dns] + user_nameservers

        ib_network.dns_nameservers = updated_nameservers
        self.infoblox.update_network_options(ib_network)

        return backend_subnet

    def delete_subnet(self, context, subnet):
        deleted_subnet = super(InfobloxIPAMController, self).delete_subnet(
            context, subnet)

        cfg = self.config_finder.find_config_for_subnet(context, subnet)
        self.infoblox.delete_network(cfg.network_view, cidr=subnet['cidr'])
        cfg.member_manager.release_member(context, cfg.network_view)

        return deleted_subnet

    def allocate_ip(self, context, subnet, host, ip=None):
        hostname = host['name']
        mac = host['mac_address']

        LOG.debug("Trying to allocate IP for %s on Infoblox NIOS" % hostname)

        cfg = self.config_finder.find_config_for_subnet(context, subnet)

        networkview_name = cfg.network_view
        dnsview_name = cfg.dns_view
        zone_auth = self.pattern_builder(cfg.domain_suffix_pattern).build(
            context, subnet)

        if ip:
            allocated_ip = self.ip_allocator.allocate_given_ip(
                networkview_name, dnsview_name, zone_auth, hostname, mac, ip)
        else:
            # Allocate next available considering IP ranges.
            ip_ranges = subnet['allocation_pools']
            # Let Infoblox try to allocate an IP from each ip_range
            # consistently, and break on the first successful allocation.
            for ip_range in ip_ranges:
                first_ip = ip_range['first_ip']
                last_ip = ip_range['last_ip']
                try:
                    allocated_ip = self.ip_allocator.allocate_ip_from_range(
                        dnsview_name, networkview_name, zone_auth, hostname,
                        mac, first_ip, last_ip)
                    break
                except exceptions.InfobloxCannotAllocateIp:
                    LOG.debug("No more free IP's in slice %s-%s." % (first_ip,
                                                                     last_ip))
                    continue
            else:
                # We went through all the ranges and Infoblox did not
                # allocated any IP.
                raise exceptions.InfobloxCannotAllocateIpForSubnet(
                    netview=networkview_name, cidr=subnet['cidr'])

        # TODO(max_lobur): As kind of optimisation we could mark IP as used by
        # neutron_ddi._allocate_specific_ip, to prevent poking already empty
        # ranges.
        LOG.debug('IP address allocated on Infoblox NIOS: %s', allocated_ip)
        return allocated_ip

    def deallocate_ip(self, context, subnet, host, ip):
        cfg = self.config_finder.find_config_for_subnet(context, subnet)
        net_id = subnet['network_id']
        self.ip_allocator.deallocate_ip(
            cfg.network_view, cfg.dns_view, ip)
        infoblox_db.delete_ip_allocation(context, net_id, subnet, ip)

        self.infoblox.restart_all_services(cfg.dhcp_member)

    def set_dns_nameservers(self, context, port):
        # Replace member IP in DNS nameservers by DNS relay IP.
        for ip in port['fixed_ips']:
            subnet = self._get_subnet(context, ip['subnet_id'])
            cfg = self.config_finder.find_config_for_subnet(context, subnet)
            net = self.infoblox.get_network(cfg.network_view, subnet['cidr'])
            if not net.members:
                continue
            if not net.has_dns_members():
                LOG.debug("No domain-name-servers option found, it will"
                          "not be updated to the private DDI relay IP.")
                continue
            if cfg.require_dhcp_relay:
                net.update_member_ip_in_dns_nameservers(ip['ip_address'])
            self.infoblox.update_network_options(net)

    def delete_network(self, context, network):
        cfg = self.config_finder.find_config_for_network(context, network)

        self.infoblox.delete_network_view(cfg.network_view)
