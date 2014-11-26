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

from neutron.ipam.drivers.infoblox import exceptions as exc
from neutron.ipam.drivers.infoblox import objects
from neutron.openstack.common import log as logging


LOG = logging.getLogger(__name__)


class InfobloxObjectManipulator(object):
    def __init__(self, connector):
        self.connector = connector

    def create_network_view(self, netview_name):
        net_view_data = {'name': netview_name}
        return self._create_infoblox_object('networkview', net_view_data)

    def create_dns_view(self, net_view_name, dns_view_name):
        dns_view_data = {'name': dns_view_name,
                         'network_view': net_view_name}
        return self._create_infoblox_object('view', dns_view_data)

    def create_network(self, net_view_name, cidr, nameservers=None,
                       members=None, gateway_ip=None, dhcp_trel_ip=None,
                       network_extattrs=None):
        network_data = {'network_view': net_view_name,
                        'network': cidr,
                        'extattrs': network_extattrs}
        members_struct = []
        for member in members:
            members_struct.append({'ipv4addr': member.ip,
                                   '_struct': 'dhcpmember'})
        network_data['members'] = members_struct

        dhcp_options = []

        if nameservers:
            dhcp_options.append({'name': 'domain-name-servers',
                                 'value': ",".join(nameservers)})

        if gateway_ip:
            dhcp_options.append({'name': 'routers',
                                 'value': gateway_ip})

        if dhcp_trel_ip:
            dhcp_options.append({'name': 'dhcp-server-identifier',
                                         'num': 54,
                                         'value': dhcp_trel_ip})

        if dhcp_options:
            network_data['options'] = dhcp_options

        return self._create_infoblox_object(
            'network', network_data, check_if_exists=False)

    def create_network_from_template(self, net_view_name, cidr, template,
                                     network_extattrs):
        network_data = {
            'network_view': net_view_name,
            'network': cidr,
            'template': template,
            'extattrs': network_extattrs
        }

        return self._create_infoblox_object('network', network_data,
                                            check_if_exists=False)

    def create_ip_range(self, network_view, start_ip, end_ip, disable):
        range_data = {'start_addr': start_ip,
                      'end_addr': end_ip,
                      'network_view': network_view,
                      'disable': disable}
        self._create_infoblox_object('range', range_data,
                                     check_if_exists=False)

    def create_host_record_for_given_ip(self, dns_view_name, zone_auth,
                                        hostname, mac, ip):
        hr = objects.HostRecordIPv4()
        hr.hostname = hostname
        hr.zone_auth = zone_auth
        hr.mac = mac
        hr.dns_view = dns_view_name
        hr.ip = ip

        created_hr = self._create_infoblox_ip_address(hr)
        return created_hr

    def create_host_record_from_range(self, dns_view_name, network_view_name,
                                      zone_auth, hostname, mac, first_ip,
                                      last_ip):
        hr = objects.HostRecordIPv4()

        hr.hostname = hostname
        hr.zone_auth = zone_auth
        hr.mac = mac
        hr.dns_view = dns_view_name
        hr.ip = objects.IPAllocationObject.next_available_ip_from_range(
            network_view_name, first_ip, last_ip)

        created_hr = self._create_infoblox_ip_address(hr)
        return created_hr

    def create_fixed_address_for_given_ip(self, network_view, mac, ip,
                                          extattrs):
        fa = objects.FixedAddress()
        fa.ip = ip
        fa.net_view = network_view
        fa.mac = mac
        fa.extattrs = extattrs
        created_fa = self._create_infoblox_ip_address(fa)
        return created_fa

    def create_fixed_address_from_range(self, network_view, mac, first_ip,
                                        last_ip, extattrs):
        fa = objects.FixedAddress()
        fa.ip = objects.IPAllocationObject.next_available_ip_from_range(
            network_view, first_ip, last_ip)
        fa.net_view = network_view
        fa.mac = mac
        fa.extattrs = extattrs
        created_fa = self._create_infoblox_ip_address(fa)
        return created_fa

    def update_host_record_eas(self, dns_view, ip, extattrs):
        fa_data = {'view': dns_view,
                   'ipv4addr': ip}
        fa = self._get_infoblox_object_or_none('record:host', fa_data)
        self._update_infoblox_object_by_ref(fa, {'extattrs': extattrs})

    def update_fixed_address_eas(self, network_view, ip, extattrs):
        fa_data = {'network_view': network_view,
                   'ipv4addr': ip}
        fa = self._get_infoblox_object_or_none('fixedaddress', fa_data)
        self._update_infoblox_object_by_ref(fa, {'extattrs': extattrs})

    def update_dns_record_eas(self, dns_view, ip, extattrs):
        fa_data = {'view': dns_view,
                   'ipv4addr': ip}
        fa = self._get_infoblox_object_or_none('record:a', fa_data)
        self._update_infoblox_object_by_ref(fa, {'extattrs': extattrs})

        fa = self._get_infoblox_object_or_none('record:ptr', fa_data)
        self._update_infoblox_object_by_ref(fa, {'extattrs': extattrs})

    def create_fixed_address_from_cidr(self, network_view, mac, cidr):
        fa = objects.FixedAddress()
        fa.ip = objects.IPAllocationObject.next_available_ip_from_cidr(
            network_view, cidr)
        fa.mac = mac
        fa.net_view = network_view
        created_fa = self._create_infoblox_ip_address(fa)
        return created_fa

    def delete_host_record(self, dns_view_name, ip_address):
        host_record_data = {'view': dns_view_name,
                            'ipv4addr': ip_address}
        self._delete_infoblox_object('record:host', host_record_data)

    def delete_fixed_address(self, network_view, ip):
        fa_data = {'network_view': network_view,
                   'ipv4addr': ip}
        self._delete_infoblox_object('fixedaddress',
                                     fa_data)

    def delete_ip_range(self, net_view, start_ip, end_ip):
        range_data = {'start_addr': start_ip,
                      'end_addr': end_ip,
                      'network_view': net_view}
        self._delete_infoblox_object('range', range_data)

    def delete_object_by_ref(self, ref):
        try:
            self.connector.delete_object(ref)
        except exc.InfobloxCannotDeleteObject as e:
            LOG.info(_("Failed to delete an object: %s"), e)

    def get_member(self, member):
        return self.connector.get_object('member', {'host_name': member.name})

    def restart_all_services(self, member):
        ib_member = self.get_member(member)[0]
        self.connector.call_func('restartservices', ib_member['_ref'],
                                 {'restart_option': 'RESTART_IF_NEEDED',
                                  'service_option': 'ALL'})

    def delete_network(self, net_view_name, cidr):
        payload = {'network_view': net_view_name,
                   'network': cidr}
        self._delete_infoblox_object('network', payload)

    def delete_network_view(self, net_view_name):
        if net_view_name == 'default':
            # never delete default network view
            return

        net_view_data = {'name': net_view_name}
        self._delete_infoblox_object('networkview', net_view_data)

    def delete_dns_view(self, net_view_name):
        net_view_data = {'name': net_view_name}
        self._delete_infoblox_object('view', net_view_data)

    def update_network_options(self, ib_network, extattrs=None):
        payload = {'options': ib_network.options}
        if extattrs:
            payload['extattrs'] = extattrs
        self._update_infoblox_object_by_ref(ib_network.ref, payload)

    def get_network(self, net_view_name, cidr):
        net_data = {'network_view': net_view_name,
                    'network': cidr}
        net = self._get_infoblox_object_or_none(
            'network', net_data, return_fields=['options', 'members'])
        if not net:
            raise exc.InfobloxNetworkNotAvailable(
                net_view_name=net_view_name, cidr=cidr)

        return objects.Network.from_dict(net)

    def bind_name_with_host_record(self, dnsview_name, ip, name):
        record_host = {
            'ipv4addr': ip,
            'view': dnsview_name
        }
        update_kwargs = {'name': name}
        self._update_infoblox_object('record:host', record_host, update_kwargs)

    def bind_name_with_record_a(self, dnsview_name, ip, name):
        # Forward mapping
        payload = {
            'name': name,
            'view': dnsview_name
        }
        additional_create_kwargs = {'ipv4addr': ip}
        self._create_infoblox_object('record:a', payload,
                                     additional_create_kwargs,
                                     check_if_exists=True)

        # Reverse mapping
        record_ptr_data = {
            'ptrdname': name,
            'view': dnsview_name
        }
        additional_create_kwargs = {'ipv4addr': ip}
        self._create_infoblox_object('record:ptr', record_ptr_data,
                                     additional_create_kwargs,
                                     check_if_exists=True)

    def unbind_name_from_record_a(self, dnsview_name, ip, name):
        dns_record_a = {
            'name': name,
            'ipv4addr': ip,
            'view': dnsview_name
        }
        self._delete_infoblox_object('record:a', dns_record_a)

        dns_record_ptr = {
            'ptrdname': name,
            'view': dnsview_name,
        }
        self._delete_infoblox_object('record:ptr', dns_record_ptr)

    def create_dns_zone(self, dns_view, dns_zone_fqdn, primary_dns_member=None,
                        secondary_dns_members=None, zone_format=None,
                        ns_group=None):
        # TODO(mirantis) support IPv6
        dns_zone_data = {'fqdn': dns_zone_fqdn,
                         'view': dns_view}
        additional_create_kwargs = {}
        if primary_dns_member:
            grid_primary = [{'name': primary_dns_member.name,
                             '_struct': 'memberserver'}]
            additional_create_kwargs['grid_primary'] = grid_primary
        if secondary_dns_members:
            grid_secondaries = [{'name': member.name,
                                 '_struct': 'memberserver'}
                                for member in secondary_dns_members]
            additional_create_kwargs['grid_secondaries'] = grid_secondaries
        if zone_format:
            additional_create_kwargs['zone_format'] = zone_format
        if ns_group:
            additional_create_kwargs['ns_group'] = ns_group

        try:
            self._create_infoblox_object(
                'zone_auth', dns_zone_data, additional_create_kwargs,
                check_if_exists=True)
        except exc.InfobloxCannotCreateObject:
            LOG.warning(
                _('Unable to create DNS zone %(dns_zone_fqdn)s '
                  'for %(dns_view)s'),
                {'dns_zone_fqdn': dns_zone_fqdn, 'dns_view': dns_view})

    def delete_dns_zone(self, dns_view, dns_zone_fqdn):
        dns_zone_data = {'fqdn': dns_zone_fqdn,
                         'view': dns_view}
        self._delete_infoblox_object('zone_auth', dns_zone_data)

    def has_networks(self, network_view_name):
        net_data = {'network_view': network_view_name}
        try:
            ib_net = self._get_infoblox_object_or_none('network', net_data)
            return bool(ib_net)
        except exc.InfobloxSearchError:
            return False

    def has_dns_zones(self, dns_view):
        zone_data = {'view': dns_view}
        try:
            zone = self._get_infoblox_object_or_none('zone_auth', zone_data)
            return bool(zone)
        except exc.InfobloxSearchError:
            return False

    def find_hostname(self, dns_view, hostname):
        data = {
            'name': hostname,
            'view': dns_view
        }

        raw_host_record = self._get_infoblox_object_or_none(
            'record:host', data, return_fields=['ipv4addrs'])

        if raw_host_record:
            hr = objects.HostRecordIPv4.from_dict(raw_host_record)

            return hr

    def get_host_record(self, dns_view, ip):
        data = {
            'view': dns_view,
            'ipv4addr': ip
        }

        raw_host_record = self._get_infoblox_object_or_none(
            'record:host', data, return_fields=['ipv4addrs'])

        if raw_host_record:
            hr = objects.HostRecordIPv4.from_dict(raw_host_record)
            return hr

    def _update_host_record_ips(self, host_record):
        ipaddrs = {'ipv4addrs': [ip.to_dict(add_host=False)
                                 for ip in host_record.ips]}
        return self._update_infoblox_object_by_ref(
            host_record.ref, ipaddrs, return_fields=['ipv4addrs'])

    def delete_ip_from_host_record(self, host_record, ip):
        host_record.ips.remove(ip)
        self._update_host_record_ips(host_record)
        return host_record

    def add_ip_to_record(self, host_record, ip, mac):
        host_record.ips.append(objects.IPv4(ip, mac))
        ips = self._update_host_record_ips(host_record)
        hr = objects.HostRecordIPv4.from_dict(ips)
        return hr

    def _create_infoblox_ip_address(self, ip_object):
        try:
            created_ip_json = self._create_infoblox_object(
                ip_object.infoblox_type,
                ip_object.to_dict(),
                check_if_exists=False,
                return_fields=ip_object.return_fields)

            return ip_object.from_dict(created_ip_json)

        except exc.InfobloxCannotCreateObject as e:
            if "Cannot find 1 available IP" in e.response['text']:
                raise exc.InfobloxCannotAllocateIp(ip_data=ip_object.to_dict())
            else:
                raise
        except exc.HostRecordNoIPv4Addrs:
            raise exc.InfobloxHostRecordIpAddrNotCreated(ip=ip_object.ip,
                                                         mac=ip_object.mac)
        except exc.InfobloxInvalidIp:
            raise exc.InfobloxDidNotReturnCreatedIPBack()

    def _create_infoblox_object(self, obj_type, payload,
                                additional_create_kwargs=None,
                                check_if_exists=True,
                                return_fields=None):
        if additional_create_kwargs is None:
            additional_create_kwargs = {}

        ib_object = None
        if check_if_exists:
            ib_object = self._get_infoblox_object_or_none(obj_type, payload)
            if ib_object:
                LOG.info(
                    _("Infoblox %(obj_type)s "
                      "already exists: %(ib_object)s"),
                    {'obj_type': obj_type, 'ib_object': ib_object})

        if not ib_object:
            payload.update(additional_create_kwargs)
            ib_object = self.connector.create_object(obj_type, payload,
                                                     return_fields)
            LOG.info(
                _("Infoblox %(obj_type)s "
                  "was created: %(ib_object)s"),
                {'obj_type': obj_type, 'ib_object': ib_object})

        return ib_object

    def _get_infoblox_object_or_none(self, obj_type, payload,
                                     return_fields=None):
        ib_object = self.connector.get_object(obj_type, payload, return_fields)
        if ib_object:
            if return_fields:
                return ib_object[0]
            else:
                return ib_object[0]['_ref']

        return None

    def _update_infoblox_object(self, obj_type, payload, update_kwargs):
        ib_object_ref = None
        warn_msg = _('Infoblox %(obj_type)s will not be updated because'
                     ' it cannot be found: %(payload)s')
        try:
            ib_object_ref = self._get_infoblox_object_or_none(obj_type,
                                                              payload)
            if not ib_object_ref:
                LOG.warning(warn_msg, {'obj_type': obj_type,
                                       'payload': payload})
        except exc.InfobloxSearchError as e:
            LOG.warning(warn_msg, obj_type, payload)
            LOG.info(e)

        if ib_object_ref:
            self._update_infoblox_object_by_ref(ib_object_ref, update_kwargs)

    def _update_infoblox_object_by_ref(self, ref, update_kwargs,
                                       return_fields=None):
        updated_object = self.connector.update_object(ref, update_kwargs,
                                                      return_fields)
        LOG.info(_('Infoblox object was updated: %s'), ref)
        return updated_object

    def _delete_infoblox_object(self, obj_type, payload):
        ib_object_ref = None
        warn_msg = _('Infoblox %(obj_type)s will not be deleted because'
                     ' it cannot be found: %(payload)s')
        try:
            ib_object_ref = self._get_infoblox_object_or_none(obj_type,
                                                              payload)
            if not ib_object_ref:
                LOG.warning(warn_msg, {'obj_type': obj_type,
                                       'payload': payload})
        except exc.InfobloxSearchError as e:
            LOG.warning(warn_msg, {'obj_type': obj_type,
                                   'payload': payload})
            LOG.info(e)

        if ib_object_ref:
            self.connector.delete_object(ib_object_ref)
            LOG.info(_('Infoblox object was deleted: %s'), ib_object_ref)
