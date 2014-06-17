# Copyright 2014 OpenStack Foundation
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

import os
import random
import socket

from oslo.config import cfg

from neutron.agent.linux import dhcp
from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.common import exceptions as exc
from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils

LOG = logging.getLogger(__name__)

OPTS = [
    cfg.StrOpt('dhcp_relay_ip',
               default=None,
               help=_('IP address of DHCP server to relay to.')),
    cfg.StrOpt('dns_relay_ip',
               default=None,
               help=_('IP address of DNS server to relay to.')),
    cfg.StrOpt('ddi_proxy_bridge',
               default=None,
               help=_('Name of a bridge through which ddi proxy agent will'
                      ' connect to external network in which DHCP and DNS'
                      ' server resides.')),
    cfg.StrOpt('dhclient_path',
               default='dhclient',
               help=_('Path to dhclient executable.')),
    cfg.StrOpt('dhcrelay_path',
               default='dhcrelay',
               help=_('Path to dhcrelay executable.')),
    cfg.BoolOpt('use_link_selection_option',
                default=True,
                help=_('Run dhcrelay with -l flag.'))
]


def _generate_mac_address():
    mac = [0x00, 0x16, 0x3e,
           random.randint(0x00, 0x7f),
           random.randint(0x00, 0xff),
           random.randint(0x00, 0xff)]
    return ':'.join(map(lambda x: "%02x" % x, mac))


class DnsDhcpProxy(dhcp.DhcpLocalProcess):
    """DHCP & DNS relay agent class."""

    MINIMUM_VERSION = 0
    DEV_NAME_LEN = 14
    RELAY_DEV_NAME_PREFIX = 'trel'

    def _calc_dev_name_len(self):
        if self.conf.interface_dev_name_len:
            return self.conf.interface_dev_name_len
        else:
            return self.DEV_NAME_LEN

    def _enable_dns_dhcp(self):
        """check if there is a subnet within the network with dhcp enabled."""
        for subnet in self.network.subnets:
            if subnet.enable_dhcp:
                return True
        return False

    def __init__(self, conf, network, root_helper='sudo',
                 version=None, plugin=None):
        super(DnsDhcpProxy, self).__init__(conf, network, root_helper,
                                           version, plugin)

        if not self.conf.ddi_proxy_bridge:
            LOG.error(_('You must specify an ddi_proxy_bridge option '
                        'in config'))
            raise exc.InvalidConfigurationOption(
                opt_name='ddi_proxy_bridge',
                opt_value=self.conf.ddi_proxy_bridge)

        dhcp_relay_ip = self._get_relay_ip('dhcp_relay_ip')
        if not dhcp_relay_ip:
            LOG.error(_('dhcp_relay_ip must be specified in config or in '
                        'network properties.'))
            raise exc.InvalidConfigurationOption(
                opt_name='dhcp_relay_ip',
                opt_value=dhcp_relay_ip
            )

        dns_relay_ip = self._get_relay_ip('dns_relay_ip')
        if not dns_relay_ip:
            LOG.error(_('dns_relay_ip must be specified in config or in '
                        'network properties.'))
            raise exc.InvalidConfigurationOption(
                opt_name='dns_relay_ip',
                opt_value=dns_relay_ip
            )

        self.dev_name_len = self._calc_dev_name_len()

    @classmethod
    def check_version(cls):
        return 0

    @classmethod
    def existing_dhcp_networks(cls, conf, root_helper):
        """Return a list of existing networks ids that we have configs for."""

        confs_dir = os.path.abspath(os.path.normpath(conf.dhcp_confs))

        return [
            c for c in os.listdir(confs_dir)
            if uuidutils.is_uuid_like(c)
        ]

    def release_lease(self, mac_address, removed_ips):
        """Release a DHCP lease."""
        pass

    def reload_allocations(self):
        """Force the DHCP server to reload the assignment database."""
        pass

    @property
    def dhcp_active(self):
        pid = self.dhcp_pid
        if not pid:
            return False
        return os.path.isdir('/proc/%s/' % pid)

    @property
    def dns_active(self):
        pid = self.dns_pid
        if not pid:
            return False
        return os.path.isdir('/proc/%s/' % pid)

    def enable(self):
        relay_iface_name = self._get_relay_device_name()
        relay_iface_mac_address = _generate_mac_address()
        self.device_manager.setup_relay(
            self.network,
            relay_iface_name,
            relay_iface_mac_address,
            self.conf.ddi_proxy_bridge)

        interface_name = self.device_manager.setup(self.network,
                                                   reuse_existing=True)
        if self.dhcp_active or self.dns_active:
            self.restart()
        elif self._enable_dns_dhcp():
            self.interface_name = interface_name
            self.spawn_process()

    def disable(self, retain_port=False):
        def kill_proc(pid):
            cmd = ['kill', '-9', pid]
            utils.execute(cmd, self.root_helper)

        if self.dhcp_active:
            kill_proc(self.dhcp_pid)
        elif self.dhcp_pid:
            LOG.debug(_('dhcrelay for %(net_id)s, dhcp_pid %(dhcp_pid)d, '
                        'is stale, ignoring command'),
                      {'net_id': self.network.id,
                       'dhcp_pid': self.dhcp_pid}
                      )
        else:
            LOG.debug(_('No dhcrelay started for %s'), self.network.id)

        if self.dns_active:
            kill_proc(self.dns_pid)
        elif self.dns_pid:
            LOG.debug(_('dnsmasq for %(net_id)s, dhcp_pid %(dns_pid)d, is'
                        ' stale, ignoring command'),
                      {'net_id': self.network.id,
                       'dns_pid': self.dns_pid}
                      )
        else:
            LOG.debug(_('No dnsmasq started for %s'), self.network.id)

        if not retain_port:
            self.device_manager.destroy(self.network, self.interface_name)
            self.device_manager.destroy_relay(
                self.network,
                self._get_relay_device_name(),
                self.conf.ddi_proxy_bridge)
        self._remove_config_files()

    def spawn_process(self):
        """Spawns a DDI proxy processes for the network."""
        self._spawn_dhcp_proxy()
        self._spawn_dns_proxy()

    @property
    def dhcp_pid(self):
        """Last known pid for the dhcrelay process spawned for this network."""
        return self._get_value_from_conf_file('dhcp_pid', int)

    @dhcp_pid.setter
    def dhcp_pid(self, value):
        dhcp_pid_file_path = self.get_conf_file_name('dhcp_pid',
                                                     ensure_conf_dir=True)
        utils.replace_file(dhcp_pid_file_path, value)

    @property
    def dns_pid(self):
        """Last known pid for the dnsmasq process spawned for this network."""
        return self._get_value_from_conf_file('dns_pid', int)

    def _spawn_dhcp_proxy(self):
        """Spawns a dhcrelay process for the network."""
        relay_ip = self._get_relay_ip('dhcp_relay_ip')

        if not relay_ip:
            LOG.error(_('DHCP relay server isn\'t defined for network %s'),
                      self.network.id)
            return

        cmd = [
            self.conf.dhcrelay_path,
            '-a',
            '-i',
            self.interface_name,
        ]

        if self.conf.use_link_selection_option:
            cmd.append('-l')
            cmd.append(self._get_relay_device_name())

        cmd.append(relay_ip)

        if self.network.namespace:
            ip_wrapper = ip_lib.IPWrapper(self.root_helper,
                                          self.network.namespace)
            ip_wrapper.netns.execute(cmd)
        else:
            utils.execute(cmd, self.root_helper)

        self._save_process_pid()

    def _spawn_dns_proxy(self):
        """Spawns a Dnsmasq process in DNS relay only mode for the network."""
        relay_ip = self._get_relay_ip('dns_relay_ip')

        if not relay_ip:
            LOG.error(_('DNS relay server isn\'t defined for network %s'),
                      self.network.id)
            return

        cmd = [
            'dnsmasq',
            '--no-hosts',
            '--no-resolv',
            '--strict-order',
            '--bind-interfaces',
            '--interface=%s' % self.interface_name,
            '--except-interface=lo',
            '--server=%s' % relay_ip,
            '--pid-file=%s' % self.get_conf_file_name(
                'dns_pid', ensure_conf_dir=True),
        ]

        if self.network.namespace:
            ip_wrapper = ip_lib.IPWrapper(self.root_helper,
                                          self.network.namespace)
            ip_wrapper.netns.execute(cmd)
        else:
            utils.execute(cmd, self.root_helper)

    def _save_process_pid(self):
        pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]

        for pid in pids:
            try:
                cmdline = open(os.path.join('/proc', pid, 'cmdline'),
                               'rb').read()
                if ((self.interface_name in cmdline) and
                        ('dhcrelay' in cmdline)):
                    self.dhcp_pid = pid
                    break
            except IOError:
                continue

    def _get_relay_device_name(self):
        return (self.RELAY_DEV_NAME_PREFIX +
                self.network.id)[:self.dev_name_len]

    def _get_relay_ip(self, ip_opt_name):
        # Try to get relay IP from the config.
        relay_ip = getattr(self.conf, ip_opt_name, None)
        # If not specified in config try to get from network object.
        if not relay_ip:
            relay_ip = getattr(self.network, ip_opt_name, None)

        if not relay_ip:
            return None

        try:
            socket.inet_aton(relay_ip)
        except socket.error:
            LOG.error(_('An invalid option value has been provided:'
                        ' %(opt_name)s=%(opt_value)s') %
                      dict(opt_name=ip_opt_name, opt_value=relay_ip))
            return None

        return relay_ip
