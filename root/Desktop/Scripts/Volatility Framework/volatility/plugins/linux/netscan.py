# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0
@contact:      atcuno@gmail.com
@organization: 
"""
import struct, yara, socket

import volatility.obj as obj
import volatility.utils as utils
import volatility.plugins.linux.common as linux_common
import volatility.plugins.malware.malfind as malfind

class linux_netscan(linux_common.AbstractLinuxCommand):
    """Carves for network connection structures"""

    def check_socket_back_pointer(self, i):
        return i.sk == i.sk.sk_socket.sk or i.sk.sk_socket.v() == 0x0
                
    def check_pointers(self, i):
        ret = self.addr_space.profile.get_symbol_by_address("kernel", i.sk.sk_backlog_rcv.v()) != None

        if ret:
            ret = self.addr_space.profile.get_symbol_by_address("kernel", i.sk.sk_error_report.v()) != None

        return ret
                  
    def check_proto(self, i):
        return i.protocol in ("TCP", "UDP", "IP")

    def check_family(self, i):
        return i.sk.__sk_common.skc_family  in (socket.AF_INET, socket.AF_INET6) #pylint: disable-msg=W0212

    def calculate(self):
        linux_common.set_plugin_members(self)

        ## the start of kernel memory taken from VolatilityLinuxIntelValidAS
        if self.addr_space.profile.metadata.get('memory_model', '32bit') == "32bit":
            kernel_start = 0xc0000000
            pack_size    = 4
            pack_fmt     = "<I"
        else:
            kernel_start = 0xffffffff80000000
            pack_size    = 8
            pack_fmt     = "<Q"
        
        checks = [self.check_family, self.check_proto, self.check_socket_back_pointer, self.check_pointers]

        destruct_offset = self.addr_space.profile.get_obj_offset("sock", "sk_destruct")

        # sk_destruct pointer value of sock
        func_addr = self.addr_space.profile.get_symbol("inet_sock_destruct")

        vals = []

        # convert address into a yara hex rule
        for bit in range(pack_size):
            idx  = (pack_size - bit - 1) * 8
            mask = 0xff << idx        
            val  = ((func_addr & mask) >> idx) & 0xff

            vals.insert(0, val)

        s = "{" + " ".join(["%.02x" % v for v in vals]) + " }"

        rules = yara.compile(sources = { 'n' : 'rule r1 {strings: $a = ' + s + ' condition: $a}' })

        scanner = malfind.DiscontigYaraScanner(rules = rules, address_space = self.addr_space) 
        for _, address in scanner.scan(start_offset = kernel_start):
            base_address = address - destruct_offset 

            i = obj.Object("inet_sock", offset = base_address, vm = self.addr_space)

                
            valid = True
            for check in checks:
                if check(i) == False:
                    valid = False
                    break

            if valid:
                state  = i.state if i.protocol == "TCP" else ""
                family = i.sk.__sk_common.skc_family #pylint: disable-msg=W0212

                sport = i.src_port 
                dport = i.dst_port 
                saddr = i.src_addr
                daddr = i.dst_addr

                yield (i, i.protocol, saddr, sport, daddr, dport, state)

    def render_text(self, outfd, data):
        for (_, proto, saddr, sport, daddr, dport, state) in data:
            outfd.write("{0:8s} {1:<16}:{2:>5} {3:<16}:{4:>5} {5:<15s}\n".format(proto, saddr, sport, daddr, dport, state))

   










