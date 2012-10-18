#!/usr/bin/python
#
# Email: Hagen Paul Pfeifer <hagen@jauu.net>
# URL: http://research.protocollabs.com

from __future__ import print_function

import sys
import os
import logging
import optparse
import dpkt
import pcap
import socket
import struct
import inspect
import math
import pprint
import time
import datetime
import subprocess
import select
import re
import wave

# optional packages
try:
    import GeoIP
except ImportError:
    GeoIP = None

try:
    import cairo
except ImportError:
    cairo = None

try:
    import numpy
except ImportError:
    cairo = None

pp = pprint.PrettyPrinter(indent=4)

# required debian packages:
#   python-dpkt
#   python-pypcap 

# optional debian packages:
#   python-geoip
#   python-cairo
#   python-numpy


__programm__ = "captcp"
__author__   = "Hagen Paul Pfeifer"
__version__  = "0.6"
__license__  = "GPLv3"

# custom exceptions
class ArgumentException(Exception): pass
class InternalSequenceException(Exception): pass
class InternalException(Exception): pass
class SequenceContainerException(InternalException): pass
class NotImplementedException(InternalException): pass
class SkipProcessStepException(Exception): pass
class PacketNotSupportedException(Exception): pass


# TCP flag constants
TH_URG = dpkt.tcp.TH_URG
TH_ACK = dpkt.tcp.TH_ACK
TH_PSH = dpkt.tcp.TH_PUSH
TH_RST = dpkt.tcp.TH_RST
TH_SYN = dpkt.tcp.TH_SYN
TH_FIN = dpkt.tcp.TH_FIN
TH_ECE = dpkt.tcp.TH_ECE
TH_CWR = dpkt.tcp.TH_CWR
# "Robust Explicit Congestion Notification (ECN)
# Signaling with Nonces" (RFC 3540) specifies an
# additional ECN Flag: NS which is out of the 8 bit
# flags section, shared with header length field. I
# emailed Jon Oberheide to get some valuable solutions.
#
# See http://tools.ietf.org/html/rfc3540#section-9

# Protocols
TCP = dpkt.tcp.TCP
UDP = dpkt.udp.UDP

# Units (bit):
# kilobit (kbit) 10^3 - kibibit (Kibit) 2^10
# megabit (Mbit) 10^6 - mebibit (Mibit) 2^20
# gigabit (Gbit) 10^9 - gibibit (Gibit) 2^30
#
# Units (byte):
# kilobyte (kB) 10^3 - kibibyte (KiB) 2^10
# megabyte (MB) 10^6 - mebibyte (MiB) 2^20
# gigabyte (GB) 10^9 - gibibyte (GiB) 2^30


class ExitCodes:
    EXIT_SUCCESS  = 0
    EXIT_ERROR    = 1
    EXIT_CMD_LINE = 2


class SequenceContainer:

    class Container: pass

    def __init__(self):
        self.sequnce_list = list()

    def __len__(self):
        return len(self.sequnce_list)

    def print_list(self):
        for i in self.sequnce_list:
            sys.stdout.write(str(i.left_edge) + "-" +
                    str(i.right_edge) + "\n" )

    # is there an other way in python to do some
    # unsigned arithmetic? Not sure but numpy seems adequate
    import numpy

    def before(self, seq1, seq2):
        s1 = numpy.array(seq1, dtype=numpy.np.dtype('uint32'))
        s2 = numpy.array(seq2, dtype=numpy.np.dtype('uint32'))
        res = numpy.array((s1 - s2), dtype=numpy.np.dtype('int32'))
        if res < 0:
            return True
        else:
            return False

    def after(self,  seq1, seq2):
        return self.before(seq2, seq1)

    # is s2 <= s1 <= s3
    def between(self, seq1, seq2, seq3):
        s1 = numpy.array(seq1, dtype=numpy.np.dtype('uint32'))
        s2 = numpy.array(seq2, dtype=numpy.np.dtype('uint32'))
        s3 = numpy.array(seq3, dtype=numpy.np.dtype('uint32'))

        if s3 - s2 >= s1 - s2:
            return True
        else:
            return False

    def add_sequence(self, array):
        if len(array) != 2:
            raise ArgumentException("array must contain excatly 2 members")

        new = SequenceContainer.Container()
        new.left_edge  = array[0]
        new.right_edge = array[1]

        if len(self.sequnce_list) <= 0:
            self.sequnce_list.append(new)
            return

        # if new element is the direct neighbour we merge
        if new.left_edge == self.sequnce_list[-1].right_edge + 1:
            self.sequnce_list[-1].right_edge = new.right_edge
            del new
            return

        # if new element is far right we add it instantly
        if self.sequnce_list[-1].right_edge < new.left_edge + 1:
            self.sequnce_list.append(new)
            return

        # check
        if not new.left_edge <= self.sequnce_list[-1].right_edge:
            raise SequenceContainerException("internal error")

        reverse_enumerate = lambda l: \
                itertools.izip(xrange(len(l)-1, -1, -1), reversed(l))
        it = reverse_enumerate(self.sequnce_list)

        # ok, the new packet is within the packets
        while True:
            try:
                (i, old) = it.next()
                # match the segment exactply?
                if (old.left_edge - 1 == new.right_edge and
                        self.sequnce_list[i - 1].right_edge + 1 == new.left_edge):
                    self.sequnce_list.remove(old)
                    self.sequnce_list[i - 1].right_edge = old.right_edge
                    return

                # check if the new packet match between a gap
                if (old.left_edge > new.right_edge and
                        self.sequnce_list[i - 1].right_edge < new.left_edge):
                    self.sequnce_list.insert(i, new)
                    return

                # can we merge one one side at least? (one end close, one new gap)
                if old.left_edge - 1 == new.right_edge:
                    if len(self.sequnce_list) <= 1:
                        old.left_edge = new.left_edge
                        del new
                        return
                    elif self.sequnce_list[i - 1].right_edge < new.left_edge:
                        old.left_edge = new.left_edge
                        del new
                        return
            except:
                break


class U:
    """ Utility module, to collect usefull functionality
    needed by several other classes. We name it U to make it short
    and non bloated"""
    
    @staticmethod
    def byte_to_unit(byte, unit):

        byte = float(byte)

        if unit == "byte" or unit == "Byte":
            return byte
        if unit == "bit" or unit == "Bit":
            return byte * 8

        if unit == "kB" or unit == "kilobyte":
            return byte / 1000
        if unit == "MB" or unit == "megabyte":
            return byte / (1000 * 1000)
        if unit == "GB" or unit == "gigabyte":
            return byte / (1000 * 1000 * 1000)

        if unit == "KiB" or unit == "kibibyte":
            return byte / 1024
        if unit == "MiB" or unit == "mebibyte":
            return byte / (1024 * 1024)
        if unit == "GiB" or unit == "gibibyte":
            return byte / (1024 * 1024 * 1024)


        if unit == "kbit" or unit == "kilobit":
            return byte * 8 / 1000
        if unit == "Mbit" or unit == "megabit":
            return byte * 8 / (1000 * 1000)
        if unit == "Gbit" or unit == "gigabit":
            return byte * 8 / (1000 * 1000 * 1000)

        if unit == "KiBit" or unit == "kibibit":
            return byte * 8 / 1024
        if unit == "MiBit" or unit == "mebibit":
            return byte * 8 / (1024 * 1024)
        if unit == "GiBit" or unit == "gibibit":
            return byte * 8 / (1024 * 1024 * 1024)

        raise ArgumentException("unit %s not known" % (unit))


    @staticmethod
    def best_match(byte):
        last_unit = "bit"
        last_val  = float(byte) * 8
        units = ("kbit", "Mbit", "Gbit")
        for unit in units:
            val = U.byte_to_unit(byte, unit)
            if val < 1.0:
                return "%.2f %s" % (last_val, last_unit)
            last_unit = unit
            last_val  = val

        return "%.2f %s" % (U.byte_to_unit(byte, "Gbit"), "Gbit")

    @staticmethod
    def percent(a, b):
        if b == 0: return 0.0
        return float(a) / b * 100



class RainbowColor:

    ANSI    = 0
    ANSI256 = 1
    HEX     = 2
    DISABLE = 3

    def __init__(self, mode=ANSI256):
        if mode == RainbowColor.ANSI:
            self.init_color_ansi()
        elif mode == RainbowColor.ANSI256:
            self.init_color_ansi256()
        elif mode == RainbowColor.HEX:
            self.init_color_hex()
        elif mode == RainbowColor.DISABLE:
            self.init_color_none()
        else:
            raise Exception()

        # this color should not be printed
        self.skip_list = ['red', 'end']

    def __getitem__(self, key):
        return self.color_palette[key]

    def init_color_none(self):
        self.color_palette = {'red':'', 'green':'', 'end':'' }

    def init_color_hex(self):
        self.color_palette = {'red':'#ff0000', 'green':'#00ff00', 'end':''}

    def init_color_ansi256(self):
        self.color_palette = dict()
        for i in range(255):
            self.color_palette[i + 1] = '\033[38;5;%dm' % (i + 1)

        self.color_palette['end'] = '\033[0m'
        self.color_palette['red'] = '\033[91m'

        del self.color_palette[1]
        del self.color_palette[9]
        del self.color_palette[52]
        del self.color_palette[88]
        del self.color_palette[89]

        del self.color_palette[124]
        del self.color_palette[125]
        del self.color_palette[126]
        del self.color_palette[127]

        del self.color_palette[160]
        del self.color_palette[161]
        del self.color_palette[162]
        del self.color_palette[163]

        del self.color_palette[196]
        del self.color_palette[197]
        del self.color_palette[198]
        del self.color_palette[199]
        del self.color_palette[200]

    def init_color_ansi(self):
        self.color_palette = { 'yellow':'\033[0;33;40m', 'foo':'\033[93m',
                'red':'\033[91m', 'green':'\033[92m', 'blue':'\033[94m', 'end':'\033[0m'}

    def next(self):
        if self.color_palette_pos >= len(self.color_palette_flat):
            raise StopIteration

        retdata = self.color_palette_flat[self.color_palette_pos]
        self.color_palette_pos  += 1

        return retdata

    def infinite_next(self):
        while True:
            found = True
            retdata = self.color_palette_flat[self.color_palette_pos % \
                    (len(self.color_palette_flat))]
            self.color_palette_pos  += 1

            for i in self.skip_list:
                if i in self.color_palette and self.color_palette[i] == retdata:
                    found = False
                    break

            if found:
                return retdata

    def __iter__(self):
        self.color_palette_pos = 0
        self.color_palette_flat = self.color_palette.values()
        return self


class Utils:

    @staticmethod
    def ts_tofloat(ts):
        return float(ts.seconds) + ts.microseconds / 1E6 + ts.days * 86400



class Converter:

    def dotted_quad_num(ip):
        "convert decimal dotted quad string to long integer"
        return struct.unpack('I', socket.inet_aton(ip))[0]
    dotted_quad_num = staticmethod(dotted_quad_num)


    def num_to_dotted_quad(n):
        "convert long int to dotted quad string"
        return socket.inet_ntoa(struct.pack('I', n))
    num_to_dotted_quad = staticmethod(num_to_dotted_quad)

    def make_mask(n):
        "return a mask of n bits as a long integer"
        return (1L << n)-1

    make_mask = staticmethod(make_mask)


    def dpkt_addr_to_string(addr):
        iaddr = int(struct.unpack('I', addr)[0])
        return Converter.num_to_dotted_quad(iaddr)

    dpkt_addr_to_string  = staticmethod(dpkt_addr_to_string)


    def ip_to_net_host(ip, maskbits):
        "returns tuple (network, host) dotted-quad addresses given IP and mask size"

        n = Converter.dotted_quad_num(ip)
        m = Converter.makeMask(maskbits)

        host = n & m
        net = n - host

        return Converter.num_to_dotted_quad(net), Converter.num_to_dotted_quad(host)

    ip_to_net_host = staticmethod(ip_to_net_host)



class PcapParser:

    def __init__(self, pcap_file_path, pcap_filter):
        self.logger = logging.getLogger()
        self.pcap_file = False

        try:
            self.pcap_file = open(pcap_file_path)
        except IOError:
            self.logger.error("Cannot open pcap file: %s" % (pcap_file_path))
            sys.exit(ExitCodes.EXIT_ERROR)
        self.pc = dpkt.pcap.Reader(self.pcap_file)
        self.decode = { pcap.DLT_LOOP:dpkt.loopback.Loopback,
                        pcap.DLT_NULL:dpkt.loopback.Loopback,
                        pcap.DLT_EN10MB:dpkt.ethernet.Ethernet } [self.pc.datalink()]

        if pcap_filter:
            self.pc.setfilter(pcap_filter)


    def __del__(self):
        if self.pcap_file:
            self.pcap_file.close()


    def register_callback(self, callback):
        self.callback = callback


    def run(self):
        try:
            for ts, pkt in self.pc:
                packet = self.decode(pkt)
                dt = datetime.datetime.fromtimestamp(ts)
                self.callback(dt, packet.data)
        except SkipProcessStepException:
            self.logger.debug("skip processing step")


class PacketInfo:

    class TcpOptions:
        def __init__(self):
            self.data = dict()
        def __getitem__(self, key):
            return self.data[key]
        def __setitem__(self, key, val):
            self.data[key] = val


    def __init__(self, packet):
        self.tcp = packet.data

        if type(self.tcp) != TCP:
            raise InternalException("Only TCP packets are allowed")

        if type(packet) == dpkt.ip.IP:
            self.sip = Converter.dpkt_addr_to_string(packet.src)
            self.dip = Converter.dpkt_addr_to_string(packet.dst)
            self.ipversion = "IP "
        elif type(packet) == dpkt.ip6.IP6:
            self.sip = socket.inet_ntop(socket.AF_INET6, packet.src)
            self.dip = socket.inet_ntop(socket.AF_INET6, packet.dst)
            self.ipversion = "IP6"
        else:
            raise InternalException("unknown protocol")
 
        self.sport = int(self.tcp.sport)
        self.dport = int(self.tcp.dport)

        self.seq = int(self.tcp.seq)
        self.ack = int(self.tcp.ack)
        self.win = int(self.tcp.win)
        self.urp = int(self.tcp.urp)
        self.sum = int(self.tcp.sum)

        self.parse_tcp_options()

    def is_ack_flag(self):
        return self.tcp.flags & TH_ACK

    def is_syn_flag(self):
        return self.tcp.flags & TH_SYN

    def is_urg_flag(self):
        return self.tcp.flags & TH_URG

    def is_psh_flag(self):
        return self.tcp.flags & TH_PSH

    def is_fin_flag(self):
        return self.tcp.flags & TH_FIN

    def is_rst_flag(self):
        return self.tcp.flags & TH_RST

    def is_ece_flag(self):
        return self.tcp.flags & TH_ECE

    def is_cwr_flag(self):
        return self.tcp.flags & TH_CWR

    def create_flag_brakets(self):
        s = "["
        if self.is_cwr_flag():
            s += "C"
        if self.is_ece_flag():
            s += "E"
        if self.is_urg_flag():
            s += "U"
        if self.is_ack_flag():
            s += "A"
        if self.is_psh_flag():
            s += "P"
        if self.is_rst_flag():
            s += "R"
        if self.is_syn_flag():
            s += "S"
        if self.is_fin_flag():
            s += "F"
        s += "]"

        return s

    def construct_tcp_options_label(self):

        ret = ""
        if self.options['mss']:
            ret += "mss: %d" % (self.options['mss'])
        if self.options['wsc']:
            ret += "wsc: %d" % (self.options['wsc'])
        if self.options['tsval'] and self.options['tsecr']:
            ret += "ts: %d:%d" % (self.options['tsval'], self.options['tsecr'])
        if self.options['sackok']:
            ret += "sackok"

    def linear_sackblocks_array(self, liste):
        retlist = list()
        i = len(liste) / 2
        while i > 0:
            r = list()
            r.append(liste.pop(-1))
            r.append(liste.pop(-1))
            retlist.append(r)
            i -= 1

        return retlist


    def parse_tcp_options(self):

        self.options = PacketInfo.TcpOptions()
        self.options['mss'] = False
        self.options['wsc'] = False
        self.options['tsval'] = False
        self.options['tsecr'] = False
        self.options['sackok'] = False
        self.options['sackblocks'] = False

        opts = []
        for opt in dpkt.tcp.parse_opts(self.tcp.opts):
            try:
                o, d = opt
                if len(d) > 32: raise TypeError
            except TypeError:
                break
            if o == dpkt.tcp.TCP_OPT_MSS:
                self.options['mss'] = struct.unpack('>H', d)[0]
            elif o == dpkt.tcp.TCP_OPT_WSCALE:
                self.options['wsc'] = ord(d)
            elif o == dpkt.tcp.TCP_OPT_SACKOK:
                self.options['sackok'] = True
            elif o == dpkt.tcp.TCP_OPT_SACK:
                ofmt="!%sI" % int(len(d) / 4)
                self.options['sackblocks'] = self.linear_sackblocks_array(list(struct.unpack(ofmt, d)))
            elif o == dpkt.tcp.TCP_OPT_TIMESTAMP:
                (self.options['tsval'], self.options['tsecr']) = struct.unpack('>II', d)

            opts.append(o)



class Geoip:

    def __init__(self, captcp):
        self.captcp = captcp
        self.parse_local_options()


    def parse_local_options(self):
        parser = optparse.OptionParser()
        parser.usage = "geoip"
        parser.add_option( "-v", "--verbose", dest="verbose", default=False,
                action="store_true", help="show verbose")

        self.opts, args = parser.parse_args(sys.argv[0:])
        self.set_opts_logevel()
        
        if len(args) < 3:
            sys.stderr.write("no IP address argument given, exiting\n")
            sys.exit(ExitCodes.EXIT_CMD_LINE)
 
        if not self.opts.verbose:
            sys.stderr = open(os.devnull, 'w')
        
        self.captcp.print_welcome()

        self.ip_address = args[2]
        sys.stderr.write("# ip address: \"%s\"\n" % self.ip_address)

    def run(self):

        if not GeoIP:
            sys.stdout.write("GeoIP package not installed on system, exiting")
            sys.exit(ExitCodes.EXIT_CMD_LINE)

        gi = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)
        
        sys.stdout.write("Country Code: " + gi.country_code_by_addr(self.ip_address) + "\n")



class CaptureLevel:

    LINK_LAYER      = 0
    NETWORK_LAYER   = 1
    TRANSPORT_LAYER = 2

class Mod:

    def register_captcp(self, captcp):
        self.captcp = captcp

    def __init__(self):
        self.captcp = None
        self.cc = ConnectionContainer()
        self.capture_level = CaptureLevel.NETWORK_LAYER

    def internal_pre_process_packet(self, ts, packet):
        """ this is a hidden preprocessing function, called for every packet"""
        assert(self.captcp != None)
        self.cc.update(ts, packet)
        self.pre_process_packet(ts, packet)

    def pre_initialize(self):
        """ called at the very beginning of module lifetime"""
        pass

    def pre_process_packet(self, ts, packet):
        """ final packet round"""
        # We simple cannot skip this processing step because it
        # is internally required for accounting. The worst case
        # scenario imagineable where pre_process_packet() is skipped
        # and later in process_packet the connection is required - which
        # in turn was never initialized. So we always pre_process_packet
        # here.
        # There ARE solutions to optimize this case - sure. But I skipped
        # this because I never run into performance problems.
        pass

    def pre_process_final(self):
        """ single call between pre_process_packet and process_packet to do some calc"""
        pass


    def process_packet(self, ts, packet):
        """ final packet round"""
        raise SkipProcessStepException()

    def process_final(self):
        """ called at the end of packet processing"""
        pass

    def set_opts_logevel(self):

        if not self.opts:
            raise InternalException("Cannot call set_opts_logevel() if no " +
                    "options parsing was done")

        if not self.opts.loglevel:
            """ this is legitim: no loglevel specified"""
            return

        if self.opts.loglevel == "debug":
            self.logger.setLevel(logging.DEBUG)
        elif self.opts.loglevel == "info":
            self.logger.setLevel(logging.INFO)
        elif self.opts.loglevel == "warning":
            self.logger.setLevel(logging.WARNING)
        elif self.opts.loglevel == "error":
            self.logger.setLevel(logging.ERROR)
        else:
            raise ArgumentException("loglevel \"%s\" not supported" % self.opts.loglevel)



class PayloadTimePortMod(Mod):

    PORT_START = 0
    PORT_END   = 65535
    DEFAULT_VAL = 0.0

    def pre_initialize(self):
        self.logger = logging.getLogger()
        self.parse_local_options()

        self.data = dict()
        self.trace_start = None


    def parse_local_options(self):
        parser = optparse.OptionParser()
        parser.add_option( "-v", "--verbose", dest="loglevel", default=None,
                type="string", help="set the loglevel (info, debug, warning, error)")
        parser.add_option( "-f", "--format", dest="format", default="3ddata",
                type="string", help="the data format for gnuplot")
        parser.add_option( "-p", "--port", dest="port", default="sport",
                type="string", help="sport or dport")
        parser.add_option( "-s", "--sampling", dest="sampling", default=50,
                type="int", help="sampling rate (default: 5 seconds)")
        parser.add_option( "-o", "--outfile", dest="outfile", default="payload-time-port.data",
                type="string", help="name of the output file (default: payload-time-port.data)")

        self.opts, args = parser.parse_args(sys.argv[0:])
        self.set_opts_logevel()
        
        if len(args) < 3:
            sys.stderr.write("no pcap file argument given, exiting\n")
            sys.exit(ExitCodes.EXIT_CMD_LINE)
 
        self.captcp.print_welcome()
        self.captcp.pcap_file_path = args[2]
        self.logger.info("pcap file: %s" % (self.captcp.pcap_file_path))


    def process_packet(self, ts, packet):
        ip = packet
        tcp = packet.data

        if type(tcp) != TCP:
            return

        time = Utils.ts_tofloat(ts - self.cc.capture_time_start)

        if self.trace_start == None:
            self.trace_start = time
            self.time_offset = time
            self.next_sampling_boundary = time + float(self.opts.sampling)

        if time > self.next_sampling_boundary:
            self.next_sampling_boundary = time + float(self.opts.sampling)


        if self.next_sampling_boundary - self.time_offset not in self.data:
            self.data[self.next_sampling_boundary - self.time_offset] = dict()

        dport  = int(tcp.dport)
        sport  = int(tcp.sport)

        if dport not in self.data[self.next_sampling_boundary - self.time_offset]:
            self.data[self.next_sampling_boundary - self.time_offset][dport] = dict()
            self.data[self.next_sampling_boundary - self.time_offset][dport]["cnt"] = 0
            self.data[self.next_sampling_boundary - self.time_offset][dport]["sum"] = 0

        self.data[self.next_sampling_boundary - self.time_offset][dport]["sum"] += len(packet)
        self.data[self.next_sampling_boundary - self.time_offset][dport]["cnt"] += 1

        if sport not in self.data[self.next_sampling_boundary - self.time_offset]:
            self.data[self.next_sampling_boundary - self.time_offset][sport] = dict()
            self.data[self.next_sampling_boundary - self.time_offset][sport]["cnt"] = 0
            self.data[self.next_sampling_boundary - self.time_offset][sport]["sum"] = 0

        self.data[self.next_sampling_boundary - self.time_offset][sport]["sum"] += len(packet)
        self.data[self.next_sampling_boundary - self.time_offset][sport]["cnt"] += 1
 

    def print_data(self):
        for timesortedtupel in sorted(self.data.iteritems(), key = lambda (k,v): float(k)):
            time = timesortedtupel[0]
            
            for port in range(PayloadTimePortMod.PORT_END + 1):

                if port in timesortedtupel[1]:
                    avg = float(timesortedtupel[1][port]["sum"]) / float(timesortedtupel[1][port]["cnt"])
                    sys.stdout.write(str(time) + " " + str(port) + " " + str(avg) + "\n")
                else:
                    pass
                    sys.stdout.write(str(time) + " " + str(port) + " " + str(PayloadTimePortMod.DEFAULT_VAL) + "\n")

            sys.stdout.write("\n")


    def process_final(self):
        self.print_data()





class TemplateMod(Mod):

    class TemplateContainer: pass

    TYPE_MAKEFILE = 1
    TYPE_GNUPLOT  = 2


    def __init__(self):
        self.logger = logging.getLogger()
        self.init_db()


    def pre_initialize(self):
        self.parse_local_options()


    def get_content_by_name(self, name):
        pathname = False

        for i in self.db:
            if i.name == name:
                pathname = i.full_path
                break

        if not pathname:
            self.logger.error("template %s not valid" % name)
            return

        fd = open(pathname, 'r')
        data = fd.read()
        fd.close()

        return data


    def init_db(self):
        self.logger.debug("initialize local template database")
        path = "%s/data/templates/" % (os.path.dirname(os.path.realpath(__file__)))
        self.db = []

        listing = os.listdir(path)
        for files in listing:
            m = re.match(r"(.*)\.(\w+)", files)
            if not m.group(0) and not m.group(1):
                self.logger.error("strange files show up in %s!" % (path))
                continue

            tc = TemplateMod.TemplateContainer()
            tc.full_path = "%s%s" % (path, files)

            if m.group(2) == "gpi":
                tc.type = TemplateMod.TYPE_GNUPLOT
                tc.name = m.group(1)
            elif m.group(2) == "make":
                tc.type = TemplateMod.TYPE_MAKEFILE
                tc.name = m.group(1)
            else:
                # catch unknown file formats (e.g. *.m - matlab files)
                tc.type = str()
                tc.name = str()

            self.db.append(tc)


    def print_available_templates(self):
        gpi = list(); mak = list()

        for i in self.db:
            if i.type == TemplateMod.TYPE_MAKEFILE:
                mak.append(i)
            elif i.type == TemplateMod.TYPE_GNUPLOT:
                gpi.append(i)
            else:
                raise InternalException("programmed error")

        sys.stdout.write("\nmakefile templates:\n")
        for i in mak:
            sys.stdout.write("\t%s\n" % (i.name))

        sys.stdout.write("\ngnuplot templates:\n")
        for i in gpi:
            sys.stdout.write("\t%s\n" % (i.name))


    def parse_local_options(self):

        self.width = self.height = 0

        parser = optparse.OptionParser()
        parser.usage = "%prog template [options] <templatename>"

        parser.add_option( "-v", "--loglevel", dest="loglevel", default=None,
                type="string", help="set the loglevel (info, debug, warning, error)")

        parser.add_option( "-o", "--output-dir", dest="outputdir", default=None,
                type="string", help="specify the output directory")

        parser.add_option( "-l", "--list", dest="list",  default=False,
                action="store_true", help="list all available templates")

        self.opts, args = parser.parse_args(sys.argv[0:])
        self.set_opts_logevel()
        
        if len(args) < 3:
            self.logger.error("no template name given, please pick on of the following")
            self.print_available_templates()
            sys.exit(ExitCodes.EXIT_CMD_LINE)

        self.captcp.print_welcome()

        self.template_name = args[2]
        self.logger.info("template_name: %s" % (self.template_name))


    def process_final(self):

        c = self.get_content_by_name(self.template_name)
        if not c:
            self.logger.error("not a valid template name %s" % (self.template_name))
            return

        sys.stdout.write(c)



class StackTraceMod(Mod):

    DEFAULT_FILTER = '*.*.*.*:*-*.*.*.*:5001'

    def pre_initialize(self):

        self.logger = logging.getLogger()

        self.parse_local_options()

        sys.stderr.write("# 1. Make sure you have a working systemtap environment\n")
        sys.stderr.write("# 2. Make sure sudo systemtap ... is working without password (or run as root)\n")
        sys.stderr.write("# 2. CTRL-C to interrupt data collecting\n")


    def create_gnuplot_environment(self):

        gnuplot_filename = "cwnd.gpi"
        makefile_filename = "Makefile"

        filepath = "%s/%s" % (self.opts.outputdir, gnuplot_filename)
        fd = open(filepath, 'w')
        fd.write("%s" % (Template.cwnd))
        fd.close()

        filepath = "%s/%s" % (self.opts.outputdir, makefile_filename)
        fd = open(filepath, 'w')
        fd.write("%s" % (Template.gnuplot_makefile))
        fd.close()


    def check_options(self):

        if not self.opts.outputdir:
            self.logger.error("No output directory specified: --output-dir")
            sys.exit(ExitCodes.EXIT_CMD_LINE)

        if not os.path.exists(self.opts.outputdir):
            self.logger.error("Not a valid directory: \"%s\"" %
                    (self.opts.outputdir))
            sys.exit(ExitCodes.EXIT_CMD_LINE)


    def create_data_files(self):

        self.stap_raw_filepath      = "%s/%s" % (self.opts.outputdir, "stap-raw.data")
        self.stap_raw_file = open(self.stap_raw_filepath, 'w')


    def close_data_files(self):
        self.stap_raw_file.close()


    def parse_local_options(self):

        self.width = self.height = 0

        parser = optparse.OptionParser()
        parser.usage = "%prog timesequence [options] <pcapfile>"

        parser.add_option( "-v", "--loglevel", dest="loglevel", default=None,
                type="string", help="set the loglevel (info, debug, warning, error)")

        parser.add_option( "-o", "--output-dir", dest="outputdir", default=None,
                type="string", help="specify the output directory")

        parser.add_option( "-f", "--filter", dest="filter", default=StackTraceMod.DEFAULT_FILTER,
                type="string", help="specify filter localIP:localPort-remoteIP:remotePort, " +
                "(default: '*.*.*.*:*-*.*.*.*:5001')")

        parser.add_option( "-i", "--init", dest="init",  default=False,
                action="store_true", help="create Gnuplot template and Makefile in output-dir")

        self.opts, args = parser.parse_args(sys.argv[0:])
        self.set_opts_logevel()
        
        self.captcp.print_welcome()

        self.check_options()

        if self.opts.init:
            self.create_gnuplot_environment()

        self.create_data_files()


    def process_final(self):

        stap_script = "%s/data/stap-scripts/tcp-trace.stp" % \
                (os.path.dirname(os.path.realpath(__file__)))

        cmd = []
        if os.geteuid() != 0:
            self.logger.info("execute script via sudo")
            cmd += ["sudo"]

        cmd += ["/usr/bin/stap", stap_script, "filter=all", "update=all", self.opts.filter]
        self.logger.debug("cmd: %s" % (cmd))

        sys.stderr.write("# compile and load kernel module, this may take some time ...\n")

        tsk = subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE)

        poll = select.poll()
        poll.register(tsk.stdout,select.POLLIN | select.POLLHUP)
        poll.register(tsk.stderr,select.POLLIN | select.POLLHUP)
        pollc = 2

        events = poll.poll()
        try:
            while pollc > 0 and len(events) > 0:
                for event in events:
                    (rfd,event) = event
                    if event & select.POLLIN:
                         if rfd == tsk.stdout.fileno():
                              line = tsk.stdout.readline()
                              if len(line) > 0:
                                  sys.stdout.write(line)
                                  sys.stdout.flush()
                                  self.stap_raw_file.write(line)
                                  self.stap_raw_file.flush
                         if rfd == tsk.stderr.fileno():
                             line = tsk.stderr.readline()
                             if len(line) > 0:
                                 sys.stderr.write("stap: %s" % line)
                    if event & select.POLLHUP:
                        poll.unregister(rfd)
                        pollc = pollc - 1
                    if pollc > 0: events = poll.poll()
            tsk.wait()
        except KeyboardInterrupt:
            sys.stderr.write("SIGINT received, flush data files and exit\n")

        self.close_data_files()
        sys.stderr.write("# now execute \"make\" in %s\n" % (self.opts.outputdir))



class TimeSequenceMod(Mod):

    class Sequence: pass

    def pre_initialize(self):
        self.logger = logging.getLogger()

        self.ids                   = None
        self.timeframe_start       = self.timeframe_end = None
        self.reference_time        = False
        self.highest_seq           = -1
        self.wscale_receiver       = 1
        self.wscale_sender_support = False

        self.parse_local_options()

        sys.stderr.write("# ADVICE: capture the data at sender side!\n")


    def create_files(self):
        self.data_flow_filepath      = "%s/%s" % (self.opts.outputdir, "seq.data")
        self.ack_flow_filepath       = "%s/%s" % (self.opts.outputdir, "ack.data")
        self.receiver_awnd_filepath  = "%s/%s" % (self.opts.outputdir, "win.data")

        self.data_arrow_filepath          = "%s/%s" % (self.opts.outputdir, "data-arrow.data")
        self.data_arrow_retrans_filepath  = "%s/%s" % (self.opts.outputdir, "data-arrow-retrans.data")
        self.data_arrow_sack_filepath     = "%s/%s" % (self.opts.outputdir, "data-arrow-sack.data")
        
        self.data_flow_file = open(self.data_flow_filepath, 'w')
        self.ack_flow_file = open(self.ack_flow_filepath, 'w')
        self.receiver_awnd_file = open(self.receiver_awnd_filepath, 'w')

        self.data_arrow_file = open(self.data_arrow_filepath, 'w')
        self.data_arrow_retrans_file = open(self.data_arrow_retrans_filepath, 'w')
        self.data_arrow_sack_file = open(self.data_arrow_sack_filepath, 'w')


    def close_files(self):
        self.data_flow_file.close()
        self.ack_flow_file.close()
        self.receiver_awnd_file.close()

        self.data_arrow_file.close()
        self.data_arrow_retrans_file.close()
        self.data_arrow_sack_file.close()


    def create_gnuplot_environment(self):
        gnuplot_filename = "time-sequence.gpi"
        makefile_filename = "Makefile"

        filepath = "%s/%s" % (self.opts.outputdir, gnuplot_filename)
        fd = open(filepath, 'w')
        fd.write("%s" % (TemplateMod().get_content_by_name("time-sequence")))
        fd.close()

        filepath = "%s/%s" % (self.opts.outputdir, makefile_filename)
        fd = open(filepath, 'w')
        fd.write("%s" % (TemplateMod().get_content_by_name("gnuplot")))
        fd.close()


    def check_options(self):
        if not self.opts.outputdir:
            self.logger.error("No output directory specified: --output-dir")
            sys.exit(ExitCodes.EXIT_CMD_LINE)

        if self.opts.init:
            self.create_gnuplot_environment()

        if not os.path.exists(self.opts.outputdir):
            self.logger.error("Not a valid directory: \"%s\"" %
                    (self.opts.outputdir))
            sys.exit(ExitCodes.EXIT_CMD_LINE)

        if self.opts.timeframe:
            self.logger.debug("split timeframe options: %s" %
                    (self.opts.timeframe))
            (start, end) = self.opts.timeframe.split(':')
            (self.timeframe_start, self.timeframe_end) = \
                    (float(start), float(end))
            sys.stderr.write("# displayed time frame: %.2fs to %.2fs\n" %
                    (self.timeframe_start, self.timeframe_end))

        if not self.opts.connections:
            self.logger.error("No data flow specified (where the data flows)")
            sys.exit(ExitCodes.EXIT_CMD_LINE)

        (self.connection_id, self.data_flow_id) = self.opts.connections.split('.')
        if int(self.data_flow_id) == 1:
            self.ack_flow_id = 2
        elif int(self.data_flow_id) == 2:
            self.ack_flow_id = 1
        else:
            raise ArgumentException("sub flow must be 1 or 2")

        sys.stderr.write("# connection: %s (data flow: %s, ACK flow: %s)\n" %
                (self.connection_id, self.data_flow_id, self.ack_flow_id))



    def parse_local_options(self):
        self.width = self.height = 0

        parser = optparse.OptionParser()
        parser.usage = "%prog timesequence [options] <pcapfile>"

        parser.add_option( "-v", "--verbose", dest="loglevel", default=None,
                type="string", help="set the loglevel (info, debug, warning, error)")

        parser.add_option( "-o", "--output-dir", dest="outputdir", default=None,
                type="string", help="specify the output directory")

        parser.add_option( "-f", "--data-flow", dest="connections", default=None,
                type="string", help="specify the number of relevant ID's")

        parser.add_option( "-t", "--time", dest="timeframe", default=None,
                type="string", help="select range of displayed packet (-t <start:stop>)")

        parser.add_option( "-i", "--init", dest="init",  default=False,
                action="store_true", help="create Gnuplot template and Makefile in output-dir")

        self.opts, args = parser.parse_args(sys.argv[0:])
        self.set_opts_logevel()
        
        if len(args) < 3:
            parser.error("no pcap file argument given, exiting")
            sys.exit(ExitCodes.EXIT_CMD_LINE)

        self.captcp.print_welcome()
        self.check_options()
        self.captcp.pcap_file_path = args[2]
        self.logger.info("pcap file: %s" % (self.captcp.pcap_file_path))
        self.create_files()


    def check_packet(self, ts, packet):
        if type(packet) != dpkt.ip.IP and type(packet) != dpkt.ip6.IP6:
            return False

        if type(packet.data) != dpkt.tcp.TCP:
            return False

        if not self.cc.is_packet_connection(packet, int(self.connection_id)):
            return False

        if not self.reference_time:
            self.reference_time = ts

        if self.timeframe_start and float(self.calculate_offset_time(ts)) < self.timeframe_start:
            return False

        if self.timeframe_end and float(self.calculate_offset_time(ts)) > self.timeframe_end:
            return False

        return True


    def pre_process_packet(self, ts, packet):
        if not self.check_packet(ts, packet):
            return


    def calculate_offset_time(self, ts):
        time_diff = ts - self.reference_time
        return float(time_diff.seconds) + time_diff.microseconds / 1E6 + time_diff.days * 86400


    def process_data_flow_packet(self, ts, packet):
        packet_time = self.calculate_offset_time(ts)
        pi = PacketInfo(packet)
        self.data_flow_file.write("%lf %s\n" % (packet_time, pi.seq))

        # support the sender wscale?
        if pi.options['wsc']:
            self.wscale_sender_support = True

        # differentiate between new data send
        # or already sent data (thus retransmissins)
        if pi.seq > self.highest_seq:
            self.data_arrow_file.write("set arrow from %lf,%s.0 to %ls,%s.0 lc rgb \"#008800\" lw 1\n" %
                            (packet_time, pi.seq, packet_time, pi.seq + len(packet.data.data)))
        else:
            self.data_arrow_retrans_file.write("set arrow from %lf,%s.0 to %ls,%s.0 lc rgb \"red\" lw 1\n" %
                            (packet_time, pi.seq, packet_time, pi.seq + len(packet.data.data)))

        # only real data packets should be accounted, no plain ACKs
        if len(packet.data.data) > 0:
            self.highest_seq = max(pi.seq, self.highest_seq)


    def calc_advertised_window(self, pi):
        # only enabled if both hosts support window scaling
        if not self.wscale_sender_support:
            return pi.win + pi.ack
        else:
            return pi.win * self.wscale_receiver + pi.ack


    def process_ack_flow_packet(self, ts, packet):
        packet_time = self.calculate_offset_time(ts)
        pi = PacketInfo(packet)

        # ignore first ACK packet
        if pi.ack == 0:
            return

        # write ACK number
        self.ack_flow_file.write("%lf %s\n" % (packet_time, pi.ack))

        # write advertised window
        self.receiver_awnd_file.write("%lf %s\n" % (packet_time, self.calc_advertised_window(pi)))

        if pi.options['sackblocks']:
            for i in range(len(pi.options['sackblocks'])):
                self.data_arrow_sack_file.write("set arrow from %lf,%s.0 to %ls,%s.0 nohead lc rgb \"#aaaaff\" lw 2\n" %
                        (packet_time, pi.options['sackblocks'][i][0],
                         packet_time, pi.options['sackblocks'][i][1]))

        # we set self.wscale_receiver at the end to bypass
        # the first SYN/ACK packet where a) the window option
        # is transmitted. This window MUST not be scaled.
        if pi.options['wsc']:
            self.wscale_receiver = math.pow(2, int(pi.options['wsc']))


    def process_packet(self, ts, packet):
        if not self.check_packet(ts, packet):
            return

        sub_connection = self.cc.sub_connection_by_packet(packet)

        if sub_connection.sub_connection_id == int(self.data_flow_id):
            self.process_data_flow_packet(ts, packet)
        elif sub_connection.sub_connection_id == int(self.ack_flow_id):
            self.process_ack_flow_packet(ts, packet)
        else:
            raise InternalException


    def process_final(self):

        self.close_files()
        sys.stderr.write("# now execute \"make\" in %s\n" % (self.opts.outputdir))



class SequenceGraphMod(Mod):
    
    class Sequence: pass

    # more then PACKET_THRESH_FEW packets and the axis labeling
    # is reduced
    PACKET_LABELING_THRESH = 100

    def pre_initialize(self):
        self.ids = None
        self.timeframe_start = self.timeframe_end = False

        if cairo == None:
            raise ImportError("Python Cairo module not available, exiting")

        self.logger = logging.getLogger()
        self.parse_local_options()
        self.setup_cairo()

        self.tracing_start = None
        self.tracing_end = None

        self.process_time_start = self.process_time_end = None

        self.packets_to_draw = 0

        self.packet_timestamp_punchcard = dict()
        self.packet_timestamp_punchcard[True]  = []
        self.packet_timestamp_punchcard[False] = []

        self.reference_time = False

    def setup_cairo(self):

        line_width = 1.6

        surface = cairo.PDFSurface(self.opts.filename, self.width, self.height)
        self.cr = cairo.Context(surface)
        self.cr.move_to(0, 0)
        self.cr.set_source_rgb(1.0, 1.0, 1.0) # white
        self.cr.rectangle(0, 0, self.width, self.height)
        self.cr.fill()
        self.cr.stroke()

        self.margin_left_right = 50
        self.margin_top_bottom = 50

        # left
        self.cr.move_to(self.margin_left_right, self.margin_top_bottom)
        self.cr.line_to (self.margin_left_right, self.height - self.margin_top_bottom)
        self.cr.set_source_rgb(0.0, 0.0, 0.0)
        self.cr.set_line_width(line_width)
        self.cr.stroke()

        text = self.opts.locallabel
        self.cr.set_font_size(12)
        x_bearing, y_bearing, width, height = self.cr.text_extents(text)[:4]
        x_off = self.margin_left_right - (width / 2)
        y_off = self.margin_top_bottom - (height) - 10
        self.cr.move_to(x_off, y_off)
        self.cr.show_text(text)
        self.cr.stroke()


        # right
        self.cr.move_to(self.width - self.margin_left_right, self.margin_top_bottom)
        self.cr.line_to (self.width - self.margin_left_right, self.height - self.margin_top_bottom)
        self.cr.set_line_width(line_width)
        self.cr.stroke()

        text = self.opts.remotelabel
        self.cr.set_font_size(12)
        x_bearing, y_bearing, width, height = self.cr.text_extents(text)[:4]
        x_off = self.width - self.margin_left_right - (width / 2)
        y_off = self.margin_top_bottom - (height) - 10
        self.cr.move_to(x_off, y_off)
        self.cr.show_text(text)
        self.cr.stroke()


    def draw_background_grid(self):

        grid_line_width = 0.1

        left  = self.margin_left_right
        right = self.width - self.margin_left_right

        i = self.margin_top_bottom

        while True:

            self.cr.move_to(left, i)
            self.cr.line_to (right, i)
            self.cr.set_source_rgb(0.9, 0.9, 0.9)
            self.cr.set_line_width(grid_line_width)
            self.cr.stroke()

            i += 20

            if i > self.height - self.margin_top_bottom:
                break



    def pre_process_final(self):

        if self.ids:
            time_start = time_end = None
            for idss in self.ids:
                conn = self.cc.connection_by_uid(int(idss))
                if conn:
                    if time_start == None:
                        time_start = conn.capture_time_start

                    if time_end == None:
                        time_end = conn.capture_time_end

                    if time_start > conn.capture_time_start:
                        time_start = conn.capture_time_start

                    if time_end < conn.capture_time_end:
                        time_end = conn.capture_time_end

            time_diff = time_end - time_start
            time_diff = float(time_diff.seconds) + time_diff.microseconds / 1E6 + time_diff.days * 86400
            time_diff += self.delay
            self.scaling_factor = time_diff / (self.height - 2 * self.margin_top_bottom)

            self.process_time_start = time_start
            self.process_time_end   = time_end

        else:

            if self.timeframe_start and self.timeframe_end:

                self.logger.debug("calculate page coordinated and scale factor")

                timedelta_s = datetime.timedelta(seconds=self.timeframe_start)
                timedelta_e = datetime.timedelta(seconds=self.timeframe_end)

                self.capture_time_start = self.reference_time + timedelta_s
                self.capture_time_end   = self.reference_time + timedelta_e

                self.process_time_start = self.capture_time_start
                self.process_time_end   = self.capture_time_end

                time_diff = self.process_time_end - self.process_time_start
                time_diff = float(time_diff.seconds) + time_diff.microseconds / 1E6 + time_diff.days * 86400
                time_diff += self.delay
                self.scaling_factor = time_diff / (self.height - 2 * self.margin_top_bottom)

            else:
                # this is the _normal_ case: the user didn't specified
                # a connection id nor a timestart, timeend limit
                time_diff = self.cc.capture_time_end - self.cc.capture_time_start
                time_diff = float(time_diff.seconds) + time_diff.microseconds / 1E6 + time_diff.days * 86400
                time_diff += self.delay
                self.scaling_factor = time_diff / (self.height - 2 * self.margin_top_bottom)

        if self.opts.grid:
            self.draw_background_grid()

        self.logger.info("now draw %d packets" % self.packets_to_draw)


    def rttbw_to_bits(self):
        if "mbps" in self.opts.rttbw.lower():
            return float(self.opts.rttbw.lower().replace("mbps",""))*1000000
        if "kbps" in self.opts.rttbw.lower():
            return float(self.opts.rttbw.lower().replace("kbps",""))*1000
        if "bps" in self.opts.rttbw.lower():
            return float(self.opts.rttbw.lower().replace("bps",""))


    def parse_local_options(self):

        self.width = self.height = 0

        parser = optparse.OptionParser()
        parser.usage = "%prog sequencegraph [options] <pcapfile>"

        parser.add_option( "-v", "--verbose", dest="loglevel", default=None,
                type="string", help="set the loglevel (info, debug, warning, error)")

        parser.add_option( "-l", "--local", dest="localaddr", default=None,
                type="string", help="specify list of local ip addresses")

        parser.add_option( "-s", "--size", dest="size", default="600x1200",
                type="string", help="specify the size of the image (default: 600x1200)")

        parser.add_option( "-r", "--rtt", dest="rtt", default=0.025,
                type="float", help="specify the average rtt per connection (default 0.025s)")

        parser.add_option( "-b", "--rtt-bw", dest="rttbw", default="100Mbps", type="string",
                          help="specify the used bandwidth for your connection (default 100Mbps)")

        parser.add_option( "-f", "--filename", dest="filename", default="seq-graph.pdf",
                type="string", help="specify the name of the generated PDF file (default: seq-graph.pdf)")

        parser.add_option( "-i", "--connection-id", dest="connections", default=None,
                type="string", help="specify the number of relevant ID's")

        parser.add_option( "-y", "--style", dest="style", default="normal",
                type="string", help="specify the style of the labels (normal or minimal)")

        parser.add_option( "-p", "--locallabel", dest="locallabel", default="Local",
                type="string", help="the default string left axis (default: Local)")

        parser.add_option( "-q", "--remotelabel", dest="remotelabel", default="Remote",
                type="string", help="the default string right axis (default: Remote)")

        parser.add_option( "-g", "--grid", dest="grid", default=False,
                type="string", help="draw background grid (default: no)")

        parser.add_option( "-t", "--time", dest="timeframe", default=None,
                type="string", help="select range of displayed packet (-t <start:stop>)")

        self.opts, args = parser.parse_args(sys.argv[0:])
        self.set_opts_logevel()
        
        if len(args) < 3:
            parser.error("no pcap file argument given, exiting")
            sys.exit(ExitCodes.EXIT_CMD_LINE)

        self.captcp.print_welcome()

        if self.opts.localaddr == None:
            self.logger.warning("No local IP address (--local <ip-addr>) specified!")

        if self.opts.timeframe:
            self.logger.debug("split timeframe options: %s" % (self.opts.timeframe))
            (start, end) = self.opts.timeframe.split(':')
            (self.timeframe_start, self.timeframe_end) = (float(start), float(end))
            self.logger.debug("%s %s" %(self.timeframe_start, self.timeframe_end))

        self.captcp.pcap_file_path = args[2]
        self.logger.info("pcap file: %s" % (self.captcp.pcap_file_path))

        (self.width, self.height) = self.opts.size.split('x')
        (self.width, self.height) = (int(self.width), int(self.height))

        self.delay = self.opts.rtt / 2.0
        self.bandwidth = self.rttbw_to_bits()

        if self.width <= 0 or self.height <= 0:
            raise ArgumentException("size cannot smaller then 0px")

        if self.opts.connections:
            self.ids = self.opts.connections.split(',')
            self.logger.info("visualization limited to the following connections: %s" % (str(self.ids)))


    def local_generated_packet(self, packet):

        if type(packet) == dpkt.ip.IP:
            if Converter.dpkt_addr_to_string(packet.src) == self.opts.localaddr:
                return True
            else:
                return False
        elif type(packet) == dpkt.ip6.IP6:
            ipv6str = socket.inet_ntop(socket.AF_INET6, packet.src)
            if ipv6str == self.opts.localaddr:
                return True
            else:
                return False
        else:
            raise InternalException()


    def ts_tofloat(self, ts):
        return float(ts.seconds) + ts.microseconds / 1E6 + ts.days * 86400


    def reduced_labeling(self):
        return self.packets_to_draw > SequenceGraphMod.PACKET_LABELING_THRESH


    def draw_timestamp(self, sequence, ts, packet):
        time = "%.5f" % (ts)

        if sequence.local:
            x_offset = 5
        else:
            x_offset = self.width - self.margin_left_right + 5

        self.cr.set_font_size(6)

        # draw test
        x_bearing, y_bearing, width, height = self.cr.text_extents(time)[:4]
        y_offset = sequence.ys + (height / 2)

        # we check that there is no label somewhere in range
        for val in self.packet_timestamp_punchcard[sequence.local]:
            if (y_offset - height - 1) < val and (y_offset + height + 1) > val:
                # skip drawing
                return
            
        self.cr.move_to(x_offset, y_offset)
        self.cr.show_text(time)
        self.cr.stroke()

        self.packet_timestamp_punchcard[sequence.local].append(y_offset)


    def construct_label_string(self, packet):
        pi = PacketInfo(packet)

        if self.opts.style == "minimal":
            text = "%s seq:%u ack:%u len: %u" % ( pi.create_flag_brakets(),
                    pi.seq, pi.ack, len(packet.data.data))
        else:
            # including "normal" style
            text = "%s seq:%u ack:%u win:%u urp:%u" % (
                    pi.create_flag_brakets(), pi.seq, pi.ack, pi.win, pi.urp)
            text += " {"
            if pi.options['mss']:
                text += " mss: %d" % (pi.options['mss'])
            if pi.options['wsc']:
                text += " wsc: %d" % (pi.options['wsc'])
            if pi.options['tsval']:
                text += " tsval: %d" % (pi.options['tsval'])
            if pi.options['sackok']:
                text += " sackok"
            text += "}"

        return text


    def draw_labels(self, sequence, ts, packet):

        local_margin = 3

        gegenkathete = sequence.ye - sequence.ys
        ankathete = self.width - (self.margin_left_right * 2)
        res = math.atan(gegenkathete/ankathete)

        if not sequence.local:
            res = (math.pi * 2) - res

        text = self.construct_label_string(packet)


        self.cr.save()

        self.cr.set_font_size(9)
        x_bearing, y_bearing, width, height = self.cr.text_extents(text)[:4]

        x_off = (self.width / 2)  - (width / 2.0)

        mid = (sequence.ys + (sequence.ye - sequence.ys) / 2.0)

        if sequence.local:
            gk = math.atan(res) * (width / 2.0)
            y_off = (mid) - (height / 2.0) - gk + local_margin
        else:
            res = math.atan(gegenkathete/ankathete)
            gk = math.atan(res) * (width / 2.0)
            if not sequence.local:
                res = (math.pi * 2) - res
            y_off = (mid) - (height / 2.0) + gk + local_margin 


        self.cr.move_to(x_off, y_off)


        self.cr.rotate(res)
        self.cr.show_text(text)
        self.cr.stroke()


        self.cr.restore()


    def draw_sequence(self, sequence, ts, packet):

        self.draw_timestamp(sequence, ts, packet)

        if not self.reduced_labeling():
            self.draw_labels(sequence, ts, packet)

        
        self.cr.set_line_width(0.5)
        self.cr.move_to(sequence.xs, sequence.ys)
        self.cr.line_to(sequence.xe, sequence.ye)
        self.cr.stroke()


    def draw_arrows(self, sequence):

        if ((sequence.xe-sequence.xs) > 0) and ((sequence.ye-sequence.ys) > 0):
            interim_angle=math.pi/2-(math.atan((sequence.ye-sequence.ys)/(sequence.xe-sequence.xs)))-0.4
            xsp = sequence.xe - (6*math.sin(interim_angle))
            ysp = sequence.ye - (6*math.cos(interim_angle))

            interim_angle=math.pi/2-(math.atan((sequence.xe-sequence.xs)/(sequence.ye-sequence.ys)))-0.4
            xep = sequence.xe - (6*math.cos(interim_angle))
            yep = sequence.ye - (6*math.sin(interim_angle))

        if ((sequence.xe-sequence.xs) > 0) and ((sequence.ye-sequence.ys) < 0):
            interim_angle=math.pi/2-(math.atan((sequence.xe-sequence.xs)/(sequence.ys-sequence.ye)))-0.4
            xsp = sequence.xe - (6*math.cos(interim_angle))
            ysp = sequence.ye + (6*math.sin(interim_angle))
 
            interim_angle=math.pi/2-(math.atan((sequence.ys-sequence.ye)/(sequence.ye-sequence.ys)))-0.4
            xep = sequence.xe - (6*math.sin(interim_angle))
            yep = sequence.ye + (6*math.cos(interim_angle))

        if ((sequence.xe-sequence.xs) < 0) and ((sequence.ye-sequence.ys) < 0):
            interim_angle=math.pi/2-(math.atan((sequence.ys-sequence.ye)/(sequence.xs-sequence.xe)))-0.4
            xsp = sequence.xe + (6*math.sin(interim_angle))
            ysp = sequence.ye + (6*math.cos(interim_angle))

            interim_angle=math.pi/2-(math.atan((sequence.xs-sequence.xe)/(sequence.ys-sequence.ye)))-0.4
            xep = sequence.xe + (6*math.cos(interim_angle))
            yep = sequence.ye + (6*math.sin(interim_angle))

        if ((sequence.xe-sequence.xs) < 0) and ((sequence.ye-sequence.ys) > 0):
            interim_angle=math.pi/2-(math.atan((sequence.ye-sequence.ys)/(sequence.xs-sequence.xe)))-0.4
            xsp = sequence.xe + (6*math.sin(interim_angle))
            ysp = sequence.ye - (6*math.cos(interim_angle))

            interim_angle=math.pi/2-(math.atan((sequence.xs-sequence.xe)/(sequence.ye-sequence.ys)))-0.4
            xep = sequence.xe + (6*math.cos(interim_angle))
            yep = sequence.ye - (6*math.sin(interim_angle))
            
        if (xsp and ysp):

            self.cr.set_source_rgb(0.0,0.0,0.0)
            self.cr.set_line_width(0.5)
            self.cr.move_to(sequence.xe, sequence.ye)
            self.cr.line_to(xsp, ysp)
            self.cr.line_to(xep, yep)
            self.cr.line_to(sequence.xe, sequence.ye)
            self.cr.close_path()
            self.cr.fill()

            
    def is_drawable_packet(self, ts, packet):
        if type(packet) != dpkt.ip.IP and type(packet) != dpkt.ip6.IP6:
            return False

        if type(packet.data) != dpkt.tcp.TCP:
            return False

        if self.process_time_start and ts < self.process_time_start:
            return False

        if self.process_time_end and ts > self.process_time_end:
            return False

        if self.ids:
            for idss in self.ids:
                if self.cc.is_packet_connection(packet, int(idss)):
                    return True
        else:
            return True

        return False


    def pre_process_packet(self, ts, packet):
        if not self.reference_time:
            # time time where the first packet is
            # captured
            self.reference_time = ts

        if not self.is_drawable_packet(ts, packet):
            return

        self.packets_to_draw += 1


    def process_packet(self, ts, packet):
        if not self.is_drawable_packet(ts, packet):
            return

        if self.process_time_start:
            ts_diff = ts - self.process_time_start
        else:
            ts_diff = ts - self.cc.capture_time_start


        s = SequenceGraphMod.Sequence

        if self.local_generated_packet(packet):
            s.local = True
            s.xs = self.margin_left_right
            s.xe = self.width - self.margin_left_right
            s.ys = self.ts_tofloat(ts_diff) / self.scaling_factor
            s.ye = (self.ts_tofloat(ts_diff) + (len(packet)/self.bandwidth) + self.delay) / self.scaling_factor
            display_time = self.ts_tofloat(ts_diff)
        else:
            s.local = False
            s.xs = self.width - self.margin_left_right
            s.xe = self.margin_left_right
            s.ys = (self.ts_tofloat(ts_diff) - (len(packet)/self.bandwidth) - self.delay) /self.scaling_factor
            s.ye = self.ts_tofloat(ts_diff) / self.scaling_factor
            display_time = self.ts_tofloat(ts_diff) - (len(packet)/self.bandwidth) - self.delay

        s.ys += self.margin_top_bottom
        s.ye += self.margin_top_bottom


        self.cr.set_source_rgb(0.0, 0.0, 0.0)
        self.draw_sequence(s, display_time, packet)
        self.draw_arrows(s) 


    def process_final(self):
        self.logger.debug("generate PDF file \"%s\"" % (self.opts.filename))
        self.cr.show_page()



class TcpConn:

    def __init__(self, packet):
        ip = packet
        tcp = packet.data

        self.ipversion = str(type(ip))
        self.sip       = Converter.dpkt_addr_to_string(ip.src)
        self.dip       = Converter.dpkt_addr_to_string(ip.dst)
        self.sport     = str(int(tcp.sport))
        self.dport     = str(int(tcp.dport))

        self.sipnum = ip.src
        self.dipnum = ip.dst

        l = [ord(a) ^ ord(b) for a,b in zip(self.sipnum, self.dipnum)]

        self.uid = "%s:%s:%s" % (
                str(self.ipversion),
                str(l),
                str(long(self.sport) + long(self.dport)))

        self.iuid = ((self.sipnum) + \
                (self.dipnum) + ((self.sport) + \
                (self.dport)))


    def __hash__(self):
        return self.iuid

    def __repr__(self):
        return "%s:%s<->%s:%s" % ( self.sip, self.sport,
                    self.dip, self.dport)


class SubConnectionStatistic:

    def __init__(self):
        self.packets_processed          = 0
        self.bytes_sent_link_layer      = 0
        self.bytes_sent_network_layer   = 0
        self.bytes_sent_transport_layer = 0
        self.bytes_sent_application_layer = 0


class SubConnection(TcpConn):

    def __init__(self, connection, packet):
        TcpConn.__init__(self, packet)
        self.connection = connection
        self.statistic = SubConnectionStatistic()
        self.user_data = dict()


    def __cmp__(self, other):

        if other == None:
            return True

        if (self.dipnum == other.dipnum and
            self.sipnum == other.sipnum and
            self.dport  == other.dport and
            self.sport  == other.sport and
            self.ipversion == other.ipversion):
                return False
        else:
            return True


    def __repr__(self):
        return "%s:%s -> %s:%s" % (
                    self.sip,
                    self.sport,
                    self.dip,
                    self.dport)

        
    def update(self, ts, packet):
        self.statistic.packets_processed += 1


    def set_subconnection_id(self, sub_connection_id):
        self.sub_connection_id = sub_connection_id


    def is_in(self, ids):
        for i in ids:
            if i.find('.') != -1:
                assert(i.count('.') == 1)
                (major, minor) = i.split('.')
                if (int(major) == self.connection.connection_id and
                        int(minor) == self.sub_connection_id):
                    return True
            else:
                if int(i) == self.connection.connection_id:
                    return True

        return False



class ConnectionStatistic:

    def __init__(self):
        self.packets_processed          = 0
        self.bytes_sent_link_layer      = 0
        self.bytes_sent_network_layer   = 0
        self.bytes_sent_transport_layer = 0
        self.bytes_sent_application_layer = 0



class Connection(TcpConn):

    static_connection_id = 1

    def __init__(self, packet):
        TcpConn.__init__(self, packet)
        (self.sc1, self.sc2) = (None, None)
        self.connection_id = Connection.static_connection_id
        Connection.static_connection_id += 1
        self.statistic = ConnectionStatistic()

        self.capture_time_start = None
        self.capture_time_end = None

        # module users could use this container
        # to stick data to a connection
        self.user_data = dict()


    def __del__(self):
        Connection.static_connection_id -= 1


    def __cmp__(self, other):
        if self.ipversion != other.ipversion:
            return False
        if (self.dipnum == other.dipnum and
            self.sipnum == other.sipnum and
            self.dport  == other.dport and
            self.sport  == other.sport):
                return True
        elif (self.dipnum == other.sipnum and
             self.sipnum  == other.dipnum and
             self.dport   == other.sport and
             self.sport   == other.dport):
                return True
        else:
            return False

    def register_container(self, container):
        self.container = container


    def update_statistic(self, packet):
        self.statistic.packets_processed  += 1


    def update(self, ts, packet):
        self.update_statistic(packet)

        sc = SubConnection(self, packet)

        if self.capture_time_start == None:
            self.capture_time_start = ts

        self.capture_time_end = ts

        if self.sc1 == None:
            self.sc1 = sc
            self.sc1.update(ts, packet)
            self.sc1.set_subconnection_id(1)
            return

        if self.sc1 == sc:
            self.sc1.update(ts, packet)
            return

        if self.sc2 == sc:
            self.sc2.update(ts, packet)
            return

        self.sc2 = sc
        sc.update(ts, packet)
        sc.set_subconnection_id(2)


    def get_subconnection(self, packet):
        # we know that packet is a TCP packet
        if self.sc1 == None:
            raise InternalException("a connection without a subconnection?!")

        if str(self.sc1.sport) == str(packet.data.sport):
            return self.sc1
        else:
            assert(self.sc2)
            return self.sc2



class ConnectionContainerStatistic:

    def __init__(self):
        self.packets_processed = 0

        self.packets_nl_arp  = 0
        self.packets_nl_ipv4 = 0
        self.packets_nl_ipv6 = 0
        self.packets_nl_unknown = 0

        self.packets_tl_tcp  = 0
        self.packets_tl_udp  = 0
        self.packets_tl_icmp  = 0
        self.packets_tl_icmp6  = 0
        self.packets_tl_unknown  = 0

        # byte accounting
        self.bytes_sent_link_layer        = 0
        self.bytes_sent_network_layer     = 0
        self.bytes_sent_transport_layer   = 0



class ConnectionContainer:


    def __init__(self):
        self.container = dict()
        self.statistic = ConnectionContainerStatistic()
        self.capture_time_start = None
        self.capture_time_end = None


    def __len__(self):
        return len(self.container)


    def connection_by_uid(self, uid):

        for i in self.container.keys():
            if self.container[i].connection_id == uid:
                return self.container[i]

        return None


    def tcp_check(self, packet):
        if type(packet) != dpkt.ip.IP and type(packet) != dpkt.ip6.IP6:
            return False

        if type(packet.data) != dpkt.tcp.TCP:
            return False

        return True


    def sub_connection_by_packet(self, packet):
        if not self.tcp_check(packet):
            return None

        c = Connection(packet)

        if not c.uid in self.container.keys():
            # this method SHOULD not be called if not
            # sure that the packet is already in the
            # container
            raise InternalException("packet MUST be in preprocesses container")

        return self.container[c.uid].get_subconnection(packet)


    def connection_by_packet(self, packet):
        if not self.tcp_check(packet):
            return None

        c = Connection(packet)

        if not c.uid in self.container.keys():
            raise InternalException("packet MUST be in preprocesses container")
        else:
            return self.container[c.uid]


    def is_packet_connection(self, packet, uid):
        if not self.tcp_check(packet):
            return None

        c = Connection(packet)

        if not c.uid in self.container.keys():
            raise InternalException("packet MUST be in preprocesses container")
        else:
            cc = self.container[c.uid]

        if cc.connection_id == uid:
            return True
        else:
            return False


    def update(self, ts, packet):
        if type(packet) != dpkt.ip.IP and type(packet) != dpkt.ip6.IP6:
            return

        if type(packet.data) != dpkt.tcp.TCP:
            return

        if self.capture_time_start == None:
            self.capture_time_start = ts

        self.capture_time_end = ts

        c = Connection(packet)

        # this is the only place where a connetion
        # is put into this container
        if not c.uid in self.container.keys():
            c.update(ts, packet)
            self.container[c.uid] = c
            c.register_container(self)
        else:
            cc = self.container[c.uid]
            cc.update(ts, packet)



class ConnectionAnalyzeMod(Mod):

    def pre_initialize(self):

        self.logger = logging.getLogger()
        parser = optparse.OptionParser()
        parser.usage = "captcp connection"
        parser.add_option( "-v", "--verbose", dest="verbose",
                default=False, action="store_true", help="show verbose")

        self.opts, args = parser.parse_args(sys.argv[0:])
        self.set_opts_logevel()
        
        if len(args) < 3:
            self.logger.error("no pcap file argument given, exiting")
            sys.exit(ExitCodes.EXIT_CMD_LINE)
 
        self.captcp.pcap_file_path = args[2]

        self.captcp.pcap_filter = None
        if args[3:]:
            self.captcp.pcap_filter = " ".join(args[3:])
            self.logger.info("pcap filter: \"" + self.captcp.pcap_filter + "\"")


    def process_final(self):
        sys.stdout.write("digraph G {\nranksep=3.0;\nnodesep=2.0;\n")
        sys.stdout.write("#size=\"7.75,10.25\";\n orientation=\"landscape\"\n")

        label = "\"%d\" [ label=\"%s\",style=filled,color=none,fontsize=6,fontname=Helvetica];\n"

        sys.stdout.write(label % (1, str("Connections")))

        for key in self.cc.container.keys():
            connection = self.cc.container[key]

            sys.stdout.write(label % (abs(hash(connection.iuid)), str(connection)))


            if connection.sc1 and connection.sc2:
                sys.stdout.write(label % (abs(hash(connection.sc1.iuid) + 1), str(connection.sc1)))
                sys.stdout.write(label % (abs(hash(connection.sc2.iuid) + 2), str(connection.sc2)))
            elif connection.sc1:
                sys.stdout.write(label % (abs(hash(connection.sc1.iuid) + 1), str(connection.sc1)))

        # connect

        label = "\"%s\" -> \"%s\" [ label=\" \",color=gray,arrowsize=0.4, penwidth=1.2 ];\n"

        for key in self.cc.container.keys():
            connection = self.cc.container[key]
            sys.stdout.write(label % (1, (abs(hash(connection.iuid)))))

            if connection.sc1 and connection.sc2:
                sys.stdout.write(label % ((abs(hash(connection.iuid))), (abs(hash(connection.sc1.iuid) + 1))))
                sys.stdout.write(label % ((abs(hash(connection.iuid))), (abs(hash(connection.sc2.iuid) + 2))))
            elif connection.sc1:
                sys.stdout.write(label % ((abs(hash(connection.iuid))), (abs(hash(connection.sc1.iuid) + 1))))

        sys.stdout.write("}\n")
        sys.stderr.write("# Tip: generate graphviz file with: \"twopi -onetwork.png -Tpng network.data\"\n")



class ThroughputMod(Mod):

    def create_gnuplot_environment(self):
        gnuplot_filename = "throughput.gpi"
        makefile_filename = "Makefile"

        filepath = "%s/%s" % (self.opts.outputdir, gnuplot_filename)
        fd = open(filepath, 'w')
        fd.write("%s" % (TemplateMod().get_content_by_name("throughput")))
        fd.close()

        filepath = "%s/%s" % (self.opts.outputdir, makefile_filename)
        fd = open(filepath, 'w')
        fd.write("%s" % (TemplateMod().get_content_by_name("gnuplot")))
        fd.close()


    def check_options(self):
        if not self.opts.outputdir:
            self.logger.error("No output directory specified: --output-dir")
            sys.exit(ExitCodes.EXIT_CMD_LINE)

        if not os.path.exists(self.opts.outputdir):
            self.logger.error("Not a valid directory: \"%s\"" %
                    (self.opts.outputdir))
            sys.exit(ExitCodes.EXIT_CMD_LINE)


    def create_data_files(self):
        self.throughput_filepath = \
                "%s/%s" % (self.opts.outputdir, "throughput.data")
        self.throughput_file = open(self.throughput_filepath, 'w')


    def close_data_files(self):
        self.throughput_file.close()


    def pre_initialize(self):
        self.logger = logging.getLogger()
        self.parse_local_options()
        self.end_time = self.start_time = False
        self.total_data_len = 0
        if not self.opts.stdio:
            # no need to check and generate Gnuplot
            # environment
            self.check_options()
            if self.opts.init:
                self.create_gnuplot_environment()
            self.create_data_files()


    def parse_local_options(self):
        self.ids = False
        parser = optparse.OptionParser()
        parser.usage = "show [options] <pcapfile> [pcapfilter]"

        parser.add_option( "-v", "--verbose", dest="loglevel", default=None,
                type="string", help="set the loglevel (info, debug, warning, error)")
        parser.add_option( "-f", "--flow", dest="connections", default=None,
                type="string", help="specify the number of displayed ID's")
        parser.add_option( "-s", "--sample-length", dest="samplelength", default=1.0,
                type="float", help="length in seconds (float) where data is accumulated (1.0)")
        parser.add_option( "-m", "--mode", dest="mode", default="goodput",
                type="string", help="layer where the data len measurement is taken (default: goodput")
        parser.add_option( "-u", "--unit", dest="unit", default="byte",
                type="string", help="unit: byte, kbyte, mbyte")
        parser.add_option( "-i", "--init", dest="init",  default=False,
                action="store_true", help="create Gnuplot template and Makefile in output-dir")
        parser.add_option("-t", "--stdio", dest="stdio",  default=False,
                action="store_true", help="don't create Gnuplot data, just stdio")
        parser.add_option( "-o", "--output-dir", dest="outputdir", default=None,
                type="string", help="specify the output directory")


        self.opts, args = parser.parse_args(sys.argv[0:])
        self.set_opts_logevel()

        if len(args) < 3:
            self.logger.error("no pcap file argument given, exiting")
            sys.exit(ExitCodes.EXIT_CMD_LINE)

        self.captcp.print_welcome()
        self.captcp.pcap_file_path = args[2]
        self.logger.info("pcap file: %s" % (self.captcp.pcap_file_path))

        if self.opts.connections:
            self.ids = self.opts.connections.split(',')
            self.logger.info("show limited to the following connections: %s" % (str(self.ids)))


    def output_data(self, time, amount):
        if self.opts.stdio:
            sys.stdout.write("%5.1f  %10.1f\n" % (time, amount))
        else:
            self.throughput_file.write("%.5f %.8f\n" % (time, amount))


    def pre_process_packet(self, ts, packet):
        sub_connection = self.cc.sub_connection_by_packet(packet)
        # only for TCP flows this can be true, therefore
        # no additional checks that this is TCP are required
        # here
        if not sub_connection:
            return

        # if the user applied a filter, we check it here
        if self.ids and not sub_connection.is_in(self.ids):
            return

        pi = PacketInfo(packet)

        if self.opts.mode == "goodput" or self.opts.mode == "application-layer":
            data_len = len(packet.data.data)
        elif self.opts.mode == "transport-layer":
            data_len = len(packet.data)
        elif self.opts.mode == "network-layer":
            data_len = len(packet)
        else:
            raise NotImplementedException("mode \"%s\" not supported" %
                    (self.opts.mode))

        # time handling
        if not self.start_time:
            self.start_time = ts
            self.last_sample = 0.0
            self.data = 0

        self.data += data_len
        self.total_data_len += data_len

        timediff = Utils.ts_tofloat(ts - self.start_time)

        if timediff >= self.last_sample + self.opts.samplelength:

            # fill silent periods between a samplelength
            while self.last_sample + (self.opts.samplelength * 2) < timediff:
                self.last_sample += self.opts.samplelength
                self.output_data(self.last_sample, 0)

            amount = U.byte_to_unit(self.data, self.opts.unit)
            self.output_data(self.last_sample + self.opts.samplelength, amount)
            self.data  = 0
            self.last_sample += self.opts.samplelength

        self.end_time = ts


    def process_final(self):
        if self.opts.stdio:
            timediff =  Utils.ts_tofloat(self.end_time - self.start_time)
            sys.stdout.write("# total data (%s): %d %s (%s)\n" %
                    (self.opts.mode, self.total_data_len, self.opts.unit,
                    U.best_match(self.total_data_len)))
            sys.stdout.write("# throughput (%s): %.2f %s/s (%s/s)\n" %
                    (self.opts.mode, float(self.total_data_len)/timediff, self.opts.unit,
                    U.best_match(float(self.total_data_len)/timediff)))
            return

        self.close_data_files()




class InFlightMod(Mod):

    def pre_initialize(self):
        self.logger = logging.getLogger()
        self.parse_local_options()
        self.packet_sequence = list()
        self.packet_prev = False
        self.inflight_max = 0
        self.start_time = False
        if not self.opts.stdio:
            self.check_options()
            if self.opts.init:
                self.create_gnuplot_environment()
            self.create_data_files()


    def parse_local_options(self):
        self.ids = False
        parser = optparse.OptionParser()
        parser.usage = "show [options] <pcapfile>"
        parser.add_option( "-v", "--verbose", dest="loglevel", default=None,
                type="string", help="set the loglevel (info, debug, warning, error)")
        parser.add_option( "-f", "--data-flow", dest="connections", default=None,
                type="string", help="specify the number of relevant ID's")
        parser.add_option( "-m", "--mode", dest="mode", default="packets",
                type="string", help="display packets or bytes in flight (default packets)")
        parser.add_option( "-s", "--stdio", dest="stdio",  default=False,
                action="store_true", help="don't create Gnuplot files, instead print to stdout")
        parser.add_option( "-i", "--init", dest="init",  default=False,
                action="store_true", help="create Gnuplot template and Makefile in output-dir")
        parser.add_option( "-o", "--output-dir", dest="outputdir", default=None,
                type="string", help="specify the output directory")

        self.opts, args = parser.parse_args(sys.argv[0:])
        self.set_opts_logevel()
        
        if len(args) < 3:
            self.logger.error("no pcap file argument given, exiting")
            sys.exit(ExitCodes.EXIT_CMD_LINE)

        self.captcp.print_welcome()
        self.captcp.pcap_file_path = args[2]
        self.logger.info("pcap file: %s" % (self.captcp.pcap_file_path))

        if not self.opts.connections:
            self.logger.error("No data flow specified (where the data flows)")
            sys.exit(ExitCodes.EXIT_CMD_LINE)

        (self.connection_id, self.data_flow_id) = self.opts.connections.split('.')
        if int(self.data_flow_id) == 1:
            self.ack_flow_id = 2
        elif int(self.data_flow_id) == 2:
            self.ack_flow_id = 1
        else:
            raise ArgumentException("sub flow must be 1 or 2")

        sys.stderr.write("# connection: %s (data flow: %s, ACK flow: %s)\n" %
                (self.connection_id, self.data_flow_id, self.ack_flow_id))


    def create_gnuplot_environment(self):
        gnuplot_filename = "inflight.gpi"
        makefile_filename = "Makefile"

        filepath = "%s/%s" % (self.opts.outputdir, gnuplot_filename)
        fd = open(filepath, 'w')
        fd.write("%s" % (TemplateMod().get_content_by_name("inflight")))
        fd.close()

        filepath = "%s/%s" % (self.opts.outputdir, makefile_filename)
        fd = open(filepath, 'w')
        fd.write("%s" % (TemplateMod().get_content_by_name("gnuplot")))
        fd.close()


    def check_options(self):
        if not self.opts.outputdir:
            self.logger.error("No output directory specified: --output-dir")
            sys.exit(ExitCodes.EXIT_CMD_LINE)

        if not os.path.exists(self.opts.outputdir):
            self.logger.error("Not a valid directory: \"%s\"" %
                    (self.opts.outputdir))
            sys.exit(ExitCodes.EXIT_CMD_LINE)


    def create_data_files(self):
        self.filepath = \
                "%s/%s" % (self.opts.outputdir, "inflight.data")
        self.file = open(self.filepath, 'w')


    def close_data_files(self):
        self.file.close()


    def process_data_flow(self, ts, packet):
        pi = PacketInfo(packet)
        data = (pi.seq, ts, packet)
        self.packet_sequence.append(data)


    def process_ack_flow(self, ts, packet):
        pi = PacketInfo(packet)
        for i in list(self.packet_sequence):
            if pi.ack >= i[0]:
                self.packet_sequence.remove(i)


    def gnuplot_out(self, time, is_data):
        #if self.packet_prev:
        #    self.file.write("%.5f %d\n" % (time - 0.00001, self.packet_prev))
        self.file.write("%.5f %d\n" % (time, len(self.packet_sequence)))
        #self.packet_prev = len(self.packet_sequence)


    def stdio_out(self, time, is_data):
        if is_data: kind = "TX"
        else: kind = "RX"
        sys.stdout.write("%.5f %s %d\t%s\n" %
                (time, kind, len(self.packet_sequence), '#' * len(self.packet_sequence)))
        self.inflight_max = max(self.inflight_max, len(self.packet_sequence))


    def pre_process_packet(self, ts, packet):
        sub_connection = self.cc.sub_connection_by_packet(packet)
        if not sub_connection:
            return

        if sub_connection.sub_connection_id == int(self.data_flow_id):
            self.process_data_flow(ts, packet)
            is_data = True
        elif sub_connection.sub_connection_id == int(self.ack_flow_id):
            self.process_ack_flow(ts, packet)
            is_data = False
        else:
            raise InternalException

        time = Utils.ts_tofloat(ts - self.cc.capture_time_start)

        if self.opts.stdio:
            self.stdio_out(time, is_data)
        else:
            self.gnuplot_out(time, is_data)


    def process_final(self):
        if not self.opts.stdio:
            self.close_data_files()
        else:
            sys.stdout.write("# inflight max %d packets\n" % (self.inflight_max))





class SpacingMod(Mod):

    def pre_initialize(self):
        self.logger = logging.getLogger()

        self.parse_local_options()

        self.packet_sequence = list()
        self.packet_prev     = False
        self.start_time      = False

        self.prev_tx_time = False
        self.prev_rx_time = False

        self.tx_time_samples = list()
        self.rx_time_samples = list()

        self.capture_time_start = False

        if not self.opts.stdio:
            self.check_options()
            if self.opts.init:
                self.create_gnuplot_environment()
            self.create_data_files()


    def parse_local_options(self):
        self.ids = False
        parser = optparse.OptionParser()
        parser.usage = "show [options] <pcapfile>"
        parser.add_option( "-v", "--verbose", dest="loglevel", default=None,
                type="string", help="set the loglevel (info, debug, warning, error)")
        parser.add_option( "-f", "--data-flow", dest="connections", default=None,
                type="string", help="specify the number of relevant ID's")
        parser.add_option( "-m", "--mode", dest="mode", default="packets",
                type="string", help="display packets or bytes in flight (default packets)")
        parser.add_option( "-s", "--stdio", dest="stdio",  default=False,
                action="store_true", help="don't create Gnuplot files, instead print to stdout")
        parser.add_option( "-i", "--init", dest="init",  default=False,
                action="store_true", help="create Gnuplot template and Makefile in output-dir")
        parser.add_option( "-o", "--output-dir", dest="outputdir", default=None,
                type="string", help="specify the output directory")
        parser.add_option( "-a", "--samples", dest="sample_no", default=10,
                type="int", help="number of packet sampled (default: 10)")

        self.opts, args = parser.parse_args(sys.argv[0:])
        self.set_opts_logevel()
        
        if len(args) < 3:
            self.logger.error("no pcap file argument given, exiting")
            sys.exit(ExitCodes.EXIT_CMD_LINE)

        self.captcp.print_welcome()
        self.captcp.pcap_file_path = args[2]
        self.logger.info("pcap file: %s" % (self.captcp.pcap_file_path))

        if not self.opts.connections:
            self.logger.error("No data flow specified! Call \"captcp statistics\"")
            sys.exit(ExitCodes.EXIT_CMD_LINE)

        (self.connection_id, self.data_flow_id) = self.opts.connections.split('.')
        if int(self.data_flow_id) == 1:
            self.ack_flow_id = 2
        elif int(self.data_flow_id) == 2:
            self.ack_flow_id = 1
        else:
            raise ArgumentException("sub flow must be 1 or 2")

        sys.stderr.write("# connection: %s (data flow: %s, ACK flow: %s)\n" %
                (self.connection_id, self.data_flow_id, self.ack_flow_id))


    def create_gnuplot_environment(self):
        gnuplot_filename = "spacing.gpi"
        makefile_filename = "Makefile"

        filepath = "%s/%s" % (self.opts.outputdir, gnuplot_filename)
        fd = open(filepath, 'w')
        fd.write("%s" % (TemplateMod().get_content_by_name("spacing")))
        fd.close()

        filepath = "%s/%s" % (self.opts.outputdir, makefile_filename)
        fd = open(filepath, 'w')
        fd.write("%s" % (TemplateMod().get_content_by_name("gnuplot")))
        fd.close()


    def check_options(self):
        if not self.opts.outputdir:
            self.logger.error("No output directory specified: --output-dir")
            sys.exit(ExitCodes.EXIT_CMD_LINE)

        if not os.path.exists(self.opts.outputdir):
            self.logger.error("Not a valid directory: \"%s\"" %
                    (self.opts.outputdir))
            sys.exit(ExitCodes.EXIT_CMD_LINE)


    def create_data_files(self):
        self.tx_filepath = "%s/%s" % (self.opts.outputdir, "tx.data")
        self.tx_file = open(self.tx_filepath, 'w')

        self.rx_filepath = "%s/%s" % (self.opts.outputdir, "rx.data")
        self.rx_file = open(self.rx_filepath, 'w')


    def close_data_files(self):
        self.tx_file.close()
        self.rx_file.close()


    def process_data_flow(self, ts, packet):
        pi = PacketInfo(packet)

        data = (pi.seq, ts, packet)
        self.packet_sequence.append(data)


    def process_ack_flow(self, ts, packet):
        pi = PacketInfo(packet)
        for i in list(self.packet_sequence):
            if pi.ack >= i[0]:
                self.packet_sequence.remove(i)


    def gnuplot_out(self, time, delta, is_data_flow):
        if is_data_flow:
            self.tx_file.write("%.5f %.5f\n" % (time, delta))
        else:
            self.rx_file.write("%.5f %.5f\n" % (time, delta))
            


    def stdio_out(self, time, delta, is_data_flow):
        if is_data_flow:
            pre = "TX"
        else:
            pre = "RX"

        sys.stdout.write("%s %.5f %.5f\n" % (pre, time, delta))


    def pre_process_packet(self, ts, packet):
        sub_connection = self.cc.sub_connection_by_packet(packet)
        if not sub_connection: return
        if not self.capture_time_start: self.capture_time_start = ts
        time = Utils.ts_tofloat(ts - self.capture_time_start)
        pi = PacketInfo(packet)
        delta = 0.0
        is_data_flow = None


        if sub_connection.sub_connection_id == int(self.data_flow_id):
            if not self.prev_tx_time:
                self.prev_tx_time = time
                return

            delta = time - self.prev_tx_time
            self.prev_tx_time = time
            is_data_flow = True
            self.tx_time_samples.append(delta)
            if len(self.tx_time_samples) < self.opts.sample_no:
                return
        elif sub_connection.sub_connection_id == int(self.ack_flow_id):
            if not self.prev_rx_time:
                self.prev_rx_time = time
                return

            delta = time - self.prev_rx_time
            self.prev_rx_time = time
            is_data_flow = False
            self.rx_time_samples.append(delta)
            if len(self.rx_time_samples) < self.opts.sample_no:
                return
        else:
            raise InternalException

        
        tmp = 0.0
        if is_data_flow:
            for i in self.tx_time_samples:
                tmp += i
            tmp /= len(self.tx_time_samples)
        else:
            for i in self.rx_time_samples:
                tmp += i
            tmp /= len(self.rx_time_samples)


        if self.opts.stdio:
            self.stdio_out(time, tmp, is_data_flow)
        else:
            self.gnuplot_out(time, tmp, is_data_flow)

        if is_data_flow:
            self.tx_time_samples = list()
        else:
            self.rx_time_samples = list()


    def process_final(self):
        if not self.opts.stdio:
            self.close_data_files()





class ShowMod(Mod):


    def pre_initialize(self):

        self.logger = logging.getLogger()
        self.parse_local_options()
        self.color_iter = self.color.__iter__()
        self.packet_no = 0


    def parse_local_options(self):
        self.ids = False

        parser = optparse.OptionParser()
        parser.usage = "show [options] <pcapfile>"

        parser.add_option( "-v", "--verbose", dest="loglevel", default=None,
                type="string", help="set the loglevel (info, debug, warning, error)")
        parser.add_option( "-i", "--connection-id", dest="connections", default=None,
                type="string", help="specify the number of displayed ID's")
        parser.add_option( "-d", "--differentiate", dest="differentiate", default="connection",
                type="string", help="specify if \"connection\" or \"flow\" should be colored")
        parser.add_option( "-m", "--match", dest="match", default=None,
                type="string", help="if statment is true the string is color in red")
        parser.add_option( "-c", "--color", dest="color", default="ansi-256",
                type="string", help="colored output modifier: ansi-256 (default), ansi, none")
        parser.add_option( "-s", "--suppress", dest="suppress", default=False,
                action="store_true", help="don't display other packets")
        parser.add_option( "-n", "--number", dest="packet_number", default=False,
                action="store_true", help="number the packets")

        self.opts, args = parser.parse_args(sys.argv[0:])
        self.set_opts_logevel()
        
        if len(args) < 3:
            self.logger.error("no pcap file argument given, exiting")
            sys.exit(ExitCodes.EXIT_CMD_LINE)

        self.captcp.print_welcome()

        self.captcp.pcap_file_path = args[2]
        self.logger.info("pcap file: %s" % (self.captcp.pcap_file_path))

        self.captcp.pcap_filter = None
        if args[3:]:
            self.captcp.pcap_filter = " ".join(args[3:])
            self.logger.info("pcap filter: \"" + self.captcp.pcap_filter + "\"")

        if self.opts.connections:
            self.ids = self.opts.connections.split(',')
            self.logger.info("show limited to the following connections: %s" % (str(self.ids)))

        if self.opts.differentiate != "connection" and self.opts.differentiate != "flow":
            self.logger.error("only connection or sub-connection allowed for --d")
            sys.exit(ExitCodes.EXIT_CMD_LINE)

        if self.opts.color == "ansi-256":
            self.color = RainbowColor(mode=RainbowColor.ANSI256)
        elif self.opts.color == "ansi":
            self.color = RainbowColor(mode=RainbowColor.ANSI)
        elif self.opts.color == "none":
            self.color = RainbowColor(mode=RainbowColor.DISABLE)



    # this provides an sandbox where the variables
    # are made public, this a match can be coded
    # as "sackblocks > 2" instead of
    # "opts[foo].sackblocks > 2
    #
    # return color is match is True
    # return False if the packet should not displayed
    # return None if the packet should be displayed
    #        with no color change
    def match(self, ts, packet, packet_len, pi):

        # default is un-machted
        match = False

        # ip
        sip = pi.sip
        dip = pi.dip
        # tcp
        seq = pi.seq
        ack = pi.ack
        win = pi.win
        urp = pi.urp
        sum = pi.sum

        sport = pi.sport
        dport = pi.dport

        ack_flag = pi.is_ack_flag()
        syn_flag = pi.is_syn_flag()
        urg_flag = pi.is_urg_flag()
        psh_flag = pi.is_psh_flag()
        fin_flag = pi.is_fin_flag()
        rst_flag = pi.is_rst_flag()
        ece_flag = pi.is_ece_flag()
        cwr_flag = pi.is_cwr_flag()

        # tcp options
        mss        = pi.options['mss']
        wsc        = pi.options['wsc']
        tsval      = pi.options['tsval']
        tsecr      = pi.options['tsecr']
        sackok     = pi.options['sackok']
        sackblocks = pi.options['sackblocks']

        exec "if " + self.opts.match + ": match = True"

        if match:
            return self.color.color_palette['red']
        else:
            if self.opts.suppress:
                return False

        # dont change the color if nothing happends
        return self.color.color_palette['end']


    def seq_plus(self, seq, length):
        return seq + length

    def pre_process_packet(self, ts, packet):

        self.packet_no += 1

        sub_connection = self.cc.sub_connection_by_packet(packet)
        # only for TCP flows this can be true, therefore
        # no additional checks that this is TCP are required
        # here
        if not sub_connection:
            return

        # if the user applied a filter, we check it here
        if self.ids:
            if not sub_connection.is_in(self.ids):
                return

        # check if we already assigned a color to this
        # sub_connection, if not we do it now
        if self.opts.differentiate == "connection":
            if "color" not in sub_connection.connection.user_data:
                sub_connection.connection.user_data["color"] = \
                        self.color_iter.infinite_next()
        elif self.opts.differentiate == "flow":
            if "color" not in sub_connection.user_data:
                sub_connection.user_data["color"] = \
                        self.color_iter.infinite_next()

        pi = PacketInfo(packet)
        data_len = len(packet.data.data)
        time = Utils.ts_tofloat(ts - self.cc.capture_time_start)

        # color init
        if self.opts.differentiate == "connection":
            line = sub_connection.connection.user_data["color"]
        else:
            line = sub_connection.user_data["color"]

        if self.opts.match:
            line = self.match(time, packet, data_len, pi)
            if line == False:
                return

        if self.opts.packet_number:
            line += "%d %.5f" % (self.packet_no, time)
        else:
            line += "%.5f" % (time)

        line += " %s %s:%d > %s:%d" % (pi.ipversion,
                pi.sip, pi.sport, pi.dip, pi.dport)
        line += " Flags: %s" % (pi.create_flag_brakets())
        line += " seq: %u:%u ack: %u win: %u urp: %u" % (
                pi.seq, self.seq_plus(pi.seq, data_len),
                pi.ack, pi.win, pi.urp)
        line += " len: %d" % (len(packet.data.data))

        line += self.color["end"]
        line += "\n"

        sys.stdout.write(line)


    def pre_process_final(self):
        pass

    def process_packet(self, ts, packet):
        pass

    def process_final(self):
        pass


class SoundMod(Mod):

    PERIOD_DATA    = 1
    PERIOD_ACK     = 2
    PERIOD_GAP = 3

    FREQUENCY_DATA_START =  300
    FREQUENCY_DATA_END   = 1000

    FREQUENCY_ACK_START = 3500
    FREQUENCY_ACK_END = 5000

    FREQUENCY_STEP = 50

    class Sample: pass

    # helper class
    class WaveGenerator:

        def __init__(self, filename, samplerate=44100):
            self.filename   = filename
            self.samplerate = samplerate
            self.signal     = str()
            self.duration   = 0.0
            self.file       = wave.open(filename, 'wb')


        def add_sample(self, frequency, duration, volume=1.0):
            samples = int(float(duration) * self.samplerate)

            period = self.samplerate / float(frequency) # in sample points
            omega = numpy.pi * 2 / period

            xaxis = numpy.arange(samples, dtype = numpy.float)
            ydata = 32768 * numpy.sin(xaxis * omega)

            signal = numpy.resize(ydata, (samples,))

            self.signal += ''.join((wave.struct.pack('h', item) for item in signal))
            self.duration += duration


        def close(self):
            samples = int(float(self.duration) * self.samplerate)
            self.file.setparams((1, 2, self.samplerate,
                int(float(self.samplerate) * self.duration), 'NONE', 'noncompressed'))
            self.file.writeframes(self.signal)
            self.file.close()


    def pre_initialize(self):
        self.logger = logging.getLogger()
        self.parse_local_options()
        self.capture_time_start = None
        self.last_packet_plus_transmission = None
        self.frequency_data = SoundMod.FREQUENCY_DATA_START
        self.frequency_ack  = SoundMod.FREQUENCY_ACK_START
        self.packet_db  = list()

        if not numpy:
            self.logger.error("Python numpy module not installed - but required for sound")
            sys.exit(ExitCodes.EXIT_CMD_LINE)


    def parse_local_options(self):
        self.ids = False
        parser = optparse.OptionParser()
        parser.usage = "sound [options] <pcapfile>"
        parser.add_option( "-v", "--verbose", dest="loglevel", default=None,
                type="string", help="set the loglevel (info, debug, warning, error)")
        parser.add_option( "-f", "--data-flow", dest="connections", default=None,
                type="string", help="specify the number of relevant ID's")
        parser.add_option( "-m", "--mode", dest="mode", default="packets",
                type="string", help="display packets or bytes in flight (default packets)")
        parser.add_option( "-o", "--outfile", dest="filename", default="packets.wav",
                type="string", help="name of the generated wav file (default: packets.wav)")
        parser.add_option( "-i", "--duration-min", dest="duration_min", default=None,
                type="float", help="minimum length of sound sample in seconds")
        parser.add_option( "-a", "--duration-max", dest="duration_max", default=None,
                type="float", help="maximum length of sound sample in seconds")
        parser.add_option( "-b", "--bandwidth", dest="link_bandwidth", default=100000000.0,
                type="int", help="netto bandwith of channel in bit/s (default 100MB)")
        parser.add_option( "-c", "--accelerator", dest="accelerator", default=0.0001,
                type="float", help="accelerator, 0.0001 times faster is default")
        parser.add_option( "-r", "--cut-gap-periodes", dest="cut_gap_periodes", default=0.5,
                type="float", help="crop longer silence periodes to this, default 0.5")

        self.opts, args = parser.parse_args(sys.argv[0:])
        self.set_opts_logevel()
        
        if len(args) < 3:
            self.logger.error("no pcap file argument given, exiting")
            sys.exit(ExitCodes.EXIT_CMD_LINE)

        self.captcp.print_welcome()
        self.captcp.pcap_file_path = args[2]
        self.logger.info("pcap file: %s" % (self.captcp.pcap_file_path))

        if not self.opts.connections:
            self.logger.error("No data flow specified! Call \"captcp statistics for valid ID's\"")
            sys.exit(ExitCodes.EXIT_CMD_LINE)

        (self.connection_id, self.data_flow_id) = self.opts.connections.split('.')
        if int(self.data_flow_id) == 1:
            self.ack_flow_id = 2
        elif int(self.data_flow_id) == 2:
            self.ack_flow_id = 1
        else:
            raise ArgumentException("sub flow must be 1 or 2")

        sys.stderr.write("# connection: %s (data flow: %s, ACK flow: %s)\n" %
                (self.connection_id, self.data_flow_id, self.ack_flow_id))

        self.wg = SoundMod.WaveGenerator(self.opts.filename)


    def bound(self, duration):
        if self.opts.duration_min:
            duration = max(self.opts.duration_min, duration)
        if self.opts.duration_max:
            duration = min(self.opts.duration_max, duration)

        return duration


    def data_frequency(self):
        self.frequency_data += SoundMod.FREQUENCY_STEP
        if self.frequency_data > SoundMod.FREQUENCY_DATA_END:
            self.frequency_data = SoundMod.FREQUENCY_DATA_START
        return self.frequency_data

    def ack_frequency(self):
        self.frequency_ack += SoundMod.FREQUENCY_STEP
        if self.frequency_ack > SoundMod.FREQUENCY_ACK_END:
            self.frequency_ack = SoundMod.FREQUENCY_ACK_START
        return self.frequency_ack


    def calc_duration(self, packet):
        packet_len = (len(packet) + StatisticMod.ETHERNET_HEADER_LEN) * 8
        duration = 1.0 / (float(self.opts.link_bandwidth) / packet_len)
        return duration


    def add_silence(self, time):
        if not len(self.packet_db): return

        last_sample = self.packet_db[-1]
        assert(last_sample.end != time)

        if last_sample.end > time:
            self.logger.error(" time anomalie: last_sample: %lf  current time: %lf" %
                    (last_sample.end, time))
            return

        sample = SoundMod.Sample()
        sample.type  = SoundMod.PERIOD_GAP
        sample.start = last_sample.end
        sample.end   = time
        self.packet_db.append(sample)


    def account_packet(self, time, is_data_flow, packet):
        # if required (mostly), add silence period
        self.add_silence(time)

        sample = SoundMod.Sample()
        sample.type = SoundMod.PERIOD_DATA if is_data_flow else SoundMod.PERIOD_ACK
        # it can happend that the time from the last packet
        # is larger as time. But we cannot add a real clever solution
        # to this problem because we don't know the exact time. Something
        # went wrong and we did not know where it went wrong
        sample.start = time
        sample.end   = time + self.calc_duration(packet)
        self.packet_db.append(sample)


    def pre_process_packet(self, ts, packet):
        sub_connection = self.cc.sub_connection_by_packet(packet)
        if not sub_connection: return
        if not self.capture_time_start: self.capture_time_start = ts
        time = Utils.ts_tofloat(ts - self.capture_time_start)
        is_data_flow = None

        if sub_connection.sub_connection_id == int(self.data_flow_id):
            is_data_flow = True
        elif sub_connection.sub_connection_id == int(self.ack_flow_id):
            is_data_flow = False
        else:
            raise InternalException

        self.account_packet(time, is_data_flow, packet)


    def format_period(self, period):
        if period == SoundMod.PERIOD_DATA:
            return "DATA"
        if period == SoundMod.PERIOD_ACK:
            return " ACK"
        if period == SoundMod.PERIOD_GAP:
            return " GAP"


    def finish(self):

        times = dict()
        times[SoundMod.PERIOD_GAP]  = [0, 0.0]
        times[SoundMod.PERIOD_DATA] = [0, 0.0]
        times[SoundMod.PERIOD_ACK]  = [0, 0.0]

        for sample in self.packet_db:
            assert(sample.end >= sample.start)
            duration = sample.end - sample.start
            times[sample.type][0] += 1
            times[sample.type][1] += duration
            self.logger.error("%s start: %lfs  end: %lfs  duration: %lfs" %
                    (self.format_period(sample.type), sample.start, sample.end, duration))

            normalized_duration = duration / self.opts.accelerator
            self.logger.error("\t\tnormalized duration: %lfs" % (normalized_duration))

            if sample.type == SoundMod.PERIOD_GAP:
                normalized_duration = min(normalized_duration, self.opts.cut_gap_periodes)
                frequency = 2
            if sample.type == SoundMod.PERIOD_DATA:
                normalized_duration = self.bound(normalized_duration)
                frequency = self.data_frequency()
            if sample.type == SoundMod.PERIOD_ACK:
                normalized_duration = self.bound(normalized_duration)
                frequency = self.ack_frequency()

            self.logger.error("\t\tbounded duration: %lfs" % (normalized_duration))

            self.wg.add_sample(frequency, normalized_duration)


        sys.stderr.write("data time: %lfs, ack time: %lfs, silence time: %lfs\n" %
                (times[SoundMod.PERIOD_DATA][1], times[SoundMod.PERIOD_ACK][1],
                    times[SoundMod.PERIOD_GAP][1]))


    def process_final(self):
        self.finish()
        self.wg.close()
        sys.stderr.write("# [x,sr] = wavread('%s');\n" % (self.opts.filename))
        sys.stderr.write("# specgram(x,8192,sr); or\n")
        sys.stderr.write("# logfsgram(x,8192,sr);\n\n")
        sys.stderr.write("# wav -> mp3\n")
        sys.stderr.write("# ffmpeg -i packets.wav -vn -acodec libmp3lame packets.mp3\n")
        sys.stderr.write("# wav -> Ogg Vorbis\n")
        sys.stderr.write("# ffmpeg -i packets.wav -f ogg -acodec libvorbis -ab 192k packets.ogg\n")



class StatisticMod(Mod):

    ETHERNET_HEADER_LEN = 14

    LABEL_DB_INDEX_DESCRIPTION = 0
    LABEL_DB_INDEX_UNIT        = 1
    LABEL_DB_INDEX_INIT_VALUE  = 2

    LABEL_DB = {
        "packets-packets":        [ "Packets",        "packets", 0],

        "link-layer-byte":        [ "Data link layer",        "bytes  ", 0],
        "network-layer-byte":     [ "Data network layer",     "bytes  ", 0],
        "transport-layer-byte":   [ "Data transport layer",   "bytes  ", 0],
        "application-layer-byte": [ "Data application layer", "bytes  ", 0],

        "rexmt-data-bytes":      [ "Retransmissions",            "bytes  ",   0],
        "rexmt-data-packets":    [ "Retransmissions",            "packets",   0],
        "rexmt-bytes-percent":   [ "Retransmissions per byte",   "percent", 0.0],
        "rexmt-packets-percent": [ "Retransmissions per packet", "percent", 0.0],

        "pure-ack-packets": [ "ACK flag set but no payload", "packets", 0],
    }


    def pre_initialize(self):
        self.color = RainbowColor(mode=RainbowColor.ANSI)
        self.logger = logging.getLogger()
        self.parse_local_options()
        self.capture_level = CaptureLevel.NETWORK_LAYER


    def parse_local_options(self):
        parser = optparse.OptionParser()
        parser.add_option( "-v", "--verbose", dest="loglevel", default=None,
                type="string", help="set the loglevel (info, debug, warning, error)")
        parser.add_option( "-i", "--filter", dest="filter", default=None,
                type="string", help="limit number of displayed connections \"sip:sport-dip:dport\", default \"*:*-*:*\"")
        parser.add_option( "-m", "--format", dest="format", default=None,
                type="string", help="skip summary and display only selected values")

        self.opts, args = parser.parse_args(sys.argv[0:])
        self.set_opts_logevel()

        if self.opts.filter:
            self.opts.filter = self.opts.filter.split(",")
        else:
            self.opts.filter = list()
        
        if len(args) < 3:
            self.logger.error("no pcap file argument given, exiting")
            sys.exit(ExitCodes.EXIT_CMD_LINE)
 
        self.captcp.print_welcome()
        self.captcp.pcap_file_path = args[2]
        self.logger.info("pcapfile: \"%s\"" % self.captcp.pcap_file_path)


    def check_new_subconnection(self, sc):
        if len(sc.user_data): return

        # initialize the data values in a loop, e.g
        #   sc.user_data["link-layer-byte"] = 0
        #   [...]
        index = StatisticMod.LABEL_DB_INDEX_INIT_VALUE
        for key in self.LABEL_DB:
            sc.user_data[key] = self.LABEL_DB[key][index]

        # helper variables comes here, helper
        # variables are marked with a leading
        # underscore.
        sc.user_data["_highest_data_seen"] = None


    def type_to_label(self, label):
        return self.LABEL_DB[label][StatisticMod.LABEL_DB_INDEX_DESCRIPTION]


    def right(self, text, width):
        return text[:width].rjust(width)


    def center(self, text, width):
        return text[:width].center(width)


    def left(self, text, width):
        return text[:width].ljust(width)


    def calc_max_label_length(self):
        max_label_length = 0
        index = StatisticMod.LABEL_DB_INDEX_DESCRIPTION
        for i in self.LABEL_DB:
            max_label_length = max(max_label_length, len(str(self.LABEL_DB[i][index])))

        return max_label_length + 3


    def calc_max_data_length(self, statistic):
        max_data_length = 0
        index = StatisticMod.LABEL_DB_INDEX_UNIT
        for i in self.LABEL_DB:
            max_data_length = max(max_data_length,
                    len(str(statistic.user_data[i])) + len(self.LABEL_DB[i][index]))

        return max_data_length + 1


    def account_general_data(self, packet):
        if type(packet) == dpkt.ip.IP:
            self.cc.statistic.packets_nl_ipv4 += 1
        elif type(packet) == dpkt.ip6.IP6:
            self.cc.statistic.packets_nl_ipv6 += 1
        elif type(packet) == dpkt.arp.ARP:
            self.cc.statistic.packets_nl_arp += 1
            raise PacketNotSupportedException()
        else:
            self.cc.statistic.packets_nl_unknown += 1
            raise PacketNotSupportedException()

        if type(packet.data) == dpkt.tcp.TCP:
            self.cc.statistic.packets_tl_tcp += 1
        elif type(packet.data) == dpkt.udp.UDP:
            self.cc.statistic.packets_tl_udp += 1
            raise PacketNotSupportedException()
        elif type(packet.data) == dpkt.icmp.ICMP:
            self.cc.statistic.packets_tl_icmp += 1
            raise PacketNotSupportedException()
        elif type(packet.data) == dpkt.icmp6.ICMP6:
            self.cc.statistic.packets_tl_icmp6 += 1
            raise PacketNotSupportedException()
        else:
            self.cc.statistic.packets_tl_unknown += 1
            raise PacketNotSupportedException()


    def account_general_tcp_data(self, sc, packet):
        sc.user_data["packets-packets"] += 1

        sc.user_data["link-layer-byte"]        += len(packet) + StatisticMod.ETHERNET_HEADER_LEN
        sc.user_data["network-layer-byte"]     += int(len(packet))
        sc.user_data["transport-layer-byte"]   += int(len(packet.data))
        sc.user_data["application-layer-byte"] += int(len(packet.data.data))

        self.cc.statistic.packets_processed += 1


    def rexmt_final(self, sc):
        # called at the end of traxing to check values
        # or do some final calculations, based on intermediate
        # values
        res = U.percent(sc.user_data["rexmt-data-bytes"], sc.user_data["application-layer-byte"])
        sc.user_data["rexmt-bytes-percent"] = "%.2f" % (res)

        res = U.percent(sc.user_data["rexmt-data-packets"], sc.user_data["packets-packets"])
        sc.user_data["rexmt-packets-percent"] = "%.2f" % (res)


    def account_rexmt(self, sc, packet, pi):
        data_len = int(len(packet.data.data))

        actual_data = pi.seq + data_len

        if not sc.user_data["_highest_data_seen"]:
            # no rexmt possible, skip rexmt processing
            sc.user_data["_highest_data_seen"] = actual_data
            return

        if actual_data > sc.user_data["_highest_data_seen"]:
            # packet sequence number is highest sequence
            # number seen so far, no rexmt therefore
            sc.user_data["_highest_data_seen"] = actual_data
            return

        if data_len == 0:
            # no data packet, cannot be a retransmission
            return

        # ok, rexmt happened
        sc.user_data["rexmt-data-packets"] += 1
        
        # now account rexmt bytes, we add one to take care
        sc.user_data["rexmt-data-bytes"] += data_len


    def account_pure_ack(self, sc, packet, pi):
        if pi.is_ack_flag() and int(len(packet.data.data)) == 0:
            sc.user_data["pure-ack-packets"] += 1


    def account_tcp_data(self, sc, ts, packet, pi):
        self.account_rexmt(sc, packet, pi)
        self.account_pure_ack(sc, packet, pi)


    def pre_process_packet(self, ts, packet):
        try:
            self.account_general_data(packet)
        except PacketNotSupportedException:
            return

        sc = self.cc.sub_connection_by_packet(packet)
        if not sc: return InternalException()

        # make sure the data structure is initialized
        self.check_new_subconnection(sc)

        self.account_general_tcp_data(sc, packet)

        # .oO guaranteed TCP packet now
        pi = PacketInfo(packet)
        self.account_tcp_data(sc, ts, packet, pi)


    def print_one_column_sc_statistic(self, cid, sc):
        raise NotImplementedException("one flow connection not supported yet")


    def print_format_two_column(self, cid, statistic):
        sc1 = statistic[0]
        sc2 = statistic[1]

        left_width  = self.calc_max_label_length()
        right_width = max(self.calc_max_data_length(sc1), self.calc_max_data_length(sc2))

        # flow specific header per column
        # l1 = self.left("%d.1" % (cid), left_width)
        # r1 = self.right("%d.2" % (cid), right_width)
        # line_length = left_width + right_width + 1
        # sys.stdout.write("\t%s   %s\n" % (self.left("%s" % (l1), line_length), self.left("%s" % (r1), line_length)))

        ordere_list = [
                "packets-packets",

                "link-layer-byte",
                "network-layer-byte",
                "transport-layer-byte",
                "application-layer-byte",

                "rexmt-data-bytes",
                "rexmt-data-packets",
                "rexmt-bytes-percent",
                "rexmt-packets-percent",

                "pure-ack-packets",
        ]

        for i in ordere_list:
            l1 = self.left(self.type_to_label(i) + ":", left_width)
            r1 = self.right(str(sc1.user_data[i]) + " " + self.LABEL_DB[i][1], right_width)

            l2 = self.left(self.type_to_label(i) + ":", left_width)
            r2 = self.right(str(sc2.user_data[i])+ " " + self.LABEL_DB[i][1], right_width)

            line_length = left_width + right_width + 1

            sys.stdout.write("\t%s   %s\n" %
                    (self.left("%s %s" % (l1, r1), line_length), self.left("%s %s" % (l2, r2), line_length)))


    def format_human(self):
        one_percent = float(self.cc.statistic.packets_processed) / 100

        prct_nl_arp     = float(self.cc.statistic.packets_nl_arp) / one_percent
        prct_nl_ip      = float(self.cc.statistic.packets_nl_ipv4) / one_percent
        prct_nl_ipv6    = float(self.cc.statistic.packets_nl_ipv6) / one_percent
        prct_nl_unknown = float(self.cc.statistic.packets_nl_unknown) / one_percent

        prct_tl_tcp     = float(self.cc.statistic.packets_tl_tcp) / one_percent
        prct_tl_udp     = float(self.cc.statistic.packets_tl_udp) / one_percent
        prct_tl_icmp    = float(self.cc.statistic.packets_tl_icmp) / one_percent
        prct_tl_icmp6   = float(self.cc.statistic.packets_tl_icmp6) / one_percent
        prct_tl_unknown = float(self.cc.statistic.packets_tl_unknown) / one_percent


        sys.stdout.write("General:\n")

        sys.stdout.write("\tPackets processed: %5d (%7.2f%%)\n" %
                (self.cc.statistic.packets_processed, float(100)))

        sys.stdout.write("\tNetwork Layer\n")
        sys.stdout.write("\t   ARP:       %8d (%7.2f%%)\n" %
                (self.cc.statistic.packets_nl_arp, prct_nl_arp))
        sys.stdout.write("\t   IPv4:      %8d (%7.2f%%)\n" %
                (self.cc.statistic.packets_nl_ipv4, prct_nl_ip))
        sys.stdout.write("\t   IPv6:      %8d (%7.2f%%)\n" %
                (self.cc.statistic.packets_nl_ipv6, prct_nl_ipv6))
        sys.stdout.write("\t   Unknown:   %8d (%7.2f%%)\n" %
                (self.cc.statistic.packets_nl_unknown, prct_nl_unknown))

        sys.stdout.write("\tTransport Layer\n")
        sys.stdout.write("\t   TCP:       %8d (%7.2f%%)\n" %
                (self.cc.statistic.packets_tl_tcp, prct_tl_tcp))
        sys.stdout.write("\t   UDP:       %8d (%7.2f%%)\n" %
                (self.cc.statistic.packets_tl_udp, prct_tl_udp))
        sys.stdout.write("\t   ICMP:      %8d (%7.2f%%)\n" %
                (self.cc.statistic.packets_tl_icmp, prct_tl_icmp))
        sys.stdout.write("\t   ICMPv6:    %8d (%7.2f%%)\n" %
                (self.cc.statistic.packets_tl_icmp6, prct_tl_icmp6))
        sys.stdout.write("\t   Unknown:   %8d (%7.2f%%)\n" %
                (self.cc.statistic.packets_tl_unknown, prct_tl_unknown))

        sys.stdout.write("\nConnections:\n")

        # first we sort in an separate dict
        d = dict()
        for key in self.cc.container.keys():
            connection = self.cc.container[key]
            d[connection.connection_id] = connection

        for key in sorted(d.keys()):
            connection = d[key]
            sys.stdout.write("\n")
            sys.stdout.write("%s %d %s %s%s\n\n" % (self.color["red"], connection.connection_id,
                self.color["yellow"], connection, self.color["end"]))

            # statistic
            sys.stdout.write("\tPackets processed: %d (%.1f%%)\n" %
                    (connection.statistic.packets_processed,
                        float(connection.statistic.packets_processed) /
                        float(self.cc.statistic.packets_processed) * 100.0))

            sys.stdout.write("\n")

            if connection.sc1 and connection.sc2:
                sys.stdout.write("%s" % (self.color["yellow"]))
                sys.stdout.write("\tFlow %s.1:  %s" % (connection.connection_id, connection.sc1))
                sys.stdout.write("%s\n" % (self.color["end"]))

                sys.stdout.write("%s" % (self.color["green"]))
                sys.stdout.write("\tFlow %s.2:  %s" % (connection.connection_id, connection.sc2))
                sys.stdout.write("%s\n" % (self.color["end"]))

                self.print_format_two_column(connection.connection_id, [connection.sc1, connection.sc2])
            elif connection.sc1:
                sys.stdout.write("\tFlow %s.1:  %s\n" % (connection.connection_id, connection.sc1))
                self.print_one_column_sc_statistic(connection.connection_id, connection.sc1)
            else:
                raise InternalException("sc1 should be the only one here")

            sys.stdout.write("\n")


    def not_limited(self, connection):
        res = list()

        if len(self.opts.filter) <= 0:
            return True

        for filter in self.opts.filter:
            try:
                (stupple, dtupple) = filter.split("-")
                (sip, sport) = stupple.split(":")
                (dip, dport) = dtupple.split(":")
            except ValueError:
                self.logger.error("not a valid filter string: \"%s\"" % (filter))
                sys.exit(ExitCodes.EXIT_CMD_LINE)

            if sip != "*" and sip != connection.sip:
                res.append(True)
                continue
            if dip != "*" and dip != connection.dip:
                res.append(True)
                continue
            if sport != "*" and sport != connection.sport:
                res.append(True)
                continue
            if dport != "*" and dport != connection.dport:
                res.append(True)
                continue

            res.append(False)

        if False in res: return True
        return False


    def format_machine(self):
        for key in self.cc.container.keys():
            connection = self.cc.container[key]
            if connection.sc1:
                if self.not_limited(connection.sc1):
                    sys.stdout.write(self.opts.format % (connection.sc1.user_data))
                    sys.stdout.write("\n")
            if connection.sc2:
                if self.not_limited(connection.sc2):
                    sys.stdout.write(self.opts.format % (connection.sc2.user_data))
                    sys.stdout.write("\n")



    def process_final_data(self):
        # first we sort in an separate dict
        d = dict()
        for key in self.cc.container.keys():
            connection = self.cc.container[key]
            d[connection.connection_id] = connection

        for key in sorted(d.keys()):
            connection = d[key]
            if connection.sc1:
                self.rexmt_final(connection.sc1)
            if connection.sc2:
                self.rexmt_final(connection.sc2)


    def process_final(self):
        self.process_final_data()
        self.format_machine() if self.opts.format else self.format_human()


class Captcp:

    modes = {
            "geoip":           "Geoip",
            "payloadtimeport": "PayloadTimePortMod",
            "template":        "TemplateMod",
            "statistic":       "StatisticMod",
            "connection":      "ConnectionAnalyzeMod",
            "sequencegraph":   "SequenceGraphMod",
            "timesequence":    "TimeSequenceMod",
            "show":            "ShowMod",
            "throughput":      "ThroughputMod",
            "inflight":        "InFlightMod",
            "spacing":         "SpacingMod",
            "stacktrace":      "StackTraceMod",
            "sound":           "SoundMod"
            }

    def __init__(self):
        self.captcp_starttime = datetime.datetime.today()
        self.setup_logging()
        self.pcap_filter = None
        self.pcap_file_path = False

    def setup_logging(self):

        ch = logging.StreamHandler()

        formatter = logging.Formatter("# %(message)s")
        ch.setFormatter(formatter)

        self.logger = logging.getLogger()
        self.logger.setLevel(logging.WARNING)
        self.logger.addHandler(ch)


    def print_welcome(self):
        major, minor, micro, releaselevel, serial = sys.version_info
        self.logger.info("captcp 2010,2011 Hagen Paul Pfeifer (c)")
        self.logger.info("python: %s.%s.%s [releaselevel: %s, serial: %s]" %
                (major, minor, micro, releaselevel, serial))

    def print_modules(self):
        for i in Captcp.modes.keys():
            sys.stderr.write("    %s\n" % (i))

    def parse_global_otions(self):

        if len(sys.argv) <= 1:
            sys.stderr.write("Usage: " + sys.argv[0] + " <modulename> [options] pcapfile\n")
            sys.stderr.write("Available modules:\n")
            self.print_modules()
            return None

        submodule = sys.argv[1].lower()

        if submodule == "-h" or submodule == "--help":
            sys.stderr.write("Usage: captcp [-h] modulename [modulename-options] <pcap-file>\n")
            sys.stderr.write("Available modules:\n")
            self.print_modules()
            return None

        if submodule not in Captcp.modes:
            sys.stderr.write("Module \"%s\" not known, available modules are:\n" % (submodule))
            self.print_modules()
            return None

        classname = Captcp.modes[submodule]
        return classname


    def run(self):
        classtring = self.parse_global_otions()
        if not classtring:
            return 1


        classinstance = globals()[classtring]()
        classinstance.register_captcp(self)

        classinstance.pre_initialize()

        # there are other usages two (without pcap parsing)
        # We check here and if pcap_file_path is not true
        # then we assume a non-pcap module
        if self.pcap_file_path:
            # parse the whole pcap file first
            pcap_parser = PcapParser(self.pcap_file_path, self.pcap_filter)
            pcap_parser.register_callback(classinstance.internal_pre_process_packet)
            self.logger.debug("call pre_process_packet [1/4]")
            pcap_parser.run()
            del pcap_parser

            self.logger.debug("call pre_process_final [2/4]")
            classinstance.pre_process_final()

            # and finally print all relevant stuff
            pcap_parser = PcapParser(self.pcap_file_path, self.pcap_filter)
            pcap_parser.register_callback(classinstance.process_packet)
            self.logger.debug("call process_packet [3/4]")
            pcap_parser.run()
            del pcap_parser


        self.logger.debug("call pre_process_final [4/4]")
        ret = classinstance.process_final()

        time_diff = datetime.datetime.today() - self.captcp_starttime
        time_diff_s = float(time_diff.seconds) + time_diff.microseconds / 1E6 + time_diff.days * 86400
        self.logger.info("processing duration: %.4f seconds" % (time_diff_s))

        return ret



if __name__ == "__main__":
    try:
        captcp = Captcp()
        sys.exit(captcp.run())
    except KeyboardInterrupt:
        sys.stderr.write("SIGINT received, exiting\n")
