#!/usr/bin/python

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

# optional packages
try:
    import GeoIP
except ImportError:
    GeoIP = None

try:
    import cairo
except ImportError:
    cairo = None

pp = pprint.PrettyPrinter(indent=4)

# required debian packages:
#   python-dpkt
#   python-pypcap 

# optional debian packages:
#   python-geoip
#   python-cairo


__programm__ = "captcp"
__author__   = "Hagen Paul Pfeifer"
__version__  = "0.5"
__license__  = "GPLv3"

# custom exceptions
class ArgumentException(Exception): pass
class InternalSequenceException(Exception): pass
class InternalException(Exception): pass
class SequenceContainerException(InternalException): pass
class NotImplementedException(InternalException): pass


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


class UtilMod:
    
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
            i += 1
            self.color_palette[i] = '\033[38;5;%dm' % (i)

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


class Colors:

    colors = [
        '\033[92m',
        '\033[93m',
        '\033[94m',
        '\033[95m'
    ]

    RED = '\033[91m'

    start = -1

    ENDC    = '\033[0m'

    @staticmethod
    def next_color():
        Colors.start += 1
        return Colors.colors[Colors.start % len(Colors.colors)]


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

        for ts, pkt in self.pc:
            packet = self.decode(pkt)
            dt = datetime.datetime.fromtimestamp(ts)
            self.callback(dt, packet.data)


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
                self.options['sackblocks'] = struct.unpack(ofmt, d)
            elif o == dpkt.tcp.TCP_OPT_TIMESTAMP:
                (self.options['tsval'], self.options['tsecr']) = struct.unpack('>II', d)

            opts.append(o)


class Template:

    payloadtimeport3d = \
"""
set pm3d map; set palette rgbformulae 30,31,32;
set terminal postscript eps enhanced color "Times" 30
set output "plot.eps"
set style line 99 linetype 1 linecolor rgb "#999999" lw 2
set key right top
set key box linestyle 99
set key spacing 1.2
set grid xtics ytics mytics
set size 2
set style line 1 lc rgb '#000' lt 1 lw 5 pt 0 pi -1 ps 3
set style line 2 lc rgb '#000' lt 5 lw 5 pt 0 pi -1 ps 3
set style line 4 lt -1 pi -4 pt 6 lw 2 ps 2
set style line 5 lt -1 pi -3 pt 4 lw 2 ps 2
set xrange[0:1500]
set xlabel 'Time [s]';
set ylabel 'Diffraction angle'
splot 'out.data' notitle
"""
    throughput = \
"""
set terminal postscript eps enhanced color "Times" 30
set output "throughput.eps"
set title "Throughput Graph"

set style line 99 linetype 1 linecolor rgb "#999999" lw 2
set key right bottom
set key box linestyle 99
set key spacing 1.2
set nokey

set grid xtics ytics mytics

#set xrange [1:60]

set size 2
set size ratio 0.4

set ylabel "Data [byte]"
set xlabel "Time [seconds]"

set style line 1 lc rgb '#0060ad' lt 1 lw 10 pt 0 pi -1 ps 3
set style line 2 lc rgb '#0060ad' lt 1 lw 10 pt 7 ps 3.5

# grayscale
set style line 1 lc rgb '#000' lt 1 pi 0 pt 6 lw 8 ps 4

plot \
  "throughput.data" using 1:2 title "rtt" with linespoints ls 1
"""


    gnuplot_makefile = \
"""
GNUPLOT_FILES = $(wildcard *.gpi)
PNG_OBJ = $(patsubst %.gpi,%.png,  $(GNUPLOT_FILES))
PDF_OBJ = $(patsubst %.gpi,%.pdf,  $(GNUPLOT_FILES))

all: $(PDF_OBJ)
png: $(PNG_OBJ)

%.eps: %.gpi
	@ echo "compillation of "$<
	@gnuplot $<

%.pdf: %.eps 
	@echo "conversion in pdf format"
	@epstopdf --outfile=$*.pdf $<
	@echo "end"

%.png: %.pdf
	@echo "conversion in png format"
	@convert -density 300 $< $*.png 
	@echo "end"

preview: all
	for i in $$(ls *.pdf); do xpdf -fullscreen $$i ; done

clean:
	@echo "cleaning ..."
	@rm -rf *.eps *.png *.pdf core

distclean: clean
	@echo "distcleaning"
	@rm -rf *.data
"""

    def __init__(self, captcp):

        self.captcp = captcp
        self.parse_local_options()

    def parse_local_options(self):
        parser = optparse.OptionParser()
        parser.add_option( "-t", "--template", dest="template", default=None,
                type="string", help="template name")

        self.opts, args = parser.parse_args(sys.argv[0:])
        
        if not self.opts.template:
            sys.stderr.write("no template name given, exiting\n")
            sys.exit(ExitCodes.EXIT_CMD_LINE)

    def usage(self):

        sys.stderr.write("""supported modules:
        payload-time-port-3d
        gnuplot-makefile
        \n""")

    def run(self):
        if self.opts.template == "payload-time-port-3d":
            sys.stdout.write(Template.payloadtimeport3d)
        elif self.opts.template == "gnuplot-makefile":
            sys.stdout.write(Template.gnuplot_makefile)
        elif self.opts.template == "throughput":
            sys.stdout.write(Template.throughput)
        else:
            self.usage()

        return ExitCodes.EXIT_SUCCESS



class Geoip:

    def __init__(self, captcp):

        self.captcp = captcp
        self.parse_local_options()


    def parse_local_options(self):

        parser = optparse.OptionParser()
        parser.usage = "geoip"
        parser.add_option( "-v", "--verbose", dest="verbose", default=False,
                action="store_true", help="show verbose")

        parser.add_option( "-p", "--port", dest="portnum", default=80,
                type="int", help="port number to run on")

        parser.add_option( "-m", "--match", dest="match", default=None,
                type="string", help="if statment is true the string is color in red")

        parser.add_option( "-s", "--suppress-other", dest="suppress", default=False,
                action="store_true", help="don't display other packets")

        self.opts, args = parser.parse_args(sys.argv[0:])
        
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



class PayloadTimePort:

    PORT_START = 0
    PORT_END   = 65535
    DEFAULT_VAL = 0.0


    def __init__(self, captcp):
        self.captcp = captcp
        self.parse_local_options()
        self.data = dict()
        self.trace_start = None


    def parse_local_options(self):
        parser = optparse.OptionParser()
        parser.usage = "payloadtimeport"
        parser.add_option( "-v", "--verbose", dest="verbose", default=False,
                action="store_true", help="show verbose")

        parser.add_option( "-f", "--format", dest="format", default="3ddata",
                type="string", help="the data format for gnuplot")

        parser.add_option( "-p", "--port", dest="port", default="sport",
                type="string", help="sport or dport")

        parser.add_option( "-s", "--sampling", dest="sampling", default=1,
                type="int", help="sampling rate (default: 5 seconds)")

        parser.add_option( "-o", "--outfile", dest="outfile", default="payload-time-port.data",
                type="string", help="name of the output file (default: payload-time-port.dat)")

        self.opts, args = parser.parse_args(sys.argv[0:])
        
        if len(args) < 3:
            sys.stderr.write("no pcap file argument given, exiting\n")
            sys.exit(ExitCodes.EXIT_CMD_LINE)
 
        if not self.opts.verbose:
            sys.stderr = open(os.devnull, 'w')
        
        self.captcp.print_welcome()

        self.pcap_file_path = args[2]
        sys.stderr.write("# pcapfile: \"%s\"\n" % self.pcap_file_path)

        self.pcap_filter = None
        if args[3:]:
            self.pcap_filter = " ".join(args[3:])
            sys.stderr.write("# pcap filter: \"" + self.pcap_filter + "\"\n")


    def process_packet(self, ts, packet):
        ip = packet
        tcp = packet.data

        if type(tcp) != TCP:
            return

        time = float(ts)

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
 

    def print_data(self):
        for timesortedtupel in sorted(self.data.iteritems(), key = lambda (k,v): float(k)):
            time = timesortedtupel[0]
            
            for port in range(PayloadTimePort.PORT_END + 1):

                if port in timesortedtupel[1]:
                    avg = float(timesortedtupel[1][port]["sum"]) / float(timesortedtupel[1][port]["cnt"])
                    sys.stdout.write(str(time) + " " + str(port) + " " + str(avg) + "\n")
                else:
                    sys.stdout.write(str(time) + " " + str(port) + " " + str(PayloadTimePort.DEFAULT_VAL) + "\n")

            sys.stdout.write("\n")


    def run(self):
        
        sys.stderr.write("# initiate PayloadTimePort module\n")

        pcap_parser = PcapParser(self.pcap_file_path, self.pcap_filter)
        pcap_parser.register_callback(self.process_packet)
        pcap_parser.run()
        del pcap_parser

        self.print_data()

        return ExitCodes.EXIT_SUCCESS


class Highlight:

    class Container: pass

    def __init__(self, captcp):

        self.captcp = captcp
        self.tuppls = {}
        self.parse_local_options()


    def parse_local_options(self):

        parser = optparse.OptionParser()
        parser.usage = "xx"
        parser.add_option( "-v", "--verbose", dest="verbose", default=False,
                action="store_true", help="show verbose")

        parser.add_option( "-p", "--port", dest="portnum", default=80,
                type="int", help="port number to run on")

        parser.add_option( "-m", "--match", dest="match", default=None,
                type="string", help="if statment is true the string is color in red")

        parser.add_option( "-s", "--suppress-other", dest="suppress", default=False,
                action="store_true", help="don't display other packets")

        self.opts, args = parser.parse_args(sys.argv[0:])
        
        if len(args) < 3:
            sys.stderr.write("no pcap file argument given, exiting\n")
            sys.exit(ExitCodes.EXIT_CMD_LINE)
 
        if not self.opts.verbose:
            sys.stderr = open(os.devnull, 'w')
        
        self.captcp.print_welcome()

        self.pcap_file_path = args[2]
        sys.stderr.write("# pcapfile: \"%s\"\n" % self.pcap_file_path)

        self.pcap_filter = None
        if args[3:]:
            self.pcap_filter = " ".join(args[3:])
            sys.stderr.write("# pcap filter: \"" + self.pcap_filter + "\"\n")


    def parse_tcp_options(self, tcp):

        tcp_options = Highlight.Container()
        tcp_options.mss = 0
        tcp_options.wsc = 0
        tcp_options.tsval = 0
        tcp_options.tsecr = 0
        tcp_options.sackok = False
        tcp_options.sackblocks = 0

        mss = wsc = tstamp = t2 = sack = 0
        sackok = False

        opts = []
        for opt in dpkt.tcp.parse_opts(tcp.opts):
            try:
                o, d = opt
                if len(d) > 32: raise TypeError
            except TypeError:
                break
            if o == dpkt.tcp.TCP_OPT_MSS:
                mss = struct.unpack('>H', d)[0]
                tcp_options.mss = mss
            elif o == dpkt.tcp.TCP_OPT_WSCALE:
                wsc = ord(d)
                tcp_options.wsc = wsc
            elif o == dpkt.tcp.TCP_OPT_SACKOK:
                sackok = True
                tcp_options.sackok = True
            elif o == dpkt.tcp.TCP_OPT_SACK:
                sack_blocks = int(len(d) / 4)
                tcp_options.sackblocks = sack_blocks
                ofmt="!%sI" % sack_blocks
                sack = struct.unpack(ofmt, d)
            elif o == dpkt.tcp.TCP_OPT_TIMESTAMP:
                tstamp = struct.unpack('>II', d)
                tcp_options.tsval = tstamp[0]
                tcp_options.tsecr = tstamp[1]

            opts.append(o)

        return {
                'opts':opts,
                'mss':mss,
                'wss':tcp.win,
                'wsc':wsc,
                'sackok':sackok,
                'sack':sack,
                'tstamp':tstamp,
                't2':t2,
                'tcp_options':tcp_options}

    def create_connection_tupple(self, ip):

        tuppl = "%s-%s-%d-%d" % (
                Converter.dpkt_addr_to_string(ip.src),
                Converter.dpkt_addr_to_string(ip.dst),
                int(ip.data.sport),
                int(ip.data.dport))

        return tuppl


    def pre_process_packet(self, ts, packet):

        ip  = packet
        tcp = packet.data

        if type(tcp) != TCP:
            return

        tuppl = self.create_connection_tupple(ip)
        
        if tuppl in self.tuppls:
            return

        self.tuppls[tuppl] = {}
        self.tuppls[tuppl]["color"] = Colors.next_color()


    def process_packet(self, ts, packet):

        ip = packet
        tcp = packet.data

        if type(tcp) != TCP:
            return
 

        seq  = int(tcp.seq)
        ack  = int(tcp.ack)

        tuppl = self.create_connection_tupple(ip)


        opts = self.parse_tcp_options(tcp)
        optionss = "[options: "
        if opts["wsc"]:
            optionss += "wscale %d " % (opts["wsc"])
        if opts["sackok"]:
            optionss += "sackOK "
        if opts["mss"]:
            optionss += "mss %s "  % (opts["mss"])
        if opts["tstamp"]:
            optionss += "tstamp %d:%d" % (opts["tstamp"][0], opts["tstamp"][1])
        if opts["sack"]:
            optionss += "sack %d " % (len(opts["sack"]) / 2)
            for i in range(len(opts["sack"])):
                if i % 2 == 0:
                    optionss += "{"
                optionss += "%d" % (opts["sack"][i])
                if i % 2 == 0:
                    optionss += ":"
                if i % 2 == 1:
                    optionss += "} "

        optionss += "]"

        c = self.tuppls[tuppl]["color"]
        options = opts["tcp_options"]

        ip.src = Converter.dpkt_addr_to_string(ip.src)
        ip.dst = Converter.dpkt_addr_to_string(ip.dst)
        dport  = int(tcp.dport)
        sport  = int(tcp.sport)

        match = False

        if self.opts.match:
            exec "if " + self.opts.match + ": match = True"

        if match:
            c = Colors.RED
        else:
            if self.opts.suppress:
                return

        sys.stdout.write(c + '%s: %s:%d > %s:%d %s\n' % (
                ts,
                ip.src,
                tcp.sport,
                ip.dst,
                tcp.dport,
                optionss)
                + Colors.ENDC)


    def run(self):
        
        sys.stderr.write("# initiate highlight module\n")

        # parse the whole pcap file first
        pcap_parser = PcapParser(self.pcap_file_path, self.pcap_filter)
        pcap_parser.register_callback(self.pre_process_packet)
        pcap_parser.run()
        del pcap_parser

        # and finally print all relevant stuff
        pcap_parser = PcapParser(self.pcap_file_path, self.pcap_filter)
        pcap_parser.register_callback(self.process_packet)
        pcap_parser.run()
        del pcap_parser

        return ExitCodes.EXIT_SUCCESS


class Mod:

    def register_captcp(self, captcp):
        self.captcp = captcp

    def __init__(self):
        self.captcp = None
        self.cc = ConnectionContainer()

    def internal_pre_process_packet(self, ts, packet):
        """ this is a hidden preprocessing function, called for every packet"""
        assert(self.captcp != None)
        self.cc.update(ts, packet)
        self.pre_process_packet(ts, packet)

    def pre_initialize(self):
        """ called at the very beginning of module lifetime"""
        pass

    def pre_process_final(self):
        """ single call between pre_process_packet and process_packet to do some calc"""
        pass

    def pre_process_packet(self, ts, packet):
        """ final packet round"""
        pass

    def process_packet(self, ts, packet):
        """ final packet round"""
        pass

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

                self.logger.debug("calculate page coordinated ans scale factor")

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

        parser.add_option( "-v", "--loglevel", dest="loglevel", default=None,
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
        self.packets_processed = 0


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
        self.packets_processed = 0


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
        self.statistic.packets_processed += 1


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
        
        if len(args) < 3:
            self.logger.error("no pcap file argument given, exiting\n")
            sys.exit(ExitCodes.EXIT_CMD_LINE)
 
        self.captcp.pcap_file_path = args[2]

        self.captcp.pcap_filter = None
        if args[3:]:
            self.captcp.pcap_filter = " ".join(args[3:])
            self.logger.info("pcap filter: \"" + self.captcp.pcap_filter + "\"")


    def process_final(self):

        sys.stdout.write("digraph G {\nranksep=3.0;\nnodesep=2.0;\n")
        # sys.stdout.write("\nsize=\"7.75,10.25\";\n orientation=\"landscape\"")

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


    def pre_initialize(self):

        self.logger = logging.getLogger()
        self.parse_local_options()
        self.start_time = False

    def parse_local_options(self):

        self.ids = False

        parser = optparse.OptionParser()
        parser.usage = "show [options] <pcapfile> [pcapfilter]"

        parser.add_option( "-v", "--loglevel", dest="loglevel", default=None,
                type="string", help="set the loglevel (info, debug, warning, error)")

        parser.add_option( "-i", "--connection-id", dest="connections", default=None,
                type="string", help="specify the number of displayed ID's")

        parser.add_option( "-s", "--samplelenght", dest="samplelenght", default=1.0,
                type="float", help="length in seconds (float) where data is accumulated (1.0)")

        parser.add_option( "-m", "--mode", dest="mode", default="goodput",
                type="string", help="layer where the data len measurement is taken (default: goodput")

        parser.add_option( "-u", "--unit", dest="unit", default="byte",
                type="string", help="unit: byte, kbyte, mbyte")

        self.opts, args = parser.parse_args(sys.argv[0:])
        self.set_opts_logevel()
        
        if len(args) < 3:
            self.logger.error("no pcap file argument given, exiting\n")
            sys.exit(ExitCodes.EXIT_CMD_LINE)

        self.captcp.print_welcome()

        self.captcp.pcap_file_path = args[2]
        self.logger.info("pcap file: %s" % (self.captcp.pcap_file_path))

        if self.opts.connections:
            self.ids = self.opts.connections.split(',')
            self.logger.info("show limited to the following connections: %s" % (str(self.ids)))


    def pre_process_packet(self, ts, packet):

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

        pi = PacketInfo(packet)

        if self.opts.mode == "goodput":
            data_len = len(packet.data.data)
        else:
            raise NotImplementedException("only goodput mode is supported")

        # time handling
        if not self.start_time:
            self.start_time = ts
            self.last_sample = 0.0
            self.data = 0
            #line += "%.5f" % (Utils.ts_tofloat(time))

        timediff = Utils.ts_tofloat(ts - self.start_time)

        self.data += data_len

        if timediff > self.last_sample + self.opts.samplelenght:

            amount = UtilMod.byte_to_unit(self.data, self.opts.unit)

            # time to print the data
            sys.stdout.write("%.5f %.3f\n" % (self.last_sample + self.opts.samplelenght,
                amount))
            self.data  = 0

            self.last_sample += self.opts.samplelenght
        




class ShowMod(Mod):


    def pre_initialize(self):

        self.logger = logging.getLogger()
        self.parse_local_options()
        self.color = RainbowColor(mode=RainbowColor.ANSI256)
        self.color_iter = self.color.__iter__()

    def parse_local_options(self):

        self.ids = False

        parser = optparse.OptionParser()
        parser.usage = "show [options] <pcapfile> [pcapfilter]"

        parser.add_option( "-v", "--loglevel", dest="loglevel", default=None,
                type="string", help="set the loglevel (info, debug, warning, error)")

        parser.add_option( "-i", "--connection-id", dest="connections", default=None,
                type="string", help="specify the number of displayed ID's")

        parser.add_option( "-d", "--differentiate", dest="differentiate", default="connection",
                type="string", help="specify if connection or sub-connections should be colored")

        parser.add_option( "-m", "--match", dest="match", default=None,
                type="string", help="if statment is true the string is color in red")

        self.opts, args = parser.parse_args(sys.argv[0:])
        self.set_opts_logevel()
        
        if len(args) < 3:
            self.logger.error("no pcap file argument given, exiting\n")
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

        if self.opts.differentiate != "connection" and self.opts.differentiate != "sub-connection":
            self.logger.error("only connection or sub-connection allowed for --d")
            sys.exit(ExitCodes.EXIT_CMD_LINE)
            

    def match(self, ts, packet):
        pass


    def seq_plus(self, seq, length):
        return seq + length

    def pre_process_packet(self, ts, packet):

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
        elif self.opts.differentiate == "sub-connection":
            if "color" not in sub_connection.user_data:
                sub_connection.user_data["color"] = \
                        self.color_iter.infinite_next()

        pi = PacketInfo(packet)
        data_len = len(packet.data.data)


        # color init
        if self.opts.differentiate == "connection":
            line = sub_connection.connection.user_data["color"]
        else:
            line = sub_connection.user_data["color"]

        # time handling
        time = ts - self.cc.capture_time_start
        line += "%.5f" % (Utils.ts_tofloat(time))

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



class StatisticMod(Mod):


    def pre_initialize(self):
        self.color = RainbowColor(mode=RainbowColor.ANSI)
        self.logger = logging.getLogger()
        self.parse_local_options()

    def parse_local_options(self):

        parser = optparse.OptionParser()
        parser.usage = "xx"
        parser.add_option( "-v", "--verbose", dest="verbose", default=False,
                action="store_true", help="show verbose")

        parser.add_option( "-p", "--port", dest="portnum", default=80,
                type="int", help="port number to run on")

        self.opts, args = parser.parse_args(sys.argv[0:])
        
        if len(args) < 3:
            self.logger.error("no pcap file argument given, exiting\n")
            sys.exit(ExitCodes.EXIT_CMD_LINE)
 
        self.captcp.print_welcome()

        self.captcp.pcap_file_path = args[2]
        self.logger.info("pcapfile: \"%s\"" % self.captcp.pcap_file_path)

        self.captcp.pcap_filter = None
        if args[3:]:
            self.captcp.pcap_filter = " ".join(args[3:])
            self.logger.info("pcap filter: \"" + self.captcp.pcap_filter + "\"")



    def pre_process_packet(self, ts, packet):

        self.cc.statistic.packets_processed += 1

        if type(packet) == dpkt.ip.IP:
            self.cc.statistic.packets_nl_ipv4 += 1
        elif type(packet) == dpkt.ip6.IP6:
            self.cc.statistic.packets_nl_ipv6 += 1
        elif type(packet) == dpkt.arp.ARP:
            self.cc.statistic.packets_nl_arp += 1
            return
        else:
            self.cc.statistic.packets_nl_unknown += 1
            return

        if type(packet.data) == dpkt.tcp.TCP:
            self.cc.statistic.packets_tl_tcp += 1
        elif type(packet.data) == dpkt.udp.UDP:
            self.cc.statistic.packets_tl_udp += 1
            return
        elif type(packet.data) == dpkt.icmp.ICMP:
            self.cc.statistic.packets_tl_icmp += 1
            return
        elif type(packet.data) == dpkt.icmp6.ICMP6:
            self.cc.statistic.packets_tl_icmp6 += 1
            return
        else:
            self.cc.statistic.packets_tl_unknown += 1
            return


    def pre_process_final(self):
        pass

    def process_packet(self, ts, packet):
        pass


    def print_two_column_sc_statistic(self, cid, sc1, sc2):
        sys.stdout.write("\n\tFlow %s.1                          Flow %s.2\n" % (cid, cid))
        sys.stdout.write("\tPackets: %-10d    \t\tPackets: %d\n" %
                (sc1.statistic.packets_processed, sc2.statistic.packets_processed))

    def print_one_column_sc_statistic(self, cid, sc):

        sys.stdout.write("\n\tFlow %s.1\n" % (cid))
        sys.stdout.write("\t\tPackets: %d\n" % (sc.statistic.packets_processed))


    def process_final(self):

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

        sys.stdout.write("\tPackets processed: %5d (%7.3f%%)\n" % (self.cc.statistic.packets_processed, float(100)))

        sys.stdout.write("\tNetwork Layer\n")
        sys.stdout.write("\t   ARP:       %8d (%7.3f%%)\n" % (self.cc.statistic.packets_nl_arp, prct_nl_arp))
        sys.stdout.write("\t   IPv4:      %8d (%7.3f%%)\n" % (self.cc.statistic.packets_nl_ipv4, prct_nl_ip))
        sys.stdout.write("\t   IPv6:      %8d (%7.3f%%)\n" % (self.cc.statistic.packets_nl_ipv6, prct_nl_ipv6))
        sys.stdout.write("\t   Unknown:   %8d (%7.3f%%)\n" % (self.cc.statistic.packets_nl_unknown, prct_nl_unknown))

        sys.stdout.write("\tTransport Layer\n")
        sys.stdout.write("\t   TCP:       %8d (%7.3f%%)\n" % (self.cc.statistic.packets_tl_tcp, prct_tl_tcp))
        sys.stdout.write("\t   UDP:       %8d (%7.3f%%)\n" % (self.cc.statistic.packets_tl_udp, prct_tl_udp))
        sys.stdout.write("\t   ICMP:      %8d (%7.3f%%)\n" % (self.cc.statistic.packets_tl_icmp, prct_tl_icmp))
        sys.stdout.write("\t   ICMPv6:    %8d (%7.3f%%)\n" % (self.cc.statistic.packets_tl_icmp6, prct_tl_icmp6))
        sys.stdout.write("\t   Unknown:   %8d (%7.3f%%)\n" % (self.cc.statistic.packets_tl_unknown, prct_tl_unknown))

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
            sys.stdout.write("\tPackets received: %d\n" % (connection.statistic.packets_processed))

            sys.stdout.write("\n")

            if connection.sc1 and connection.sc2:
                sys.stdout.write("\tFlow %s.1:  %s\n" % (connection.connection_id, connection.sc1))
                sys.stdout.write("\tFlow %s.2:  %s\n" % (connection.connection_id, connection.sc2))
                self.print_two_column_sc_statistic(connection.connection_id, connection.sc1, connection.sc2)
            elif connection.sc1:
                sys.stdout.write("\tFlow %s.1:  %s\n" % (connection.connection_id, connection.sc1))
                self.print_one_column_sc_statistic(connection.connection_id, connection.sc1)
            else:
                raise InternalException("sc1 should be the only one here")


            sys.stdout.write("\n")


class Captcp:

    modes = {
            "highlight":       "Highlight",
            "geoip":           "Geoip",
            "payloadtimeport": "PayloadTimePort",
            "template":        "Template",
            "statistic":       "StatisticMod",
            "connection":      "ConnectionAnalyzeMod",
            "sequencegraph":   "SequenceGraphMod",
            "show":            "ShowMod",
            "throughtput":     "ThroughputMod"
            }

    def __init__(self):
        self.captcp_starttime = datetime.datetime.today()
        self.setup_logging()
        self.pcap_filter = None

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

        if (classtring == "StatisticMod" or
                classtring == "ConnectionAnalyzeMod" or
                classtring == "ShowMod" or
                classtring == "ThroughputMod" or
                classtring == "SequenceGraphMod"):

            classinstance = globals()[classtring]()
            classinstance.register_captcp(self)

            classinstance.pre_initialize()

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


        else:
            classinstance = globals()[classtring](self)
            return classinstance.run()



if __name__ == "__main__":
    try:
        captcp = Captcp()
        sys.exit(captcp.run())
    except KeyboardInterrupt:
        sys.stderr.write("SIGINT received, exiting\n")
