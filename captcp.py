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

# optional packages
try:
    import GeoIP
except ImportError:
    GeoIP = None

# required debian packages:
#   python-dpkt
#   python-pypcap 

__author__  = "Hagen Paul Pfeifer"
__version__ = "0.5"
__license__ = "GPLv3"


# TCP flag constants
TH_URG = dpkt.tcp.TH_URG
TH_ACK = dpkt.tcp.TH_ACK
TH_PSH = dpkt.tcp.TH_PUSH
TH_RST = dpkt.tcp.TH_RST
TH_SYN = dpkt.tcp.TH_SYN
TH_FIN = dpkt.tcp.TH_FIN

# Protocols
TCP = dpkt.tcp.TCP
UDP = dpkt.udp.UDP


class ExitCodes:
    EXIT_SUCCESS  = 0
    EXIT_ERROR    = 1
    EXIT_CMD_LINE = 2

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

        self.pcap_file = open(pcap_file_path)
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

            if type(packet.data) != dpkt.ip.IP:
                #sys.stderr.write("not ipv4 or ipv6 - ignoring\n")
                continue

            self.callback(ts, packet.data)

class Container:
    pass


class Template:

    payloadtimeport3d = \
"""
set pm3d map; set palette rgbformulae 30,31,32;
set xrange[0:4500]
set xlabel 'Time [s]'; set ylabel 'Diffraction angle'
splot '3ddata.dat' notitle
set terminal png large transparent size 600,500;
set out '3ddata.png'
"""

    gnuplot_makefile = \
"""
GNUPLOT_FILES = $(wildcard *.gpi)
PNG_OBJ = $(patsubst %.gpi,%.png,  $(GNUPLOT_FILES))
PDF_OBJ = $(patsubst %.gpi,%.pdf,  $(GNUPLOT_FILES))

all: $(PDF_OBJ)
png: $(PNG_OBJ)

%.eps: %.gpi data
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
	@rm -rf *.eps *.png *.pdf *.data core
"""

    def __init__(self, captcp):

        self.captcp = captcp
        self.parse_local_options()


    def parse_local_options(self):

        parser = optparse.OptionParser()

        parser.add_option(
                "-t",
                "--template",
                dest="template",
                default=None,
                type="string",
                help="template name")

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
        else:
            self.usage()

        return ExitCodes.EXIT_SUCCESS





class Geoip:

    def __init__(self, captcp):

        self.captcp = captcp
        self.parse_local_options()


    def parse_local_options(self):

        parser = optparse.OptionParser()
        parser.usage = "xx"
        parser.add_option(
                "-v",
                "--verbose",
                dest="verbose",
                default=False,
                action="store_true",
                help="show verbose")

        parser.add_option(
                "-p",
                "--port",
                dest="portnum",
                default=80,
                type="int",
                help="port number to run on")

        parser.add_option(
                "-m",
                "--match",
                dest="match",
                default=None,
                type="string",
                help="if statment is true the string is color in red")

        parser.add_option(
                "-s",
                "--suppress-other",
                dest="suppress",
                default=False,
                action="store_true",
                help="don't display other packets")

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
        parser.usage = "xx"
        parser.add_option(
                "-v",
                "--verbose",
                dest="verbose",
                default=False,
                action="store_true",
                help="show verbose")

        parser.add_option(
                "-f",
                "--format",
                dest="format",
                default="3ddata",
                type="string",
                help="the data format for gnuplot")

        parser.add_option(
                "-p",
                "--port",
                dest="port",
                default="sport",
                type="string",
                help="sport or dport")

        parser.add_option(
                "-s",
                "--sampling",
                dest="sampling",
                default=1,
                type="int",
                help="sampling rate (default: 5 seconds)")

        parser.add_option(
                "-o",
                "--outfile",
                dest="outfile",
                default="payload-time-port.data",
                type="string",
                help="name of the output file (default: payload-time-port.dat)")

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
                    print(str(time) + " " + str(port) + " " + str(avg))
                else:
                    print(str(time) + " " + str(port) + " " + str(PayloadTimePort.DEFAULT_VAL))

            print("\n")


    def run(self):
        
        sys.stderr.write("# initiate PayloadTimePort module\n")

        pcap_parser = PcapParser(self.pcap_file_path, self.pcap_filter)
        pcap_parser.register_callback(self.process_packet)
        pcap_parser.run()
        del pcap_parser

        self.print_data()

        return ExitCodes.EXIT_SUCCESS


class Highlight:

    def __init__(self, captcp):

        self.captcp = captcp
        self.tuppls = {}
        self.parse_local_options()


    def parse_local_options(self):

        parser = optparse.OptionParser()
        parser.usage = "xx"
        parser.add_option(
                "-v",
                "--verbose",
                dest="verbose",
                default=False,
                action="store_true",
                help="show verbose")

        parser.add_option(
                "-p",
                "--port",
                dest="portnum",
                default=80,
                type="int",
                help="port number to run on")

        parser.add_option(
                "-m",
                "--match",
                dest="match",
                default=None,
                type="string",
                help="if statment is true the string is color in red")

        parser.add_option(
                "-s",
                "--suppress-other",
                dest="suppress",
                default=False,
                action="store_true",
                help="don't display other packets")

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

        tcp_options = Container()
        tcp_options.mss = 0
        tcp_options.wsc = 0
        tcp_options.tsval = 0
        tcp_options.tsecr = 0
        tcp_options.sackok = False
        tcp_options.sackblocks = 0

        mss = 0
        wsc = 0
        tstamp = 0
        t2 = 0
        sackok = False
        sack = 0

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
        time = float(ts)

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

        sys.stdout.write(c + '%lf: %s:%d > %s:%d %s\n' % (
                float(ts),
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


class Captcp:

    modes = {
            "highlight": "Highlight",
            "geoip": "Geoip",
            "payloadtimeport": "PayloadTimePort",
            "template": "Template"
            }

    def print_welcome(self):
        major, minor, micro, releaselevel, serial = sys.version_info
        sys.stderr.write("# captcp 2010,2011 Hagen Paul Pfeifer (c)\n")
        sys.stderr.write("# python: %s.%s.%s [releaselevel: %s, serial: %s]\n" %
                (major, minor, micro, releaselevel, serial))


    def parse_global_otions(self):

        if len(sys.argv) <= 1:
            sys.stderr.write("usage: " + sys.argv[0] + " <modulename> [options] pcapfile [pcapfilter]\n")
            return None


        submodule = sys.argv[1]

        if submodule.lower() not in Captcp.modes:
            sys.stderr.write("module not known\n")
            return None

        classname = Captcp.modes[submodule.lower()]
        return classname


    def __init__(self):
        pass


    def run(self):
        classtring = self.parse_global_otions()
        if not classtring:
            return 1

        classinstance = globals()[classtring](self)
        return classinstance.run()



    
if __name__ == "__main__":
    captcp = Captcp()
    sys.exit(captcp.run())
