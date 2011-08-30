#!/usr/bin/python

from __future__ import print_function


import sys
import os
import logging
import optparse

__author__  = "Hagen Paul Pfeifer"
__version__ = "0.5"
__license__ = "GPLv3"

class ExitCodes:
    EXIT_SUCCESS  = 0
    EXIT_ERROR    = 1
    EXIT_CMD_LINE = 2


class Highlight:

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
                "-e",
                "--eval",
                dest="eval",
                default=None,
                type="string",
                help="evaluated string to color in red")

        self.opts, args = parser.parse_args(sys.argv[0:])
        
        if len(args) < 3:
            sys.stderr.write("no pcap file argument given, exiting\n")
            sys.exit(ExitCodes.EXIT_CMD_LINE)
 
        if not self.opts.verbose:
            sys.stderr = open(os.devnull, 'w')
        
        self.captcp.print_welcome()

        self.pcap_file_path = args[2]
        sys.stderr.write("# pcapfile: \"%s\"\n" % self.pcap_file_path)

        if args[3:]:
            self.filter = " ".join(args[3:])
            sys.stderr.write("# pcap filter: \"" + self.filter + "\"\n")


    def run(self):
        
        sys.stderr.write("# initiate Highlight module\n")

        return ExitCodes.EXIT_SUCCESS


class Captcp:

    modes = {
            "highlight": "Highlight"
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
