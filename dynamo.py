#!/usr/bin/python

import getpass
from InfobloxAPI import InfobloxAPI
import json
from optparse import OptionParser, OptionGroup
import os
import re
import sys

versionstr = "%prog 1.0"

debug   = False
verbose = False
opt     = {}

gridmgr = '10.69.15.170'

# Remove hardcode
allowed_ranges  = [ '10.39.2.0/23',
                    '10.39.32.0/24',
		'192.168.255.24/29'
                    ]

# Remove hardcode
allowed_domains = [ 'ci.snops.net',
                    'ops.sn.corp',
                    'snops.net',
		'unittest.sn.corp'
                    ]

def main():
    global opt, debug, verbose

    # most cli optnios available in global hash opt; e.g., opt['hostname']
    get_options()

    wapi = InfobloxAPI(gridmgr, opt['uid'], opt['passwd'], 
                       debug=debug, verbose=verbose, verify=False)

    r = { }  # r will hold response from wapi calls

    if not opt['noaction']:
        r = wapi.rh_add( opt['iprange'],
                         wapi.next_available_ip(opt['iprange']),
                         opt['hostname'] )
    else:
        print "Bailing due to noaction flag."
        return 1

    if not r:
        print "Unknown error in WAPI call."
        return 0
    

    r['iprange'] = opt['iprange']
    return print_output(r)


def print_output(r):
    if opt['outputtype'].lower() == "user":
        print "Assigning " + r['ipaddr'] + " to " + r['name'] + "."
    elif opt['outputtype'].lower() == "json":
        print json.dumps( { 'hostname'  : r['name'],
                            'ipaddress' : r['ipaddr'],
                            'iprange'   : r['iprange'] } )
    elif outputtype.lower() == "xml":
        print "Sorry, XML not supported yet..."
        return 1

    return 0

def get_options():
    global debug, verbose, opt

    usage = "Usage: %prog [options] <FQDN to register> <IP range>"
    epilog = """
-----------------------------------------------------------------------------
Assigns the hostname <FQDN to register> to the first available IP
address in <IP range>.
-----------------------------------------------------------------------------
Examples:

> dynamo.py heyd.snops.net 10.39.32.0/24 --username 123456 --password "p@ssw0rd"
Assigning 10.39.32.32 to heyd.snops.net.

> dynamo.py heye.snops.net 10.39.32.0/24 --username 123456 --password "p@ssw0rd" --output json
{"hostname": "heye.snops.net", "ipaddress": "10.39.32.33", "iprange": "10.39.32.0/24"}

"""
    # Set up format_epilog to not strip newlines
    OptionParser.format_epilog = lambda self, formatter: self.epilog
    parser = OptionParser(usage=usage, epilog=epilog, version=versionstr)

    parser.add_option("-d", "--debug", dest="debug", default=False,
                      help="Debugging output to STDERR", action="store_true")
    parser.add_option("-v", "--verbose", dest="verbose", default=False,
                      help="Verbose output to STDERR", action="store_true")
    parser.add_option("--noaction", dest="noaction", default=False,
                      help="Don't make any changes", action="store_true")

    pgLogin   = OptionGroup(parser, "Infoblox Login Options",
                          "These are your Infoblox login; probably AD.")
    pgLogin.add_option("-p", "--password", dest="password",
                      help="Your password.  Will prompt if not provided.")
    pgLogin.add_option("-u", "--username", dest="username",
                      help="Your username.  Will prompt if not provided.")
    parser.add_option_group(pgLogin)


    parser.add_option("-a", "--allowed", dest="allowed", default=False,
                      help="Print allowed domains and ranges and exit", action="store_true")
    parser.add_option("-o", "--output", dest="outputtype", default="user",
                      help="Output results as JSON or XML")


    (options, args) = parser.parse_args()
    if options.debug:
        debug = True
        print "Debug on."

    if options.verbose:
        verbose = True
        print "Verbose on."

    if options.allowed:
        print "Allowed domains are as follows:"
        for domain in allowed_domains:
            print "  " + domain
        print "Allowed IP ranges are as follows:"
        for ipr in allowed_ranges:
            print "  " + ipr
        sys.exit(0)

    if len(args) == 2:
        opt['hostname'] = args[0]
        opt['iprange']  = args[1]

        if debug:
            print "hostname " + opt['hostname']
            print "iprange " + opt['iprange']
    else:
        parser.error("Incorrect number arguments")
                                  
    opt['noaction'] = False
    if options.noaction:
        opt['noaction'] = True
        if debug or verbose:
            print "Noaction: dry run."

    opt['outputtype'] = options.outputtype
    if opt['outputtype'] == "xml":
        print "Sorry, XML not supported yet."
        sys.exit(1)

    if opt['hostname']:
        hn_elems = opt['hostname'].split(".")
        if ( len(hn_elems) < 3 or
             not (hn_elems[-1] == "net" or hn_elems[-1] == "com" or
                  hn_elems[-1] == "corp" )
             ):
            if debug:
                print len(hn_elems)
                print hn_elems
                print hn_elems[-1]
            print "{0:s} does not appear to be a valid FQDN.".format(opt['hostname'])
            sys.exit(1)
        elif ".".join(hn_elems[1:]) not in allowed_domains:
            print "{0:s} is not an allowed domain.".format(".".join(hn_elems[1:]))
            print "Allowed domains are as follows:"
            for domain in allowed_domains:
                print "  " + domain
            sys.exit(1)

    iprange = opt['iprange']
    if not re.match('([0-9]+)(?:\.[0-9]+){3}', iprange):
        print "{0:s} does not appear to be a valid IP range".format(iprange)
        sys.exit(1)
    elif not iprange in allowed_ranges:
        print "{0:s} is not an allowed IP range".format(iprange)
        print "Allowed IP ranges are as follows:"
        for ipr in allowed_ranges:
            print "  " + ipr
        sys.exit(1)

    opt['uid'] = ""
    if options.username:
        opt['uid'] = options.username

    opt['passwd'] = ""
    if options.password:
        opt['passwd'] = options.password

    (opt['uid'], opt['passwd']) = get_login(opt['uid'], opt['passwd'])
    if debug:
        print "{0:s}, {1:s}".format(opt['uid'], opt['passwd'])


def get_login(uid, passwd):
    """Should return tuple of uid in form (123456) and clear text password.
       e.g., ("123456", "p@ssw0rd")
    """

    if not uid:
        while True:
            sys.stdout.write("Please enter your employee ID: ")
            uid = raw_input()
            if re.match("\d{6}", uid):
                break
            else:
                sys.stdout.write("Invalid response!\n")

    if not passwd:
        while True:
            # sys.stdout.write("Please enter your domain password: ")
            passwd = getpass.getpass("Please enter your domain password: ")
            if True:
                break
            else:
                sys.stdout.write("Invalid response!\n")

    return (uid, passwd)



if __name__ == "__main__":
    sys.exit(main())


