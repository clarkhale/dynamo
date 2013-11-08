#!/usr/bin/python

import getpass
from InfobloxAPI import InfobloxAPI
import json
from optparse import OptionParser
import os
import re
import sys

debug   = False
verbose = False
opt     = {}

gridmgr = '10.69.15.170'

# Remove hardcode
allowed_ranges  = [ '10.39.2.0/23',
                    '10.39.32.0/24',
                    ]

# Remove hardcode
allowed_domains = [ 'ci.snops.net',
                    'ops.sn.corp',
                    ]

def main():
    global opt, debug, verbose

    # most cli optnios available in global hash opt; e.g., opt['hostname']
    get_options()

    wapi = InfobloxAPI(gridmgr, opt['uid'], opt['passwd'], 
                       debug=debug, verbose=verbose, verify=False)

    r = { }  # r will hold response from wapi calls
    iprange  = opt['iprange']
    if opt['hostname']:
        hostname = opt['hostname']
    else:
        hostname = wapi.next_available_name(opt['prefix'], 217, opt['domain'], digits=3)
    if not opt['noaction']:
        r = wapi.rh_add( iprange,
                         wapi.next_available_ip(iprange),
                         hostname )
    else:
        print "Bailing due to noaction flag."
        return 1

    if not r:
        print "Unknown error in WAPI call."
        return 0
    

    r['iprange'] = iprange
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
    parser = OptionParser(usage=usage)
    # parser.add_option("-n", "--name", dest="hostname",
    #                   help="hostname to register")
    # parser.add_option("-i", "--iprange", dest="iprange",
    #                   help="IP address to register")
    parser.add_option("-a", "--allowed", dest="allowed", default=False,
                      help="Print allowed domains and ranges and exit", action="store_true")
    parser.add_option("-d", "--debug", dest="debug", default=False,
                      help="Debugging output to STDERR", action="store_true")
    parser.add_option("-f", "--prefix", dest="prefix", default="",
                      help="Prefix for autogen hostname")
    parser.add_option("-m", "--domain", dest="domain", default="",
                      help="Domain for autogen hostname")
    parser.add_option("-n", "--name", dest="hostname", default="",
                      help="FQDN to be added")
    parser.add_option("--noaction", dest="noaction", default=False,
                      help="Don't make any changes", action="store_true")
    parser.add_option("-o", "--output", dest="outputtype", default="user",
                      help="Output results as JSON or XML")
    parser.add_option("-p", "--password", dest="password",
                      help="Your domain password")
    parser.add_option("-u", "--username", dest="username",
                      help="Your numeric company user ID")
    parser.add_option("-v", "--verbose", dest="verbose", default=False,
                      help="Verbose output to STDERR", action="store_true")


    (options, args) = parser.parse_args()

    if options.allowed:
        print "Allowed domains are as follows:"
        for domain in allowed_domains:
            print "  " + domain
        print "Allowed IP ranges are as follows:"
        for ipr in allowed_ranges:
            print "  " + ipr
        sys.exit(0)

    debug = False
    if options.debug:
        debug = True
        print "Debug on."

    verbose = True
    if options.verbose:
        verbose = True
        print "Verbose on."

    opt['noaction'] = False
    if options.noaction:
        opt['noaction'] = True
        if debug or verbose:
            print "Noaction: dry run."

    opt['outputtype'] = options.outputtype
    if opt['outputtype'] == "xml":
        print "Sorry, XML not supported yet."
        sys.exit(1)

    opt['hostname'] = ''
    opt['prefix']   = ''
    opt['domain']   = ''

    if options.hostname:
        opt['hostname'] = options.hostname
        if debug:
            print "hostname: " + opt['hostname']

    if options.prefix or options.domain:
        if not options.prefix and options.domain:
            print "Exiting because either prefix or domain but not both."
            sys.exit(1)
        elif options.hostname:
            print "Exiting because hostname given with prefix and domain."
            sys.exit(1)

        opt['prefix'] = options.prefix
        opt['domain'] = options.domain

    if not opt['hostname'] and not (opt['prefix'] and opt['domain']):
        print "Hostanme not given, and no prefix and domain given."
        sys.exit(1)
        
    if len(args) != 1:
        print usage
        sys.exit(1)

    opt['iprange']  = args[0]

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


