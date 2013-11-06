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

gridmgr = '10.69.15.170'

# Remove hardcode
allowed_ranges  = [ '10.39.2.0/23',
                    ]

# Remove hardcode
allowed_domains = [ 'ci.snops.net',
                    ]

def main():
    global debug, verbose
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
    parser.add_option("-n", "--noaction", dest="noaction", default=False,
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
        return 0

    if options.debug:
        debug = True
        print "Debug on."


    if options.verbose:
        verbose = True
        print "Verbose on."

    noaction = False
    if options.noaction:
        noaction = True
        if debug or verbose:
            print "Noaction: dry run."

    outputtype = options.outputtype
    if outputtype == "xml":
        print "Sorry, XML not supported yet."
        return 1
        
    if len(args) != 2:
        print usage
        return 1

    hostname = args[0]
    iprange  = args[1]

    hn_elems = hostname.split(".")
    if ( len(hn_elems) < 3 or
         not (hn_elems[-1] == "net" or hn_elems[-1] == "com" or
              hn_elems[-1] == "corp" )
         ):
        if debug:
            print len(hn_elems)
            print hn_elems
            print hn_elems[-1]
        print "{0:s} does not appear to be a valid FQDN.".format(hostname)
        return 1
    elif ".".join(hn_elems[1:]) not in allowed_domains:
        print "{0:s} is not an allowed domain.".format(".".join(hn_elems[1:]))
        print "Allowed domains are as follows:"
        for domain in allowed_domains:
            print "  " + domain
        return 1

    if not re.match('([0-9]+)(?:\.[0-9]+){3}', iprange):
        print "{0:s} does not appear to be a valid IP range".format(iprange)
        return 1
    elif not iprange in allowed_ranges:
        print "{0:s} is not an allowed IP range".format(iprange)
        print "Allowed IP ranges are as follows:"
        for ipr in allowed_ranges:
            print "  " + ipr
        return 1

    uid = ""
    if options.username:
        uid = options.username

    passwd = ""
    if options.password:
        passwd = options.password

    (uid, passwd) = get_login(uid, passwd)
    if debug:
        print "{0:s}, {1:s}".format(uid, passwd)

    wapi = InfobloxAPI(gridmgr, uid, passwd, 
                       debug=True, verbose=True, verify=False)

    r = { }
    if not noaction:
        r = wapi.rh_add( iprange,
                         wapi.next_available_ip(iprange),
                         hostname )

    if not r:
        print "Unknown error in WAPI call."
        return 0
    
    if outputtype.lower() == "user":
        print "Assigning " + r['ipaddr'] + " to " + r['name'] + "."
    elif outputtype.lower() == "json":
        print json.dumps( { 'hostname'  : r['name'],
                            'ipaddress' : r['ipaddr'],
                            'iprange'   : iprange } )
    elif outputtype.lower() == "xml":
        print "Sorry, XML not supported yet..."
        return 1

    return 0


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


