#!/usr/bin/python

import getpass
from InfobloxAPI import InfobloxAPI
from optparse import OptionParser
import os
import re
import sys

debug   = False
verbose = False
opt     = {}

gridmgr = '10.69.15.170'

def main():
    global opt, debug, verbose

    # most cli optnios available in global hash opt; e.g., opt['hostname']
    get_options()

    wapi = InfobloxAPI(gridmgr, opt['uid'], opt['passwd'], 
                       debug=debug, verbose=verbose, verify=False)

    print wapi.next_available_name(opt['prefix'], opt['countstart'], opt['domain'], digits=opt['digits'])


def print_output(r):
    if opt['outputtype'].lower() == "user":
        print "Assigning " + r['ipaddr'] + " to " + r['name'] + "."
    elif opt['outputtype'].lower() == "json":
        print json.dumps( { 'hostname'  : r['name'],
                            'ipaddress' : r['ipaddr'],
                            'iprange'   : iprange } )
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
    parser.add_option("-c", "--count", dest="countstart", default="10",
                      help="Number to start checking for autogen hostname")
    parser.add_option("-d", "--debug", dest="debug", default=False,
                      help="Debugging output to STDERR", action="store_true")
    parser.add_option("-f", "--prefix", dest="prefix", default="",
                      help="Prefix for autogen hostname")
    parser.add_option("-g", "--digits", dest="digits", default="3",
                      help="Number to start checking for autogen hostname")
    parser.add_option("-m", "--domain", dest="domain", default="",
                      help="Domain for autogen hostname")
    parser.add_option("-p", "--password", dest="password",
                      help="Your domain password")
    parser.add_option("-u", "--username", dest="username",
                      help="Your numeric company user ID")
    parser.add_option("-v", "--verbose", dest="verbose", default=False,
                      help="Verbose output to STDERR", action="store_true")


    (options, args) = parser.parse_args()

    debug = False
    if options.debug:
        debug = True
        print "Debug on."

    verbose = True
    if options.verbose:
        verbose = True
        print "Verbose on."

    opt['prefix']   = ''
    opt['domain']   = ''

    opt['countstart'] = int(options.countstart)
    opt['digits']     = int(options.digits)

    if not options.prefix and options.domain:
        print "Exiting because either prefix or domain but not both."
        sys.exit(1)

    opt['prefix'] = options.prefix
    opt['domain'] = options.domain
    
    if not opt['prefix']:
        print "Invalid prefix."
        sys.exit(1)

    if not opt['domain']:
        print "Invalid domain."
        sys.ext(1)

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
            # hardcode TODO
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


