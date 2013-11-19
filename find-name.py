#!/usr/bin/python

import getpass
from InfobloxAPI import InfobloxAPI
from optparse import OptionParser, OptionGroup
import os
import re
import socket
import sys

debug   = False
verbose = False
opt     = {}

def main():
    get_options()

    if debug:
        print "prefix: " + opt['prefix']
        print "count:  " + str(opt['count_start'])
        print "digits: " + str(opt['digits'])
        print "domains:"
        for i in opt['domain']:
            print '  ' + i

    i = InfobloxAPI('10.69.15.170', opt['uid'], opt['passwd'], 
                    # verbose=verbose, debug=debug, verify=False)
                    verify=False)

    cnt = opt['count_start']
    end = 10 ** opt['digits']
    while cnt < end:
        hostname = "{0:s}{1:s}".format(opt['prefix'], 
                                        str(cnt).zfill(opt['digits']))
        if verbose:
            print "Checking {0:s}".format(hostname),
        available = True
        for d in opt['domain']:
            fqdn = hostname + '.' + d
            if verbose:
                print " .{0:s}".format(d), 

            # Test DNS
            try:
                socket.gethostbyname(fqdn)
                available = False
                break
            except:
                pass

            # Test record:a
            if i.ra_exists(fqdn):
                if verbose:
                    print "Infoblox record:a"
                available = False
                break

            # Test record:host
            if i.rh_exists(fqdn):
                if verbose:
                    print "Infoblox record:host"
                available = False
                break

        if verbose:
            print ""

        if available:
            if verbose:
                print "Available!"
            print hostname
            return 0

        cnt += 1

    return 1

def get_options():
    global debug, verbose, opt

    usage = "Usage: %prog [options] <Prefix> <Count> <Digits> <Domain>"
    epilog = """
The automated names generated will take the form:

    Prefix + Count + '.' + Domain

...with the count zero-filled out to Digits characters.  If the
generated name appears to be used somehow; e.g., a record:A in
Infoblox, then count is incremented and the process begins again.  The
first name which appears free is then returned.

Note that this process breaks if your DNS server always returns an A
record, such as DNS servers that redirect you to an "ads" page telling
you that host doesn't exist.  **** those guys.

Examples:

> find-name.py opskzlp 100 3 ops.sn.corp 
Please enter your employee ID: 134270
Please enter your domain password: 
opskzlp108

> find-name.py opsklp 4 5 ops.sn.corp --username 123456 --password "p@ssw0rd"
opsklp00004

"""
    # Set up format_epilog to not strip newlines
    OptionParser.format_epilog = lambda self, formatter: self.epilog
    parser = OptionParser(usage=usage, epilog=epilog)

    pgLogin   = OptionGroup(parser, "Infoblox Login Options",
                          "These are your Infoblox login; probably AD.")
    pgLogin.add_option("-p", "--password", dest="password",
                      help="Your password.  Will prompt if not provided.")
    pgLogin.add_option("-u", "--username", dest="username",
                      help="Your username.  Will prompt if not provided.")
    parser.add_option_group(pgLogin)


    parser.add_option("-d", "--debug", dest="debug", default=False,
                      help="Debugging output", action="store_true")
    parser.add_option("-v", "--verbose", dest="verbose", default=False,
                      help="Verbose output", action="store_true")


    (options, args) = parser.parse_args()

    if options.debug:
        debug = True
        print "Debug on."

    if options.verbose:
        verbose = True
        print "Verbose on."

    if len(args) == 4:
        opt['prefix']      =     args[0]
        opt['count_start'] = int(args[1])
        opt['digits']      = int(args[2])
        opt['domain']      =     args[3].split(',')

        if debug:
            print "prefix " + opt['prefix']
            print "count  " + str(opt['count_start'])
            print "digits " + str(opt['digits'])
            print "domain " + str(opt['domain'])
    else:
        parser.error("Incorrect number arguments")
                                  
    max_count = 10**opt['digits']
    if opt['count_start'] >= max_count:
        if debug:
            print str(opt['count_start']) + ' vs. ' + str(max_count)
        parser.error("{0:d} has more than {1:d} digits.".format(opt['count_start'], opt['digits']))

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


