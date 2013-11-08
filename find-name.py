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
            print "Checking {0:s}".format(hostname)
        available = True
        for d in opt['domain']:
            if verbose:
                print "  {0:s}: ".format(d), 

            # Test DNS
            try:
                socket.gethostbyname(fqdn)
                print "DNS lookup"
                available = False
                break
            except:
                pass

            # Test record:a
            if i.ra_exists(hostname + '.' + d):
                if verbose:
                    print "Infoblox record:a"
                available = False
                break

            # Test record:host
            if i.rh_exists(hostname + '.' + d):
                if verbose:
                    print "Infoblox record:host"
                available = False
                break

            print ""

        if available:
            if verbose:
                print "Available!"
            print hostname
            return 0

        cnt += 1

    return 1

def next_available_name(self, prefix, cnt_start, domain, digits=4, run=1024):
    """Find the next available name of form prefix + 0001 + domain

       Starts at cnt_start and then checks sequentially up to 
       cnt_start + run, looking for available names.

       Checks the Infoblox API for record:host entry, record:a
       entry, and finally just a DNS lookup.  The first name which
       shows clear in all those is returned.
    """
    for i in range(cnt_start, run):
        if self.debug:
            print "i: " + str(i)
        fqdn = prefix + str(i).zfill(digits) + '.' + domain
        if self.debug:
            print fqdn

        if self.rh_exists(fqdn):
            continue
        elif self.ra_exists(fqdn):
            continue
        elif True:
            try:
                socket.gethostbyname(fqdn)
                continue
            except:
                return fqdn
        else:
            return fqdn
    return False


def get_options():
    global debug, verbose, opt

    usage = "Usage: %prog [options] <FQDN to register> <IP range>"
    parser = OptionParser(usage=usage)

    parser.add_option("-c", "--count", dest="count_start", default=217,
                      help="Count start for autogen hostname")
    parser.add_option("-d", "--debug", dest="debug", default=False,
                      help="Debugging output to STDERR", action="store_true")
    parser.add_option("-f", "--prefix", dest="prefix", default="kwsn",
                      help="Prefix for autogen hostname")
    parser.add_option("-g", "--digits", dest="digits", default=3,
                      help="Zero fill count for autogen hostname")
    parser.add_option("-m", "--domain", dest="domain", 
                      default="snops.net,sn.corp",
                      help="Domain for autogen hostname")
    parser.add_option("-p", "--password", dest="password",
                      help="Your domain password")
    parser.add_option("-u", "--username", dest="username",
                      help="Your numeric company user ID")
    parser.add_option("-v", "--verbose", dest="verbose", default=False,
                      help="Verbose output to STDERR", action="store_true")


    (options, args) = parser.parse_args()

    if options.debug:
        debug = True
        print "Debug on."

    if options.verbose:
        verbose = True
        print "Verbose on."

    opt['prefix'] = options.prefix
    opt['digits'] = int(options.digits)
    foo = options.domain
    opt['domain'] = foo.split(',')
    opt['count_start'] = int(options.count_start)

    if not opt['prefix'] and opt['domain']:
        print "Exiting because not both prefix or domain."
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


