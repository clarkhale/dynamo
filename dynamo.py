#!/usr/bin/python

import base64
import json
from optparse import OptionParser
import os
import re
import sys
import urllib
import urllib2
from urlparse import urlparse

debug   = False
verbose = False

baseurl = 'https://10.69.15.170/wapi/v1.1/'

allowed_ranges  = [ '10.39.2.0/23',
                    ]

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
    parser.add_option("-d", "--debug", dest="debug", default=False,
                      help="Debugging output to STDERR", action="store_true")
    parser.add_option("-u", "--username", dest="username",
                      help="Your numeric company user ID")
    parser.add_option("-v", "--verbose", dest="verbose", default=False,
                      help="Verbose output to STDERR", action="store_true")
    parser.add_option("-p", "--password", dest="password",
                      help="Your domain password")


    (options, args) = parser.parse_args()

    if options.debug:
        debug = True
        print "Debug on."

    if options.verbose:
        verbose = True
        print "Verbose on."

    if len(args) != 2:
        print usage
        return 1

    hostname = args[0]
    iprange  = args[1]

    hn_elems = hostname.split(".")
    if ( len(hn_elems) < 3 or
         not (hn_elems[-1] == "net" or hn_elems[-1] == "com" or
              hn_elems[-1] == "corps" )
         ):
        print len(hn_elems)
        print hn_elems
        print hn_elems[-1]
        print "{0:s} does not appear to be a valid FQDN.".format(hostname)
        return 1
    elif ".".join(hn_elems[1:]) not in allowed_domains:
        print "{0:s} is not an allowed domain.".format(".".join(hn_elems[1:]))
        return 1

    if not re.match('([0-9]+)(?:\.[0-9]+){3}', iprange):
        print "{0:s} does not appear to be a valid IP range".format(iprange)
        return 1
    elif not iprange in allowed_ranges:
        print "{0:s} is not an allowed IP range".format(iprange)
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

    iprangeref = get_network_ref(uid, passwd, iprange)
    availip = get_next_available(uid, passwd, iprangeref, 5)
    if verbose:
        print "Next available IP address is " + availip

    hostref = register_host(uid, passwd, availip, hostname)

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
            sys.stdout.write("Please enter your domain password: ")
            passwd = raw_input()
            if True:
                break
            else:
                sys.stdout.write("Invalid response!\n")

    return (uid, passwd)


def get_network_ref(uid, passwd, iprange):
    """Get and return the Infoblox refencence to this network.
       Much of this taken from http://www.voidspace.org.uk/python/articles/authentication.shtml#introduction
    """

    if debug:
        print "Entering get_network_ref: {0:s}, {1:s}, {2:s}".format(uid, 
                                                                     passwd, 
                                                                     iprange)

    url    = baseurl + "network"
    values = { 'network' : iprange }
    data   = urllib.urlencode(values)
    if debug:
        print "Trying URL {0:s}".format(url + '?' + data)

    req    = urllib2.Request(url + '?' + data)
    handle = rest_call(uid, passwd, req)



    #results = handle.read()

    data = json.load(handle)

    if len(data) > 1:
        print "I should have only one network returned, erroring out."
        sys.exit(1)

    if debug:
        print "Full data returned:"
        print data
    if verbose:
        print "{0:s} ref: {1:s}".format(iprange,data[0]["_ref"])

    return data[0]["_ref"]

def get_next_available(uid, passwd, iprangeref, cnt=10):
    url    = baseurl + iprangeref
    
    values = { '_function' : 'next_available_ip',
               'num'       : cnt
               }
    data = urllib.urlencode(values)

    if debug:
        print "next avail url: {0:s}".format(url)

    req    = urllib2.Request(url, data)
    if debug:
        print req.get_full_url()
        print req.get_data()
        print req.get_method()
        # help(req)
    handle = rest_call(uid, passwd, req)

    #results = handle.read()

    data = json.load(handle)
    if debug:
        print data

    if len(data) > 1:
        print "I should have only one network returned, erroring out."
        sys.exit(1)

    for ipaddr in data['ips']:
        resp = os.system("ping -c 1 " + ipaddr + " >> /dev/null")
        if resp == 0:
            if debug:
                print ipaddr, "is up!"
            print "\n"
            print "========================================================"
            print "Please open a case with the OCC.  IP {0:s}".format(ipaddr)
            print "is pingable, but is not listed in Infoblox Grid as a"
            print "used IP address."
            print "========================================================"
            print "\n"
        else:
            if debug:
                print ipaddr, "is down!"
            return ipaddr
    print "No IP addresses available, exiting."
    sys.exit(1)

def register_host(uid, passwd, ipaddr, fqdn):
    url    = baseurl + "record:host"
    values = json.dumps( { 'ipv4addrs' : [ { 'ipv4addr' : ipaddr } ],
                           'name'      : fqdn,
                           'view'      : 'Infoblox Internal'
                           })

    # data = urllib.urlencode(values)

    if debug:
        print "register host url: {0:s}".format(url)

    req    = urllib2.Request(url, values, {'Content-Type': 'application/json'})
    if debug:
        print req.get_full_url()
        print req.get_data()
        print req.get_method()
        # help(req)
    handle = rest_call(uid, passwd, req)

    data = json.load(handle)

    if debug:
        print "Full data returned:"
        print data
    if verbose:
        print "{0:s} ref: {1:s}".format(fqdn,data)

    return data


def rest_call(uid, passwd, urllib2req):
    try:
        resp   = urllib2.urlopen(urllib2req)
    except IOError, e:
        pass
    else:
        print "Page not protected?  That shouldn't happen; erroring out..."
        sys.exit(1)

    if not hasattr(e, 'code') or e.code != 401:
        # we got an error - but not a 401 error
        print "This page isn't protected by authentication."
        print 'But we failed for another reason.'
        sys.exit(1)

    authline = e.headers['www-authenticate']
    # this gets the www-authenticate line from the headers
    # which has the authentication scheme and realm in it


    authobj = re.compile(
        r'''(?:\s*www-authenticate\s*:)?\s*(\w*)\s+realm=['"]([^'"]+)['"]''',
        re.IGNORECASE)
    # this regular expression is used to extract scheme and realm
    matchobj = authobj.match(authline)

    if not matchobj:
        # if the authline isn't matched by the regular expression
        # then something is wrong
        print 'The authentication header is badly formed.'
        print authline
        sys.exit(1)

    scheme = matchobj.group(1)
    realm = matchobj.group(2)
    # here we've extracted the scheme
    # and the realm from the header
    if scheme.lower() != 'basic':
        print 'This example only works with BASIC authentication.'
        sys.exit(1)

    base64string = base64.encodestring(
        '%s:%s' % (uid, passwd))[:-1]
    authheader =  "Basic %s" % base64string
    urllib2req.add_header("Authorization", authheader)
    try:
        handle = urllib2.urlopen(urllib2req)
    except IOError, e:
        # here we shouldn't fail if the username/password is right
        print "It looks like the username or password is wrong."
        sys.exit(1)

    return handle


if __name__ == "__main__":
    sys.exit(main())


