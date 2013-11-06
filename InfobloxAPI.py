"""
A class object to abstract interaction with the Infoblox Grid Manager
Web API v1.1.

API v1.1 info:
Docs: https://support.infoblox.com/technical-documents
Spec: Infoblox_RESTful_API_Documentation_1.1                          

"""

import json
import os
import requests

class InfobloxAPI:
    """ Return an object with all the information required to start
        making WAPI calls.

        Examples:

        Generate a new hostname and assign it to the first available
        IP address in a network.  Start checking availble names from
        prexix0010.example.com:
        
        from InfobloxAPI import InfobloxAPI

        i = InfobloxAPI('gridmgr.exapmle.com', 'username', 'password')
        network = '192.168.1.0/24'
        i.rh_add( network, 
                  i.next_available_ip(network),
                  i.next_available_name('prefix', 10, 'example.com') )
    
    """

    def __init__(self, server, username, password, 
                 verbose=False, debug=False, verify=True):
        """ Initialize InfobloxAPI.  Requires API server to connect to,
            as well as username and password for authentication and
            authorization.  No calls are made yet, so there is no test
            yet of the information the object is initialized with.
        """
        self.server   = server
        self.username = username
        self.password = password

        self.verbose  = verbose
        self.debug    = debug
        self.verify   = verify

        self.url      = 'https://' + self.server + '/wapi/v1.1/'

    def rh_exists(self, hostname, like=False):
        """Test if a record:host for name=hostname exists.
        """
        if like:
            data = { 'name~' : hostname  }
        else:
            data = { 'name'  : hostname  }
        self.r = requests.get(self.url + 'record:host',
                              params=data,
                              auth=(self.username, self.password),
                              verify=self.verify)
        if self.debug:
            print "inside rh_exists: " + hostname
            print self.r.text
        return self.r.json()

    # def rh_exists_like(self, hostname, max=10):
    #     """record:host for name~=hostname exist?"""
    #     data = { 'name~'        : hostname,
    #              '_max_results' : max
    #              }
    #     self.r = requests.get(self.url + 'record:host',
    #                           params=data,
    #                           auth=(self.username, self.password),
    #                           verify=self.verify)
    #     if self.debug:
    #         print "inside rh_exists_like:"
    #         print self.r.text
    #     return self.r.json()

    def ra_exists(self, hostname, like=False):
        """record:a_record for name=hostname exist?"""
        if like:
            data = { 'name~' : hostname  }
        else:
            data = { 'name'  : hostname  }
        self.r = requests.get(self.url + 'record:a',
                              params=data,
                              auth=(self.username, self.password),
                              verify=self.verify)
        if self.debug:
            print "inside ra_exists: " + hostname
            print self.r.text
        return self.r.json()

    # def ra_exists_like(self, hostname, max=10):
    #     """record:a_record for name~=hostname exist?"""
    #     data = { 'name~'        : hostname,
    #              '_max_results' : max
    #              }
    #     self.r = requests.get(self.url + 'record:a',
    #                           params=data,
    #                           auth=(self.username, self.password),
    #                           verify=self.verify)
    #     if self.debug:
    #         print "inside ra_exists_like:"
    #         print self.r.text
    #     return self.r.json()

    def network_ref(self, network):
        """Return _ref where network=network"""

        data = { 'network' : network }
        self.r = requests.get(self.url + 'network',
                              params=data,
                              auth=(self.username, self.password),
                              verify=self.verify)
        if self.debug:
            print "inside network ref:"
            print self.r.text
        return self.r.json()[0][u'_ref']

    def next_available_ip(self, network, count=10):
        """Return next available IP in network

           Look up the network reference, then get the count next
           available IPs.  Sequentially test each one via ping, and
           return the first one that does not respond.

           In verbose mode, it throws out a warning if one of the
           available IPs responds to ping.
        """
        netref = self.network_ref(network)
        data = { '_function' : 'next_available_ip', 
                 'num'       : count }
        self.r = requests.post(self.url + netref,
                               params=data,
                               auth=(self.username, self.password),
                               verify=self.verify)
        if self.debug:
            print "inside next_available:"
            print self.r.text
        for ipaddr in self.r.json()['ips']:
            resp = os.system("ping -c 1 " + ipaddr + " >> /dev/null")
            if resp == 0:
                if self.debug:
                    print ipaddr, "is up!"
                    # Remove hardcode                                                   
                    if self.verbose:
                        print "\n"
                        print "========================================================\
"
                        print "Please open a case with the OCC.  IP {0:s}".format(ipaddr)
                        print "is pingable, but is not listed in Infoblox Grid as a"
                        print "used IP address. (ignore for now)"
                        print "========================================================\
"
                        print "\n"
            else:
                if self.debug:
                    print ipaddr, "is down!"
                return ipaddr
        return False

    def rh_add(self, network, ipaddr, fqdn):
        """Create record:host for network=network, 
           name=hostname and ipaddr=ipaddr"""

        netr = self.network_ref(network)
        data = { 
            'ipv4addrs'  : [ { 'ipv4addr' : ipaddr }, ],
            'name'       : fqdn,
            # removed hardcoded view and comment.  Add date to comment. TODO
            'view'       : 'Infoblox Internal',
            'comment'    : 'Dynamically entered by ' + self.username
            }
        headers = { 'content-type' : 'application/json' }
        if self.debug:
            print data
        self.r = requests.post(self.url + 'record:host',
                               data=json.dumps(data),
                               auth=(self.username, self.password),
                               verify=self.verify)
        if self.debug:
            print "inside rh_add: " + fqdn
            print self.r.text
            
        return( { 'ipaddr' : ipaddr,
                  'name'   : fqdn } )


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
