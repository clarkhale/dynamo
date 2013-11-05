import json
import os
import requests

class InfoBloxAPI:
    """Object holding data, methods to interface with InfoBlox Grid Manager
       API 1.1 spec.
    """

    def __init__(self, server, username, password, 
                 verbose=False, debug=False, verify=True):
        self.server   = server
        self.username = username
        self.password = password

        self.verbose  = verbose
        self.debug    = debug
        self.verify   = verify

        self.url      = 'https://' + self.server + '/wapi/v1.1/'

    def rh_exists(self, hostname):
        """record:host for name=hostname exist?"""
        data = { 'name'  : hostname  }
        self.r = requests.get(self.url + 'record:host',
                              params=data,
                              auth=(self.username, self.password),
                              verify=self.verify)
        if self.debug:
            print "inside rh_exists: " + hostname
            print self.r.text
        return self.r.json()

    def rh_exists_like(self, hostname, max=10):
        """record:host for name~=hostname exist?"""
        data = { 'name~'        : hostname,
                 '_max_results' : max
                 }
        self.r = requests.get(self.url + 'record:host',
                              params=data,
                              auth=(self.username, self.password),
                              verify=self.verify)
        if self.debug:
            print "inside rh_exists_like:"
            print self.r.text
        return self.r.json()

    def ra_exists(self, hostname):
        """record:a_record for name=hostname exist?"""
        data = { 'name'  : hostname  }
        self.r = requests.get(self.url + 'record:a',
                              params=data,
                              auth=(self.username, self.password),
                              verify=self.verify)
        if self.debug:
            print "inside ra_exists: " + hostname
            print self.r.text
        return self.r.json()

    def ra_exists_like(self, hostname, max=10):
        """record:a_record for name~=hostname exist?"""
        data = { 'name~'        : hostname,
                 '_max_results' : max
                 }
        self.r = requests.get(self.url + 'record:a',
                              params=data,
                              auth=(self.username, self.password),
                              verify=self.verify)
        if self.debug:
            print "inside ra_exists_like:"
            print self.r.text
        return self.r.json()

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
        """Return next available IP in network"""
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
            'view'       : 'Infoblox Internal',
            'comment'    : 'Dynamically entered by ' + self.username
            }
        headers = { 'content-type' : 'application/json' }
        print data
        self.r = requests.post(self.url + 'record:host',
                               data=json.dumps(data),
                               auth=(self.username, self.password),
                               verify=self.verify)
        if self.debug:
            print "inside rh_add: " + fqdn
            print self.r.text

    def next_available_name(self, prefix, domain, cnt_start, digits=4, run=1024):
        """Find the next available name of form prefix + 0001 + domain"""
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
