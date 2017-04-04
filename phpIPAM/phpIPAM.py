#! /usr/bin/env python
__author__ = 'michaelluich'
author_email = 'mluich@stonesrose.com',

import requests
from requests.auth import HTTPBasicAuth
import json
import inspect

requests.packages.urllib3.disable_warnings()

import logging
logger = logging.getLogger(__name__)

class phpIPAM(object):
    """An interface to phpIPAM web API."""

    def __init__(self, server, app_id, username, password, ssl_verify=True, debug=False):
        """Parameters:
        server: the base server location.
        app_id: the app ID to access
        username: username
        password: password
        ssl_verify: should the certificate being verified"""
        self.error = 0
        self.error_message = ""
        self.server = server
        self.app_id = app_id
        self.username = username
        self.password = password
        self.appbase = "%s/api/%s" %(self.server,self.app_id)
        self.ssl_verify = ssl_verify
        self.token = None
        if debug:
            self.enable_debug()
        self.login()

    def enable_debug(self):
        try:
            import http.client as http_client
        except ImportError:
            # Python 2
            import httplib as http_client
        http_client.HTTPConnection.debuglevel = 1
        logging.basicConfig()
        logging.getLogger().setLevel(logging.DEBUG)
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True

    def __query(self, entrypoint, method=requests.get, data=None, auth=None):
        headers = {}
        if self.token:
            headers['token'] = self.token
        if data != None:
            if type(data) != str: data = json.dumps(data)
            headers['Content-Type'] = 'application/json'
            if method == requests.get:
                method = requests.post

        p = method(
            self.appbase + entrypoint,
            data=data,
            headers=headers,
            auth=auth,
            verify=self.ssl_verify
        )
        response = json.loads(p.text)
        callingfct = inspect.getouterframes(inspect.currentframe(), 2)[1][3]

        if p.status_code != 200:
            logging.error("phpipam.%s: Failure %s" % (callingfct, p.status_code))
            logging.error(response)
            self.error = p.status_code
            self.error_message = response['message']
            raise requests.exceptions.HTTPError(response=response)

        if not response['success']:
            logging.error("phpipam.%s: FAILURE: %s" % (callingfct, response['code']))
            self.error = response['code']
            raise requests.exceptions.HTTPError(response=response)

        logging.info("phpipam.%s: success %s" % (callingfct, response['success']))
        return response['data']


    # Authentication

    def login(self):
        "Login to phpIPAM and get a token."
        ticketJson = self.__query('/user/', auth=HTTPBasicAuth(self.username, self.password), method=requests.post)
        # Ok So now we have a token!
        self.token = ticketJson['token']
        self.token_expires= ticketJson['expires']
        logging.info("phpipam.login: Sucessful Login to %s" %(self.server))
        logging.debug("phpipam.login: IPAM Ticket expiration: %s" %(self.token_expires))
        return {"expires":self.token_expires}


    def ticket_check(self):
        "check if a ticket is still valid"
        try:
            return self.__query("/user/")
        except:
            return self.login()

    def ticket_extend(self):
        "Extends ticket duration (ticket last for 6h)"
        return self.__query("/user/")


    # Authorization

    def authorization(self, controller):
        "Check the authorization of a controller and get a list of methods"
        return self.__query("/%s/" %(controller))['methods']

    ### Controllers

    ## Sections

    def sections_get_all(self):
        "Get a list of all sections"
        return self.__query("/sections/?links=false")

    def sections_get_id(self, section):
        """Get the ID of a section

        Parameters:
            section: The name of the section you are looking for
        """
        return self.__query("/sections/%s/?links=false" % (section))['id']

    def sections_get(self, section_id):
        """Get the details for a specific section

        Parameters:
            section_id = section identifier. Can be the id number or name.
        """
        return self.__query("/sections/%s/?links=false" %(section_id))

    def sections_get_subnets(self, section_id):
        """Get the subnets for a specific section

         Parameters:
             section_id = section identifier. Can be the id number or name.
         """
        return self.__query("/sections/%s/subnets/?links=false" % (section_id))

    def sections_create(self, section_id, masterSection=0):
        """Create a section

         Parameters:
             section_id = section name.
         """
        data = {'name': section_id}
        if masterSection != 0 : data['masterSection'] = masterSection
        return self.__query("/sections/", data=data)

    def sections_delete(self, section_id,):
        """Delete a section

        Parameters:
        section_id = section name or id.
        """
        return self.__query("/sections/%s/" %(section_id), method=requests.delete)

    ## Subnet

    def subnet_get(self, subnet_id):
        """Get Information about a specific subnet

        Parameters:
        subnet_id: The subnet identifier either the ID or cidr
        """
        return self.__query("/subnets/%s/?links=false" % (subnet_id))

    def subnet_search(self, subnet_id):
        """Search by cidr

        Parameters:
        subnet_id: The subnet cidr
        """
        return self.__query("/subnets/cidr/%s/?links=false" % (subnet_id))

    def subnet_all(self, subnet_id):
        """Get all addresses in a subnet

        Parameters:
        subnet_id: The subnet id
        """
        return self.__query("/subnets/%s/addresses/?links=false" % (subnet_id))

    def subnet_first_available(self, subnet_id):
        """Get first available

        Parameters:
        subnet_id: The subnet id
        """
        return self.__query("/subnets/%s/first_free/?links=false" % (subnet_id))


    def subnet_create(self, subnet, mask, sectionId, description="", vlanid=None, mastersubnetid=0, nameserverid=None):
        """Create new subnet

        Parameters:
        subnet: The subnet
        mask: the subnet mask
        sectionId
        description: description
        vlanid:
        mastersubnetid:
        nameserverid:"""
        data={
            'subnet' : subnet,
            'mask' : mask,
            "sectionId" : sectionId,
            'description' : description,
            'vlanId' : vlanid,
            'masterSubnetId' : mastersubnetid,
            'nameserverId' : nameserverid
        }
        return self.__query("/subnets/", data=data)

    def subnet_delete(self, subnet_id, ):
        """Delete a subnet

        Parameters:
        subnet_id = subnet name or id.
        """
        return self.__query("/subnets/%s/" % (subnet_id), method=requests.delete)

    ## Address

    def address_get(self, address_id):
        """Get Information about a specific address

        Parameters:
        address_id: The address identifier either the ID or cidr
        """
        return self.__query("/addresses/%s/?links=false" % (address_id))

    def address_search(self, address):
        """Search for a specific address

        Parameters:
        address: The address identifier either the ID or address
        """
        return self.__query("/addresses/search/%s/?links=false" % (address))

    def address_update(self, ip, hostname=None, description=None, is_gateway=None, mac=None):
        """Update address informations"""
        orgdata = self.address_search(ip)[0]
        data = {}
        if hostname != None: data["hostname"] = hostname
        if description != None: data["description"] = description
        if is_gateway != None: data["is_gateway"] = is_gateway
        if mac != None: data["mac"] = mac
        return self.__query("/addresses/%s/"%orgdata['id'], method=requests.patch, data=data)

    def address_create(self, ip, subnetId, hostname, description="", is_gateway=0, mac=""):
        """Create new address

        Parameters:
        number: address number
        name: short name
        description: description"""
        data = {
            "ip":ip,
            "subnetId":subnetId,
            "hostname":hostname,
            "description":description,
            "is_gateway":is_gateway,
            "mac": mac,
        }
        return self.__query("/addresses/", data=data)

    ## VLAN

    def vlan_get(self, vlan_id):
        """Get Information about a specific vlan

        Parameters:
        vlan_id: The vlan identifier either the ID or cidr
        """
        return self.__query("/vlans/%s/?links=false" % (vlan_id))

    def vlan_get_id(self, vlan_id):
        """vlan_get_id
        search for the ID of a vlan.

        Parameters:
        vlan: The vlan to search for
        """
        return self.__query("/vlans/search/%s/?links=false" % (vlan_id))[0]['id']

    def vlan_subnets(self, vlan_id):
        """Get vlan subnets

        Parameters:
        vlan_id: The vlan identifier
        """
        return self.__query("/vlans/%s/subnets/?links=false" % (vlan_id))

    def vlan_create(self, number, name, description=""):
        """Create new vlan

        Parameters:
        number: vlan number
        name: short name
        description: description
        """
        data={
            'number' : number,
            'name' : name,
            'description' : description,
        }
        return self.__query("/vlans/", data=data)

    def vlan_delete(self, vlan_id, ):
        """Delete a vlan

        Parameters:
        vlan_id = vlan name or id.
        """
        return self.__query("/vlans/%s/" % (vlan_id))
