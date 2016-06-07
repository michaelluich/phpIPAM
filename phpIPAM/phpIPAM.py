#! /usr/bin/env python
__author__ = 'michaelluich'
author_email = 'mluich@stonesrose.com',

import requests
from requests.auth import HTTPBasicAuth
import json

import logging
logger = logging.getLogger(__name__)

class phpIPAM(object):
    """An interface to phpIPAM web API.

    Attributes:
        server: the base server location.
        app_id: the app ID to access
        username: Login username
        password: Login Password
    """

    def __init__(self, server, app_id, username, password):
        self.error = 0
        self.error_message = ""
        self.server = server
        self.app_id = app_id
        self.username = username
        self.password = password
        self.base = "%s/api/%s/" %(self.server,self.app_id)
        self.login()


    """ Authentication """

    """   Login to phpIPAM and get a token. """
    def login(self):
        p = requests.post(self.base + 'user/', auth=HTTPBasicAuth(self.username, self.password))
        # print the html returned or something more intelligent to see if it's a successful login page.
        if p.status_code != 200:
            logging.error("phpipam.login: Login Problem %s " %(p.status_code))
            logging.error(p.text)
            self.error=77
            return self.error
        # Ok So now we have a token!
        ticketJson = json.loads(p.text)
        self.token = ticketJson['data']['token']
        self.token_expires= ticketJson['data']['expires']
        logging.info("phpipam.login: Sucessful Login to %s" %(self.server))
        logging.debug("phpipam.login: IPAM Ticket: %s" %(ticketJson['data']['token']))
        logging.debug("phpipam.login: IPAM Ticket expiration: %s" %(self.token_expires))


    """ check if a ticket is still valid"""
    def ticket_check(self):
        headers = {'token': self.token}
        p = requests.get(self.base + 'user/', headers=headers)
        if p.status_code != 200:
            logging.error("phpipam.ticket_check: Invalid ticket relogging in")
            logging.error(p.text)
            self.login()
        logging.info("phpipam.ticket_check: IPAM Ticket expiration: %s" %(self.token_expires))


    """ Although the ticket last 6 hours. You can extend the time """
    def ticket_extend(self):
        headers = {'token': self.token}
        p = requests.patch(self.base + 'user/', headers=headers)
        logging.info("phpipam.ticket_extend: IPAM Ticket expiration: %s" % (self.token_expires))


    """ Authorization """

    """    Check the authorization of acontroller and get a list of methods"""
    def authorization(self,controller):
        headers = {'token': self.token}
        p = requests.options(self.base+"%s/" %(controller), headers=headers)
        auth_json = json.loads(p.text)

        if p.status_code != 200:
            logging.error("phpipam.authorization: Failure %s" %(p.status_code))
            logging.error(auth_json)
            self.error = p.status_code
            self.error_message=auth_json['message']
            return self.error,self.error_message

        if not auth_json['success']:
            logging.error("phpipam.authorization: FAILURE: %s" %(auth_json['code']))
            self.error=auth_json['code']
            return self.error

        logging.info("phpipam.authorization: success %s" %(auth_json['success']))
        return auth_json['data']['methods']


    """ Controllers """

    """ Sections"""

    """ Get a list of all sections"""
    def sections_get_all(self):
        headers = {'token': self.token}
        p = requests.get(self.base + "sections/?links=false", headers=headers)
        sections_get_all_json = json.loads(p.text)

        if p.status_code != 200:
            logging.error("phpipam.sections_get_all: Failure %s" % (p.status_code))
            logging.error(sections_get_all_json)
            self.error = p.status_code
            self.error_message = sections_get_all_json['message']
            return self.error, self.error_message

        if not sections_get_all_json['success']:
            logging.error("phpipam.sections_get_all: FAILURE: %s" % (sections_get_all_json['code']))
            self.error = sections_get_all_json['code']
            return self.error

        logging.info("phpipam.sections_get_all: success %s" % (sections_get_all_json['success']))
        return sections_get_all_json

    """ Get the ID of a section

    Attributes:
        section: The name of the section you are looking for
    """
    def sections_get_id(self, section):
        headers = {'token': self.token}
        p = requests.get(self.base + "sections/%s/?links=false" % (section), headers=headers)
        sections_get_id_json = json.loads(p.text)

        if p.status_code != 200:
            logging.error("phpipam.sections_get_id: Failure %s" % (p.status_code))
            logging.error(sections_get_id_json)
            self.error = p.status_code
            self.error_message = sections_get_id_json['message']
            return self.error, self.error_message

        if not sections_get_id_json['success']:
            logging.error("phpipam.sections_get_id: FAILURE: %s" % (sections_get_id_json['code']))
            self.error = sections_get_id_json['code']
            return self.error

        logging.info("phpipam.sections_get_id: success %s" % (sections_get_id_json['success']))
        return sections_get_id_json['data']['id']


    """ Get the details for a specific section

    Attributes:
        section_id = section identifier. Can be the id number or name.
    """
    def sections_get(self, section_id):
        headers = {'token': self.token}
        p = requests.get(self.base + "sections/%s/?links=false" %(section_id), headers=headers)
        sections_get = json.loads(p.text)

        if p.status_code != 200:
            logging.error("phpipam.sections_get: Failure %s" % (p.status_code))
            logging.error(sections_get)
            self.error = p.status_code
            self.error_message = sections_get['message']
            return self.error, self.error_message

        if not sections_get['success']:
            logging.error("phpipam.sections_get: FAILURE: %s" % (sections_get['code']))
            self.error = sections_get['code']
            return self.error

        logging.info("phpipam.sections_get: success %s" % (sections_get['success']))
        return sections_get['data']

    """ Get the subnets for a specific section

     Attributes:
         section_id = section identifier. Can be the id number or name.
     """

    def sections_get_subnets(self, section_id):
        headers = {'token': self.token}
        p = requests.get(self.base + "sections/%s/subnets/?links=false" % (section_id), headers=headers)
        sections_get_subnets = json.loads(p.text)

        if p.status_code != 200:
            logging.error("phpipam.sections_get_subnets: Failure %s" % (p.status_code))
            logging.error(sections_get_subnets)
            self.error = p.status_code
            self.error_message = sections_get_subnets['message']
            return self.error, self.error_message

        if not sections_get_subnets['success']:
            logging.error("phpipam.sections_get_subnets: FAILURE: %s" % (sections_get_subnets['code']))
            self.error = sections_get_subnets['code']
            return self.error

        logging.info("phpipam.sections_get_subnets: success %s" % (sections_get_subnets['success']))
        return sections_get_subnets['data']

    """ Create a section 

     Attributes:
         section_id = section name.
     """
    def sections_create(self, section_id, masterSection=0):
        headers = {'token': self.token}
        data = {'name': section_id
        }
        if masterSection != 0 : data['masterSection'] = masterSection

        p = requests.post(self.base + "sections/", headers=headers, data=data)
        sections_create = json.loads(p.text)

        if p.status_code != 201:
            logging.error("phpipam.sections_create: Failure %s" % (p.status_code))
            logging.error(sections_create)
            self.error = p.status_code
            self.error_message = sections_create['message']
            return self.error, self.error_message

        if not sections_create['success']:
            logging.error("phpipam.sections_create: FAILURE: %s" % (sections_create['code']))
            self.error = sections_create['code']
            return self.error

        logging.info("phpipam.sections_create: success %s" % (sections_create['success']))
        return sections_create['data']


    """ Delete a section 
    
     Attributes:
         section_id = section name or id.
     """
    def sections_delete(self, section_id,):
        headers = {'token': self.token}
        p = requests.delete(self.base + "sections/%s/" %(section_id), headers=headers)
        print p.text
        sections_delete = json.loads(p.text)
    
        if p.status_code != 200:
            logging.error("phpipam.sections_delete: Failure %s" % (p.status_code))
            logging.error(sections_delete)
            self.error = p.status_code
            self.error_message = sections_delete['message']
            return self.error, self.error_message
    
        if not sections_delete['success']:
            logging.error("phpipam.sections_delete: FAILURE: %s" % (sections_delete['code']))
            self.error = sections_delete['code']
            return self.error
    
        logging.info("phpipam.sections_delete: success %s" % (sections_delete['success']))
        return sections_delete['code']
    
    """ Subnet """

    """ Get Information about a specific subnet
    
        Attributes:
            subnet_id: The subnet identifier either the ID or cidr
    """

    def subnet_get(self, subnet_id):
        headers = {'token': self.token}
        p = requests.get(self.base + "subnets/%s/?links=false" % (subnet_id), headers=headers)
        subnet_get = json.loads(p.text)

        if p.status_code != 200:
            logging.error("phpipam.subnet_get: Failure %s" % (p.status_code))
            logging.error(subnet_get)
            self.error = p.status_code
            self.error_message = subnet_get['message']
            return self.error, self.error_message

        if not subnet_get['success']:
            logging.error("phpipam.subnet_get: FAILURE: %s" % (subnet_get['code']))
            self.error = subnet_get['code']
            return self.error

        logging.info("phpipam.subnet_get: success %s" % (subnet_get['success']))
        return subnet_get['data']


    """ Search by cidr

        Attributes:
            subnet_id: The subnet cidr
    """


    def subnet_search(self, subnet_id):
        headers = {'token': self.token}
        p = requests.get(self.base + "subnets/cidr/%s/?links=false" % (subnet_id), headers=headers)
        subnet_search = json.loads(p.text)
    
        if p.status_code != 200:
            logging.error("phpipam.subnet_search: Failure %s" % (p.status_code))
            logging.error(subnet_search)
            self.error = p.status_code
            self.error_message = subnet_search['message']
            return self.error, self.error_message
    
        if not subnet_search['success']:
            logging.error("phpipam.subnet_search: FAILURE: %s" % (subnet_search['code']))
            self.error = subnet_search['code']
            return self.error
    
        logging.info("phpipam.subnet_search: success %s" % (subnet_search['success']))
        return subnet_search['data'][0]

    """ get all addresses in a subnet

           Attributes:
               subnet_id: The subnet id
       """

    def subnet_all(self, subnet_id):
        headers = {'token': self.token}
        p = requests.get(self.base + "subnets/%s/addresses/?links=false" % (subnet_id), headers=headers)
        subnet_all = json.loads(p.text)

        if p.status_code != 200:
            logging.error("phpipam.subnet_all: Failure %s" % (p.status_code))
            logging.error(subnet_all)
            self.error = p.status_code
            self.error_message = subnet_all['message']
            return self.error, self.error_message

        if not subnet_all['success']:
            logging.error("phpipam.subnet_all: FAILURE: %s" % (subnet_all['code']))
            self.error = subnet_all['code']
            return self.error

        logging.info("phpipam.subnet_all: success %s" % (subnet_all['success']))
        return subnet_all['data']



    """ get first available
    
        Attributes:
            subnet_id: The subnet id
    """
    
    
    def subnet_first_available(self, subnet_id):
        headers = {'token': self.token}
        p = requests.get(self.base + "subnets/%s/first_free/?links=false" % (subnet_id), headers=headers)
        subnet_first_available = json.loads(p.text)
    
        if p.status_code != 200:
            logging.error("phpipam.subnet_first_available: Failure %s" % (p.status_code))
            logging.error(subnet_first_available)
            self.error = p.status_code
            self.error_message = subnet_first_available['message']
            return self.error, self.error_message
    
        if not subnet_first_available['success']:
            logging.error("phpipam.subnet_first_available: FAILURE: %s" % (subnet_first_available['code']))
            self.error = subnet_first_available['code']
            return self.error
    
        logging.info("phpipam.subnet_first_available: success %s" % (subnet_first_available['success']))
        return subnet_first_available['data']

    """ Create new subnet

        Attributes:
            subnet: The subnet
            mask: the subnet mask
            sectionId
            description: description
            vlanid:
            mastersubnetid:
            nameserverid:

    """

    def subnet_create(self, subnet, mask, sectionId, description="", vlanid=None, mastersubnetid=0, nameserverid=None):
        headers = {'token': self.token}
        data={
            'subnet' : subnet,
            'mask' : mask,
            "sectionId" : sectionId,
            'description' : description,
            'vlanId' : vlanid,
            'masterSubnetId' : mastersubnetid,
            'nameserverId' : nameserverid
        }
        p = requests.post(self.base + "subnets/", headers=headers, data=data)
        subnet_first_available = json.loads(p.text)

        if p.status_code != 201:
            logging.error("phpipam.subnet_first_available: Failure %s" % (p.status_code))
            logging.error(subnet_first_available)
            self.error = p.status_code
            self.error_message = subnet_first_available['message']
            return self.error, self.error_message

        if not subnet_first_available['success']:
            logging.error("phpipam.subnet_first_available: FAILURE: %s" % (subnet_first_available['code']))
            self.error = subnet_first_available['code']
            return self.error

        logging.info("phpipam.subnet_first_available: success %s" % (subnet_first_available['success']))
        return subnet_first_available['data']


    """ Delete a subnet 
    
     Attributes:
         subnet_id = subnet name or id.
     """
    
    
    def subnet_delete(self, subnet_id, ):
        headers = {'token': self.token}
        p = requests.delete(self.base + "subnets/%s/" % (subnet_id), headers=headers)
        print p.text
        subnets_delete = json.loads(p.text)
    
        if p.status_code != 200:
            logging.error("phpipam.subnets_delete: Failure %s" % (p.status_code))
            logging.error(subnets_delete)
            self.error = p.status_code
            self.error_message = subnets_delete['message']
            return self.error, self.error_message
    
        if not subnets_delete['success']:
            logging.error("phpipam.subnets_delete: FAILURE: %s" % (subnets_delete['code']))
            self.error = subnets_delete['code']
            return self.error
    
        logging.info("phpipam.subnets_delete: success %s" % (subnets_delete['success']))
        return subnets_delete['code']

    """ Address """

    """ Get Information about a specific address

                Attributes:
                    address_id: The address identifier either the ID or cidr
            """

    def address_get(self, address_id):
        headers = {'token': self.token}
        p = requests.get(self.base + "addresses/%s/?links=false" % (address_id), headers=headers)
        address_get = json.loads(p.text)

        if p.status_code != 200:
            logging.error("phpipam.address_get: Failure %s" % (p.status_code))
            logging.error(address_get)
            self.error = p.status_code
            self.error_message = address_get['message']
            return self.error, self.error_message

        if not address_get['success']:
            logging.error("phpipam.address_get: FAILURE: %s" % (address_get['code']))
            self.error = address_get['code']
            return self.error

        logging.info("phpipam.address_get: success %s" % (address_get['success']))
        return address_get['data']

    """ Search for a specific address

                Attributes:
                    address: The address identifier either the ID or address
            """

    def address_search(self, address):
        headers = {'token': self.token}
        p = requests.get(self.base + "addresses/search/%s/?links=false" % (address), headers=headers)
        address_get = json.loads(p.text)

        if p.status_code != 200:
            logging.error("phpipam.address_get: Failure %s" % (p.status_code))
            logging.error(address_get)
            self.error = p.status_code
            self.error_message = address_get['message']
            return self.error, self.error_message

        if not address_get['success']:
            logging.error("phpipam.address_get: FAILURE: %s" % (address_get['code']))
            self.error = address_get['code']
            return self.error

        logging.info("phpipam.address_get: success %s" % (address_get['success']))
        return address_get['data']

    """ Create new address

           Attributes:
               number: address number
               name: short name
               description: description

       """

    def address_create(self, ip, subnetId, hostname, description="", is_gateway=0, mac="" ):
        headers = {'token': self.token}
        data = {
            "ip":ip,
            "subnetId":subnetId,
            "hostname":hostname,
            "description":description,
            "is_gateway":is_gateway,
            "mac": mac
        }
        p = requests.post(self.base + "addresses/", headers=headers, data=data)
        address_create = json.loads(p.text)

        if p.status_code != 201:
            logging.error("phpipam.address_create: Failure %s" % (p.status_code))
            logging.error(address_create)
            self.error = p.status_code
            self.error_message = address_create['message']
            return self.error, self.error_message

        if not address_create['success']:
            logging.error("phpipam.address_create: FAILURE: %s" % (address_create['code']))
            self.error = address_create['code']
            return self.error

        logging.info("phpipam.address_create: success %s" % (address_create['success']))
        return address_create['data']

    """ VLAN """

    """ Get Information about a specific vlan

            Attributes:
                vlan_id: The vlan identifier either the ID or cidr
        """

    def vlan_get(self, vlan_id):
        headers = {'token': self.token}
        p = requests.get(self.base + "vlans/%s/?links=false" % (vlan_id), headers=headers)
        vlan_get = json.loads(p.text)

        if p.status_code != 200:
            logging.error("phpipam.vlan_get: Failure %s" % (p.status_code))
            logging.error(vlan_get)
            self.error = p.status_code
            self.error_message = vlan_get['message']
            return self.error, self.error_message

        if not vlan_get['success']:
            logging.error("phpipam.vlan_get: FAILURE: %s" % (vlan_get['code']))
            self.error = vlan_get['code']
            return self.error

        logging.info("phpipam.vlan_get: success %s" % (vlan_get['success']))
        return vlan_get['data']


    """ vlan_get_id
        search for the ID of a vlan.

            Attributes:
                vlan: The vlan to search for
        """


    def vlan_get_id(self, vlan_id):
        headers = {'token': self.token}
        p = requests.get(self.base + "vlans/search/%s/?links=false" % (vlan_id), headers=headers)
        vlan_get = json.loads(p.text)

        if p.status_code != 200:
            logging.error("phpipam.vlan_get: Failure %s" % (p.status_code))
            logging.error(vlan_get)
            self.error = p.status_code
            self.error_message = vlan_get['message']
            return self.error, self.error_message

        if not vlan_get['success']:
            logging.error("phpipam.vlan_get: FAILURE: %s" % (vlan_get['code']))
            self.error = vlan_get['code']
            return self.error

        logging.info("phpipam.vlan_get: success %s" % (vlan_get['success']))
        return vlan_get['data'][0]['id']


    """ Get vlan subnets

            Attributes:
                vlan_id: The vlan identifier
        """


    def vlan_subnets(self, vlan_id):
        headers = {'token': self.token}
        p = requests.get(self.base + "vlans/%s/subnets/?links=false" % (vlan_id), headers=headers)
        print p.text
        vlan_subnets = json.loads(p.text)

        if p.status_code != 200:
            logging.error("phpipam.vlan_subnets: Failure %s" % (p.status_code))
            logging.error(vlan_subnets)
            self.error = p.status_code
            self.error_message = vlan_subnets['message']
            return self.error, self.error_message

        if not vlan_subnets['success']:
            logging.error("phpipam.vlan_subnets: FAILURE: %s" % (vlan_subnets['code']))
            self.error = vlan_subnets['code']
            return self.error

        logging.info("phpipam.vlan_subnets: success %s" % (vlan_subnets['success']))
        return vlan_subnets['data']

    """ Create new vlan

        Attributes:
            number: vlan number
            name: short name
            description: description

    """

    def vlan_create(self, number, name, description=""):
        headers = {'token': self.token}
        data={
            'number' : number,
            'name' : name,
            'description' : description,
        }
        p = requests.post(self.base + "vlans/", headers=headers, data=data)
        vlan_create = json.loads(p.text)

        if p.status_code != 201:
            logging.error("phpipam.vlan_create: Failure %s" % (p.status_code))
            logging.error(vlan_create)
            self.error = p.status_code
            self.error_message = vlan_create['message']
            return self.error, self.error_message

        if not vlan_create['success']:
            logging.error("phpipam.vlan_create: FAILURE: %s" % (vlan_create['code']))
            self.error = vlan_create['code']
            return self.error

        logging.info("phpipam.vlan_create: success %s" % (vlan_create['success']))
        return vlan_create['data']


    """ Delete a vlan 
    
     Attributes:
         vlan_id = vlan name or id.
     """
    
    
    def vlan_delete(self, vlan_id, ):
        headers = {'token': self.token}
        p = requests.delete(self.base + "vlans/%s/" % (vlan_id), headers=headers)
        print p.text
        vlans_delete = json.loads(p.text)
    
        if p.status_code != 200:
            logging.error("phpipam.vlans_delete: Failure %s" % (p.status_code))
            logging.error(vlans_delete)
            self.error = p.status_code
            self.error_message = vlans_delete['message']
            return self.error, self.error_message
    
        if not vlans_delete['success']:
            logging.error("phpipam.vlans_delete: FAILURE: %s" % (vlans_delete['code']))
            self.error = vlans_delete['code']
            return self.error
    
        logging.info("phpipam.vlans_delete: success %s" % (vlans_delete['success']))
        return vlans_delete['code']