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

    """    Check the authorization of acontroller """
    def authorization(self,controller):
        headers = {'token': self.token}
        p = requests.options(self.base+"%s/" %(controller), headers=headers)
        if p.status_code != 200:
            logging.error("phpipam.authorization: Failure %s" %(p.status_code))
            logging.error(p.text)
            self.error = 75
            return self.error