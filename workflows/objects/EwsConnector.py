#!/usr/bin/env python3
# -*- coding: utf8 -*-

import logging
from exchangelib import DELEGATE, Account, Credentials, Configuration, NTLM

class EwsConnector:
    'Exchange web service connector'

    def __init__(self, cfg=None, username=None, password=None, auth_type=None, server=None, smtp_address=None):
        self.logger = logging.getLogger('workflows.' + __name__)
        self.cfg = cfg
        self.username = username
        self.password = password
        self.auth_type = auth_type
        self.server = server
        self.smtp_address = smtp_address
        self.account = self.getAccount()

    def getAccount(self):
        self.logger.info('%s.getAccount starts', __name__)
        try:
            username = self.username if isinstance(self.username, str) else self.cfg.get('EWS', 'username')
            password = self.password if isinstance(self.password, str) else self.cfg.get('EWS', 'password')
            authType = self.auth_type if isinstance(self.auth_type, str) else self.cfg.get('EWS', 'auth_type')
            credentials = Credentials(username=username, password=password)

            ews_server = self.server if isinstance(self.server, str) else self.cfg.get('EWS', 'server')
            smtp_address = self.smtp_address if isinstance(self.smtp_address, str) else self.cfg.get('EWS', 'smtp_address')

            if authType == 'NTLM':
                config = Configuration(server=ews_server,
                    credentials=credentials,
                    auth_type=NTLM)
            elif authType == 'None':
                #O365 does not use NTLM auth
                config = Configuration(server=ews_server,
                    credentials=credentials,
                    auth_type=None)
            else:
                raise ValueError(authType)

            account = Account(primary_smtp_address=smtp_address,
                config=config, autodiscover=False, access_type=DELEGATE)

            return account
        except ValueError:
            self.logger.error('authType not supported: %s', authType)
            raise
        except Exception as e:
            self.logger.error('Failed to get account', exc_info=True)
            raise


    def scan(self, folderName):
        #returns a query set of unread emails
        #<class 'exchangelib.queryset.QuerySet'>

        self.logger.info('%s.scan starts', __name__)

        folder = None
        try:
            #get the folder first
            if folderName == 'inbox':
                folder = self.account.inbox
            else:
                for f in self.account.root.walk():
                    if f.name == folderName:
                        folder = f

            if folder is None:
                raise ValueError('folder %s not found', folderName)

            unread = folder.filter(is_read = False)

            return unread

        except Exception as e:
            self.logger.error('Failed to get unread emails', __name__, exc_info = True)
            raise

    def markAsRead(self, msg):
        self.logger.info('%s.markAsRead starts', __name__)
        msg.is_read = True
        msg.save()
        return msg
