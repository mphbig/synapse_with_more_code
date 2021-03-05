#!/usr/bin/env python3
# -*- coding: utf8 -*-

import os
import json
import logging

from cbapi import CbPSCBaseAPI # used for alerts and dismiss
from cbapi import CbDefenseAPI # used for notifications
from cbapi.psc.models import BaseAlert # used to query alerts


class CBConnector:
    """
    Carbon Black Connector, uses the official library
    Needs a config file in working directory (/opt/Synapse) or in $HOME : .carbonblack/credentials.psc
    NEEDS A CONFIG FILE IN /etc/carbonblack/carbonblack.psc
    For config file, see : https://github.com/carbonblack/cbapi-python#api-token
    For usage examples, see : https://github.com/carbonblack/cbapi-python/tree/master/examples
    """

    def __init__(self):
        self.logger = logging.getLogger('workflows.' + __name__)
        #currentPath = os.path.dirname(os.path.abspath(__file__))
        #confPath = os.path.join(currentPath, "..", "..", "conf", "carbonblack.json")


    def getAllNotifications(self, defense_profile, psc_profile):
        """
        Get all the new notifications
        """
        self.logger.info('%s.getAllNotifications starts', __name__)

        def merge_info(dict1, dict2):
            dict_ret = {}
            for key, value in dict1.items():
                dict_ret[key] = value
            for key, value in dict2.items():
                dict_ret[key] = value
            return dict_ret

        notifications = []

        cbDefense = CbDefenseAPI(profile=defense_profile)
        cbPSC = CbPSCBaseAPI(profile=psc_profile)

        # get the alerts, named "notifications" on CB
        alerts = cbDefense.get_notifications()
        for alert in alerts:
            query = cbPSC.select(BaseAlert).set_legacy_alert_ids([str(alert['threatInfo']['incidentId'])])
            moreInfo = list(query)[0]
            # gives an object, change CarbonBlack2Alerts.py or use .__dict__ ?
            notifications.append(merge_info(alert, moreInfo.__dict__))

        return notifications


    def dismissAlert(self, alert_ids, client, dismiss=True, remediation=None, comment=None):
        """
        If dismiss is True, this will dismiss an alert, else it will undismiss it

        Client must be the trigram of the client for example : "THP"

        alert_ids MUST be a list
        """
        self.logger.info('%s.dismissAlert starts', __name__)

        if not isinstance(alert_ids, list):
            raise TypeError("alert_ids must be a list")

        with open(confPath) as f:
            config = json.load(f)

        organization = None
        for org in config['orgs']:
            if org['short-name'].upper() == client.upper():
                organization = org
                break

        cbPSC = CbPSCBaseAPI(profile=organization['alerts_profile'])

        # search the alerts
        query = cbPSC.select(BaseAlert).set_legacy_alert_ids(alert_ids)

        req = None
        if dismiss:
            # request dismiss
            req = query.dismiss(remediation=remediation, comment=comment)
        else:
            # there is no "undismiss" function in cbapi, but the "update"
            # function lefts the alerts in an OPEN state when used
            req = query.update(remediation=remediation, comment=comment)

        # possible to monitor the status of the request is it usefull ?
        from cbapi.psc.models import WorkflowStatus
        import time
        status = cbPSC.select(WorkflowStatus, req)
        while not status.finished:
            # do something
            self.logger.debug("CB dismiss is not done yet !")
            time.sleep(5)
