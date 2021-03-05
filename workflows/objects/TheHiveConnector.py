#!/usr/bin/env python3
# -*- coding: utf8 -*-

import logging
import json
import requests

from thehive4py.api import TheHiveApi
from thehive4py.models import Case, CaseTask, CaseTaskLog, CaseObservable, AlertArtifact, Alert
from thehive4py.query import *

class TheHiveConnector:
    'TheHive connector'

    def __init__(self, cfg):
        self.logger = logging.getLogger('workflows.' + __name__)
        self.cfg = cfg

        self.theHiveApi = self.connect()

    def connect(self):
        self.logger.info('%s.connect starts', __name__)

        url = self.cfg.get('TheHive', 'url')
        api_key = self.cfg.get('TheHive', 'api_key')

        return TheHiveApi(url, api_key)

    def searchCaseByDescription(self, string):
        #search case with a specific string in description
        #returns the ES case ID

        self.logger.info('%s.searchCaseByDescription starts', __name__)

        query = dict()
        query['_string'] = 'description:"{}"'.format(string)
        range = 'all'
        sort = []
        response = self.theHiveApi.find_cases(query=query, range=range, sort=sort)

        if response.status_code != 200:
            error = dict()
            error['message'] = 'search case failed'
            error['query'] = query
            error['payload'] = response.json()
            self.logger.error('Query to TheHive API did not return 200')
            raise ValueError(json.dumps(error, indent=4, sort_keys=True))

        if len(response.json()) == 1:
            #one case matched
            esCaseId = response.json()[0]['id']
            return esCaseId
        elif len(response.json()) == 0:
            #no case matched
            return None
        else:
            #unknown use case
            raise ValueError('unknown use case after searching case by description')


    def craftCase(self, title, description, tlp=2):
        self.logger.info('%s.craftCase starts', __name__)

        case = Case(title=title,
            tlp=tlp,
            tags=['Synapse'],
            description=description,
            )

        return case

    def createCase(self, case):
        self.logger.info('%s.createCase starts', __name__)

        response = self.theHiveApi.create_case(case)

        if response.status_code == 201:
            esCaseId =  response.json()['id']
            createdCase = self.theHiveApi.case(esCaseId)
            return createdCase
        else:
            self.logger.error('Case creation failed')
            raise ValueError(json.dumps(response.json(), indent=4, sort_keys=True))

    def assignCase(self, case, assignee):
        self.logger.info('%s.assignCase starts', __name__)

        esCaseId = case.id
        case.owner = assignee
        self.theHiveApi.update_case(case)

        updatedCase = self.theHiveApi.case(esCaseId)
        return updatedCase

    def craftCommTask(self):
        self.logger.info('%s.craftCommTask starts', __name__)

        commTask = CaseTask(title='Communication',
            status='InProgress',
            owner='synapse')

        return commTask

    def createTask(self, esCaseId, task):
        self.logger.info('%s.createTask starts', __name__)

        response = self.theHiveApi.create_case_task(esCaseId, task)

        if response.status_code == 201:
            esCreatedTaskId = response.json()['id']
            return esCreatedTaskId
        else:
            self.logger.error('Task creation failed')
            raise ValueError(json.dumps(response.json(), indent=4, sort_keys=True))

    def craftAlertArtifact(self, **attributes):
        self.logger.info('%s.craftAlertArtifact starts', __name__)

        alertArtifact = AlertArtifact(dataType=attributes["dataType"], message=attributes["message"], data=attributes["data"], tags=attributes['tags'])

        return alertArtifact

    def craftTaskLog(self, textLog):
        self.logger.info('%s.craftTaskLog starts', __name__)

        log = CaseTaskLog(message=textLog)

        return log

    def addTaskLog(self, esTaskId, textLog):
        self.logger.info('%s.addTaskLog starts', __name__)

        response = self.theHiveApi.create_task_log(esTaskId, textLog)

        if response.status_code == 201:
            esCreatedTaskLogId = response.json()['id']
            return esCreatedTaskLogId
        else:
            self.logger.error('Task log creation failed')
            raise ValueError(json.dumps(response.json(), indent=4, sort_keys=True))

    def getTaskIdByTitle(self, esCaseId, taskTitle):
        self.logger.info('%s.getTaskIdByName starts', __name__)

        response = self.theHiveApi.get_case_tasks(esCaseId)
        for task in response.json():
            if task['title'] == taskTitle:
                return task['id']

        #no <taskTitle> found
        return None

    def addFileObservable(self, esCaseId, filepath, comment, tags=[]):
        self.logger.info('%s.addFileObservable starts', __name__)

        file_observable = CaseObservable(dataType='file',
            data=[filepath],
            tlp=2,
            ioc=False,
            tags=tags,
            message=comment
        )

        response = self.theHiveApi.create_case_observable(
            esCaseId, file_observable)

        if response.status_code == 201:
            esObservableId = response.json()[0]['id']
            return esObservableId
        else:
            self.logger.error('File observable upload failed')
            raise ValueError(json.dumps(response.json(), indent=4, sort_keys=True))

    def addObservable(self, caseid, dataType, data, tags=[], tlp=2, ioc=False, message=""):
        self.logger.info('%s.addObservable starts', __name__)

        observable = CaseObservable(dataType=dataType,
            data=data,
            tlp=tlp,
            ioc=ioc,
            tags=tags,
            message=message
        )

        response = self.theHiveApi.create_case_observable(
            caseid, observable)

        if response.status_code == 201:
            esObservableId = response.json()['id']
            return esObservableId
        else:
            self.logger.error('Observable creation failed')
            raise ValueError(json.dumps(response.json(), indent=4, sort_keys=True))

    def craftAlert(self, title, description, severity, date, tags, tlp, status, type, source,
        sourceRef, artifacts, caseTemplate, customFields):
        self.logger.info('%s.craftAlert starts', __name__)

        alert = Alert(title=title,
            description=description,
            severity=severity,
            date=date,
            tags=tags,
            tlp=tlp,
            type=type,
            source=source,
            sourceRef=sourceRef,
            artifacts=artifacts,
            caseTemplate=caseTemplate,
            customFields=customFields)

        return alert

    def createAlert(self, alert):
        self.logger.info('%s.createAlert starts', __name__)

        response = self.theHiveApi.create_alert(alert)

        if response.status_code == 201:
            return response.json()
        else:
            self.logger.error('Alert creation failed')
            raise ValueError(json.dumps(response.json(), indent=4, sort_keys=True))

    def updateAlert(self, alertRef, alert):
        """
        Update an alert in TheHive to add new fields

        :param alertRef: The reference of the alert to update
        :type alertRef: string
        :param alert: The alert object with new data only, appending to the old data is done in this function
        :type alert: thehive4py.models.Alert

        :return results: response of the update as a dict
        :rtype results: dict
        """
        self.logger.info("{}.updateAlert starts".format(__name__))

        res = self.findAlert(Eq("sourceRef", alertRef))[0]

        oldAlert = Alert(json=res)
        oldAlert.id = res['id']
        newAlert = Alert(json=json.loads(alert.jsonify()))
        # update description
        oldAlert.description += newAlert.description
        # update severity
        oldAlert.severity = max(oldAlert.severity, newAlert.severity)

        # check for new artifacts, append new ones to old alert
        oldArtifacts_type = []
        oldArtifacts_data = []
        for artifact in oldAlert.artifacts:
            oldArtifacts_type.append(artifact.dataType)
            oldArtifacts_data.append(artifact.data)
        for artifact in newAlert.artifacts:
            if artifact.dataType not in oldArtifacts_type or artifact.data not in oldArtifacts_data:
                oldAlert.append(artifact)

        # append new tags
        for tag in newAlert.tags:
            if tag not in oldAlert.tags:
                oldAlert.tags.append(tag)

        # update alert
        ret = self.theHiveApi.update_alert(oldAlert.id, oldAlert, fields=['description', 'tags', 'severity', 'artifacts'])
        if ret.status_code == 200 or ret.status_code == 201:
            return ret.json()
        else:
            self.logger.error('Alert update failed')
            raise ValueError(json.dumps(ret.json(), indent=4, sort_keys=True))

    def findAlert(self, q):
        """
            Search for alerts in TheHive for a given query

            :param q: TheHive query
            :type q: dict

            :return results: list of dict, each dict describes an alert
            :rtype results: list
        """

        self.logger.info('%s.findAlert starts', __name__)

        response = self.theHiveApi.find_alerts(query=q)
        if response.status_code == 200:
            results = response.json()
            return results
        else:
            self.logger.error('findAlert failed')
            raise ValueError(json.dumps(response.json(), indent=4, sort_keys=True))

    def findFirstMatchingTemplate(self, searchstring):
        self.logger.info('%s.findFirstMatchingTemplate starts', __name__)

        query = Eq('status', 'Ok')
        allTemplates = self.theHiveApi.find_case_templates(query=query)
        if allTemplates.status_code != 200:
            raise ValueError('Could not find matching template !')

        for template in allTemplates.json():
            if searchstring in template['name']:
                return template

        return None

    def deleteCase(self, caseId):
        self.logger.info('%s.deleteCase starts', __name__)

        # OK = 204
        url = self.theHiveApi.url + "/api/case/{}/force".format(caseId)
        try:
            return requests.delete(url, headers={'Content-Type': 'application/json'}, proxies=self.theHiveApi.proxies, auth=self.theHiveApi.auth, verify=self.theHiveApi.cert)
        except requests.exceptions.RequestException as e:
            raise ValueError("Case deletion error: {}".format(e))

    def listArtifactDataType(self):
        self.logger.info('%s.listArtifactDataType starts', __name__)

        url = self.theHiveApi.url + "/api/list/list_artifactDataType"
        try:
            res = requests.get(url, headers={"Accept": "application/json"}, proxies=self.theHiveApi.proxies, auth=self.theHiveApi.auth, verify=self.theHiveApi.cert)
            return list(res.json().values())
        except requests.exceptions.RequestException as e:
            raise ValueError("Failed to get artifact DataType list: {}".format(e))

    def getAllAlertsOfCase(self, case):
        self.logger.info('%s.getAllAlertsOfCase starts', __name__)

        query = Eq("case", str(case))
        alerts = self.findAlert(query)

        return alerts

    def get_username(self, user):
        self.logger.info('%s.get_username starts', __name__)

        url = "{}/api/user/{}".format(self.theHiveApi.url, user)

        try:
            res = requests.get(url, headers={"Accept": "application/json"}, proxies=self.theHiveApi.proxies, auth=self.theHiveApi.auth, verify=self.theHiveApi.cert)
            return res
        except requests.exceptions.RequestException as e:
            raise ValueError("Failed to get artifact DataType list: {}".format(e))
