#!/usr/bin/env python3
# -*- coding: utf8 -*-

import os, sys
import logging
import copy
import json

from time import sleep

current_dir = os.path.dirname(os.path.abspath(__file__))
app_dir = current_dir + '/..'
sys.path.insert(0, current_dir)

from common.common import getConf
from objects.QRadarConnector import QRadarConnector
from objects.TheHiveConnector import TheHiveConnector
from thehive4py.models import CustomFieldHelper, Alert, AlertArtifact
from thehive4py.query import Eq

def getEnrichedOffenses(qradarConnector, timerange):
    enrichedOffenses = []

    for offense in qradarConnector.getOffenses(timerange):
        enrichedOffenses.append(enrichOffense(qradarConnector, offense))

    return enrichedOffenses

def enrichOffense(qradarConnector, offense):

    enriched = copy.deepcopy(offense)

    artifacts = []

    enriched['offense_type_str'] = \
                qradarConnector.getOffenseTypeStr(offense['offense_type'])

    enriched['domain_str'] = \
                qradarConnector.getDomainStr(offense['domain_id'])

    # Add the offense source explicitly 
    if enriched['offense_type_str'] == 'Username':
        artifacts.append({'data':offense['offense_source'], 'dataType':'username', 'message':'Offense Source', 'tags': [str(offense['id'])]})

    # Add the local and remote sources
    #scrIps contains offense source IPs
    srcIps = list()
    #dstIps contains offense destination IPs
    dstIps = list()
    #srcDstIps contains IPs which are both source and destination of offense
    srcDstIps = list()
    for ip in qradarConnector.getSourceIPs(enriched):
        srcIps.append(ip)

    for ip in qradarConnector.getLocalDestinationIPs(enriched):
        dstIps.append(ip)

    #making copies is needed since we want to
    #access and delete data from the list at the same time
    s = copy.deepcopy(srcIps)
    d = copy.deepcopy(dstIps)

    for srcIp in s:
        for dstIp in d:
            if srcIp == dstIp:
                srcDstIps.append(srcIp)
                srcIps.remove(srcIp)
                dstIps.remove(dstIp)

    for ip in srcIps:
        artifacts.append({'data':ip, 'dataType':'ip', 'message':'Source IP', 'tags':['Source IP', str(offense['id'])]})
    for ip in dstIps:
        artifacts.append({'data':ip, 'dataType':'ip', 'message':'Local destination IP', 'tags':['Local destination IP', str(offense['id'])]})
    for ip in srcDstIps:
        artifacts.append({'data':ip, 'dataType':'ip', 'message':'Source and local destination IP', 'tags':['Source IP', 'Local destination IP', str(offense['id'])]})

    # Add all the observables
    enriched['artifacts'] = artifacts

    # waiting 1s to make sure the logs are searchable
    sleep(1)
    #adding the first 3 raw logs
    #enriched['logs'] = qradarConnector.getOffenseLogs(enriched)
    #enriched['logs'] = []

    # add the first 3 CREs raw logs (they are more interresting than raw logs)
    enriched['logs'] = qradarConnector.getOffenseCREs(enriched)

    # add the contributing rules to the alert
    enriched['rules'] = qradarConnector.getRules(enriched)

    return enriched

def qradarOffenseToHiveAlert(theHiveConnector, offense):

    #
    # Creating the alert
    #

    client = offense['domain_str']

    tags = []

    SEVERITIES = [1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 4]

    if "categories" in offense:
        for cat in offense['categories']:
            tags.append(cat)

    # we fetch Observable DataTypes here, in case we want a new field
    # from QRadar we just need to add it as a new Observable DataType in TheHive
    defaultObservableDatatype = theHiveConnector.listArtifactDataType()

    artifacts = []
    for artifact in offense['artifacts']:
        if artifact['dataType'] in defaultObservableDatatype:
            hiveArtifact = theHiveConnector.craftAlertArtifact(dataType=artifact['dataType'], data=artifact['data'], message=artifact['message'], tags=artifact['tags'])
        else:
            hiveArtifact = theHiveConnector.craftAlertArtifact(dataType='other', data=artifact['data'], message=artifact['message'], tags=["type:{}".format(artifact['dataType']), str(offense['id'])])
        artifacts.append(hiveArtifact)

    for rule in offense['rules']:
        artifacts.append(theHiveConnector.craftAlertArtifact(
            dataType='qradar_rule',
            data=rule['name'],
            message="Rule participating in offense.",
            tags=[
                "type:{}".format(rule['type']),
                "origin:{}".format(rule['origin']),
                "id:{}".format(rule['id']),
                "owner:{}".format(rule['owner']),
                str(offense['id'])]))

    artifacts.append(AlertArtifact(
        dataType='qradar_offense_id',
        data=str(offense['id']),
        message="ID of offense in QRadar",
        tags=[str(offense['id'])],
        ignoreSimilarity=True))

    customFields = CustomFieldHelper()\
        .add_string('client', client)\
        .add_number('lastEventCount', int(offense['event_count']))\
        .add_date('lastUpdated', int(offense['last_updated_time']))\
        .add_string('offense-type', offense['offense_type_str'])\
        .add_string('offenseSource', offense['offense_source'])\
        .build()

    # Build TheHive alert
    alert = theHiveConnector.craftAlert(
        title=offense['description'],
        description=craftAlertDescription(offense),
        severity=SEVERITIES[offense['severity']],
        date=offense['start_time'],
        tags=tags,
        tlp=2,
        status='New',
        type='SIEM',
        source='QRadar',
        sourceRef=str(offense['id']),
        artifacts=artifacts,
        caseTemplate='QRadar Offense',
        customFields=customFields)

    return alert


def allOffense2Alert(timerange):
    """
       Get all openned offense created within the last
       <timerange> minutes and creates alerts for them in
       TheHive
    """
    logger = logging.getLogger(__name__)
    logger.info('%s.allOffense2Alert starts', __name__)

    report = dict()
    report['success'] = True
    report['offenses'] = list()

    try:
        cfg = getConf()

        qradarConnector = QRadarConnector(cfg)
        theHiveConnector = TheHiveConnector(cfg)

        offensesList = qradarConnector.getOffenses(timerange)

        #each offenses in the list is represented as a dict
        #we enrich this dict with additional details
        for offense in offensesList:
            #searching if the offense has already been converted to alert
            logger.info('Looking for offense %s in TheHive alerts', str(offense['id']))
            # Update only new Alerts, as Ignored it will be closed on QRadar and should not be updated,
            # as Imported we will do a responder to fetch latest info in the case
            results = theHiveConnector.findAlert(Eq("sourceRef", str(offense['id'])))
            offense_report = dict()
            try:
                if len(results) == 0:
                    logger.info('Offense %s not found in TheHive alerts, creating it', str(offense['id']))
                    enrichedOffense = enrichOffense(qradarConnector, offense)

                    theHiveAlert = qradarOffenseToHiveAlert(theHiveConnector, enrichedOffense)
                    theHiveEsAlertId = theHiveConnector.createAlert(theHiveAlert)['id']

                    offense_report['type'] = "Creation"
                    offense_report['raised_alert_id'] = theHiveEsAlertId
                    offense_report['qradar_offense_id'] = offense['id']
                    offense_report['success'] = True

                    report['offenses'].append(offense_report)

                elif results[0]['status'] not in ['Ignored', 'Imported']:
                    # update alert if alert is not imported and not dimissed
                    # will only update 'lastEventCount' and 'lastUpdatedTime' custom fields
                    logger.info('Updating offense %s', str(offense['id']))

                    alert = Alert(json=results[0])
                    cf = CustomFieldHelper()

                    alert.title = offense['description']

                    if 'lastEventCount' not in alert.customFields:
                        alert.customFields['lastEventCount'] = {}

                    if 'lastUpdated' not in alert.customFields:
                        alert.customFields['lastUpdated'] = {}

                    if 'offenseSource' not in alert.customFields:
                        alert.customFields['offenseSource'] = {}

                    alert.customFields['lastEventCount']['number'] = offense['event_count']
                    alert.customFields['lastUpdated']['date'] = offense['last_updated_time']
                    alert.customFields['offenseSource']['string'] = offense['offense_source'] # updated maybe ?

                    # should improve TheHiveConnector.updateAlert() rather than using this
                    updatedAlert = theHiveConnector.theHiveApi.update_alert(results[0]['id'], alert, fields=['customFields', 'title'])
                    if not updatedAlert.ok:
                        raise ValueError(json.dumps(updatedAlert.json()))

                    offense_report['type'] = "Update"
                    offense_report['updated_alert_id'] = updatedAlert.json()['id']
                    offense_report['qradar_offense_id'] = offense['id']
                    offense_report['success'] = True

                    report['offenses'].append(offense_report)

                else:
                    logger.info("Offense already exists")

            except Exception as e:
                logger.error('%s.allOffense2Alert failed', __name__, exc_info=True)
                offense_report['success'] = False
                if isinstance(e, ValueError):
                    errorMessage = json.loads(str(e))['message']
                    offense_report['message'] = errorMessage
                else:
                    offense_report['message'] = str(e) + ": Couldn't raise alert in TheHive"
                offense_report['offense_id'] = offense['id']
                # Set overall success if any fails
                report['success'] = False

    except Exception as e:

            logger.error('Failed to create alert from QRadar offense (retrieving offenses failed)', exc_info=True)
            report['success'] = False
            report['message'] = "%s: Failed to create alert from offense" % str(e)

    return report


def craftAlertDescription(offense):
    """
        From the offense metadata, crafts a nice description in markdown
        for TheHive
    """
    logger = logging.getLogger(__name__)
    logger.info('craftAlertDescription starts')

    cfg = getConf()
    QRadarIp = cfg.get('QRadar', 'server')
    url = "https://{QRadarIp}/console/qradar/jsp/QRadar.jsp?appName=Sem&pageId=OffenseSummary&summaryId={offense_id}"\
        .format(QRadarIp=QRadarIp, offense_id=offense['id'])

    # Summary
    description = (
        "| **Summary**             | {offense_id}           |\n"\
        "| :---------------------- | :--------------------: |\n"\
        "| **Description**         | {description}          |\n"\
        "| **Domain**              | {domain_str}           |\n"\
        "| **Offense Type**        | {offense_type_str}     |\n"\
        "| **Offense Source**      | {offense_source}       |\n"\
        "| **Destination Network** | {destination_networks} |\n"\
        "| **Source Network**      | {source_network}      |\n"\
        "| **Initial Event Count** | {event_count}          |\n\n"\
        .format(
            offense_id=offense['id'],
            description=offense['description'].replace('\n', ''),
            domain_str=offense['domain_str'],
            offense_type_str=offense['offense_type_str'],
            offense_source=offense['offense_source'],
            destination_networks=", ".join(offense['destination_networks']),
            source_network=offense['source_network'],
            event_count=offense['event_count']))

    # Contributing rules
    #description += (
    #    '---\n' +
    #    '| **Contributing Rules**   |\n' +
    #    '| :----------------------: |\n')
    #for rule in offense['rules']:
    #    description += '| ' + str(rule) + ' |\n'

    # CRE Events
    description += ('\n\n' +
        '---\n' +
        '| **CRE Event** |\n' +
        '| ------------- |\n')
    for log in offense['logs']:
        description += '| {log} |\n'.format(log=log['utf8_payload'].replace('\n', ' '))

    # First 3 raw logs
    #description += '\n\n```\n'
    #for log in offense['logs']:
    #    description += log['utf8_payload'] + '\n'
    #description += '```\n\n'

    # QRadar URL
    description += '\n\n'\
    '---\n'\
    '### [🔍 Investigate in QRadar]({offense_url})\n'\
    '---\n'.format(offense_url=url)

    return description

if __name__ == '__main__':
    #hardcoding timerange as 1 minute when not using the API
    #timerange = 1
    #offense2Alert(timerange)
    cfg = getConf()
    QRadarConnector(cfg).getDomainStr(2)
