#!/usr/bin/env python3
# -*- coding: utf8 -*-

import os, sys
import logging
import json
import datetime

current_dir = os.path.dirname(os.path.abspath(__file__))
app_dir = os.path.join(current_dir, "..")
sys.path.insert(0, current_dir)

SEVERITIES = {1:1, 2:1, 3:2, 4:2, 5:2, 6:2, 7:3, 8:3, 9:3, 10:4}

from common.common import getConf
from objects.CBConnector import CBConnector
from objects.TheHiveConnector import TheHiveConnector
from thehive4py.models import CustomFieldHelper, AlertArtifact


def allNotifs2Alert():
    logger = logging.getLogger('workflows.' + __name__)

    logger.info('%s.allNotifs2Alert starts', __name__)

    result = dict()
    result['success'] = bool()
    result['message'] = str()

    try:
        carbonBlack = CBConnector()


        # DEBUG PURPOSES ONLY !
        #logger.info(str(allNotifications))

        conf = getConf()
        theHiveConnector = TheHiveConnector(conf)

        with open(os.path.join(current_dir, "..", "conf", "carbonblack.json")) as fd:
            organizations = json.load(fd)['orgs']

        for org in organizations:
            notifications = carbonBlack.getAllNotifications(org['notifications_profile'], org['alerts_profile'])
            for notification in notifications:
                #TODO: maybe we should set ALL the variables containing relevant info here to avoid .get() everywhere, btw is .get() actually usefull ?
                #TODO: maybe cut a lot of this variable process in a few (or a lot of) functions, juste like "descriptionCrafter" and "artifactCrafter"
                # This and the next try...catch is to avoid backslashes '\' in a tag, as it is breaking TheHive sorting mechanism
                orgName = org['name']
                orgTagName = org['tag-name']
                orgShortName = org['short-name']
                orgId = org['orgId']
                client = org['jira-project']

                deviceName = str(notification['deviceInfo']['deviceName'])
                summary = str(notification['threatInfo']['summary'])
                severity = int(SEVERITIES[int(notification['threatInfo']['score'])])
                date_created = int(notification['eventTime'])
                source_ref = "{}-{}".format(orgShortName, str(notification['threatInfo']['incidentId']))
                sensor_id = str(notification['deviceInfo']['deviceId'])
                offense_id = str(notification['threatInfo']['incidentId'])

                tags = []

                customFields = CustomFieldHelper()\
                    .add_string('client', client)\
                    .add_string('sensorID', sensor_id)\
                    .add_string('hostname', deviceName)\
                    .build()

                artifacts = artifactCrafter(notification, theHiveConnector, tags)
                artifacts.append(AlertArtifact(
                    dataType='carbon_black_alert_id',
                    data=offense_id,
                    message="ID of alert in Carbon Black",
                    tags=[offense_id],
                    ignoreSimilarity=True))

                alert = theHiveConnector.craftAlert(
                    title=summary,
                    description=descriptionCrafter(notification, orgName, orgId),
                    severity=severity,
                    date=date_created,
                    tags=tags,
                    tlp=2,
                    status="New",
                    type='EDR',
                    source='Carbon Black',
                    sourceRef=source_ref,
                    artifacts=artifacts,
                    caseTemplate='Carbon Black Case',
                    customFields=customFields)

                try:
                    ret = theHiveConnector.createAlert(alert)
                    logger.info('Alert {} created in TheHive'.format(str(ret['id'])))
                except ValueError:
                    logger.warning('Failed to create alert trying to update')
                    try:
                        ret = theHiveConnector.updateAlert(alert.sourceRef, alert)
                        logger.info('Alert {} updated in TheHive'.format(str(ret['id'])))
                    except ValueError as error:
                        logger.error("Failed to create alert ! {}".format(error))

        result['success'] = True
    except Exception as error:
        result['success'] = False
        result['message'] = str(error)

    return result

def descriptionCrafter(notification, orgName, orgId):
    alert_triage = \
            "https://defense-eu.conferdeploy.net/triage?deviceId={sensorId}&threatId={threatId}&incidentId={incidentId}&orgId={orgId}"\
            .format(
                sensorId=notification['deviceInfo']['deviceId'],
                threatId=notification['threatInfo']['threatCause']['causeEventId'],
                incidentId=notification['threatInfo']['incidentId'],
                orgId=orgId)

    return (
        '| **SUMMARY**             | **{alertId}**       |\n'\
        '|:------------------------|:-------------------:|\n'\
        '| **Organization**        | {orgName}           |\n'\
        '| **Process Name**        | {process_name}      |\n'\
        '| **Policy Name**         | {policy_name}       |\n'\
        '| **Policy Applied**      | {policy_applied}    |\n'\
        '| **Sensor Action**       | {sensor_action}     |\n'\
        '| **Run State**           | {run_state}         |\n'\
        '| **Threat Summary**      | {threat_summary}    |\n'\
        '| **Threat Score**        | {threat_score}      |\n'\
        '| **Threat Category**     | {threat_category}   |\n'\
        '| **Threat Reputation**   | {threat_reputation} |\n'\
        '| **Device Hostname**     | {device_hostname}   |\n'\
        '| **Device Version**      | {device_version}    |\n'\
        '| **Device Internal IP**  | {device_intIP}      |\n'\
        '| **Device External IP**  | {device_extIP}      |\n'\
        '| **Device e-mail**       | {device_email}      |\n'\
        '| **Detection Date**      | {detection_date}    |\n'\
        '---\n'\
        '### [📋 Investigate in Carbon Black PSC]({PSC})\n'\
        '---'\
        '\n'\
        '---\n'\
        '### [🔍 Alert Triage in Carbon Black PSC]({alert_triage})\n'\
        '---'\
        '\n'\
        '\n'\
        .format(
            alertId=notification['threatInfo']['incidentId'],
            orgName=orgName,
            process_name=notification['_info']['process_name'],
            policy_name=notification['_info']['policy_name'],
            policy_applied=notification['_info']['policy_applied'],
            sensor_action=notification['_info']['sensor_action'],
            run_state=notification['_info']['run_state'],
            threat_summary=notification['threatInfo']['summary'],
            threat_score=notification['threatInfo']['score'],
            threat_category=notification['threatInfo']['threatCause']['threatCategory'],
            threat_reputation=notification['threatInfo']['threatCause']['reputation'],
            device_hostname=notification['deviceInfo']['deviceName'],
            device_version=notification['deviceInfo']['deviceVersion'],
            device_intIP=notification['deviceInfo']['internalIpAddress'],
            device_extIP=notification['deviceInfo']['externalIpAddress'],
            device_email=notification['deviceInfo']['email'],
            PSC=notification['url'],
            alert_triage=alert_triage,
            detection_date=datetime.datetime.fromtimestamp(int(notification['eventTime']) / 1000).strftime("%a %d %b %Y, %T")))


def artifactCrafter(notification, theHiveConnector, alert_tags):
    threat_cause_found = False
    artifacts = list()

    # device hostname
    artifacts.append(AlertArtifact(
        dataType='hostname',
        data=str(notification['deviceInfo']['deviceName']),
        message=str("{}\n\n{}".format(notification['deviceInfo']['email'], notification['deviceInfo']['deviceId'])),
        tags=[notification['threatInfo']['incidentId']]))

    # threat indicators (processes)
    for indicator in notification['_info']['threat_indicators']:
        alert_tags.extend(indicator['ttps'])
        tags = indicator['ttps']
        tags.append(str(notification['threatInfo']['incidentId']))
        if indicator['sha256'] == notification['_info']['threat_cause_actor_sha256']:
            tags.append("THREAT CAUSE")
            threat_cause_found = True
        artifacts.append(AlertArtifact(
            dataType='hash',
            data=str(indicator['sha256']),
            message=str(indicator['process_name']),
            tags=tags))

    # threat cause, sometimes not in _info.threat_indicators for whatever reason
    if not threat_cause_found:
        artifacts.append(AlertArtifact(
            dataType='hash',
            data=str(notification['_info']['threat_cause_actor_sha256']),
            message=str(notification['_info']['threat_cause_actor_name']),
            tags=["THREAT CAUSE", str(notification['threatInfo']['incidentId'])]))

    return artifacts
