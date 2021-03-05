#!/usr/bin/env python3
# -*- coding: utf8 -*-

import os, sys
import logging
import json
import datetime
from dateutil.parser import parse as dateutil_parse
from hurry.filesize import size

current_dir = os.path.dirname(os.path.abspath(__file__))
app_dir = os.path.join(current_dir, "..")
sys.path.insert(0, current_dir)

from common.common import getConf
from objects.SentinelOneConnector import SentinelOneConnector
from objects.TheHiveConnector import TheHiveConnector
from thehive4py.models import CustomFieldHelper, AlertArtifact, Alert
from thehive4py.query import Eq


def threats2Alert():
    logger = logging.getLogger('workflows.' + __name__)
    logger.info('%s.threats2Alert starts', __name__)

    theHiveConnector = TheHiveConnector(getConf())

    organizations = None
    with open(os.path.join(current_dir, "..", "conf", "sentinelone.json")) as fd:
        organizations = json.load(fd)['organizations']

    for org in organizations:
        threats = SentinelOneConnector(org['mgt_url'], org['token']).get_threats()

        for threat in threats:
            tags = []
            for indicator in threat['indicators']:
                tags.append(indicator['category'])
                for tactic in indicator['tactics']:
                    tags.append(tactic['name'])

            customFields = CustomFieldHelper()\
                .add_string('client', org['name'])\
                .add_string('hostname', str(threat['agentRealtimeInfo']['agentComputerName']))\
                .build()

            sourceRef = "{}-{}".format(org['trigram'],threat['id'])
            severity = {"na":1, "suspicious":2, "malicious":3}[threat['threatInfo']['confidenceLevel']]

            # external link attribute is TheHive 4 only
            alert = Alert(
                title="{} performing {} activity".format(threat['threatInfo']['threatName'], threat['threatInfo']['classification']),
                description=descriptionCrafter(threat, org),
                severity=severity,
                tags=tags,
                tlp=2,
                date=int(dateutil_parse(threat['threatInfo']['createdAt']).timestamp()) * 1000,
                status="New",
                type='EDR',
                source='Sentinel One',
                sourceRef=sourceRef,
                artifacts=artifactsCrafter(threat),
                caseTemplate='Sentinel One Case',
                customFields=customFields,
                externalLink="{mgt_url}/incidents/threats/{threat_id}/overview"\
                    .format(mgt_url=org['mgt_url'], threat_id=threat['id']))

            find = theHiveConnector.theHiveApi.find_alerts(query=Eq('sourceRef', sourceRef))
            find.raise_for_status()
            find = find.json()

            if len(find) > 0:
                pass
                # update because already exists
                # disabled for now
                #ret = theHiveConnector.theHiveApi.update_alert(find['id'], alert)
                #ret.raise_for_status()
                #logger.info("Alert {} updated in TheHive".format(find['id']))
            else:
                # create because does not exists in TheHive
                ret = theHiveConnector.theHiveApi.create_alert(alert)
                ret.raise_for_status()
                logger.info('Alert {} created in TheHive'.format(ret.json()['id']))

    return {'success': True, 'message': ""}


def descriptionCrafter(notification, org):
    alert_overview = "{mgt_url}/incidents/threats/{threat_id}/overview"\
        .format(mgt_url=org['mgt_url'], threat_id=str(notification['id']))

    ret='| **SUMMARY**                |                   |\n'\
        '|:---------------------------|:-----------------:|\n'\
        '| **Organization**           | {orgName}         |\n'\
        '| **Automatically Resolved** | {auto_resolved}   |\n'\
        '| **Parent Process Name**    | {parent_name}     |\n'\
        '| **Threat Name**            | {threat_name}     |\n'\
        '| **Threat Category**        | {threat_category} |\n'\
        '| **Threat User**            | {threat_user}     |\n'\
        '| **Device Hostname**        | {device_hostname} |\n'\
        '| **Detection Date**         | {detection_date}  |\n'\
        '\n'\
        '---\n'\
        '### [📋 Investigate in Sentinel One]({alert_overview})\n'\
        '---\n\n'\
        .format(
            orgName=notification['agentDetectionInfo']['accountName'],
            auto_resolved="Yes" if notification['threatInfo']['automaticallyResolved'] else "No",
            parent_name=notification['threatInfo']['originatorProcess'],
            threat_name=notification['threatInfo']['threatName'],
            threat_category=notification['threatInfo']['classification'],
            threat_user=notification['threatInfo']['processUser'],
            device_hostname=notification['agentRealtimeInfo']['agentComputerName'],
            detection_date=dateutil_parse(notification['threatInfo']['createdAt']).strftime("%Y-%m-%d %H:%M"),
            alert_overview=alert_overview)

    return ret


def artifactsCrafter(notification):
    artifacts = []

    # device artifact
    message = \
        '- **Private IP**              : {private_ip}\n'\
        '- **Public IP**               : {public_ip}\n'\
        '- **Agent OS**                : {agent_os}\n'\
        '- **Agent OS Revision**       : {os_revision}\n'\
        '- **Agent Version**           : {agent_version}\n'\
        '- **Machine Type**            : {machine_type}\n'\
        '- **Last Logged In Username** : {last_user}\n'\
        .format(
            private_ip=notification['agentDetectionInfo']['agentIpV4'],
            public_ip=notification['agentDetectionInfo']['externalIp'],
            agent_os=notification['agentDetectionInfo']['agentOsName'],
            os_revision=notification['agentDetectionInfo']['agentOsRevision'],
            agent_version=notification['agentDetectionInfo']['agentVersion'],
            machine_type=notification['agentRealtimeInfo']['agentMachineType'],
            last_user=notification['agentDetectionInfo']['agentLastLoggedInUserName'])
    artifacts.append(AlertArtifact(
        dataType='hostname',
        data=str(notification['agentRealtimeInfo']['agentComputerName']),
        message=message,
        ignoreSimilarity=False,
        tags=[notification['id']]))

    # threat artifact
    hash = ""
    if notification['threatInfo']['sha256'] != None:
        hash = notification['threatInfo']['sha256']
    elif notification['threatInfo']['sha1'] != None:
        hash = notification['threatInfo']['sha1']
    elif notification['threatInfo']['md5'] != None:
        hash = notification['threatInfo']['md5']
    else:
        return artifacts
    message = \
        '- **Threat Name**         : {threat_name}\n'\
        '- **Threat Path**         : {threat_path}\n'\
        '- **File Size**           : {file_size}\n'\
        '- **File Extension**      : {file_ext}\n'\
        '- **File Extension Type** : {file_ext_type}\n'\
        '- **Classification**      : {classification}\n'\
        '- **Publisher Name**      : {publisher}\n'\
        .format(
            threat_name=notification['threatInfo']['threatName'],
            threat_path=notification['threatInfo']['filePath'],
            file_size=size(int(notification['threatInfo']['fileSize'])),
            file_ext=notification['threatInfo']['fileExtension'],
            file_ext_type=notification['threatInfo']['fileExtensionType'],
            classification=notification['threatInfo']['classification'],
            publisher=notification['threatInfo']['publisherName'])
    artifacts.append(AlertArtifact(
        dataType='hash',
        data=hash,
        message=message,
        tags=[notification['id']]))

    return artifacts
