#!/usr/bin/env python3
# -*- coding: utf8 -*-

import os
import sys
import logging
import uuid
import datetime
from dateutil import parser as dateutil_parser

current_dir = os.path.dirname(os.path.abspath(__file__))
app_dir = os.path.join(current_dir, "..")
sys.path.insert(0, current_dir)

from common.common import getConf
from objects.CBConnector import CBConnector
from objects.TheHiveConnector import TheHiveConnector
from thehive4py.models import AlertArtifact, CustomFieldHelper


def rapid7IDRAlerts2Alerts(alert_data, org_name):
    logger = logging.getLogger('workflows.' + __name__)
    logger.info('%s.rapid7IDRAlerts2Alert starts', __name__)

    result = {}
    result['success'] = bool()

    conf = getConf()
    theHiveConnector = TheHiveConnector(conf)

    logger.info("Building custom fields ...")
    customFields = CustomFieldHelper()\
        .add_string('client', org_name)\
        .build()

    tags = []

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    alert_date = dateutil_parser.parse(alert_data.get('timestamp', now))

    for user in alert_data.get('actors', {}).get('users', []):
        tags.append(user.get('name', ""))

    for asset in alert_data.get('actors', {}).get('assets', []):
        tags.append(asset.get('shortname', ""))

    logger.info("Building description ...")
    description = descriptionCrafter(alert_data, org_name)

    logger.info("Building alert ...")
    alert = theHiveConnector.craftAlert(
        title=alert_data.get('title', alert_data.get('name', "New alert from Rapid7 Insight IDR")),
        description=description,
        severity=2,#is there a way to determine efficiently this thing ?
        date=int(alert_date.timestamp())*1000,
        tags=tags,
        tlp=2,
        status="New",
        type="SIEM",
        source="Rapid7 Insight IDR",
        sourceRef=alert_data.get('investigationId', str(uuid.uuid4())),
        artifacts=artifactsCrafter(alert_data),
        caseTemplate="Insight IDR Case",
        customFields=customFields)

    logger.info("Sending alert to TheHive ...")
    try:
        ret = theHiveConnector.createAlert(alert)
        logger.info("Alert {} created in TheHive".format(str(ret['id'])))
        result['success'] = True
    except ValueError:
        logger.warning("Alert creation failed, trying to update ...")
        try:
            ret = theHiveConnector.updateAlert(alert.sourceRef, alert)
            logger.info("Alert {} updated in TheHive".format(str(ret['id'])))
            result['success'] = True
        except Exception as error:
            logger.error("Alert update failed ! {}".format(error))
            result['success'] = False

    return result


def artifactsCrafter(alert_data):
    alert_id = alert_data.get('investigationId', "")
    artifacts = []
    emails = []
    usernames = []
    hostnames = []

    users = alert_data.get('actors', {}).get('users', [])
    assets = alert_data.get('actors', {}).get('assets', [])

    if len(users) > 0:
        for user in users:
            emails.append([user.get('name', ""), user.get('emails', [])])
            usernames.append([user.get('name', ""), user.get('distinguishedName', "")])

    if len(assets) > 0:
        for asset in assets:
            hostnames.append([asset.get('hostname', ""), asset.get('fqdn', ""), asset.get('shortname', "")])

    for email in emails:
        for mail in email[1]:
            artifacts.append(AlertArtifact(
                dataType="mail",
                data=mail,
                message="",
                tags=[alert_id, email[0]]))

    for username in usernames:
        artifacts.append(AlertArtifact(
            dataType="username",
            data=username[0],
            message=username[1],
            tags=[alert_id, username[0]]))

    for hostname in hostnames:
        artifacts.append(AlertArtifact(
            dataType="hostname",
            data=hostname[0],
            message="{}\n\n{}".format(hostname[1], hostname[2]),
            tags=[alert_id]))



    return artifacts


def descriptionCrafter(alert_data, org_name):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    alert_date = dateutil_parser.parse(alert_data.get('timestamp', now))

    description =\
        '| **SUMMARY**             |                     |\n'\
        '|:------------------------|:-------------------:|\n'\
        '| **Organization**        | {orgName}           |\n'\
        '| **Alert Type**          | {AlertType}         |\n'\
        '| **Alert Name**          | {AlertName}         |\n'\
        '| **Description**         | {AlertDescription}  |\n'\
        '| **Detection Date**      | {DetectionDate}     |\n'\
        '\n\n'.format(
            orgName=org_name,
            AlertType=alert_data.get('type', ""),
            AlertName=alert_data.get('name', ""),
            AlertDescription=alert_data.get('description', ""),
            DetectionDate=alert_date.strftime("%a %d %b %Y"))

    link = alert_data.get('link', "")
    if link != "":
        description +=\
            '---\n'\
            '### [🔍 Investigate in Rapid7 Insight IDR]({alert_link})\n'\
            '---'.format(alert_link=str(link))

    description += '\n\n\n'

    return description
