#!/usr/bin/env python3
# -*- coding: utf8 -*-

import os
import sys
import logging
import json
import uuid

current_dir = os.path.dirname(os.path.abspath(__file__))
app_dir = current_dir + '/..'
sys.path.insert(0, current_dir)
store_dir = "/tmp"

logger = logging.getLogger(__name__)
logger.info('%s.connectEws starts', __name__)

from common.common import getConf
from objects.EwsConnector import EwsConnector
from objects.TheHiveConnector import TheHiveConnector
from objects.TempAttachment import TempAttachment
from thehive4py.models import Alert, AlertArtifact, CustomFieldHelper
from datetime import datetime
from bs4 import BeautifulSoup

def exception_handler(type, value, tb):
    logger.exception("Uncaught exception", exc_info=(type, value, tb))
    logger.error('Exception in Ews2Case.py')

sys.excepthook = exception_handler

def connectEws():

    report = dict()
    report['success'] = bool()

    clients = None
    with open('/opt/Synapse/conf/mailboxes.json') as f:
        clients = json.load(f)
    mailboxes = clients['mailboxes']

    cfg = getConf()
    theHiveConnector = TheHiveConnector(cfg)

    for mailbox in mailboxes:
        ewsConnector = EwsConnector(
            username=mailbox['username'],
            password=mailbox['password'],
            auth_type=mailbox['auth_type'],
            server=mailbox['server'],
            smtp_address=mailbox['smtp_address'])

        unread = ewsConnector.scan(mailbox['folder_name'])

        for msg in unread:
            #type(msg)
            #<class 'exchangelib.folders.Message'>
            conversationId = msg.conversation_id.id

            origin_mail = msg.attachments[0].item

            fullBody = getEmailBody(msg)

            alertTitle = "{}; {}".format(msg.subject, ''.join([i if ord(i) < 128 else '' for i in origin_mail.subject]))
            alertDescription = ('```\n' +
                'Alert created by Synapse\n' +
                'conversation_id: "' +
                str(msg.conversation_id.id) +
                '"\n\n' +
                'Original mail:\n\n' +
                fullBody[3:])

            # rapporteur
            reporter = str(msg.sender.email_address).lower()
            # expéditeur
            sender = str(origin_mail.sender.email_address).lower()
            # date de réception originale et en-tant que spam
            rcv_date_timestamp = origin_mail.datetime_received.timestamp() * 1000
            # date de signalement à la boîte support
            rpt_date_timestamp = msg.datetime_received.timestamp() * 1000

            customFields = CustomFieldHelper()\
                .add_string('reporter', reporter)\
                .add_string('sender', sender)\
                .add_date('receivedDate', rcv_date_timestamp)\
                .add_date('reportedDate', rpt_date_timestamp)\
                .add_string('client', mailbox['name'])\
                .build()

            file_paths = []
            artifacts = []

            artifacts.append(AlertArtifact(dataType='mail', data=reporter, ignoreSimilarity=True, tags=['Synapse']))
            artifacts.append(AlertArtifact(dataType='mail', data=sender, message="Original sender of the e-mail", tags=['Synapse', 'Sender']))
            artifacts.append(AlertArtifact(dataType='mail_subject', data=str(origin_mail.subject), message="Original subject of the e-mail", tags=['Synapse']))

            attachedFiles = getFileAttachments(msg)
            for attached in attachedFiles:
                artifacts.append(AlertArtifact(dataType='file', data=[attached['path']], tags=['Attachment', 'Synapse']))
                file_paths.append(attached['path'])


            alert = Alert(title=alertTitle,
                description=alertDescription,
                severity=2,
                date=rcv_date_timestamp,
                tags=[],
                tlp=2,
                status="New",
                type="Phishing",
                source="BAL Phishing",
                sourceRef="{}-{}".format(mailbox['short_name'], str(uuid.uuid4())[24:].upper()),
                artifacts=artifacts,
                caseTemplate="Suspicious Email Case",
                customFields=customFields
                )

            theHiveConnector.createAlert(alert)

            ewsConnector.markAsRead(msg)

            logger.info("Cleaning temp files ...")
            for temp_file in file_paths:
                try:
                    os.remove(temp_file)
                except OSError as errRm:
                    logger.error("'{}' could not be removed.{}".format(temp_file, errRm))

    report['success'] = True
    return report


def getFileAttachments(msg):
    files = []
    for attachmentLvl1 in msg.attachments:
        #uploading the attachment as file observable
        #is the attachment is a .msg, the eml version
        #of the file is uploaded
        tempAttachment = TempAttachment(attachmentLvl1)

        if not tempAttachment.isInline:
            #adding the attachment only if it is not inline
            #inline attachments are pictures in the email body
            # this weird notation is to prevent any unicode characters (emojis)
            file_name = 'file_' + ''.join([i if ord(i) < 128 else '' for i in tempAttachment.filename])
            tmpFilepath = tempAttachment.writeFile(file_path=file_name)

            files.append({'path': tmpFilepath})

            if tempAttachment.isEmailAttachment:
                # recursively extracts attachements from attached e-mails
                files.extend(getFileAttachments(attachmentLvl1.item))

    return files


def getEmailBody(email):
    #crafting some "reply to" info
    #From
    #Sent
    #To
    #Cc
    #Subject
    to = str()
    cc = str()
    #making sure that there is a recipient
    #because cannot iterate over None object
    if email.to_recipients:
        to = '; '.join([recipient.email_address for recipient in email.to_recipients])

    if email.cc_recipients:
        cc = '; '.join([recipient.email_address for recipient in email.cc_recipients])

    replyToInfo = (
        'From: {sender_mail}\n' +
        'Sent: {sent_time}\n' +
        'To: {to_mail}\n' +
        'Cc: {cc}\n' +
        'Subject: {subject}\n\n')\
        .format(
            sender_mail=str(email.author.email_address).lower(),
            sent_time=email.datetime_sent,
            to_mail=to.lower(),
            cc=cc.lower(),
            subject=email.subject)

    body = email.text_body

    if body is None:
        soup = BeautifulSoup(email.body, 'html.parser')
        try:
            body = soup.body.text
        except AttributeError:
            body = soup.text

    return ('```\n{replyToInfo}{body}\n```'.format(replyToInfo=replyToInfo, body=body))

if __name__ == '__main__':
    connectEws()
