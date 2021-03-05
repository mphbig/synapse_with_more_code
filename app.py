#!/usr/bin/env python3
# -*- coding: utf8 -*-

import os
import json
import logging, logging.handlers
from flask import Flask, request, jsonify

from workflows.common.common import getConf
from workflows.Ews2Case import connectEws
from workflows.QRadar2Alert import allOffense2Alert
from workflows.ManageWebhooks import manageWebhook
from workflows.CarbonBlack2Alert import allNotifs2Alert
from workflows.Rapid72Alert import rapid7IDRAlerts2Alerts
from workflows.SentinelOne2Alert import threats2Alert

app_dir = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(app_dir, "conf", "synapse_webhook_access.json")) as f:
    WEBHOOK_ACCESS = json.load(f)

#create logger
logger = logging.getLogger('workflows')
if not logger.handlers:
    logger.setLevel(logging.DEBUG)
    #log format as: 2013-03-08 11:37:31,411 :: WARNING :: Testing foo
    formatter = logging.Formatter('%(asctime)s :: %(levelname)s :: %(message)s')
    #handler writes into, limited to 1Mo in append mode
    if not os.path.exists('logs'):
        #create logs directory if does no exist (typically at first start)
        os.makedirs('logs')
    pathLog = os.path.join(app_dir, "logs", "synapse.log")
    file_handler = logging.handlers.RotatingFileHandler(pathLog, 'a', 1000000, 1)
    #level debug
    file_handler.setLevel(logging.DEBUG)
    #using the format defined earlier
    file_handler.setFormatter(formatter)
    #Adding the file handler
    logger.addHandler(file_handler)


def access_granted(authentication, allow):
    return authentication in list(WEBHOOK_ACCESS.keys()) \
        and WEBHOOK_ACCESS[authentication]['active'] == 1 \
        and allow in WEBHOOK_ACCESS[authentication]['allowed']


app = Flask(__name__)


@app.route('/QRadar2alert', methods=['POST'])
def QRadar2alert():
    auth = request.headers.get('Authorization', "")

    if access_granted(auth, "QRadar"):
        logger.info("[QRadar] New request from '{}'".format(WEBHOOK_ACCESS[auth]['description']))
        if request.is_json:
            content = request.get_json()
            if 'timerange' in content:
                workflowReport = allOffense2Alert(content['timerange'])
                if workflowReport['success']:
                    logger.info("[QRadar] Request finished successfully : {}".format(workflowReport))
                    return "", 200
                else:
                    logger.error("[QRadar] Request failed : {}".format(workflowReport))
                    return "", 200
            else:
                logger.error("[QRadar] Missing <timerange> key/value")
                return "", 500
        else:
            logger.error("[QRadar] Not json request")
            return "", 500
    else:
        logger.error("[QRadar] Authentication failure | Headers: {} | Body: {}".format(request.headers, request.data))
        return "", 500


@app.route('/S12Alert', methods=['GET'])
def sentinelone2alert():
    auth = request.headers.get('Authorization', "")

    if access_granted(auth, "SentinelOne"):
        logger.info("[SentinelOne] New request from '{}'".format(WEBHOOK_ACCESS[auth]['description']))
        workflowReport = threats2Alert()

        if workflowReport['success']:
            logger.info("[SentinelOne] Request finished successfully : {}".format(workflowReport))
            return "", 200

        else:
            logger.error("[SentinelOne] Workflow error")
            return "", 500

    else:
        logger.error("[SentinelOne] Authentication failure | Headers: {} | Body: {}".format(request.headers, request.data))
        return "", 500


@app.route('/ews2case', methods=['GET'])
def ews2case():
    auth = request.headers.get('Authorization', "")

    if access_granted(auth, "Ews2Case"):
        logger.info("[Ews2Case] New request from '{}'".format(WEBHOOK_ACCESS[auth]['description']))
        workflowReport = connectEws()

        if workflowReport['success']:
            logger.info("[Ews2Case] Request finished successfully : {}".format(workflowReport))
            return "", 200

        else:
            logger.error("[Ews2Case] Workflow error")
            return "", 500

    else:
        logger.error("[Ews2Case] Authentication failure | Headers: {} | Body: {}".format(request.headers, request.data))
        return "", 500


@app.route('/CarbonBlack2Alert', methods=['GET'])
def CarbonBlack2Alert():
    auth = request.headers.get('Authorization', "")

    if access_granted(auth, "CarbonBlack2Alert"):
        logger.info("[CarbonBlack2Alert] New request from '{}'".format(WEBHOOK_ACCESS[auth]['description']))
        result = allNotifs2Alert()

        if result['success']:
            logger.info("[CarbonBlack2Alert] Request finished successfully : {}".format(result))
            return "", 200

        else:
            logger.error("[CarbonBlack2Alert] Workflow error : {}".format(result['message']))
            return "", 500

    else:
        logger.error("[CarbonBlack2Alert] Authentication failure | Headers: {} | Body: {}".format(request.headers, request.data))
        return "", 500


@app.route('/r72a', methods=['POST'])
def Rapid7IDRAlerts2Alert():
    status_code = 0
    reason = ""
    user_agent = request.headers.get('User-Agent', "")
    event_type = request.headers.get('X-Rapid7-Event', "")
    auth = request.headers.get('Authorization', "")
    signature = request.headers.get('X-Rapid7-Signature', "")
    content_type = request.headers.get('Content-Type', "")
    content_length = int(request.headers.get('Content-Length', 0))

    if user_agent == "Rapid7 Webhook Data Exporter" \
            and access_granted(auth, "Rapid7IDRAlerts2Alert") \
            and signature != "" \
            and content_type == "application/json; charset=UTF-8":

        if event_type == "test":
            # test request, for testing purposes, just reply that everything is fine
            body = request.get_json()
            logger.info("[Rapid7IDRAlerts2Alert] Test request, timestamp: {} | webhook_id: {} | webhook_name: {}"\
                .format(body['timestamp'], body['webhook_id'], body['webhook_name']))
            return "", 200

        elif event_type == "idr_alert":
            #Insight IDR alert, create the alert in TheHive

            result = rapid7IDRAlerts2Alerts(request.get_json(), WEBHOOK_ACCESS[auth]['org_name'])

            if result['success']:
                logger.info("[Rapid7IDRAlerts2Alert] Request finished successfully : {}".format(result))
                logger.info("Success, alert will be created")
                return "", 200
            else:
                status_code = 200
                reason = "Workflow error"
        else:
            status_code = 500
            reason = "Wrong event type received"
    else:
        status_code = 500
        reason = "Bad request"
    logger.error("[Rapid7IDRAlerts2Alert] ({}) Headers: {} | Event: {} | Data: {}"\
        .format(reason, request.headers, request.headers.get("X-Rapid7-Event", ""), request.get_json()))
    return "", status_code


##### ROUTES DISABLED #####

#@app.route('/webhook', methods=['POST'])
def listenWebhook():
    if request.is_json:
         try:
            logger.info(request.get_json())
            webhook = request.get_json()
            workflowReport = manageWebhook(webhook)
            if workflowReport['success']:
                return jsonify(workflowReport), 200
            else:
                return jsonify(workflowReport), 500
         except Exception as e:
             logger.error('Failed to listen or action webhook')
             return jsonify({'success':False}), 500
    else:
        return jsonify({'success':False, 'message':'Not JSON'}), 400


#@app.route('/version', methods=['GET'])
def getSynapseVersion():
    return jsonify({'version': '1.1.1'}), 200


if __name__ == '__main__':
    cfg = getConf()
    app.run(debug=cfg.getboolean('api', 'debug'),
        host=cfg.get('api', 'host'),
        port=cfg.get('api', 'port'),
        threaded=cfg.get('api', 'threaded')
    )
