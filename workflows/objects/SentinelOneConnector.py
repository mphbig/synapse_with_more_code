#!/usr/bin/env python3
# -*- coding: utf8 -*-

import os
import json
import logging
import requests



class SentinelOneConnector:
    """
    SentinelOne connector, built with API version 2.1 from official docs
    """

    def __init__(self, mgt_url, token):
        self.logger = logging.getLogger('workflows.' + __name__)

        self.mgt_url = mgt_url
        self.token = token


    def _do_request(self, method, url, params={}, headers={}, body=None):
        req_headers = {
            'Content-Type': "application/json",
            'Authorization': "ApiToken {}".format(self.token)
        }

        for key, value in headers.items():
            req_headers[key] = value

        res = requests.request(method, self.mgt_url + url , params=params, headers=req_headers, json=body)
        res.raise_for_status()

        return res


    def get_threats(self):
        self.logger.info('%s.get_threats starts', __name__)

        params = {
            'limit': 100,
            'incidentStatuses': "unresolved"
        }
        url = "/web/api/v2.1/threats"

        threats = []

        res = self._do_request("GET", url, params=params)
        json_response = res.json()

        while True:
            for threat in json_response['data']:
                threats.append(threat)

            if json_response['pagination']['nextCursor'] == None:
                break

            params['cursor'] = json_response['pagination']['nextCursor']
            res = self._do_request("GET", url, params=params)
            json_response = res.json()


        return threats
