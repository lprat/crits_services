# (c) 2019, Lionel PRAT <lionel.prat9@gmail.com>
# based on service virustotal lookup.
# use docker: https://github.com/lprat/docker-snort
# All rights reserved.

import logging
import json
import urllib
import urllib2
import urlparse
import requests

from hashlib import md5

from django.conf import settings
from django.template.loader import render_to_string
from django.core.exceptions import ValidationError as DjangoValidationError

from crits.services.core import Service, ServiceConfigError
from crits.pcaps.handlers import handle_pcap_file
from crits.domains.handlers import upsert_domain
from crits.domains.domain import Domain
from crits.core.user_tools import get_user_organization
from crits.vocabulary.relationships import RelationshipTypes

from . import forms

logger = logging.getLogger(__name__)


class WebSnortService(Service):
    """
    Check the WebSnort API to see if it contains community signature in PCAP file.

    """

    name = "websnort"
    version = '1.0.0'
    supported_types = ['PCAP']
    required_fields = []
    description = "Check community signature snort on Pcap file"

    @staticmethod
    def get_config(existing_config):
        # Generate default config from form and initial values.
        config = {}
        fields = forms.WebSnortConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial

        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config

    @staticmethod
    def parse_config(config):
        if not config['ws_query_url']:
            raise ServiceConfigError("WebSnort API URL required.")

    @classmethod
    def generate_config_form(self, config):
        # Convert sigfiles to newline separated strings
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.WebSnortConfigForm(initial=config),
                                 'config_error': None})
        form = forms.WebSnortConfigForm
        return form, html

    @staticmethod
    def get_config_details(config):
        display_config = {}

        # Rename keys so they render nice.
        fields = forms.WebSnortConfigForm().fields
        for name, field in fields.iteritems():
            display_config[field.label] = config[name]

        return display_config

    def run(self, obj, config):
        # We assign config and obj to self because it is referenced often
        # outside this script
        # This is model after the guys who wrote the cuckoo script and all
        # credit goes to them on this cool trick
        self.config = config
        self.obj = obj

        # Pull configuration and check to see if a key is presented
        websnort_url = config.get('ws_query_url', '')
        if not websnort_url:
            self._error("No URL API WebSnort found")
            return

        # Process parameters for a GET request for Sample, Domain, or IP adress
        response_dict = {}
        with self._write_to_file() as pcap_file:
            with open(pcap_file, 'r') as pcapfo:
                files = {'file': pcapfo}
                #websnort is not on internet, local service
                proxies = {
                  "http": None,
                  "https": None,
                }
                try:
                    response = requests.post(websnort_url, files=files, verify=False, proxies=proxies)
                except Exception as e:
                    logger.error("WebSnort API: network connection error (%s)" % str(e))
                    self._error("Network connection error checking WebSnort API (%s)" % str(e))
                    return
                #print str(r.content)
                # Execute GET request
                if response.status_code == 200:
                    try:
                        jsonc = response.content
                        response_dict = json.loads(jsonc)
                    except Exception as e:
                        logger.error("WebSnort API return bad format json (%s)" % str(e))
                        self._error("WebSnort API return bad format json (%s)" % str(e))
                        return
                else:
                    logger.error("WebSnort API return code error (%s)" % str(response.status_code))
                    self._error("WebSnort API return code error (%s)" % str(response.status_code))
                    return

        # Log and exit if no match found or error
        if "status" in response_dict and response_dict['status'] == "Success" and 'analyses' in response_dict:
            #analyse ok
            for analyse in response_dict['analyses']:
                if "alerts" in analyse and len(analyse['alerts']) > 0:
                    #alert detect
                    self._info("Signatures found in your PCAP file: (%s)" % str(len(analyse['alerts'])))
                    subtype = 'Signature detected'
                    for alerte in analyse['alerts']:
                        try:
                            result = alerte['classtype']
                            data = {'priority': alerte['priority'], 'message': alerte['message'], 'timestamp': alerte['timestamp'], 'src': alerte['source'],'dst': alerte['destination'], 'proto': alerte['protocol'], 'sid': alerte['sid']}
                            self._add_result(subtype, result, data)
                        except Exception as e:
                            self._info("Error during treat of result: (%s)" % str(e))
                            continue
                else:
                    #no alert
                    self._info("No signature found in your PCAP file!")
                    self._info("Return: %s" % str(response_dict))
                    self._add_result('Signature detected', "", {})
                    return
        else:
           logger.error("WebSnort API return error in analyse (%s)" % str(response_dict['errors']))
           logger.error("WebSnort API return error in analyse detail (%s)" % str(response_dict))
           self._error("WebSnort API return  error in analyse (%s)" % str(response_dict['errors']))
           self._error("WebSnort API return  error in analyse detail (%s)" % str(response_dict))
           return
