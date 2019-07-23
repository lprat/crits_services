# (c) 2017-2019, Lionel PRAT <lionel.prat9@gmail.com>
# based on service pdf2txt of Adam Polkosnik && meta_office => Thank!
# use tool : https://github.com/lprat/static_analysis
# All rights reserved.
import logging
import requests
import hashlib
import shutil
import os
import tempfile
import re
from datetime import datetime
import subprocess
import json

from django.template.loader import render_to_string

from crits.core.user_tools import get_user_info
from crits.services.core import Service, ServiceConfigError
from crits.samples.handlers import handle_file
from crits.vocabulary.relationships import RelationshipTypes
from crits.vocabulary.acls import SampleACL
from crits.core.class_mapper import class_from_id
from django.conf import settings
from django.template.loader import render_to_string

# for adding the extracted files
from crits.screenshots.handlers import add_screenshot

#get info Sample object
from crits.samples.sample import Sample

from crits.indicators.indicator import Indicator
from crits.indicators.handlers import handle_indicator_ind
from crits.vocabulary.acls import IndicatorACL
from crits.vocabulary.indicators import (
    IndicatorCI,
    IndicatorAttackTypes,
    IndicatorThreatTypes,
    IndicatorTypes
)

from . import forms

logger = logging.getLogger(__name__)


class SFAService(Service):
    """
    Static Files Analysis with clamscan & Yara. Use API!
    """

    name = "SFA"
    version = '0.0.3'
    #template = "extract_embedded_service_template.html"
    supported_types = ['Sample', 'Indicator']
    description = "Static files Analysis with clamscan & yara."

    @staticmethod
    def parse_config(config):
        sfa_api = config.get("sfa_api", "")
        if not sfa_api:
            raise ServiceConfigError("You must specify a URI for SFA API.")
        key_api = config.get("key_api", "")
        if not key_api:
            raise ServiceConfigError("You must specify a valid key api for SFA.")
        tlp_value = config.get("tlp_value", "")

    @staticmethod
    def get_config(existing_config):
        # Generate default config from form and initial values.
        config = {}
        fields = forms.SFAConfigForm().fields
        for name, field in fields.iteritems():
            config[name] = field.initial

        # If there is a config in the database, use values from that.
        if existing_config:
            for key, value in existing_config.iteritems():
                config[key] = value
        return config

    @staticmethod
    def get_config_details(config):
        return {'sfa_api': config['sfa_api'],
                'key_api': config['key_api'],
                'tlp_value': config['tlp_value']}

    @classmethod
    def generate_config_form(self, config):
        html = render_to_string('services_config_form.html',
                                {'name': self.name,
                                 'form': forms.SFAConfigForm(initial=config),
                                 'config_error': None})
        form = forms.SFAConfigForm
        return form, html

    @staticmethod
    def valid_for(obj):
        if obj._meta['crits_type'] == 'Indicator' and obj['ind_type'] == 'URI':
            return True
        elif not obj.filedata:
            return False
        #work for all types
        return True

    @staticmethod
    def save_runtime_config(config):
        if config['debug_log']:
            del config['debug_log']
#        if config['import_file']:
#            del config['import_file']
        if config['import_file_ioc']:
            del config['import_file_ioc']
        if config['import_file_yara']:
            del config['import_file_yara']
        if config['import_yara_score']:
            del config['import_yara_score']

    @staticmethod
    def bind_runtime_form(analyst, config):
        if 'debug_log' not in config:
            config['debug_log'] = False
#        if 'import_file' not in config:
#            config['import_file'] = False
        if 'import_file_ioc' not in config:
            config['import_file_ioc'] = False
        if 'import_file_yara' not in config:
            config['import_file_yara'] = False
        if 'import_yara_score' not in config:
            config['import_yara_score'] = "7"
        form = forms.SFARunForm(data=config)
        return form

    @classmethod
    def generate_runtime_form(self, analyst, config, crits_type, identifier):
        html = render_to_string("services_run_form.html",
                                {'name': self.name,
                                 'form': forms.SFARunForm(),
                                 'crits_type': crits_type,
                                 'identifier': identifier})
        return html

    def run(self, obj, config):
        if  bool(re.search(r'^\d+$', config['import_yara_score'])):
            logger.error("SFA COnfig SCORE YARA dont format interger")
            self._error("SFA COnfig SCORE YARA dont format interger")
            return ""
        obj.filedata.seek(0)
        data8 = obj.filedata.read(8)
        obj.filedata.seek(0)
        user = self.current_task.user
        self.config = config
        self.obj = obj
        self._info("SFA started")
        tlp_value = self.config.get("tlp_value", "tlp_value")
        sfa_api = self.config.get("sfa_api", '')
        key_api = self.config.get("key_api", '')
        if not sfa_api:
            self._error("No URI for SFA API found")
            return
        if not key_api:
            self._error("No API KEY found")
            return
        response_dict = {}
        proxies = {
                   "http": None,
                   "https": None,
                  }
        headers = {
                   "x-api-key": key_api
                  }
        #IF URL
        if (obj._meta['crits_type'] == 'Indicator' and obj['ind_type'] == 'URI'):
            self._info("Analyse URI on API: %s" % str(sfa_api))
            url = obj['value']
            try:
                headers['Content-Type'] = 'application/json'
                response = requests.post(sfa_api+'api/sfa_check_url', json={"url": url}, verify=False, proxies=proxies, headers=headers)
            except Exception as e:
                logger.error("SFA API: network connection error (%s)" % str(e))
                self._error("Network connection error checking SFA API (%s)" % str(e))
                return
            if response.status_code == 200:
                try:
                    jsonc = response.content
                    response_dict = json.loads(jsonc)
                except Exception as e:
                    logger.error("SFA API return bad format json (%s)" % str(e))
                    self._error("SFA API return bad format json (%s)" % str(e))
                    return
            else:
                logger.error("SFA API return code error (%s)" % str(response.status_code))
                self._error("SFA API return code error (%s)" % str(response.status_code))
                return
        #IF FILE
        else:
        #write out the sample stored in the db to a tmp file
            self._info("Analyse Sample on API: %s" % str(sfa_api))
            with self._write_to_file() as tmp_file:
                with open(tmp_file, 'r') as tmpfo:
                    files = {'file': tmpfo}
                    #SFA is not on internet, local service
                    try:
                        response = requests.post(sfa_api+'api/sfa_check_file', files=files, verify=False, proxies=proxies, headers=headers)
                    except Exception as e:
                        logger.error("SFA API: network connection error (%s)" % str(e))
                        self._error("Network connection error checking SFA API (%s)" % str(e))
                        return
                    #print str(r.content)
                    # Execute GET request
                    if response.status_code == 200:
                        try:
                            jsonc = response.content
                            response_dict = json.loads(jsonc)
                        except Exception as e:
                            logger.error("SFA API return bad format json (%s)" % str(e))
                            self._error("SFA API return bad format json (%s)" % str(e))
                            return
                    else:
                        logger.error("SFA API return code error (%s)" % str(response.status_code))
                        self._error("SFA API return code error (%s)" % str(response.status_code))
                        return
            #make temp file for get json result and graph
            self._info("Reponse request:"+str(response_dict))
            if 'risk_score' in response_dict:
                risk=response_dict['risk_score']
                if risk:
                    self._add_result("Risk Score of Sample", str(risk) , {})
            if 'trace-serr.debug' in response_dict:
                trace_serr=download(self, response_dict['trace-serr.debug'])
                if trace_serr:
                    self._info(trace_serr)
            if 'trace-sout.debug' in response_dict and config['debug_log']:
                trace_sout=download(self, response_dict['trace-sout.debug'])
                if trace_sout:
                    self._info(trace_sout)
            if 'result.json' in response_dict:
                result=download(self, response_dict['result.json'])
                if result:
                    try:
                        result_json = json.loads(result)
                    except Exception as e:
                        logger.error("Analysis JSON result error: (%s)" % str(e))
                        self._error("Analysis JSON result error: (%s)" % str(e))
                    parse_result(self, result_json, response_dict, config, None)
            if 'graph.png' in response_dict:
                graph=download(self, response_dict['graph.png'])
                if graph:
                    dirtmp = tempfile._get_default_tempdir()
                    file_png=dirtmp+'/'+next(tempfile._get_candidate_names())+'.png'
                    with open(file_png, 'w+') as fpng:
                        fpng.write(graph)
                        fpng.seek(0)
                        res = add_screenshot(description='Render of static analysis',
                                     tags=None,
                                     method=self.name,
                                     source=obj.source,
                                     reference=None,
                                     analyst=self.current_task.user.username,
                                     screenshot=fpng,
                                     screenshot_ids=None,
                                     oid=obj.id,
                                     tlp=tlp_value,
                                     otype="Sample")
                        if res.get('message') and res.get('success') == True:
                            self._warning("res-message: %s id:%s" % (res.get('message'), res.get('id') ) )
                            self._add_result('Graph analysis', res.get('id'), {'Message': res.get('message')})
                        self._info("id:%s, file: %s" % (res.get('id'), file_png))
                    if os.path.isfile(file_png):
                        os.remove(file_png)

def parse_result(self, result_extract, response_dict, config, md5_parent):
    stream_md5 = None
    user = self.current_task.user
    self.config = config
    acl_write = user.has_access_to(SampleACL.WRITE)
    if type(result_extract) is dict:
        #make reccursion extract each file embbed
        if 'FileMD5' in result_extract and result_extract['FileMD5']:
            tmp_dict={}
            b_yara=False
            b_ioc=False
            #extract info
            no_info=['ExtractInfo','ContainedObjects', 'Yara', 'PathFile', 'FileMD5', 'RootFileType', 'TempDirExtract', 'GlobalIOC']
            for key, value in result_extract.iteritems():
                if not key in no_info:
                    self._add_result('File: '+result_extract['FileMD5'] + ' - Info', key, {'value': str(value)})
            #add download info
            if result_extract['FileMD5'] in response_dict:
                self._add_result('File: '+result_extract['FileMD5'] + ' - Info', 'Download embed file', {'value': sfa_api+vx})
            #GLOBAL IOC
            if 'GlobalIOC' in result_extract and result_extract['GlobalIOC']:
                for key, value in result_extract['GlobalIOC'].iteritems():
                    self._add_result('Global IOC by categories', key, {'value': str(value)})
            #extract yara match
            if result_extract['Yara']:
                for item_v in result_extract['Yara']:
                    #self._info("Dict:"+str(item_v))
                    for key, value in item_v.iteritems():
                        data={'description': '', 'ioc': '', 'tags': '', 'score':'0'}
                        for kx, vx in value.iteritems():
                            data[kx]=str(vx)
                        self._add_result('File: '+result_extract['FileMD5'] + ' - Signatures yara matched', key, data)
                        score_conf=re.sub("\D", "", config['import_yara_score'])
                        if acl_write and config['import_file_yara'] and 'score' in value and int(value['score']) >= int(score_conf):
                            id_ = Sample.objects(md5=result_extract['FileMD5']).only('id').first()
                            if id_:
                                self._info('Add relationship with sample existed:'+str(stream_md5))
                                #make relationship
                                id_.add_relationship(rel_item=self.obj,
                                     rel_type=RelationshipTypes.CONTAINED_WITHIN,
                                     rel_date=datetime.now(),
                                     analyst=self.current_task.user.username)
                            elif result_extract['FileMD5'] in response_dict:
                                content_tmp=download(self, response_dict[result_extract['FileMD5']])
                                if content_tmp:
                                    name = str(result_extract['FileMD5'])
                                    if 'CDBNAME' in result_extract:
                                        name=str(result_extract['CDBNAME'])
                                    obj_parent = None
                                    if md5_parent:
                                        obj_parent = Sample.objects(md5=md5_parent).only('id').first()
                                    if not obj_parent:
                                        sample = handle_file(name, content_tmp, self.obj.source,
                                            related_id=str(self.obj.id),
                                            related_type=str(self.obj._meta['crits_type']),
                                            campaign=self.obj.campaign,
                                            source_method=self.name,
                                            relationship=RelationshipTypes.CONTAINED_WITHIN,
                                            user=self.current_task.user)
                                    else:
                                        sample = handle_file(name, content_tmp, obj_parent.source,
                                            related_id=str(obj_parent.id),
                                            related_type=str(obj_parent._meta['crits_type']),
                                            campaign=obj_parent.campaign,
                                            source_method=self.name,
                                            relationship=RelationshipTypes.CONTAINED_WITHIN,
                                            user=self.current_task.user)
                                    self._info('Add sample '+str(name)+' - MD5:'+str(result_extract['FileMD5']))
            #extract IOC
            if result_extract['ExtractInfo']:
                for item_v in result_extract['ExtractInfo']:
                    for key, value in item_v.iteritems():
                        self._add_result('File: '+result_extract['FileMD5'] + ' - Extract potential IOC', key, {'value': str(value)})
                        if acl_write and config['import_file_ioc']:
                            id_ = Sample.objects(md5=result_extract['FileMD5']).only('id').first()
                            if id_:
                                self._info('Add relationship with sample existed:'+str(stream_md5))
                                #make relationship
                                id_.add_relationship(rel_item=self.obj,
                                     rel_type=RelationshipTypes.CONTAINED_WITHIN,
                                     rel_date=datetime.now(),
                                     analyst=self.current_task.user.username)
                            elif result_extract['FileMD5'] in response_dict:
                                content_tmp=download(self, response_dict[result_extract['FileMD5']])
                                if content_tmp:
                                    name = str(result_extract['FileMD5'])
                                    if 'CDBNAME' in result_extract:
                                        name=str(result_extract['CDBNAME'])
                                    obj_parent = None
                                    if md5_parent:
                                        obj_parent = Sample.objects(md5=md5_parent).only('id').first()
                                    if not obj_parent:
                                        sample = handle_file(name, content_tmp, self.obj.source,
                                            related_id=str(self.obj.id),
                                            related_type=str(self.obj._meta['crits_type']),
                                            campaign=self.obj.campaign,
                                            source_method=self.name,
                                            relationship=RelationshipTypes.CONTAINED_WITHIN,
                                            user=self.current_task.user)
                                    else:
                                        sample = handle_file(name, content_tmp, obj_parent.source,
                                            related_id=str(obj_parent.id),
                                            related_type=str(obj_parent._meta['crits_type']),
                                            campaign=obj_parent.campaign,
                                            source_method=self.name,
                                            relationship=RelationshipTypes.CONTAINED_WITHIN,
                                            user=self.current_task.user)
                                    self._info('Add sample '+str(name)+' - MD5:'+str(result_extract['FileMD5']))
            #contains file
            if 'ContainedObjects' in result_extract and type(result_extract['ContainedObjects']) is list and result_extract['ContainedObjects']:
                for item_v in result_extract['ContainedObjects']:
                    if item_v['FileMD5'] and item_v['FileType'] and item_v['FileSize']:
                        #search if file exist
                        id_ = Sample.objects(md5=str(item_v['FileMD5'])).only('id').first()
                        sample_exist = False
                        ioc_exist = False
                        if id_:
                            sample_exist = True
                            id_.add_relationship(rel_item=self.obj,
                                     rel_type=RelationshipTypes.RELATED_TO,
                                     #rel_date=datetime.now(),
                                     analyst=self.current_task.user.username)
                        id_ =  Indicator.objects(value=str(item_v['FileMD5'])).only('id').first()
                        if id_:
                            ioc_exist = True
                            id_.add_relationship(rel_item=self.obj,
                                     rel_type=RelationshipTypes.RELATED_TO,
                                     #rel_date=datetime.now(),
                                     analyst=self.current_task.user.username)
                        self._add_result('File: '+result_extract['FileMD5'] + ' - Contains md5 files', item_v['FileMD5'], {'type': str(item_v['FileType']), 'size': str(item_v['FileSize']), 'Exists Sample': str(sample_exist), 'Exists IOC md5': str(ioc_exist)})
                for item_v in result_extract['ContainedObjects']:
                    #re do loop for best display result
                    parse_result(self, item_v, response_dict, config, stream_md5)

def download(self, url):
    if not url:
        return ""
#    self._info("Get url:"+str(url))
    sfa_api = self.config.get("sfa_api", '')
    key_api = self.config.get("key_api", '')
    proxies = {
               "http": None,
               "https": None,
              }
    headers = {
               "x-api-key": key_api
              }
    try:
        response = requests.get(sfa_api+url, verify=False, proxies=proxies, headers=headers)
    except Exception as e:
        logger.error("SFA API: network connection error (%s)" % str(e))
        self._error("Network connection error checking SFA API (%s)" % str(e))
        return ""
    if response.status_code == 200:
        return response.content
    else:
        logger.error("SFA API return code error (%s)" % str(response.status_code))
        self._error("SFA API return code error (%s)" % str(response.status_code))
        return ""

