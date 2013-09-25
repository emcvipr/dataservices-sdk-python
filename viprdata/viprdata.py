#
# Copyright (c) 2013 EMC Corporation
# All Rights Reserved
#
# This software contains the intellectual property of EMC Corporation
# or is licensed to EMC Corporation from third parties.  Use of this
# software and the intellectual property contained therein is expressly
# limited to the terms and conditions of the License Agreement under which
# it is provided by or on behalf of EMC.
#

import os
import copy
from email.Utils import formatdate
import json
import requests
import urllib
import hmac
import hashlib
import base64

URI_S3_SERVICE_BASE             = ''
URI_S3_BUCKET_INSTANCE          = URI_S3_SERVICE_BASE + '/{0}'

URI_SWIFT_SERVICE_BASE          = '/v1'
URI_SWIFT_CONTAINER_INSTANCE    = URI_SWIFT_SERVICE_BASE + '/{0}/{1}'

S3_INSECURE_PORT                = '9020'
S3_PORT                         = '9021'
ATMOS_INSECURE_PORT             = '9022'
ATMOS_PORT                      = '9023'
SWIFT_INSECURE_PORT             = '9024'
SWIFT_PORT                      = '9025'

USE_SSL                         = os.getenv('BOURNE_USE_SSL', '0')
BOURNE_DEBUG                    = os.getenv('BOURNE_DEBUG', '0')

FILE_ACCESS_MODE_HEADER         = "x-emc-file-access-mode"
FILE_ACCESS_DURATION_HEADER     = "x-emc-file-access-duration"
FILE_ACCESS_HOST_LIST_HEADER    = "x-emc-file-access-host-list"
FILE_ACCESS_USER_HEADER         = "x-emc-file-access-uid"
FILE_ACCESS_TOKEN_HEADER        = "x-emc-file-access-token"
FILE_ACCESS_START_TOKEN_HEADER  = "x-emc-file-access-start-token"
FILE_ACCESS_END_TOKEN_HEADER    = "x-emc-file-access-end-token"

# Number of seconds a request should wait for response.
# It only effects the connection process itself, not the downloading of the response body
MAX_REQUEST_TIMEOUT_SECONDS = 600

CONTENT_TYPE_JSON='application/json'
CONTENT_TYPE_XML='application/xml'

# decorator to reset headers to default
# use this if an api changes _headers
def resetHeaders(func):
    def inner_func(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        finally:
            self._reset_headers()
    return inner_func

class ViprData:
    _DEFAULT_HEADERS = {
        'Content-Type': 'application/json',
        'ACCEPT': 'application/json,application/xml,text/html,application/octet-stream'
    }

    def __init__(self):
        self._reset_headers()

    def _reset_headers(self):
        self._headers = copy.deepcopy(ViprData._DEFAULT_HEADERS)

    def connect(self, ipaddr, port = 8443):
        self._ipaddr = ipaddr
        self._port = port
        
    def pretty_print_json(self, jsonObj):
        print json.dumps(jsonObj, sort_keys=True, indent=4)
    
    # req_timeout: Number of seconds a request should wait for response. It only effects the connection process itself, not the downloading of the response body
    def __run_request(self, method, uri, body, req_timeout):
        scheme = 'https://'
        ipaddr = self._ipaddr
        port = str(self._port)

        if USE_SSL == '0':
            scheme = 'http://'
            if port == S3_PORT:
                port = S3_INSECURE_PORT
            elif port == ATMOS_PORT:
                port = ATMOS_INSECURE_PORT
            elif port == SWIFT_PORT:
                port = SWIFT_INSECURE_PORT
            else:
                port   = '8080'
       
        if(BOURNE_DEBUG == '1'):
            print "PORT="+port
           
        url = scheme+ipaddr+':'+port+uri
        newHeaders = self._headers
        if(BOURNE_DEBUG == '1'):
            print 'debug headers: ', newHeaders
        try:
            if method == 'POST':
                if(BOURNE_DEBUG == '1'):
                    print 'debug post to ' + url + ' with data ' + str(body)
                response = requests.post(url,data=body,headers=newHeaders, verify=False, timeout=req_timeout)
            elif method == 'PUT':
                if(BOURNE_DEBUG == '1'):
                    print 'debug put to ' + url + ' with data ' + str(body)
                response = requests.put(url,data=body,headers=newHeaders, verify=False, timeout=req_timeout)
            elif method == 'DELETE':
                if(BOURNE_DEBUG == '1'):
                    print 'debug delete ' + url
                response = requests.delete(url,headers=newHeaders,verify=False, timeout=req_timeout)         
            elif method == 'HEAD':
                if(BOURNE_DEBUG == '1'):
                    print 'debug head ' + url
                response = requests.head(url,headers=newHeaders,verify=False, timeout=req_timeout)         
            else:
                if(BOURNE_DEBUG == '1'):
                    print 'debug get ' + url
                response = requests.get(url,headers=newHeaders,verify=False, timeout=req_timeout) 
            if(BOURNE_DEBUG == '1'):
                print 'debug rsp code ' + str(response.status_code)
            if(response.status_code > 299):
                raise RuntimeError('ViPR request failed (%s): %s' % (response.status_code, response.text.strip()))
            return response
        except:
            raise
 
    def __api(self, method, uri, parms = None, qparms = None, content_type=CONTENT_TYPE_JSON, accept=CONTENT_TYPE_JSON, req_timeout = MAX_REQUEST_TIMEOUT_SECONDS):
        body = None
        if (parms and content_type==CONTENT_TYPE_JSON):
            body = json.dumps(parms)
        else:
            body = parms

        if (qparms):
            if( '?' in uri ):
                first = False
            else:
                uri += "?"
                first = True
            for qk in qparms.iterkeys():
                if (not first):
                    uri += '&'
                    uri += qk
                else:
                    first = False
                    uri += qk

                if (qparms[qk] != None):
                    uri += '=' + qparms[qk]

        if(BOURNE_DEBUG == '1'):
            print 'debug body: ' + str(body)
            self.pretty_print_json(parms)
            print 'debug uri ' + method + ": " + str(uri)
        self._headers['Content-Type'] = content_type
        self._headers['ACCEPT'] = accept
        return self.__run_request(method, uri, body, req_timeout=req_timeout)
  
    def coreapi(self, method, uri, parms = None, qparms = None, user = None, content_type = CONTENT_TYPE_JSON):
        return self.__api(method, uri, parms, qparms, content_type=content_type, accept=content_type, req_timeout=600)

    def _s3_hmac_base64_sig(self, method, bucket, objname, uid, secret, content_type, parameters_to_sign=None):
        '''
        calculate the signature for S3 request
        
         StringToSign = HTTP-Verb + "\n" +
         * Content-MD5 + "\n" +
         * Content-Type + "\n" +
         * Date + "\n" +
         * CanonicalizedAmzAndEmcHeaders +
         * CanonicalizedResource
        '''
        buf = ""
        # HTTP-Verb
        buf += method + "\n"
         
        # Content-MD5, a new line is needed even if it does not exist
        md5 = self._headers.get('Content-MD5')
        if md5 != None:
            buf += md5
        buf += "\n"

        #Content-Type, a new line is needed even if it does not exist
        if content_type != None:
            buf+=content_type
        buf += "\n"

        # Date, it should be removed if "x-amz-date" is set
        if self._headers.get("x-amz-date") == None:
            date = self._headers.get('Date')
            if date != None:
                buf += date
        buf += "\n"

        # CanonicalizedAmzHeaders, does not support multiple headers with same name
        canonicalizedAmzHeaders = []
        for header in self._headers.keys():
            if header.startswith("x-amz-") or header.startswith("x-emc-"):
                canonicalizedAmzHeaders.append(header)
        
        canonicalizedAmzHeaders.sort()
        
        for name in canonicalizedAmzHeaders:
            buf +=name+":"+str(self._headers[name])+"\n"
            
        #CanonicalizedResource represents the Amazon S3 resource targeted by the request.
        buf += "/"
        if bucket != None:
            buf += bucket
        if objname != None:
            buf += "/" + urllib.quote(objname)
        
        if parameters_to_sign !=None:
            para_names = parameters_to_sign.keys()
            para_names.sort()
            separator = '?';
            for name in para_names: 
                value = parameters_to_sign[name]
                buf += separator
                buf += name 
                if value != None and value != "":
                    buf += "=" + value
                separator = '&'

        if BOURNE_DEBUG == '1':
            print 'message to sign with secret[%s]: %s\n' % (secret, buf)
        macer = hmac.new(secret.encode('UTF-8'), buf, hashlib.sha1)

        signature = base64.b64encode(macer.digest())
        if BOURNE_DEBUG == '1':
            print "calculated signature:"+signature

        # The signature
        self._headers['Authorization'] = 'AWS ' + uid + ':' + signature
        
    def _set_auth_and_ns_header(self, method, namespace, bucket, objname, uid, secret, content_type = CONTENT_TYPE_XML, parameters_to_sign=None):
        if self._headers.get("x-amz-date") == None:
            self._headers['Date'] = formatdate()
        self._s3_hmac_base64_sig(method, bucket, objname, uid, secret, content_type, parameters_to_sign)

    @resetHeaders
    def bucket_switch(self, namespace, bucket, mode, hosts, duration, token, user, uid, secret):
        self._headers[FILE_ACCESS_MODE_HEADER] = mode
        if (user != None):
            self._headers[FILE_ACCESS_USER_HEADER] = user
        if (hosts != None):
            self._headers[FILE_ACCESS_HOST_LIST_HEADER] = hosts
        if (duration != None):
            self._headers[FILE_ACCESS_DURATION_HEADER] = duration
        if (token != None):
            self._headers[FILE_ACCESS_TOKEN_HEADER] = token
        else:
            if (self._headers.has_key(FILE_ACCESS_TOKEN_HEADER)):
                del self._headers[FILE_ACCESS_TOKEN_HEADER]
  
        qparms = {'accessmode': None}
        self._set_auth_and_ns_header('PUT', namespace, bucket, None, uid, secret, parameters_to_sign = qparms)
        response = self.coreapi('PUT', URI_S3_BUCKET_INSTANCE.format(bucket), None, qparms , content_type=CONTENT_TYPE_XML) 
        return response

    @resetHeaders
    def bucket_fileaccesslist(self, namespace,  bucket, uid, secret):
        qparms = {'fileaccess':None}
        self._set_auth_and_ns_header('GET', namespace, bucket, None, uid, secret, parameters_to_sign = qparms)

        return self.coreapi('GET', URI_S3_BUCKET_INSTANCE.format(bucket), None, qparms, content_type=CONTENT_TYPE_XML)

    @resetHeaders
    def bucket_switchget(self, namespace, bucket, uid, secret):
        qparms = {'accessmode':None}
        self._set_auth_and_ns_header('GET', namespace, bucket, None, uid, secret, parameters_to_sign = qparms)

        response = self.coreapi('GET', URI_S3_BUCKET_INSTANCE.format(bucket), None, qparms, content_type=CONTENT_TYPE_XML)
        return response

    @resetHeaders
    def container_switchfileaccess(self, namespace, container, mode, hosts, duration, token, user, uid, secret):
        self._headers[FILE_ACCESS_MODE_HEADER] = mode
        if (user != None):
            self._headers[FILE_ACCESS_USER_HEADER] = user
        if (hosts != None):
            self._headers[FILE_ACCESS_HOST_LIST_HEADER] = hosts
        if (duration != None):
            self._headers[FILE_ACCESS_DURATION_HEADER] = duration
        if (token != None):
            self._headers[FILE_ACCESS_TOKEN_HEADER] = token
        else:
            if (self._headers.has_key(FILE_ACCESS_TOKEN_HEADER)):
                del self._headers[FILE_ACCESS_TOKEN_HEADER]

        response = self.coreapi('PUT', URI_SWIFT_CONTAINER_INSTANCE.format(namespace, container), None, {'accessmode':None}, content_type=CONTENT_TYPE_XML)
        return response

    @resetHeaders
    def container_getfileaccess(self, namespace, container, uid, secret):
        response = self.coreapi('GET', URI_SWIFT_CONTAINER_INSTANCE.format(namespace, container), None, 
            {'fileaccess': None, 'format': 'json'},
            None, CONTENT_TYPE_XML)
        return response

    @resetHeaders
    def container_getaccessmode(self, namespace, container, uid, secret):
        response = self.coreapi('GET', URI_SWIFT_CONTAINER_INSTANCE.format(namespace, container), None, {'accessmode':None}, content_type=CONTENT_TYPE_XML)
        return response

