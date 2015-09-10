#!/usr/bin/env python

from eucaops import Eucaops
from eucaops import EC2ops
from eutester.eutestcase import EutesterTestCase
import sys, os, base64, datetime, hashlib, hmac
import requests
import xml.dom.minidom

class ComputeSigV4Test(EutesterTestCase):
    def __init__(self, extra_args= None):
        self.setuptestcase()
        self.setup_parser()
        self.parser.add_argument('--clean_on_exit',
                                 action='store_true', default=True,
                                 help='Boolean, used to flag whether to run clean up method after running test list)')
        if extra_args:
            for arg in extra_args:
                self.parser.add_argument(arg)
        self.get_args()

        if self.args.region:
            self.tester = EC2ops( credpath=self.args.credpath, region=self.args.region )
        else:
            self.tester = Eucaops( credpath=self.args.credpath, config_file=self.args.config,password=self.args.password )
        
        self.regions = []
        for region in self.tester.ec2.get_all_regions():
            region_info = {'name': str(region.name),
                           'endpoint': str(region.endpoint)}
            self.regions.append(region_info)

    @classmethod
    def assertEquals(cls, x, y, msg):
        assert x == y, str(x) + ' is not equal to ' + str(y) + ': ' + msg

    def clean_method(self):
        for region in self.regions:
            del region

    def request_params(self):
        method = 'GET'
        service = 'ec2'
        request_parameters = 'Action=DescribeRegions&Version=2013-10-15'
        return (method, service, request_parameters) 

    def sign(self, key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

    def getSignatureKey(self, key, datestamp, region, service):
        sigDate = self.sign(('AWS4' + key).encode('utf-8'), datestamp)
        sigRegion = self.sign(sigDate, region)
        sigService = self.sign(sigRegion, service)
        sigSigning = self.sign(sigService, 'aws4_request')
        return sigSigning

    def createCanonicalRequest(self, method, request_parameters, host, amzdate):
        canonical_uri = '/'
        canonical_querystring = request_parameters
        canonical_headers = 'host:' + host + '\n' + 'x-amz-date:' + amzdate + '\n'
        signed_headers = 'host;x-amz-date'
        payload_hash = hashlib.sha256('').hexdigest()
        canonical_request = (method + '\n'
                             + canonical_uri + '\n'
                             + canonical_querystring + '\n'
                             + canonical_headers + '\n'
                             + signed_headers + '\n'
                             + payload_hash)  
        return canonical_request

    def createStringtoSign(self, datestamp, region, service, amzdate, canonical_request):
        algorithm = 'AWS4-HMAC-SHA256'
        credential_scope = datestamp + '/' + region + '/' + service + '/' + 'aws4_request'
        string_to_sign = (algorithm + '\n'
                          +  amzdate + '\n'
                          +  credential_scope + '\n'
                          +  hashlib.sha256(canonical_request).hexdigest())
        return string_to_sign

    def createAuthHeader(self, datestamp, region, signature, service):
        algorithm = 'AWS4-HMAC-SHA256'
        credential_scope = datestamp + '/' + region + '/' + service + '/' + 'aws4_request'
        signed_headers = 'host;x-amz-date'
        authorization_header = (algorithm + ' '
                                + 'Credential='
                                + self.tester.ec2.aws_access_key_id + '/'
                                + credential_scope + ', '
                                +  'SignedHeaders=' + signed_headers + ', '
                                + 'Signature=' + signature)
        return authorization_header

    def sigV4Test(self):
        for region in self.regions:
            (method, service, request_parameters) = self.request_params()
            host = region['endpoint'].strip('http://')
            
            t = datetime.datetime.utcnow()
            amzdate = t.strftime('%Y%m%dT%H%M%SZ')
            datestamp = t.strftime('%Y%m%d')

            canonical_request = self.createCanonicalRequest(method,
                                                            request_parameters,
                                                            host,
                                                            amzdate)
            string_to_sign = self.createStringtoSign(datestamp,
                                                     region['name'],
                                                     service,
                                                     amzdate,
                                                     canonical_request)
            signing_key = self.getSignatureKey(self.tester.ec2.aws_secret_access_key,
                                               datestamp,
                                               region['name'],
                                               service)
            signature = hmac.new(signing_key,
                                 (string_to_sign).encode('utf-8'),
                                 hashlib.sha256).hexdigest() 
            authorization_header = self.createAuthHeader(datestamp,
                                                         region['name'],
                                                         signature,
                                                         service)
            headers = {'x-amz-date':amzdate, 'Authorization':authorization_header}
            request_url = region['endpoint'] + '?' + request_parameters
            self.tester.info("\nAWS SigV4 Compute Test against {region} endpoint".format(
                             region=region['name']))
            self.tester.info("\nBEGIN REQUEST +++++++++++++++++++++++++++++++++++++")
            self.tester.info("Request URL = {request_url}".format(
                              request_url=request_url))
            try:
                sigv4_request = requests.get(request_url, headers=headers, timeout=5)
            except requests.exceptions.ConnectionError:
                self.tester.debug("Connection error occurred using "
                                  + "endpoint {region_endpoint}".format(
                                  region_endpoint=region['endpoint']))
            except requests.exceptions.Timeout:
                self.tester.debug("Connection timeout occurred using "
                                  + "endpoint {region_endpoint} : {error}".format(
                                  region_endpoint=region['endpoint']))
            except requests.exceptions.RequestException as e:
                self.tester.debug("Exception occurred during 'GET' request using "
                                  + "{request_url} : {error}".format(
                                  request_url=request_url,
                                  error=e.message))
                raise e

            sigv4_xml_resp = xml.dom.minidom.parseString(sigv4_request.text)
            sigv4_response = sigv4_xml_resp.toprettyxml()
            self.tester.info("\nRESPONSE ++++++++++++++++++++++++++++++++++++++++++")
            self.tester.info("Response code: {code}\n{response}".format(
                              code=sigv4_request.status_code,
                              response=sigv4_response))
            self.assertEquals(sigv4_request.status_code, 200, "AWS SigV4 Request Failed.") 

if __name__ == "__main__":
    testcase = ComputeSigV4Test()
    list = ['sigV4Test']
    unit_list = []
    for test in list:
        unit_list.append( testcase.create_testunit_by_name(test) )
    result = testcase.run_test_case_list(unit_list, clean_on_exit=testcase.args.clean_on_exit)
    exit(result)
