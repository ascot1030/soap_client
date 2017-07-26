#!/usr/bin/python
from suds.client import Client
from suds.wsse import *
from wsse.suds import WssePlugin
from suds.transport import Transport
from requests import Session
import datetime, pytz, os

from lxml import etree

# for custom transport:
from suds.transport.https import HttpAuthenticated
from urllib.request import HTTPSHandler
import ssl

import uuid


# Logging Options
# import logging
# logging.basicConfig(level=logging.INFO)
# logging.getLogger('suds.client').setLevel(logging.DEBUG)
# logging.getLogger('suds.wsse').setLevel(logging.DEBUG)
# logging.getLogger('wsse.suds').setLevel(logging.DEBUG)

# logging.getLogger('suds.wsdl').setLevel(logging.DEBUG)
# logging.getLogger('suds.transport').setLevel(logging.DEBUG) 
# logging.getLogger('suds.xsd.schema').setLevel(logging.DEBUG)
# logging.getLogger('suds.resolver').setLevel(logging.DEBUG)
# logging.getLogger('suds.xsd.query').setLevel(logging.DEBUG)
# logging.getLogger('suds.xsd.sxbasic').setLevel(logging.DEBUG)
# logging.getLogger('suds.xsd.sxbase').setLevel(logging.DEBUG)
# logging.getLogger('suds.metrics').setLevel(logging.DEBUG)
# logging.getLogger('suds.binding.marshaller').setLevel(logging.DEBUG)
 

def logResult(success,status,error=''):
    with open('MOHLOG.TXT','a') as f:
        f.write('Success/Fail:{}\nStatus:{}\nError:{}\n---------------\n'.format(success, status, error))
def logStart(auditID, mohID, servUser, userID, stime, action):
    with open('MOHLOG.TXT','a') as f:
        f.write('---------------\nauditID:{}\nMOH ID:{}\nServiceUser:{}\n'.format(auditID, mohID, servUser) +
                'UserID:{}\nTimestamp:{}\nAction:{}\n'.format(userID, stime, action))


class CustomTransport(HttpAuthenticated):

    def u2handlers(self):

        # use handlers from superclass
        handlers = HttpAuthenticated.u2handlers(self)

        # create custom ssl context, e.g.:
        ctx = ssl.create_default_context(cafile="./cert/test.cer")
        # configure context as needed...
        ctx.check_hostname = False

        # add a https handler using the custom context
        handlers.append(HTTPSHandler(context=ctx))
        return handlers

def get_timestamp(timestamp=None):
    timestamp = timestamp or datetime.datetime.utcnow()
    timestamp = timestamp.replace(tzinfo=pytz.utc, microsecond=0)
    return timestamp.isoformat()

 
# Setup variables
WSDL_URL = "file:///" + os.getcwd() + "/HCValidationService.wsdl"#"https://ws.conf.ebs.health.gov.on.ca:1444/HCVService/HCValidationService?wsdl"
MY_CERTFILE   = 'cert/cert.pem'
MY_KEYFILE    = 'cert/key.pem'
THEIR_CERTFILE = 'cert/Entrust.Certification.Authority.-.L1K.cer'
 
hcnum = '9999999999'
hcver = 'YX'
AuditId = str(uuid.uuid4())
SoftKey = '844b6fcf-07e1-4b30-963d-d15b30a61bad'#'24a1ad39-255a-4693-ae58-dedabd2c07a0'
ServUsr = '010637'
TUserID = 'confsu61@outlook.com'
TPasswd = 'Password0!'
TmStamp = get_timestamp()
Action  = 'HCValidationService.validate({},{})'.format(hcnum,hcver)
Success = 'Success'
Status  = ''
Error   = ''
NOSEND  = True
if not NOSEND:
    logStart(AuditId,'',ServUsr,TUserID,TmStamp,Action)
# WSSE Security
security = Security()
utoken = UsernameToken(TUserID, TPasswd)
ttoken = Timestamp()
security.tokens.append(utoken)
security.tokens.append(ttoken)

client = Client(WSDL_URL,
    # doctor = doctor,
    transport=CustomTransport(),
    wsse=security,
    nosend=NOSEND,
    plugins=[
        WssePlugin(
            keyfile=MY_KEYFILE,
            certfile=MY_CERTFILE,
            their_certfile=THEIR_CERTFILE,
        ),
    ],
)


ebs = client.factory.create("{http://ebs.health.ontario.ca/}ebs_header")
ebs.SoftwareConformanceKey = SoftKey
ebs.AuditId = AuditId
# ebs.
idp = client.factory.create("{http://idp.ebs.health.ontario.ca/}idp_header")
idp.ServiceUserMUID = ServUsr
client.set_options(soapheaders = [ebs,None,idp])
# print(dir(client))
req = client.factory.create('hcvRequest')
req.healthNumber = hcnum
req.versionCode = hcver

# print(client)
resp = client.service.validate(requests=[{'hcvRequest':req}],locale='en')
print(resp.envelope.decode('utf-8'))
                
