#on nix: pacman -Sy xmlsec 
#on osx: brew install libxmlsec1
#---------pip3 install suds-jurko
#---------pip3 install py-wsse
#pip3 install requests[security]
#pip3 install zeep[xmlsec]
#pip3 install pyjks

# HC Validation service
# to check where certificates are:
# import certifi
# certifi.where()


import logging.config
logging.config.dictConfig({
    'version': 1,
    'formatters': {
        'verbose': {
            'format': '%(name)s: %(message)s'
        }
    },
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'zeep.transports': {
            'level': 'DEBUG',
            'propagate': True,
            'handlers': ['console'],
        },
    }
})
import ssl
import ipaddress, socket
def match_hostname_fixed(cert, hostname):
    """Verify that *cert* (in decoded format as returned by
    SSLSocket.getpeercert()) matches the *hostname*.  RFC 2818 and RFC 6125
    rules are followed, but IP addresses are not accepted for *hostname*.
    
    **NB** CORRECTION: fixed to accept IP address as *hostname*

    CertificateError is raised on failure. On success, the function
    returns nothing.
    """
    if not cert:
        raise ValueError("empty or no certificate, match_hostname needs a "
                         "SSL socket or SSL context with either "
                         "CERT_OPTIONAL or CERT_REQUIRED")
    try:
        host_ip = ipaddress.ip_address(hostname)
    except ValueError:
        # Not an IP address (common case)
        host_ip = None
    dnsnames = []
    san = cert.get('subjectAltName', ())
    for key, value in san:
        if key == 'DNS':
            if host_ip is None and ssl._dnsname_match(value, hostname): #match hostnames
                return
            elif host_ip and ssl._ipaddress_match(socket.gethostbyname(value), host_ip): #"hostname" is IP address, look up the IP of the host trying to match with it
                return
            dnsnames.append(value)
        elif key == 'IP Address':
            if host_ip is not None and ssl._ipaddress_match(value, host_ip):
                return
            dnsnames.append(value)
    if not dnsnames:
        # The subject is only checked when there is no dNSName entry
        # in subjectAltName
        for sub in cert.get('subject', ()):
            for key, value in sub:
                # XXX according to RFC 2818, the most specific Common Name
                # must be used.
                if key == 'commonName':
                    if _dnsname_match(value, hostname):
                        return
                    dnsnames.append(value)
    if len(dnsnames) > 1:
        raise CertificateError("hostname %r "
            "doesn't match either of %s"
            % (hostname, ', '.join(map(repr, dnsnames))))
    elif len(dnsnames) == 1:
        raise CertificateError("hostname %r "
            "doesn't match %r"
            % (hostname, dnsnames[0]))
    else:
        raise CertificateError("no appropriate commonName or "
            "subjectAltName fields were found")

ssl.match_hostname = match_hostname_fixed

import requests
# suppress insecure connection warning
# from requests.packages.urllib3.exceptions import InsecureRequestWarning
# requests.packages.urllib3.disable_warnings(InsecureRequestWarning)



def log(auditID, mohID, servUser, userID, stime, action, success, status, error=''):
    with open('MOHLOG.TXT','a') as f:
        f.write('---------------\nauditID:{}\nMOH ID:{}\nServiceUser:{}\n'.format(auditID, mohID, servUser) +
                'UserID:{}\nTimestamp:{}\nAction:{}\n'.format(userID, stime, action) +
                'Success/Fail:{}\nStatus:{}\nError:{}\n---------------\n'.format(success, status, error))
def _line():
    try:
        import sys
        exc_type, exc_obj, exc_tb = sys.exc_info()
        return str(exc_tb.tb_lineno)
    except Exception as e:
        return ''
# debug printing
import traceback
def dbp(*arg,**kwargs):
    if ('debug' in kwargs): 
        print(traceback.extract_stack()[-2][2]+'()',end='') #just the name of the caller function here
    else:#this is an error - print the stack trace
        for item in traceback.extract_stack()[0:-1]:
            # grab the name of the file itself (not the full path)
            filename = '/'.join(item[0].split('/')[-2:])
            # grab the line number
            line = str(item[1])
            # grab the offending function
            func = str(item[2])
            # the actual line of code:
            code = str(item[3])
            print( line.rjust(5),func.rjust(30),"\t",filename,'("',code,'")')
    print( "\n----------------------------------------")
    for a in arg:
        print(a,end='__')
    try:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print("\n",exc_type, fname, exc_tb.tb_lineno)
    except Exception as e:
        pass
    print( "\n----------------------------------------")
#end dbp
def validate(hcnum,hcver):
    try:
        pathPrefix = './'
        import uuid
        import zeep
        from zeep.wsse.username import UsernameToken
        from zeep.wsse.signature import Signature
        from zeep.wsse.utils import get_timestamp
        from zeep.transports import Transport
        from zeep import xsd, Client
        from requests import Session
        import lxml.etree as ET

        # import jks, base64, textwrap
        # def toText(der_bytes, pemType):
        #     result = "-----BEGIN %s-----\r\n" % pemType
        #     result += "\r\n".join(textwrap.wrap(base64.b64encode(der_bytes).decode('ascii'), 64))
        #     result += "\r\n-----END %s-----" % pemType
        #     return result

        # from lxml import etree as ET
        # ks = jks.KeyStore.load(pathPrefix+"privatestore.jks",'pass')
        # # key = 
        # for alias, pk in ks.private_keys.items():
        #     # print("Private key: %s" % pk.alias)
        #     if pk.algorithm_oid == jks.util.RSA_ENCRYPTION_OID:
        #         open(pathPrefix+'privkey.pem','w').write(toText(pk.pkey,'RSA PRIVATE KEY'))
        #         # print("RSA::\n",toText(pk.pkey,'RSA PRIVATE KEY'))
        #     else:
        #         print("NRM::\n",toText(pk.pkey_pkcs8,'PRIVATE KEY'))
        #         # print_pem(pk.pkey_pkcs8, "PRIVATE KEY")

        #     for c in pk.cert_chain:
        #         open(pathPrefix+'pubcert.pem','w').write(toText(c[1],'CERTIFICATE'))
        #         # print_pem(c[1], "CERTIFICATE")
        AuditId = str(uuid.uuid4())
        SoftKey = '46d55090-dda5-4747-b04f-8b2e36492ca6'#'24a1ad39-255a-4693-ae58-dedabd2c07a0'
        ServUsr = '432200'#'010637'
        TUserID = 'confsu312@yandex.com'#'confsu61@outlook.com'
        TPasswd = 'Password0!'
        TmStamp = get_timestamp()
        Action  = 'HCValidationService.validate({},{})'.format(hcnum,hcver)
        Success = 'Success'
        Status  = ''
        Error   = ''

        # wsdl = pathPrefix+'HCValidationService.wsdl'
        wsdl = 'https://ws.conf.ebs.health.gov.on.ca:1444/HCVService/HCValidationService?wsdl'

        session = Session()
        # session.verify = '/usr/local/lib/python3.6/site-packages/certifi/cacert.pem'#'/md/projects/ALERA/MOH/hcv_wsdl/root_cert/'
        transport = Transport(session=session)
        client = Client(
                wsdl=wsdl
                ,transport = transport
                ,wsse = [
                    UsernameToken(TUserID,TPasswd),
                    Signature(
                        pathPrefix+'server.key', #key
                        pathPrefix+'server.pem'  #certificate
                    )
                ]
            )
        #set up request itself
        req ={
            'healthNumber':hcnum,
            'versionCode':hcver,
        }
        requests = [{'hcvRequest':req}]

        ebs_proto = xsd.Element(
            '{http://ebs.health.ontario.ca/}EBS',
            xsd.ComplexType([
                xsd.Element(
                    'SoftwareConformanceKey', xsd.String()
                ),
                xsd.Element(
                    'AuditId', xsd.String()
                ),
            ])
        )
        idp_proto = xsd.Element(
            '{http://idp.ebs.health.ontario.ca/}IDP',
            xsd.ComplexType([
                xsd.Element(
                    'ServiceUserMUID', xsd.String()
                ),
            ])
        )
        headers = []
        headers.append(ebs_proto(SoftKey,AuditId))
        headers.append(idp_proto(ServUsr))

        # resp = client.service.validate(requests,'en',_soapheaders=headers)
        # print("RESPPPPPPPP:::",resp)
        node = client.create_message(client.service, 'validate', requests = requests, _soapheaders=headers)
        tree = ET.ElementTree(node)
        tree.write('test.xml',pretty_print=True)
        # return True
    except Exception as e:
        print(_line(),e)
        print(traceback.format_exc())
        try:
            nsm = {'ns1': 'http://ebs.health.ontario.ca/'}
            Success = 'Fail'
            Status = 'Error'
            if hasattr(e,'detail'):
                ebsfault = e.detail.find('ns1:EBSFault',namespaces=nsm)
                Status = ebsfault.find('code').text
                Error  = ebsfault.find('message').text
                print("code:",Status)
                print("msg:",Error)
        except Exception as err:
            print(_line())
            print('some other exception',err)
            print('original:',e)
    log(AuditId,'',ServUsr,TUserID,TmStamp,Action,Success,Status,Error)
validate('1286844022','YX')

# log('auditID', 'mohID', 'servUser', 'userID', 'stime', 'action', 'success', 'status', 'error')
# config = {
#     'auditUID' : auditUID,

#     'LoggingRequired': True,
#     'KeystoreUser' : 'alias',
#     'KeystorePassword' : 'pass',
#     'UserNameTokenUser' : 'confsu61@outlook.com',
#     'UserNameTokenPassword':'sU3p*Mks5ZBr',
#     'ServiceUrl':'https://ws.conf.ebs.health.gov.on.ca:1440/HCVService/HCValidationService',
#     'ConformanceKey':'24a1ad39-255a-4693-ae58-dedabd2c07a0',
#     'ServiceId':'010637',
#     'ServiceUserMUID':'010637'
# }