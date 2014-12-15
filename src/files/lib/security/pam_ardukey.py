#!/usr/bin/env python3

"""
ArduKey 2FA
PAM implementation.
@author Philipp Meisberger, Bastian Raschke

Copyright 2014 Philipp Meisberger, Bastian Raschke.
All rights reserved.
"""

import sys, syslog
sys.path.append('/usr/lib')

from pamardukey.Config import *
from pamardukey.version import VERSION

import json
import random, string
import hmac, hashlib

def __calculateHmac(self, data):
    """
    Calculates a hexadecimal Hmac of given data dictionary.

    @param dict data
    The dictionary that contains data.

    @return string
    """

    ## Only process dictionaries
    if ( type(data) != dict ):
        raise ValueError('The given data is not a dictionary!')

    ## Checks if shared secret is given
    if ( len(sharedSecret) == 0 ):
        raise ValueError('No shared secret given!')

    payloadData = ''

    ## Sort dictionary by key, to calculate the same Hmac always
    for k in sorted(data):
        payloadData += str(data[k])

    sharedSecret = sharedSecret.encode('utf-8')
    payloadData = payloadData.encode('utf-8')

    ## Calculate HMAC of current response
    return hmac.new(sharedSecret, msg=payloadData, digestmod=hashlib.sha256).hexdigest()


def __showMessage(pamh, text):
    """
    Shows a PAM conversation text info.

    @param pamh
    @param string text
    """

    if ( type(text) != str ):
        raise ValueError('The given parameter is not a string!')

    text = 'pam-ardukey ' + VERSION + ': '+ text
    msg = pamh.Message(pamh.PAM_TEXT_INFO, text)
    pamh.conversation(msg)


def auth_log(message, priority=syslog.LOG_INFO):
    """
    Sends errors to default authentication log

    @param string message
    @param integer priority

    @return void
    """

    syslog.openlog(facility=syslog.LOG_AUTH)
    syslog.syslog(priority, 'pam_ardukey: ' + message)
    syslog.closelog()


def pam_sm_authenticate(pamh, flags, argv):
    """
    PAM service function for user authentication.

    @param pamh
    @param flags
    @param argv

    @return integer
    """

    ## Tries to get user which is asking for permission
    try:
        userName = pamh.ruser

        ## Fallback
        if ( userName == None ):
            userName = pamh.get_user()

        ## Be sure the user is set
        if ( userName == None ):
            raise Exception('The user is not known!')

    except Exception as e:
        auth_log(e.message, syslog.LOG_CRIT)
        return pamh.PAM_USER_UNKNOWN

    auth_log('The user "' + userName + '" is asking for permission for service "' + str(pamh.service) + '".', syslog.LOG_DEBUG)

    ## Tries to init mapping file in users home directory
    try:
        mappingFile = Config('/home/' + userName + '/.pam-ardukey.mapping')

        ## Public ID exists in mapping file?
        if ( mappingFile.itemExists('Mapping', 'public_id') == False ):
            raise Exception('No "public_id" was specified in mapping file!')

        publicId = mappingFile.readString('Mapping', 'public_id')

        if ( publicId == '' ):
            raise Exception('Public_id must not be empty!')

    except Exception as e:
        auth_log(e.message, syslog.LOG_ERR)
        return pamh.PAM_ABORT

    typedOTP = pamh.conversation(pamh.Message(pamh.PAM_PROMPT_ECHO_ON, 'Please connect ArduKey and press button...'))
    typedOTP = typedOTP.resp

    ## Get the config file via PAM argument
    equal = argv[1].index('=')

    if ( equal != -1 ):
        configFile = argv[1][equal+1:]
    else:
        configFile = '/etc/pam-ardukey.conf'

    ## Tries to init Config
    try:
        globalConfig = Config(configFile)

    except Exception as e:
        auth_log(e.message, syslog.LOG_CRIT)
        return pamh.PAM_IGNORE

    ## Try to connect to auth server
    try:
        servers = globalConfig.readList('pam-ardukey', 'servers')
        requestTimeout = globalConfig.readInteger('pam-ardukey', 'timeout')
        apiId = globalConfig.readInteger('pam-ardukey', 'apiId')
        sharedSecret = globalConfig.readString('pam-ardukey', 'sharedSecret')

    except Exception as e:
        auth_log(e.message, syslog.LOG_ERR)
        return pamh.PAM_ABORT

    nonce = ''

    ## Generate random nonce
    for _ in range(32):
        chars = random.SystemRandom().choice(string.ascii_uppercase + string.digits)
        nonce = nonce + ''.join(chars)

    print('OTP: '+ typedOTP)
    print('nonce: '+ nonce)
    print('apiId: '+ str(apiId))

    ## Set up request
    request = {}
    request['otp'] = typedOTP
    request['nonce'] = nonce
    request['apiId'] = apiId
    request['hashmac'] = self.__calculateHmac(request)

    for server in servers:
        print(server)
        try:
            ## TODO: Check timeout issue
            connection = http.client.HTTPConnection(server, timeout=requestTimeout)
            #headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
            connection.request('GET', '/ardukeyotp/1.0/verify?otp='+ request['otp'] +'&nonce='+ request['nonce'] +'&apiId='+ str(request['apiId']) +'&hmac='+ request['hmac'])
            httpResponse = connection.getresponse()
            httpResponseData = httpResponse.read().decode()
            requestError = False
            break

        except:
            requestError = True
            continue

    ## Error occured?
    if ( requestError == False ):
        ## TODO: if auth server is not available
        __showMessage(pamh, 'Connection failed!')
        return pamh.PAM_ABORT

    print(httpResponseData)

    ## Parse JSON response from server
    try:
        ## Convert JSON response to Python dict
        httpResponse = json.loads(httpResponseData)

        ## Save the HMAC
        responseHmac = httpResponse['hmac']

        ## Exclude response HMAC itself from HMAC calculation
        httpResponse['hmac'] = ''

        ## Calculate HMAC of HTTP response
        calculatedResponeHmac = __calculateHmac(httpResponse)

        ## Check if calculated HMAC matches received
        if ( responseHmac != calculatedResponeHmac ):
            raise BadHmacSignatureError('The response HMAC signature is not valid!')

        ## Retrieve response data
        responseOtp = httpResponse['otp']
        responseNonce = httpResponse['nonce']
        responseStatus = httpResponse['status']
        responseTime = httpResponse['time']

    except BadHmacSignatureError as e:
        __showMessage(pamh, e)
        return pamh.PAM_AUTH_ERR

    except KeyError:
        __showMessage(pamh, 'Error while parsing HTTP response!')
        return pamh.PAM_AUTH_ERR

    except:
        __showMessage(pamh, 'Error occured: '+ str(sys.exc_info()[1]))
        return pamh.PAM_ABORT


    ## Check OTP matches public ID
    if ( typedOTP == publicId ):
        auth_log('Access granted!')
        __showMessage(pamh, 'Access granted!')
        return pamh.PAM_SUCCESS
    else:
        auth_log('The found match is not assigned to user!', syslog.LOG_WARNING)
        __showMessage(pamh, 'Access denied!')
        return pamh.PAM_AUTH_ERR

    ## Denies for default
    return pamh.PAM_AUTH_ERR


def pam_sm_setcred(pamh, flags, argv):
    """
    PAM service function to alter credentials.

    @param pamh
    @param flags
    @param argv
    @return integer
    """

    return pamh.PAM_SUCCESS

def pam_sm_acct_mgmt(pamh, flags, argv):
    """
    PAM service function for account management.

    @param pamh
    @param flags
    @param argv
    @return integer
    """

    return pamh.PAM_SUCCESS

def pam_sm_open_session(pamh, flags, argv):
    """
    PAM service function to start session.

    @param pamh
    @param flags
    @param argv
    @return integer
    """

    return pamh.PAM_SUCCESS

def pam_sm_close_session(pamh, flags, argv):
    """
    PAM service function to terminate session.

    @param pamh
    @param flags
    @param argv
    @return integer
    """

    return pamh.PAM_SUCCESS

def pam_sm_chauthtok(pamh, flags, argv):
    """
    PAM service function for authentication token management.

    @param pamh
    @param flags
    @param argv
    @return integer
    """

    return pamh.PAM_SUCCESS
