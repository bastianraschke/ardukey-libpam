#!/usr/bin/env python3

"""
ArduKey 2FA
PAM implementation.
@author Philipp Meisberger, Bastian Raschke

Copyright 2014 Philipp Meisberger, Bastian Raschke.
All rights reserved.
"""

import sys, syslog
sys.path.append('/usr/lib/')

from pamardukey.Config import *
from pamardukey.version import VERSION

import httplib
import json
import random, string
import hmac, hashlib


class BadHmacSignatureError(Exception):
    """
    Dummy exception class for bad Hmac signature check.

    """

    pass


def calculateHmac(data, sharedSecret):
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


def showPAMTextMessage(pamh, message):
    """
    Shows a PAM conversation text info.

    @param pamh
    @param string message

    @return void
    """

    if ( type(message) != str ):
        raise ValueError('The given parameter is not a string!')

    msg = pamh.Message(pamh.PAM_TEXT_INFO, 'pam-ardukey ' + VERSION + ': '+ message)
    pamh.conversation(msg)


def auth_log(message, priority=syslog.LOG_INFO):
    """
    Sends errors to default authentication log

    @param string message
    @param integer priority

    @return void
    """

    syslog.openlog(facility=syslog.LOG_AUTH)
    syslog.syslog(priority, 'pam_ardukey '+ VERSION + ': '+ message)
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

        showPAMTextMessage(pamh, 'DEBUG: Requested user: '+ userName)

        ## Be sure the user is set
        if ( userName == None ):
            raise Exception('The user is not known!')

    except Exception as e:
        auth_log('Error occured while trying to get user name: '+ str(e), syslog.LOG_CRIT)
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
        auth_log('Error occured while parsing mapping file: '+ str(e), syslog.LOG_ERR)
        return pamh.PAM_ABORT

    typedOTP = pamh.conversation(pamh.Message(pamh.PAM_PROMPT_ECHO_ON, 'Please connect ArduKey and press button...'))
    typedOTP = typedOTP.resp

    if ( len(typedOTP) == 0 ):
        auth_log('No ArduKey OTP was typed! Please check your ArduKey.')
        showPAMTextMessage(pamh, 'No ArduKey OTP was typed! Please check your ArduKey.')
        return pamh.PAM_ABORT

    ## Get the config file via PAM argument
    equal = argv[1].index('=')

    if ( equal != -1 ):
        configFile = argv[1][equal+1:]
    else:
        configFile = '/etc/pam-ardukey.conf'

    try:
        ## Tries to init Config
        globalConfig = Config(configFile)

        ## Try to get server connection data
        servers = globalConfig.readList('pam-ardukey', 'servers')
        requestTimeout = globalConfig.readInteger('pam-ardukey', 'timeout')
        apiId = globalConfig.readInteger('pam-ardukey', 'apiId')
        sharedSecret = globalConfig.readString('pam-ardukey', 'sharedSecret')

        ## Check emptiness of servers
        if ( len(servers) == 0 ):
            raise ValueError('No value for attribute "servers"!')

        ## TODO: Check timeout

        ## Check API id
        if ( apiId <= 0 ):
            raise ValueError('No valid value for attribute "apiId"!')

        ## Check shared secret
        if ( len(sharedSecret) == 0):
            raise ValueError('No value for attribute "sharedSecret"!')

    except Exception as e:
        auth_log('Error occured while reading config file "'+ configFile +'": '+ str(e), syslog.LOG_ERR)
        return pamh.PAM_ABORT

    nonce = ''

    ## Generate random nonce
    for _ in range(32):
        chars = random.SystemRandom().choice(string.ascii_uppercase + string.digits)
        nonce = nonce + ''.join(chars)

    print('DEBUG: OTP: '+ typedOTP)
    print('DEBUG: nonce: '+ nonce)
    print('DEBUG: apiId: '+ str(apiId))
    print('DEBUG: sharedSecret: '+ sharedSecret)

    ## Set up request
    request = {}
    request['otp'] = typedOTP
    request['nonce'] = nonce
    request['apiId'] = apiId
    request['hmac'] = calculateHmac(request, sharedSecret)

    for server in servers:
        try:
            ## TODO: Check timeout issue
            ## Start connection to auth server
            connection = httplib.HTTPConnection(server, timeout=requestTimeout)

            ## Send client auth data
            connection.request('GET', '/ardukeyotp/1.0/verify?otp='+ request['otp'] +'&nonce='+ request['nonce'] +'&apiId='+ str(request['apiId']) +'&hmac='+ request['hmac'])

            ## Receive the response from auth server
            httpResponse = connection.getresponse()
            httpResponseData = httpResponse.read().decode()
            requestError = False

            print('DEBUG: Requested auth server: '+ server)
            break

        except:
            requestError = True
            continue

    ## Error occured?
    if ( requestError == True ):
        showPAMTextMessage(pamh, 'Connection to auth server failed!')
        return pamh.PAM_ABORT

    print(httpResponseData)

    ## Parse JSON response from server
    try:
        ## Convert JSON response to Python dict
        httpResponse = json.loads(httpResponseData)

        ## Retrieve response data
        ## TODO: Escape input
        response = {}
        response['otp'] = httpResponse['otp']
        response['nonce'] = httpResponse['nonce']
        response['status'] = httpResponse['status']
        response['time'] = httpResponse['time']

        ## Save the HMAC
        responseHmac = httpResponse['hmac']

        ## Calculate HMAC of HTTP response
        calculatedResponseHmac = calculateHmac(response, sharedSecret)

        ## Check if calculated HMAC matches received
        if ( responseHmac != calculatedResponseHmac ):
            raise BadHmacSignatureError('The response Hmac signature is not valid!')

    except BadHmacSignatureError as e:
        showPAMTextMessage(pamh, str(e))
        return pamh.PAM_AUTH_ERR

    except KeyError:
        showPAMTextMessage(pamh, 'Error while parsing HTTP response!')
        return pamh.PAM_AUTH_ERR

    except Exception as e:
        showPAMTextMessage(pamh, 'Unknown error occured: '+ str(e))
        return pamh.PAM_ABORT


    ## Check if nonce is the same as by request
    if ( request['nonce'] != response['nonce'] ):
        auth_log('Nonce of response differs from request!', syslog.LOG_ERR)
        showPAMTextMessage(pamh, 'Access denied!')
        return pamh.PAM_AUTH_ERR

    ## Check if OTP is the same as by request
    if ( response['otp'] != request['otp'] ):
        auth_log('OTP of response differs from request!', syslog.LOG_ERR)
        showPAMTextMessage(pamh, 'Access denied!')
        return pamh.PAM_AUTH_ERR

    ## Check OTP matches public ID
    if ( typedOTP[0:12] != publicId ):
        auth_log('The found match is not assigned to user!', syslog.LOG_WARNING)
        showPAMTextMessage(pamh, 'Access denied!')
        return pamh.PAM_AUTH_ERR

    ## TODO: Maybe check time?

    ## Grand access only on status "OK"
    if ( response['status'] == 'OK' ):
        auth_log('Access granted!')
        showPAMTextMessage(pamh, 'Access granted!')
        return pamh.PAM_SUCCESS
    else:
        auth_log('Auth server denied access (status: '+ response['status'] +')', syslog.LOG_ERR)
        showPAMTextMessage(pamh, 'Access denied!')
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
