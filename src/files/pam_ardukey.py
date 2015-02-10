#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
PAM ArduKey implementation

Copyright 2015 Philipp Meisberger <p.meisberger@posteo.de>,
               Bastian Raschke <bastian.raschke@posteo.de>
All rights reserved.
"""

import os, sys, syslog
import httplib
import json
import random, string
import hmac, hashlib

from pamardukey.Config import Config


class BadHmacSignatureError(Exception):
    """
    Dummy exception class for bad Hmac signature check.

    """

    pass

def calculateHmac(data, sharedSecret):
    """
    Calculate hmac of given dictionary and return it as a hexadecimal string.

    @param dict data
    The dictionary that contains data.

    @return string
    """

    ## Only process dictionaries
    if ( type(data) != dict ):
        raise ValueError('The given data is not a dictionary!')

    ## Check if shared secret is given
    if ( len(sharedSecret) == 0 ):
        raise ValueError('No shared secret given to perform hmac calculation!')

    dataString = ''

    ## Sort dictionary by key, to calculate the same hmac always
    for k in sorted(data):
        dataString += str(data[k])

    sharedSecret = sharedSecret.encode('utf-8')
    dataString = dataString.encode('utf-8')

    ## Calculate hmac of payload
    return hmac.new(sharedSecret, msg=dataString, digestmod=hashlib.sha256).hexdigest()

def showPAMTextMessage(pamh, message):
    """
    Shows a PAM conversation text info.

    @param pamh
    The PAM handle.

    @param string message
    The message to print.

    @return void
    """

    if ( type(message) != str ):
        raise ValueError('The given parameter is not a string!')

    msg = pamh.Message(pamh.PAM_TEXT_INFO, 'pam_ardukey: ' + message)
    pamh.conversation(msg)

def auth_log(message, priority=syslog.LOG_INFO):
    """
    Sends errors to default authentication log

    @param string message
    The message to write to syslog.

    @param integer priority
    The priority of the syslog message.

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

        if ( userName == None ):
            userName = pamh.get_user()

        ## Be sure the user is set
        if ( userName == None ):
            raise Exception('The user is not known!')

    except Exception as e:
        auth_log('Error occured while trying to get user name: '+ str(e), syslog.LOG_CRIT)
        return pamh.PAM_USER_UNKNOWN

    auth_log('The user "' + userName + '" is asking for permission for service "' + str(pamh.service) + '".', syslog.LOG_DEBUG)

    ## Tries to init mapping file in users home directory
    try:
        mappingFile = Config(os.getenv('HOME') + '/.pam-ardukey.mapping')

        ## Public ID exists in mapping file?
        if ( mappingFile.itemExists('Mapping', 'public_id') == False ):
            raise Exception('No "public_id" was specified in mapping file!')

        publicId = mappingFile.readString('Mapping', 'public_id')

        if ( publicId == '' ):
            raise Exception('Public_id must not be empty!')

    except Exception as e:
        auth_log('Error occured while parsing mapping file: '+ str(e), syslog.LOG_ERR)
        return pamh.PAM_ABORT

    typedOTP = pamh.conversation(pamh.Message(pamh.PAM_PROMPT_ECHO_ON,
        'Please connect ArduKey and press button...')).resp

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

    ## Generate random nonce
    nonce = ''.join(random.SystemRandom().choice(
        string.ascii_uppercase + string.digits) for _ in range(32))

    request = {
        'otp': typedOTP,
        'nonce': nonce,
        'apiId': apiId,
    }

    ## Calculate request hmac
    request['hmac'] = calculateHmac(request, sharedSecret)

    ## Try connect server by server to be sure one is up
    for server in servers:
        try:
            connection = httplib.HTTPConnection(server, timeout=requestTimeout)

            ## Send request to server
            connection.request('GET', '/ardukeyotp/1.0/verify?otp=' + request['otp'] + '&nonce=' + request['nonce'] + '&apiId=' + str(request['apiId']) + '&hmac=' + request['hmac'])

            ## Receive the response from auth server
            httpResponseData = connection.getresponse().read().decode()

            requestError = False
            break

        except:
            requestError = True
            continue

    if ( requestError == True ):
        showPAMTextMessage(pamh, 'Connection to auth server failed!')
        return pamh.PAM_ABORT

    ## Try to parse JSON response
    try:
        ## Convert JSON response to dictionary
        httpResponse = json.loads(httpResponseData)

        ## Retrieve response data
        ## TODO: Escape input
        response = {}
        response['otp'] = httpResponse['otp']
        response['nonce'] = httpResponse['nonce']
        response['status'] = httpResponse['status']
        response['time'] = httpResponse['time']

        ## Calculate HMAC of server response
        calculatedResponseHmac = calculateHmac(response, sharedSecret)

        ## Check if calculated HMAC matches received
        if ( httpResponse['hmac'] != calculatedResponseHmac ):
            raise BadHmacSignatureError('The response Hmac signature is not valid!')

    except BadHmacSignatureError as e:
        showPAMTextMessage(pamh, str(e))
        return pamh.PAM_AUTH_ERR

    except KeyError:
        showPAMTextMessage(pamh, 'Error while parsing HTTP response!')
        return pamh.PAM_AUTH_ERR

    except Exception as e:
        showPAMTextMessage(pamh, 'Unknown error occured: '+ str(e))
        return pamh.PAM_AUTH_ERR

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

    ## Important: Check if OTP matches public ID
    if ( typedOTP[0:12] != publicId ):
        auth_log('The found match is not assigned to user!', syslog.LOG_WARNING)
        showPAMTextMessage(pamh, 'Access denied!')
        return pamh.PAM_AUTH_ERR

    ## TODO: Maybe additionally check time?

    ## Grand access only if the status is good
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
