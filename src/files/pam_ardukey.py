#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
PAM ArduKey implementation

Copyright 2015 Philipp Meisberger <team@pm-codeworks.de>,
               Bastian Raschke <bastian.raschke@posteo.de>
All rights reserved.
"""

import syslog
import os
import httplib
import json
import random, string
import hmac, hashlib

import pamardukey.configuration as configuration
from pamardukey import __version__ as VERSION


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

    @return str
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

    @param str message
    The message to print.

    @return void
    """

    if ( type(message) != str ):
        raise ValueError('The given parameter is not a string!')

    msg = pamh.Message(pamh.PAM_TEXT_INFO, 'pam_ardukey ' + VERSION + ': ' + message)
    pamh.conversation(msg)

def auth_log(message, priority=syslog.LOG_INFO):
    """
    Sends errors to default authentication log

    @param str message
    The message to write to syslog.

    @param int priority
    The priority of the syslog message.

    @return void
    """

    syslog.openlog(facility=syslog.LOG_AUTH)
    syslog.syslog(priority, 'pam_ardukey: ' + VERSION + ': ' + message)
    syslog.closelog()

def pam_sm_authenticate(pamh, flags, argv):
    """
    PAM service function for user authentication.

    @param pamh
    @param flags
    @param argv

    @return int
    """

    ## Try to get user which is asking for permission
    try:
        userName = pamh.ruser

        if ( userName == None ):
            userName = pamh.get_user()

        ## Be sure the user is set
        if ( userName == None ):
            raise Exception('The user is not known!')

    except Exception as e:
        auth_log('Error occured while getting user name: ' + str(e), syslog.LOG_CRIT)
        return pamh.PAM_USER_UNKNOWN

    auth_log('The user "' + userName + '" is asking for permission ' + \
        'for service "' + str(pamh.service) + '".', syslog.LOG_DEBUG)

    ## Try to read mapping file in users home directory
    try:
        mappingFilePath = os.path.expanduser('~') + '/.pam-ardukey.mapping'

        ## Check if path/file is readable
        if ( os.access(mappingFilePath, os.R_OK) == False ):
            raise Exception('The mapping file was not found!')

        mappingFile = configuration.Configuration()
        mappingFile.setFilePath(mappingFilePath)

        publicId = mappingFile.get('public_id', 'Mapping')

        if ( publicId is None ):
            raise ValueError('No public id is given in mapping file!')

    except Exception as e:
        auth_log('Error occured while reading mapping file: ' + str(e), syslog.LOG_ERR)
        return pamh.PAM_ABORT

    typedOTP = pamh.conversation(pamh.Message(pamh.PAM_PROMPT_ECHO_ON,
        'pam_ardukey ' + VERSION + ': Please type ArduKey OTP: ')).resp

    if ( len(typedOTP) == 0 ):
        auth_log('No ArduKey OTP was typed!')
        showPAMTextMessage(pamh, 'No ArduKey OTP was typed! Please check your ArduKey.')
        return pamh.PAM_ABORT

    ## IMPORTANT FOR SECURITY: Check if OTP matches public id
    if ( typedOTP[0:12] != publicId ):
        auth_log('Access denied: The public id "' + typedOTP[0:12] + '" of OTP is not assigned to user!', syslog.LOG_WARNING)
        showPAMTextMessage(pamh, 'Access denied!')
        return pamh.PAM_AUTH_ERR

    ## Try to read global configuration file
    try:
        configurationFilePath = '/etc/pam-ardukey.conf'

        configurationInstance = configuration.getInstance()
        configurationInstance.setFilePath(configurationFilePath)

        servers = configurationInstance.getList('servers')
        requestTimeout = configurationInstance.get('timeout', default = 4.0)
        apiId = configurationInstance.get('api_id')
        sharedSecret = configurationInstance.get('shared_secret')

        ## Check if any auth servers are given
        if ( servers is None or len(servers) == 0 ):
            raise ValueError('No valid auth servers are given in configuration!')

        ## Check if an API id is given
        if ( apiId is None ):
            raise ValueError('No valid API id is given in configuration!')

        ## Check shared secret
        if ( sharedSecret is None ):
            raise ValueError('No valid shared secret is given in configuration!')

    except Exception as e:
        auth_log('Error occured while reading configuration file: ' + str(e), syslog.LOG_ERR)
        return pamh.PAM_ABORT

    ## Generate random nonce
    nonce = ''.join(random.SystemRandom().choice(
        string.ascii_lowercase + string.digits) for _ in range(32))

    request = {
        'otp': typedOTP,
        'nonce': nonce,
        'apiId': apiId,
    }

    ## Calculate request hmac
    request['hmac'] = calculateHmac(request, sharedSecret)

    ## Try connect server by server to be sure one is up
    for server in servers:

        connection = httplib.HTTPConnection(server, timeout=float(requestTimeout))

        try:
            ## Send request to server
            connection.request('GET', '/ardukeyotp/1.0/verify?' + \
                'otp=' + request['otp'] + \
                '&nonce=' + request['nonce'] + \
                '&apiId=' + request['apiId'] + \
                '&hmac=' + request['hmac']
            )

            ## Receive the response from auth server
            httpResponseData = connection.getresponse().read().decode()

            lastConnectionException = None
            break

        except Exception as e:
            lastConnectionException = e
            continue

        finally:
            connection.close()

    if ( lastConnectionException != None ):
        auth_log('The connection to auth server failed: ' + str(lastConnectionException))
        showPAMTextMessage(pamh, 'The connection to auth server failed!')
        return pamh.PAM_ABORT

    ## Try to parse JSON response
    try:
        ## Convert JSON response to dictionary
        ## IMPORTANT: This is potential dangerous input from outside,
        ## so we must handle it very carefully!
        response = json.loads(httpResponseData)

        responseHmac = response['hmac']
        response['hmac'] = ''

        ## Calculate hmac of server response
        calculatedResponseHmac = calculateHmac(response, sharedSecret)

        ## Check if calculated hmac matches received
        if ( responseHmac != calculatedResponseHmac ):
            raise BadHmacSignatureError()

    except KeyError:
        auth_log('The response data from auth server is invalid!', syslog.LOG_ERR)
        showPAMTextMessage(pamh, 'The response data from auth server is invalid!')
        return pamh.PAM_AUTH_ERR

    except BadHmacSignatureError:
        auth_log('The response signature from auth server is invalid!', syslog.LOG_ERR)
        showPAMTextMessage(pamh, 'The response signature from auth server is invalid!')
        return pamh.PAM_AUTH_ERR

    except Exception as e:
        auth_log('Unknown error occured while parsing response: ' + str(e), syslog.LOG_ERR)
        showPAMTextMessage(pamh, 'Unknown error occured!')
        return pamh.PAM_AUTH_ERR

    ## Check if nonce is the same as by request
    if ( request['nonce'] != response['nonce'] ):
        auth_log('Access denied: Nonce of response differs from request!', syslog.LOG_ERR)
        showPAMTextMessage(pamh, 'Access denied!')
        return pamh.PAM_AUTH_ERR

    ## Check if OTP is the same as by request
    if ( response['otp'] != request['otp'] ):
        auth_log('Access denied: OTP of response differs from request!', syslog.LOG_ERR)
        showPAMTextMessage(pamh, 'Access denied!')
        return pamh.PAM_AUTH_ERR

    ## Grant access only if the status is good
    if ( response['status'] == 'OK' ):
        auth_log('Access granted!')
        showPAMTextMessage(pamh, 'Access granted!')
        return pamh.PAM_SUCCESS
    else:
        auth_log('Access denied (status code: ' + response['status'] + ')!', syslog.LOG_WARNING)
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
    @return int
    """

    return pamh.PAM_SUCCESS

def pam_sm_acct_mgmt(pamh, flags, argv):
    """
    PAM service function for account management.

    @param pamh
    @param flags
    @param argv
    @return int
    """

    return pamh.PAM_SUCCESS

def pam_sm_open_session(pamh, flags, argv):
    """
    PAM service function to start session.

    @param pamh
    @param flags
    @param argv
    @return int
    """

    return pamh.PAM_SUCCESS

def pam_sm_close_session(pamh, flags, argv):
    """
    PAM service function to terminate session.

    @param pamh
    @param flags
    @param argv
    @return int
    """

    return pamh.PAM_SUCCESS

def pam_sm_chauthtok(pamh, flags, argv):
    """
    PAM service function for authentication token management.

    @param pamh
    @param flags
    @param argv
    @return int
    """

    return pamh.PAM_SUCCESS
