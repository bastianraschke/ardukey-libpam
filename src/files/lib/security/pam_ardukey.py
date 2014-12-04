#!/usr/bin/env python3

"""
ArduKey 2FA
PAM implementation.
@author Philipp Meisberger, Bastian Raschke

Copyright 2014 Philipp Meisberger, Bastian Raschke.
All rights reserved.
"""

import sys
sys.path.append('/usr/lib')

from pamardukey.Config import *
from pamardukey.version import VERSION

#import hashlib
import syslog

def auth_log(message, priority=syslog.LOG_INFO):
    """
    Sends errors to default authentication log

    @param string message
    @param integer priority
    @return void
    """

    syslog.openlog(facility=syslog.LOG_AUTH)
    syslog.syslog(priority, 'ArduKey PAM: ' + message)
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

    ## TODO: config file via argument!
    configFile = '/etc/pam-ardukey.conf'

    ## Tries to init Config
    try:
        globalConfig = Config(configFile)

    except Exception as e:
        auth_log(e.message, syslog.LOG_CRIT)
        return pamh.PAM_IGNORE

    auth_log('The user "' + userName + '" is asking for permission for service "' + str(pamh.service) + '".', syslog.LOG_DEBUG)

    ## Tries to init mapping file in users home directory
    try:
        mappingFile = Config('/home/' + userName + '/.pam-ardukey.mapping')

        ## Public ID exists in mapping file?
        if ( mappingFile.itemExists('Mapping', 'public_id') == False ):
            raise Exception('No "public_id" was specified in mapping file!')

        publicId = mappingFile.readString('Mapping', 'public_id')

        if (publicId == ''):
            raise Exception('Public_id must not be empty!')

    except Exception as e:
        auth_log(e.message, syslog.LOG_ERR)
        return pamh.PAM_ABORT


    ## TODO: if auth server is not available
    ## pamh.conversation(pamh.Message(pamh.PAM_TEXT_INFO, 'ArduKey ' + VERSION + ': Initialization failed!'))
    ## return pamh.PAM_ABORT

    response = pamh.conversation(pamh.Message(pamh.PAM_PROMPT_ECHO_OFF, 'Please connect ArduKey and press button...'))

    ## Check OTP matches public ID
    if (response.resp == publicId):
        return pamh.PAM_SUCCESS
    else:
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
