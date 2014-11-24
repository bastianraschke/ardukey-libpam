"""
ArduKey 2FA
PAM implementation.

Copyright 2014 Bastian Raschke.
All rights reserved. 
"""

#import hashlib


def auth_log(message):
    """
    Send errors to default auth log

    """

    syslog.openlog(facility=syslog.LOG_AUTH)
    syslog.syslog("ArduKey: " + message)
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

    except:
        e = sys.exc_info()[1]
        auth_log('Exception occured: ' + e.message)
        return pamh.PAM_USER_UNKNOWN

    auth_log('The user "' + userName + '" is asking for permission for service "' + str(pamh.service) + '".')


    ## TODO: read users public id in config file

    ## Checks if the the user was added in configuration
    if ( config.itemExists('Users', userName) == False ):
        logger.error('The user was not added!')
        return pamh.PAM_IGNORE

    ## Tries to get user information (template position, fingerprint hash)
    try:
        userData = config.readList('Users', userName)
        
        ## Validates user information
        if ( len(userData) != 2 ):
            raise Exception('The user information of "' + userName + '" is invalid!')

        expectedPositionNumber = int(userData[0])
        expectedFingerprintHash = userData[1]

    except:
        e = sys.exc_info()[1]
        logger.error(e.message, exc_info=False)
        return pamh.PAM_AUTH_ERR



    ## TODO: if auth server is not available
    ## pamh.conversation(pamh.Message(pamh.PAM_TEXT_INFO, 'pamfingerprint ' + VERSION + ': Sensor initialization failed!'))
    ## return pamh.PAM_ABORT




    response = pamh.conversation(pamh.Message(pamh.PAM_PROMPT_ECHO_OFF, 'Please connect ArduKey and press button...'))




    try:

        ## Checks if the calculated hash is equal to expected hash from user
        if ( fingerprintHash == expectedFingerprintHash ):
            logger.info('Access granted!')
            pamh.conversation(pamh.Message(pamh.PAM_TEXT_INFO, 'pamfingerprint ' + VERSION + ': Access granted!'))
            return pamh.PAM_SUCCESS
        else:
            logger.info('The found match is not assigned to user!')
            pamh.conversation(pamh.Message(pamh.PAM_TEXT_INFO, 'pamfingerprint ' + VERSION + ': Access denied!'))
            return pamh.PAM_AUTH_ERR

    except:
        e = sys.exc_info()[1]
        logger.error('Fingerprint read failed!', exc_info=True)
        pamh.conversation(pamh.Message(pamh.PAM_TEXT_INFO, 'pamfingerprint ' + VERSION + ': Access denied!'))
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
