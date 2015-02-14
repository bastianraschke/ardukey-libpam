#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
PAM ArduKey

Copyright 2015 Bastian Raschke <bastian.raschke@posteo.de>,
               Philipp Meisberger <team@pm-codeworks.de>
All rights reserved.
"""

import threading
import ConfigParser
import os


class Configuration(object):
    """
    Configuration file reader.

    @attribute str __configurationFilePath
    The path to the configuration file.

    @attribute ConfigParser __configParser
    The ConfigParser object.
    """

    __configurationFilePath = ''
    __configParser = None

    def __init__(self):
        """
        Constructor

        """

        pass

    def setFilePath(self, configurationFilePath):
        """
        Set path to the configuration file.

        @attribute str configurationFilePath
        The path to the configuration file.

        @return void
        """

        ## Check if path/file is readable
        if ( os.access(configurationFilePath, os.R_OK) == False ):
            raise ValueError('The configuration file "' + configurationFilePath + '" is not readable!')

        self.__configurationFilePath = configurationFilePath

        self.__configParser = ConfigParser.ConfigParser()
        self.__configParser.read(self.__configurationFilePath)

    def saveFile(self):
        """
        Writes modifications to configuration file.

        @return bool
        """

        ## Check if path/file is writable
        if ( os.access(self.__configurationFilePath, os.W_OK) == True ):

            fileHandle = open(self.__configurationFilePath, 'w')
            self.__configParser.write(fileHandle)
            fileHandle.close()

            return True

        return False

    def exists(self, key, section = 'Configuration'):
        """
        Check if an option exists.

        @param str key
        The option key.

        @param str section
        The section of the key.

        @return bool
        """

        return self.__configParser.has_option(section, key)

    def get(self, key, section = 'Configuration', default = None):
        """
        Get an option by key.

        @param str key
        The option key.

        @param object default
        If no option is found, return default value instead.

        @param str section
        The section of the key.

        @return object
        """

        return self.__configParser.get(section, key, fallback=default)

    def getList(self, key, section = 'Configuration', default = None):
        """
        Get an list option by key.

        @param str key
        The option key.

        @param object default
        If no option is found, return default value instead.

        @param str section
        The section of the key.

        @return list
        """

        packedList = self.get(key, section, default)

        if ( packedList is not None ):
            unpackedList = packedList.split(',')

        return unpackedList

    def set(self, key, value, section = 'Configuration'):
        """
        Set an option by key.

        @param str key
        The option key.

        @param object value
        The option value.

        @param str section
        The section of the key.

        @return void
        """

        ## Create section if not exist
        if ( self.__configParser.has_section(section) == False ):
            self.__configParser.add_section(section)

        return self.__configParser.set(section, key, value)

    def setList(self, key, value, section = 'Configuration'):
        """
        Set an list option by key.

        @param str key
        The option key.

        @param list value
        The option value.

        @param str section
        The section of the key.

        @return void
        """

        if ( type(value) != list ):
            raise ValueError('The given value is not a list!')

        self.set(key, ','.join(value), section)

## Lock object to provide mutal exclusion
mutexLock = threading.Lock()

## Object instance on module level
moduleInstance = None

def getInstance():
    """
    Singleton method to get instance at module level.

    @return Configuration
    """

    try:
        mutexLock.acquire()

        global moduleInstance

        if ( moduleInstance is None ):
            moduleInstance = Configuration()

        returnValue = moduleInstance

    finally:
        mutexLock.release()

    return returnValue
