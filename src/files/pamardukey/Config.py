#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
ArduKey PAM

Copyright 2015 Philipp Meisberger <team@pm-codeworks.de>,
               Bastian Raschke <bastian.raschke@posteo.de>
All rights reserved.
"""

## Documentation: @see http://docs.python.org/3/library/configparser.html
from ConfigParser import ConfigParser
import os


class Config(object):
    """
    Configuration file management.

    The config file path.
    @var string

    Flag that indicates config file will be not modified.
    @var boolean

    The ConfigParser instance.
    @var ConfigParser
    """
    __configFile = None
    __readOnly = False
    __configParser = None

    def __init__(self, configFile, readOnly = False):
        """
        Constructor

        @param string configFile
        @param boolean readOnly
        """

        # Checks if path/file is readable
        if ( readOnly == True and os.access(configFile, os.R_OK) == False ):
            raise Exception('The configuration file "' + configFile + '" is not readable!')

        ## Create file if not exists
        if ( readOnly == False and not os.path.exists(configFile) ):
            file(configFile, "w")

        self.__configFile = configFile
        self.__readOnly = readOnly

        self.__configParser = ConfigParser()
        self.__configParser.read(configFile)

    def __del__(self):
        """
        Destructor

        """

        self.save()

    def save(self):
        """
        Writes modifications to config file.

        @return boolean
        """

        if ( self.__configFile == None ) or ( self.__readOnly == True ):
            return False

        # Checks if path/file is writable
        if ( os.access(self.__configFile, os.W_OK) == True ):

            f = open(self.__configFile, 'w')
            self.__configParser.write(f)
            f.close()

            return True

        return False

    def get(self, section, name):
        """
        Reads a string value.

        @param string section
        @param string name
        @return string
        """

        return self.__configParser.get(section, name)

    def set(self, section, name, value):
        """
        Writes a string value.

        @param string section
        @param string name
        @param string value
        @return void
        """

        ## Create section if not exist
        if ( self.__configParser.has_section(section) == False ):
            self.__configParser.add_section(section)

        self.__configParser.set(section, name, value)

    def readList(self, section, name):
        """
        Reads a list.

        @param string section
        @param string name
        @return list
        """

        unpackedList = self.readString(section, name)
        return unpackedList.split(',')

    def writeList(self, section, name, value):
        """
        Writes a list.

        @param string section
        @param string name
        @param list value
        @return void
        """

        delimiter = ','
        self.__configParser.set(section, name, delimiter.join(value))

    def itemExists(self, section, name):
         """
         Checks if an item in a given section exists.

         @param string section
         @param string name
         @return boolean
         """

         return self.__configParser.has_option(section, name)
