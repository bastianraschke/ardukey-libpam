#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

setup(
    name            = 'pamardukey',
    version         = '1.0.1', ## Never forget to change module version as well!
    description     = 'Pluggable Authentication Module for 2FA with ArduKey.',
    author          = 'Philipp Meisberger',
    author_email    = 'team@pm-codeworks.de',
    url             = 'http://www.pm-codeworks.de',
    license         = 'D-FSL',
    package_dir     = {'': 'files'},
    packages        = ['pamardukey'],
)
