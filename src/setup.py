#!/usr/bin/env python
# -*- coding: utf-8 -*-

from distutils.core import setup

setup(
    name            = 'PAM ArduKey',
    version         = '1.0.1',
    description     = 'Pluggable Authentication Module for 2FA with ArduKey.',
    author          = 'Philipp Meisberger',
    author_email    = 'team@pm-codeworks.de',
    url             = 'http://www.pm-codeworks.de',
    license         = 'D-FSL',
    package_dir     = {'': 'files'},
    packages        = ['pamardukey'],
)
