#!/usr/bin/env python

from distutils.core import setup

setup(
    name            = 'PAM ArduKey',
    version         = '1.0',
    description     = 'Pluggable Authentication Module for 2FA with ArduKey',
    author          = 'Philipp Meisberger',
    author_email    = 'p.meisberger@posteo.de',
    url             = 'https://sicherheitskritisch.de',
    license         = 'Simplified BSD License',
    package_dir     = {'': 'files'},
    packages        = ['pamardukey'],
)
