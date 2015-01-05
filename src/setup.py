#!/usr/bin/env python3

from distutils.core import setup

setup(
    name            = 'libpam-ardukey',
    version         = '1.0',
    description     = 'ArduKey authentication server for 2FA written in Python 3.',
    author          = 'Philipp Meisberger',
    author_email    = 'p.meisberger@posteo.de',
    url             = 'https://sicherheitskritisch.de',
    license         = 'Simplified BSD License',
    package_dir     = {'': 'files'},
)
