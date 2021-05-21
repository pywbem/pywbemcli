# Copyright 2021 IBM Corp. All Rights Reserved.
# (C) Copyright 2021 Inova Development Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
pywbemcli mock script that calls the WBEMServerMock class in
tests/unit/pywbemcli/testmock and creates an instance of a WBEM server using the
default dictionary definition of the server defined in the same file as the
WBEMServerMock class.  This just separates the class from the script initiator
in pywbemcli so that other dictionary definitions of the mock can be created.
"""

from __future__ import absolute_import, print_function
import sys

from tests.unit.pywbemcli.testmock.wbemserver_mock_class import *  # noqa: F403

#
def _setup(conn, server, verbose):
    """
    _setup call the WBEMServerMock class to install the mock wbem server
    """
    WbemServerMock(conn, server,
                   interop_ns=None,
                   verbose=verbose)

# Execute setup depending on the version of python

if sys.version_info >= (3, 5):
    # New-style setup

    # If the function is defined directly, it will be detected and refused
    # by the check for setup() functions on Python <3.5, despite being defined
    # only conditionally. The indirect approach with exec() addresses that.
    # pylint: disable=exec-used
    exec("""
def setup(conn, server, verbose):
    _setup(conn, server, verbose)
""")

else:
    # Old-style setup

    global CONN  # pylint: disable=global-at-module-level
    global SERVER  # pylint: disable=global-at-module-level
    global VERBOSE  # pylint: disable=global-at-module-level

    # pylint: disable=undefined-variable
    _setup(CONN, SERVER, VERBOSE)  # noqa: F821
