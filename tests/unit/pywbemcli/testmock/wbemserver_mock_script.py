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

This script has the DMTF model itself as a dependent but we are not
registering the pieces of the model as a dependent because we don't really
know what changes in the model.
"""

from __future__ import absolute_import, print_function

import os
import sys

from tests.unit.pywbemcli.testmock.wbemserver_mock_class import \
    WbemServerMock  # noqa: F403


def _setup(conn, server, verbose):
    # pylint: disable=unused-argument
    """
    Setup for this mock script.

    Parameters:
      conn (FakedWBEMConnection): Connection
      server (PywbemServer): Server
      verbose (bool): Verbose flag
    """
    if sys.version_info >= (3, 5):
        this_file_path = __file__
    else:
        # Unfortunately, it does not seem to be possible to find the file path
        # of the current script when it is executed using exec(), so we hard
        # code the file path. This requires that the tests are run from the
        # repo main directory.
        this_file_path = 'tests/unit/pywbemcli/simple_interop_mock_script.py'
        assert os.path.exists(this_file_path)
    fn = "wbemserver_mock_class.py"
    dep_path = os.path.join(os.path.dirname(this_file_path), fn)
    conn.provider_dependent_registry.add_dependents(this_file_path, dep_path)

    WbemServerMock(conn, server, verbose=verbose)


if sys.version_info >= (3, 5):
    # New-style setup

    # If the function is defined directly, it will be detected and refused
    # by the check for setup() functions on Python <3.5, despite being defined
    # only conditionally. The indirect approach with exec() addresses that.
    # pylint: disable=exec-used
    exec("""
def setup(conn, server, verbose):
    _setup(conn, server, verbose=verbose)
""")

else:
    # Old-style setup
    # pylint: disable=undefined-variable

    global CONN  # pylint: disable=global-at-module-level
    global SERVER  # pylint: disable=global-at-module-level
    global VERBOSE  # pylint: disable=global-at-module-level

    # pylint: disable=undefined-variable
    _setup(CONN, SERVER, VERBOSE)  # noqa: F821, F405
