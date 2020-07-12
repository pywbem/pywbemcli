#!/usr/bin/env python

# (C) Copyright 2017 IBM Corp.
# (C) Copyright 2017 Inova Development Inc.
# All Rights Reserved
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
Tests for _contest_obj functions and classes
"""

from __future__ import absolute_import, print_function

import unittest

from pywbemtools.pywbemcli._context_obj import ContextObj
from pywbemtools.pywbemcli._pywbem_server import PywbemServer


class ContextObjTests(unittest.TestCase):
    """Test the click context object class"""

    def simple_test(self):
        """Test create context object"""

        server = 'http://localhost'
        ns = 'root/cimv2'
        user = 'Fred'
        pw = 'blah'
        svr = PywbemServer(server, ns, user=user, password=pw)

        output_format = 'mof'
        use_pull = 'either'
        pull_max_cnt = 100
        timestats = False
        log = 'all'
        verbose = True
        pdb = False
        deprecation_warnings = False
        connections_repo = None

        ctxobj = ContextObj(
            pywbem_server=svr,
            output_format=output_format,
            use_pull=use_pull,
            pull_max_cnt=pull_max_cnt,
            timestats=timestats,
            log=log,
            verbose=verbose,
            pdb=pdb,
            deprecation_warnings=deprecation_warnings,
            connections_repo=connections_repo)

        self.assertEqual(ctxobj.pywbem_server, svr)


if __name__ == '__main__':
    unittest.main()
