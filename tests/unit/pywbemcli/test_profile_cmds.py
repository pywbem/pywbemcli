# Copyright 2020 IBM Corp. All Rights Reserved.
# (C) Copyright 2017 Inova Development Inc.
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
Tests the profile command group
"""

from __future__ import absolute_import, print_function

import os
import pytest

from .cli_test_extensions import CLITestsBase
from .common_options_help_lines import CMD_OPTION_HELP_HELP_LINE

TEST_DIR = os.path.dirname(__file__)

# A mof file that defines basic qualifier decls, classes, and instances
# but not tied to the DMTF classes.
SIMPLE_MOCK_FILE = 'simple_mock_model.mof'
INVOKE_METHOD_MOCK_FILE = 'simple_mock_invokemethod.py'

MOCK_SERVER_MODEL = os.path.join(TEST_DIR, 'testmock',
                                 'wbemserver_mock_script.py')

# The following lists define the help for each command in terms of particular
# parts of lines that are to be tested.
# For each list, try to include:
# 1. The usage line and in particular the argument component
# 2. The first line of the command comment (i.e. the summary sentence)
# 3. The last line CMD_OPTION_HELP_HELP_LINE
# 4. Each option including at least the long and short names

PROFILE_HELP_LINES = [
    'Usage: pywbemcli [GENERAL-OPTIONS] profile COMMAND [ARGS] '
    '[COMMAND-OPTIONS]',
    'Command group for WBEM management profiles.',
    CMD_OPTION_HELP_HELP_LINE,
    'list          List WBEM management profiles advertised by the server.',
    'centralinsts  List WBEM management profile central instances on the '
    ' server',
]

PROFILE_LIST_HELP_LINES = [
    'Usage: pywbemcli [GENERAL-OPTIONS] profile list [COMMAND-OPTIONS]',
    'List WBEM management profiles advertised by the server.',
    "-o, --organization ORG-NAME  Filter by the defined organization.",
    "-p, --profile PROFILE-NAME   Filter by the profile name",
    CMD_OPTION_HELP_HELP_LINE,
]

PROFILE_CENTRAL_INSTS_HELP_LINES = [
    'Usage: pywbemcli [GENERAL-OPTIONS] profile centralinsts  '
    '[COMMAND-OPTIONS]',
    'List WBEM management profile central instances on the server',
    '-o, --organization ORG-NAME Filter by the defined organization',
    '-p, --profile PROFILE-NAME Filter by the profile name',
    '--cc, --central-class CLASSNAME Optional. Required only if profiles',
    '--sc, --scoping-class CLASSNAME Optional. Required only if profiles',
    '--sp, --scoping-path CLASSLIST Optional. Required only if profiles',
    '--rd, --reference-direction [snia|dmtf] Navigation direction',
    CMD_OPTION_HELP_HELP_LINE,
]


OK = True  # mark tests OK when they execute correctly
RUN = True  # Mark OK = False and current test case being created RUN
FAIL = False  # Any test currently FAILING or not tested yet

# pylint: enable=line-too-long
TEST_CASES = [

    # List of testcases.
    # Each testcase is a list with the following items:
    # * desc: Description of testcase.
    # * inputs: String, or tuple/list of strings, or dict of 'env', 'args',
    #     'general', and 'stdin'. See the 'inputs' parameter of
    #     CLITestsBase.command_test() in cli_test_extensions.py for detailed
    #     documentation.
    # * exp_response: Dictionary of expected responses (stdout, stderr, rc) and
    #     test definition (test: <testname>). See the 'exp_response' parameter
    #     of CLITestsBase.command_test() in cli_test_extensions.py for
    #     detailed documentation.
    # * mock: None, name of file (.mof or .py), or list thereof.
    # * condition: If True the test is executed, if 'pdb' the test breaks in the
    #     the debugger, if 'verbose' print verbose messages, if False the test
    #     is skipped.

    ['Verify profile command --help response',
     '--help',
     {'stdout': PROFILE_HELP_LINES,
      'test': 'innows'},
     None, OK],

    ['Verify profile command -h response',
     '-h',
     {'stdout': PROFILE_HELP_LINES,
      'test': 'innows'},
     None, OK],

    ['Verify profile list --help response',
     ['list', '--help'],
     {'stdout': PROFILE_LIST_HELP_LINES,
      'test': 'innows'},
     None, OK],

    ['Verify server command profiles -h response',
     ['list', '-h'],
     {'stdout': PROFILE_LIST_HELP_LINES,
      'test': 'innows'},
     None, OK],


    ['Verify server command get-centralinsts  --help response',
     ['centralinsts', '--help'],
     {'stdout': PROFILE_CENTRAL_INSTS_HELP_LINES,
      'test': 'innows'},
     None, OK],

    ['Verify server command centralinsts  -h response',
     ['centralinsts', '-h'],
     {'stdout': PROFILE_CENTRAL_INSTS_HELP_LINES,
      'test': 'innows'},
     None, OK],

    ['Verify server command profiles',
     {'args': ['list'],
      'general': ['-o', 'simple']},
     {'stdout': ['Advertised management profiles:',
                 'Organization    Registered Name       Version',
                 '--------------  --------------------  ---------',
                 'DMTF            Component             1.4.0',
                 'DMTF            Indications           1.1.0',
                 'DMTF            Profile Registration  1.0.0',
                 'SNIA            Array                 1.4.0',
                 'SNIA            SMI-S                 1.2.0',
                 'SNIA            Server                1.1.0',
                 'SNIA            Server                1.2.0',
                 'SNIA            Software              1.4.0'],
      'rc': 0,
      'test': 'innows'},
     MOCK_SERVER_MODEL, OK],

    ['Verify server command profiles, filtered by org',
     {'args': ['list', '-o', 'DMTF'],
      'general': ['-o', 'simple']},
     {'stdout': ['Advertised management profiles: org=DMTF',
                 'Organization    Registered Name       Version',
                 '--------------  --------------------  ---------',
                 'DMTF            Component             1.4.0',
                 'DMTF            Indications           1.1.0',
                 'DMTF            Profile Registration  1.0.0'],
      'rc': 0,
      'test': 'innows'},
     MOCK_SERVER_MODEL, OK],

    ['Verify server command profiles, filtered by org, long',
     {'args': ['list', '--organization', 'DMTF'],
      'general': ['-o', 'simple']},
     {'stdout': ['Advertised management profiles: org=DMTF',
                 'Organization    Registered Name       Version',
                 '--------------  --------------------  ---------',
                 'DMTF            Component             1.4.0',
                 'DMTF            Indications           1.1.0',
                 'DMTF            Profile Registration  1.0.0'],
      'rc': 0,
      'test': 'innows'},
     MOCK_SERVER_MODEL, OK],

    ['Verify server command profiles, filtered by org, and name',
     {'args': ['list', '--organization', 'DMTF', '--profile', 'Component'],
      'general': ['-o', 'plain']},
     {'stdout': ['Advertised management profiles: org=DMTF name=Component',
                 'Organization    Registered Name       Version',
                 'DMTF            Component             1.4.0'],
      'rc': 0,
      'test': 'innows'},
     MOCK_SERVER_MODEL, OK],

    ['Verify server command profiles, filtered by name',
     {'args': ['list', '-p', 'Profile Registration'],
      'general': ['-o', 'simple']},
     {'stdout': ['Advertised management profiles:',
                 'Organization    Registered Name       Version',
                 '--------------  --------------------  ---------',
                 'DMTF            Profile Registration  1.0.0'],
      'rc': 0,
      'test': 'innows'},
     MOCK_SERVER_MODEL, OK],

    ['Verify server command profiles, filtered by org, long',
     {'args': ['list', '--profile', 'Profile Registration'],
      'general': ['-o', 'simple']},
     {'stdout': ['Advertised management profiles:',
                 'Organization    Registered Name       Version',
                 '--------------  --------------------  ---------',
                 'DMTF            Profile Registration  1.0.0'],
      'rc': 0,
      'test': 'innows'},
     MOCK_SERVER_MODEL, OK],

    ['Verify server command centralinsts based on wbem server mock.',
     {'args': ['centralinsts', '-o', 'SNIA',
               '-p', 'Server'],
      'general': ['-o', 'simple']},
     {'stdout': ['Advertised Central Instances:',
                 'Profile',
                 'Central Instance paths',
                 'SNIA:Server:1.1.0',
                 'SNIA:Server:1.2.0',
                 'root/cimv2:MCK_StorageComputerSystem'],
      'rc': 0,
      'test': 'innows'},
     MOCK_SERVER_MODEL, OK],

]


class TestSubcmdServer(CLITestsBase):
    """
    Execute the testcases for server command variations.
    """
    command_group = 'profile'

    @pytest.mark.parametrize(
        "desc, inputs, exp_response, mock, condition",
        TEST_CASES)
    def test_class(self, desc, inputs, exp_response, mock, condition):
        """
        Common test method for those commands and options in the
        class subcmd that can be tested.  This includes:

          * Subcommands like help that do not require access to a server

          * Subcommands that can be tested with a single execution of a
            pywbemcli command.
        """
        self.command_test(desc, self.command_group, inputs, exp_response,
                          mock, condition)
