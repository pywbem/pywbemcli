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
Tests the commands in the server command group.
"""

from __future__ import absolute_import, print_function

import os
import pytest

from .cli_test_extensions import CLITestsBase

from .common_options_help_lines import CMD_OPTION_HELP_HELP_LINE

TEST_DIR = os.path.dirname(__file__)
SIMPLE_MOCK_FILE = 'simple_mock_model.mof'
SIMPLE_MOCK_FILE_PATH = os.path.join(TEST_DIR, SIMPLE_MOCK_FILE)

MOCK_SERVER_MODEL = os.path.join(TEST_DIR, 'testmock',
                                 'wbemserver_mock_script.py')

STATISTICS_HELP_LINES = [
    'Usage: pywbemcli [GENERAL-OPTIONS] statistics COMMAND [ARGS] '
    '[COMMAND-OPTIONS]',
    "Command group for WBEM operation statistics.",
    CMD_OPTION_HELP_HELP_LINE,
    'reset              Reset client maintained statistics.',
    'server-on          Enable server maintained statistics.',
    'server-off         Disable server maintained statistics.',
    'status             Show enabled status of client and server maintained '
    'statistics.',
    'server-show        Display server maintained statistics.',
    'show               Display client maintained statistics.',
]

STATISTICS_SERVER_ON_HELP_LINES = [
    'Usage: pywbemcli [GENERAL-OPTIONS] statistics server-on [COMMAND-OPTIONS]',
    'Enable server maintained statistics.'
]

STATISTICS_SERVER_OFF_HELP_LINES = [
    'Usage: pywbemcli [GENERAL-OPTIONS] statistics server-off '
    '[COMMAND-OPTIONS]',
    'Disable server maintained statistics.'
]

STATISTICS_STATUS_HELP_LINES = [
    'Usage: pywbemcli [GENERAL-OPTIONS] statistics status [COMMAND-OPTIONS]',
    'Show enabled status of client and server maintained statistics.'
]

STATISTICS_RESET_HELP_LINES = [
    'Usage: pywbemcli [GENERAL-OPTIONS] statistics reset [COMMAND-OPTIONS]',
    'Reset client maintained statistics.'
]

STATISTICS_SHOW_HELP_LINES = [
    'Usage: pywbemcli [GENERAL-OPTIONS] statistics show [COMMAND-OPTIONS]',
    'Display client maintained statistics.'
]

STATISTICS_SERVER_SHOW_HELP_LINES = [
    'Usage: pywbemcli [GENERAL-OPTIONS] statistics server-show '
    '[COMMAND-OPTIONS]',
    'Display server maintained statistics.'
]

OK = True     # mark tests OK when they execute correctly
RUN = True    # Mark OK = False and current test case being created RUN
FAIL = False  # Any test currently FAILING or not tested yet

TEST_CASES = [
    # List of testcases.
    # Each testcase is a list with the following items:
    # * desc: Description of testcase.
    # * inputs: String, or tuple/list of strings, or dict of 'env', 'args',
    #     'general', cmdgrp, and 'stdin'. See the 'inputs' parameter of
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

    #
    #   statistics --help
    #
    ['Verify statistics command --help response',
     {'general': [],
      'cmdgrp': 'statistics',
      'args': ['--help']},
     {'stdout': STATISTICS_HELP_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify statistics command --help response',
     {'general': [],
      'cmdgrp': 'statistics',
      'args': ['-h']},
     {'stdout': STATISTICS_HELP_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],


    ['Verify statistics command --help command order',
     {'general': [],
      'cmdgrp': 'statistics',
      'args': ['--help']},
     {'stdout': r'Commands:'
                '.*\n  reset'
                '.*\n  server-on'
                '.*\n  server-off'
                '.*\n  server-show'
                '.*\n  show'
                '.*\n  status',
      'rc': 0,
      'test': 'regex'},
     None, OK],

    #
    #  statistics commands help responses
    #
    ['Verify statistics command reset --help response',
     {'general': [],
      'cmdgrp': 'statistics',
      'args': ['reset', '--help']},
     {'stdout': STATISTICS_RESET_HELP_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify statistics command reset --help response',
     {'general': [],
      'cmdgrp': 'statistics',
      'args': ['reset', '-h']},
     {'stdout': STATISTICS_RESET_HELP_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify statistics command server-on --help response',
     {'general': [],
      'cmdgrp': 'statistics',
      'args': ['server-on', '--help']},
     {'stdout': STATISTICS_SERVER_ON_HELP_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify statistics command server-on --help response',
     {'general': [],
      'cmdgrp': 'statistics',
      'args': ['server-on', '-h']},
     {'stdout': STATISTICS_SERVER_ON_HELP_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify statistics command server-off --help response',
     {'general': [],
      'cmdgrp': 'statistics',
      'args': ['server-off', '--help']},
     {'stdout': STATISTICS_SERVER_OFF_HELP_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify statistics command server-off --help response',
     {'general': [],
      'cmdgrp': 'statistics',
      'args': ['server-off', '-h']},
     {'stdout': STATISTICS_SERVER_OFF_HELP_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],


    ['Verify statistics command server-show --help response',
     {'general': [],
      'cmdgrp': 'statistics',
      'args': ['server-show', '--help']},
     {'stdout': STATISTICS_SERVER_SHOW_HELP_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify statistics command server-show --help response',
     {'general': [],
      'cmdgrp': 'statistics',
      'args': ['server-show', '-h']},
     {'stdout': STATISTICS_SERVER_SHOW_HELP_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify statistics command show --help response',
     {'general': [],
      'cmdgrp': 'statistics',
      'args': ['show', '--help']},
     {'stdout': STATISTICS_SHOW_HELP_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify statistics command show --help response',
     {'general': [],
      'cmdgrp': 'statistics',
      'args': ['show', '-h']},
     {'stdout': STATISTICS_SHOW_HELP_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify statistics command status --help response',
     {'general': [],
      'cmdgrp': 'statistics',
      'args': ['status', '--help']},
     {'stdout': STATISTICS_STATUS_HELP_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify statistics command status --help response',
     {'general': [],
      'cmdgrp': 'statistics',
      'args': ['status', '-h']},
     {'stdout': STATISTICS_STATUS_HELP_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    # Test client statistics options against a mock environment.

    ['Verify statistics option -T against mock executes op and displays client '
     'statistics',
     {'general': ['-T'],
      'cmdgrp': 'qualifier',
      'args': ['get', 'Key']},
     {'stdout': ['Qualifier Key : boolean = false',
                 'Client statistics',
                 'Operation Count Errors',
                 'GetQualifier 1 0'],
      'rc': 0,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify statistics option --timestats with statistics reset command '
     'displays empty client statistics',
     {'general': ['--timestats'],
      'cmdgrp': 'statistics',
      'args': ['reset']},
     {'stdout': ['Client statistics',
                 'Operation Count Errors'],  # Not perfect: Not verifying empty
      'rc': 0,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify statistics option --timestats against mock executes op and '
     'displays client statistics',
     {'general': ['--timestats'],
      'cmdgrp': 'qualifier',
      'args': ['get', 'Key']},
     {'stdout': ['Qualifier Key : boolean = false',
                 'Client statistics',
                 'Operation Count Errors',
                 'GetQualifier 1 0'],
      'rc': 0,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify statistics option --no-timestats against mock executes op and '
     'displays no statistics',
     {'general': ['--no-timestats'],
      'cmdgrp': 'qualifier',
      'args': ['get', 'Key']},
     {'stdout': ['GetQualifier 1 0'],
      'rc': 0,
      'test': 'not-innows'},
     SIMPLE_MOCK_FILE, OK],


    ['Verify statistics option -T against mock executes op and displays '
     'client statistics',
     {'general': ['-T'],
      'cmdgrp': 'qualifier',
      'args': ['get', 'Key']},
     {'stdout': ['Qualifier Key : boolean = false',
                 'Client statistics',
                 'Operation Count Errors',
                 'GetQualifier 1 0'],
      'rc': 0,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify Statistics status statistics off',
     {'general': [],
      'cmdgrp': 'statistics',
      'args': ['status']},
     {'stdout': [],
      'stderr': ['Error: Server connection failed'],
      'rc': 1,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify use of statistis reset.',
     {'general': ['--mock-server', SIMPLE_MOCK_FILE_PATH],
      # args not allowed in interactive mode
      'stdin': ['class enumerate --di --no',
                'class enumerate --di --no',
                'statistics reset',
                'class enumerate --di --no',
                'statistics show', ],
      'cmdgrp': None,
      },
     {'stdout': [r'EnumerateClassNames +1 '],
      'rc': 0,
      'test': 'regex'},
     None, OK],

    ['Verify use of statistis reset does not disable statistics display.',
     {'general': ['--mock-server', SIMPLE_MOCK_FILE_PATH],
      # Should show statistics with count of 2 and with count of 1
      'stdin': ['class enumerate  --di --no',
                'class enumerate  --di --no',
                'statistics show',
                'statistics reset',
                'class enumerate  --di --no',
                'statistics show'],
      'cmdgrp': None,
      },
     {'stdout': [r'EnumerateClassNames +2 ',
                 r'EnumerateClassNames +1 '],
      'rc': 0,
      'test': 'regex'},
     None, OK],

    # NOTE: The following 4 tests do not enable statistics to keep
    # the results simple
    ['Verify Statistics server-on against mock executes op server-on',
     {'general': [],
      'cmdgrp': 'statistics',
      'args': ['server-on']},
     {'stdout': ['Server statistics gathering set to on'],
      'rc': 0,
      'test': 'innows'},
     MOCK_SERVER_MODEL, OK],

    ['Verify Statistics  server-off against mock executes',
     {'general': [],
      'cmdgrp': 'statistics',
      'args': ['server-on']},
     {'stdout': ['Server statistics gathering set to on'],
      'rc': 0,
      'test': 'innows'},
     MOCK_SERVER_MODEL, OK],

    ['Verify Statistics status against mock executes',
     {'general': ['--output-format', 'text'],
      'cmdgrp': 'statistics',
      'args': ['status']},
     {'stdout': ['Statistics status: client=off; server=off'],
      'rc': 0,
      'test': 'innows'},
     MOCK_SERVER_MODEL, OK],

    ['Verify Statistics auto option against mock multiple statistics cmds',
     {'general': ['--output-format', 'text'],
      'cmdgrp': 'statistics',
      'args': ['status']},
     {'stdout': ['Statistics status: client=off; server=off'],
      'rc': 0,
      'test': 'innows'},
     MOCK_SERVER_MODEL, OK],

    ['Verify Statistics against mock multiple statistics on/off/status cmds '
     'output-format text',
     {'general': ['--output-format', 'text'],
      'stdin': ['statistics server-on',
                'statistics status',
                'statistics server-off',
                'statistics status',
                '-T statistics status']},
     {'stdout': ['Server statistics gathering set to on',
                 'Statistics status: client=off; server=on',
                 'Server statistics gathering set to off',
                 'Statistics status: client=off; server=off',
                 'Statistics status: client=off; server=off',
                 'Statistics status: client=on; server=off'],
      'rc': 0,
      'test': 'innows'},
     MOCK_SERVER_MODEL, OK],


    ['Verify Statistics status default output format (table)',
     {'general': ['--output-format', 'table', '-T'],
      'stdin': ['statistics server-on',
                'statistics status']},
     {'stdout': ['Server statistics gathering set to on',
                 'Statistics status',
                 'Item                         Status',
                 '---------------------------  --------',
                 'client statistics display    on',
                 'server statistics gathering  on'],
      'rc': 0,
      'test': 'innows'},
     MOCK_SERVER_MODEL, OK],

    ['Verify Statistics server-show displays table',
     {'general': ['--output-format', 'simple'],
      'stdin': ['statistics server-on',
                'server add-mof '
                'tests/unit/pywbemcli/cimstatisticaldatainstances.mof '
                '-n interop',
                'statistics server-show']},
     {'stdout': ['Server statistics',
                 'Operation Count',
                 'EnumerateInstances',
                 'GetClass'],
      'rc': 0,
      'test': 'innows'},
     MOCK_SERVER_MODEL, OK],


    # TODO tests not done
    # 1. Tests against a real server that returns statistics to show
    #    the server times in the table.
    # 2. Test of statistics commands with no current server (Should fail).
    #    We need to set our own server definitions file to be sure there
    #    is no default connection definition
    # 3. Tests for server that has no CIM_ObjectManager class, or the
    #    GatherStatisticalData property, or the property is not
    #    modifiable.

]


class TestSubcmd(CLITestsBase):  # pylint: disable=too-few-public-methods
    """
    Test all of the instance command variations.
    """
    @pytest.mark.parametrize(
        "desc, inputs, exp_response, mock, condition", TEST_CASES)
    def test_execute_pywbemcli(self, desc, inputs, exp_response, mock,
                               condition):
        """
        Execute pybemcli with the defined input and test output.
        """
        cmd_grp = inputs['cmdgrp'] if 'cmdgrp' in inputs else ''
        self.command_test(desc, cmd_grp, inputs, exp_response,
                          mock, condition)
