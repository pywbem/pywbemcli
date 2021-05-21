# Copyright 2018 IBM Corp. All Rights Reserved.
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
Tests the class command
"""

from __future__ import absolute_import, print_function
import os
import pytest

from .cli_test_extensions import CLITestsBase
from .common_options_help_lines import CMD_OPTION_NAMES_ONLY_HELP_LINE, \
    CMD_OPTION_HELP_HELP_LINE, CMD_OPTION_SUMMARY_HELP_LINE, \
    CMD_OPTION_NAMESPACE_HELP_LINE

TEST_DIR = os.path.dirname(__file__)
MOCK_SERVER_MODEL_PATH = os.path.join(TEST_DIR, 'testmock',
                                      'wbemserver_mock.py')


SUBSCRIPTION_HELP_LINES = [
    'Usage: pywbemcli [COMMAND-OPTIONS] subscription COMMAND [ARGS]...',
    'Command group to manage WBEM indication subscriptions.',
    CMD_OPTION_HELP_HELP_LINE,
    'add-destinations     Add new listener destinations.',
    'add-filter           Add a new indication filter.',
    'add-subscription     Add a new indication subscription.',
    'list                 List indication subscriptions overview.',
    'list-destinations    List Indication listener destinations on the '
    'WBEM server.',
    'list-filters         List indication filters on the WBEM server.',
    'list-subscriptions   List indication subscriptions on the WBEM server.',
    'remove-destination   Delete a destination from the WBEM server.',
    'remove-filter        Delete an indication filter from the WBEM server.',
    'remove-server        Delete the server identified by the server_id.',
    'remove-subscription  Remove an indication subscription from the WBEM '
    'server.',
    'send-test-indication Generate test indications.',
]

CMD_OPTION_LISTENER_URL_LINE = "-l, --listener-url URL  Add a listener " \
    "destination url for indications."

CMD_OPTION_OWNED_LINE = "--owned   Limit the operation to owned"

SUBSCRIPTION_ADD_DESTINATIONS_HELP_LINES = [
    'Usage: pywbemcli [COMMAND-OPTIONS] subscription add-destinations',
    'Add new listener destinations.',
    CMD_OPTION_LISTENER_URL_LINE,
    CMD_OPTION_OWNED_LINE,
    CMD_OPTION_HELP_HELP_LINE,
]

SUBSCRIPTION_ADD_FILTER_HELP_LINES = [
    'Usage: pywbemcli [COMMAND-OPTIONS] subscription add-filter',
    'Add a new indication filter.',
    CMD_OPTION_HELP_HELP_LINE,
]

SUBSCRIPTION_ADD_SUBSCRIPTION_HELP_LINES = [
    'Usage: pywbemcli [GENERAL-OPTIONS] subscription add-subscription '
    'Add a new indication subscription.',
    CMD_OPTION_HELP_HELP_LINE,
]

SUBSCRIPTION_LIST_DESTINATIONS_HELP_LINES = [
    'Usage: pywbemcli [COMMAND-OPTIONS] subscription list-destinations',
    'list subscription destinations.',
    CMD_OPTION_HELP_HELP_LINE,
]

SUBSCRIPTION_LIST_FILTERS_HELP_LINES = [
    'Usage: pywbemcli [COMMAND-OPTIONS] subscription list-filters',
    'list indication filters.',
    CMD_OPTION_HELP_HELP_LINE,
]

SUBSCRIPTION_LIST_SUBSCRIPTIONS_HELP_LINES = [
    'Usage: pywbemcli [COMMAND-OPTIONS] subscription list-subscriptions',
    'list indication subscriptions.',
    CMD_OPTION_HELP_HELP_LINE,
]

SUBSCRIPTION_REMOVE_DESTINATION_HELP_LINES = [
    'Usage: pywbemcli [COMMAND-OPTIONS] subscription remove-destination',
    'remove listener destination.',
    CMD_OPTION_HELP_HELP_LINE,
]

SUBSCRIPTION_REMOVE_FILTER_HELP_LINES = [
    'Usage: pywbemcli [COMMAND-OPTIONS] subscription remove-filter',
    'remove indication filter.',
    CMD_OPTION_HELP_HELP_LINE,
]

SUBSCRIPTION_REMOVE_SUBSCRIPTION_HELP_LINES = [
    'Usage: pywbemcli [COMMAND-OPTIONS] subscription remove-subscription',
    'remove indication subscription.',
    CMD_OPTION_HELP_HELP_LINE,
]

SUBSCRIPTION_TEST_INDICATION_HELP_LINES = [
    'Usage: pywbemcli [GENERAL-OPTIONS] class test-indication '
    'METHODNAME [COMMAND-OPTIONS]',
    CMD_OPTION_HELP_HELP_LINE,
]


OK = False     # mark tests OK when they execute correctly
RUN = True    # Mark OK = False and current test case being created RUN
FAIL = False  # Any test currently FAILING or not tested yet

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

    ['Verify subscription command --help response',
     ['--help'],
     {'stdout': SUBSCRIPTION_HELP_LINES,
      'test': 'innows'},
     None, OK],

    ['Verify subscription command -h response',
     ['-h'],
     {'stdout': SUBSCRIPTION_HELP_LINES,
      'test': 'innows'},
     None, OK],

    ['Verify subscription command --help command order',
     ['--help'],
     {'stdout': r'Commands:'
                '.*\n  add-destinations'
                '.*\n  add-filter'
                '.*\n  add-subscription'
                '.*\n  list'
                '.*\n  list-destinations'
                '.*\n  list-filters'
                '.*\n  list-subscriptions'
                '.*\n  remove-destination'
                '.*\n  remove-filter'
                '.*\n  remove-server'
                '.*\n  remove-subscription'
                '.*\n  test-indication',
      'test': 'regex'},
     None, OK],


    #
    # Test help commands
    #
    ['Verify subscription command add-destination --help response',
     ['add-destination', '--help'],
     {'stdout': SUBSCRIPTION_ADD_DESTINATIONS_HELP_LINES,
      'test': 'innows'},
     None, OK],

    ['Verify subscription command add-filter --help response',
     ['add-filter', '--help'],
     {'stdout': SUBSCRIPTION_ADD_FILTER_HELP_LINES,
      'test': 'innows'},
     None, OK],

    ['Verify subscription command add-subscription --help response',
     ['add-subscription', '--help'],
     {'stdout': SUBSCRIPTION_ADD_FILTER_HELP_LINES,
      'test': 'innows'},
     None, OK],

    ['Verify subscription command list-destination --help response',
     ['list-destination', '--help'],
     {'stdout': SUBSCRIPTION_LIST_DESTINATIONS_HELP_LINES,
      'test': 'innows'},
     None, OK],

    ['Verify subscription command list-filter --help response',
     ['list-filter', '--help'],
     {'stdout': SUBSCRIPTION_LIST_FILTERS_HELP_LINES,
      'test': 'innows'},
     None, OK],

    ['Verify subscription command list-subscription --help response',
     ['list-subscription', '--help'],
     {'stdout': SUBSCRIPTION_LIST_SUBSCRIPTIONS_HELP_LINES,
      'test': 'innows'},
     None, OK],

    ['Verify subscription command remove-destination --help response',
     ['remove-destination', '--help'],
     {'stdout': SUBSCRIPTION_REMOVE_DESTINATION_HELP_LINES,
      'test': 'innows'},
     None, OK],

    ['Verify subscription command remove-filter --help response',
     ['remove-filter', '--help'],
     {'stdout': SUBSCRIPTION_REMOVE_FILTER_HELP_LINES,
      'test': 'innows'},
     None, OK],

    ['Verify subscription command remove-subscription --help response',
     ['remove-subscription', '--help'],
     {'stdout': SUBSCRIPTION_REMOVE_FILTER_HELP_LINES,
      'test': 'innows'},
     None, OK],

    ['Verify subscription command test-indication --help response',
     ['remove-subscription', '--help'],
     {'stdout': SUBSCRIPTION_TEST_INDICATION_HELP_LINES,
      'test': 'innows'},
     None, OK],

    #
    #  Create a destination and list the connection in the
    #  next command
    #
    ['Verify interactive create mock with bad file name does not fail.',
     {'connections_file_args': ('tmpconfig.yaml', None),
      'general': ['-m', MOCK_SERVER_MODEL_PATH],
      'stdin': ['subscription add-destinations -l http://someone:50000 --owned',
                '-o simple subscription list']},
     {'stdout': ['WBEM server indication instances for server_id '
                 'http://FakedUrl:5988',
                 'CIM_class                     owned    not_owned    all',
                 '--------------------------  -------  -----------  -----',
                 'CIM_IndicationSubscription        0            0      0',
                 'CIM_IndicationFilter              0            0      0',
                 'CIM_IndicationFilter              1            0      1'],
      'stderr': [],
      'test': 'innows'},
     None, RUN],

    ['Verify interactive create mock with bad file name does not fail.',
     {'connections_file_args': ('tmpconfig.yaml', None),
      'general': ['-m', MOCK_SERVER_MODEL_PATH],
      'stdin': ['subscription add-destinations -l http://someone:50000',
                'subscription add-filter -q "SELECT * from CIM_Indication '
                '--filter-id filter3 --owned',
                'subscription add-subscription --select --owned',
                '-o simple subscription list']},
     {'stdout': ['WBEM server indication instances for server_id '
                 'http://FakedUrl:5988',
                 'CIM_class                     owned    not_owned    all',
                 '--------------------------  -------  -----------  -----',
                 'CIM_IndicationSubscription        1            0      1',
                 'CIM_IndicationFilter              1            0      1',
                 'CIM_IndicationFilter              0            1      1'],
      'stderr': [],
      'test': 'innows'},
     None, FAIL],
]


class TestSubcmdClass(CLITestsBase):  # pylint: disable=too-few-public-methods
    """
    Test all of the class command variations.
    """
    command_group = 'subscription'

    @pytest.mark.parametrize(
        "desc, inputs, exp_response, mock, condition",
        TEST_CASES)
    def test_class(self, desc, inputs, exp_response, mock, condition):
        """
        Common test method for those commands and options in the
        class command that can be tested.  This includes:

          * Subcommands like help that do not require access to a server

          * Subcommands that can be tested with a single execution of a
            pywbemcli command.
        """
        self.command_test(desc, self.command_group, inputs, exp_response,
                          mock, condition)
