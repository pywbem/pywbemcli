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
Tests the server command group
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

# The empty mock model is used to ensure that the new model that is added does
# not modify any existing elements in the repository.
EMPTY_MOCK_MODEL = 'empty_mock_model.mof'

SIMPLE_MOCK_MODEL = 'simple_mock_model.mof'
SIMPLE_MOCK_MODEL_FILEPATH = os.path.join(
    os.path.dirname(__file__), SIMPLE_MOCK_MODEL)
SIMPLE_MOCK_MODEL_FILEPATH_REL = os.path.relpath(SIMPLE_MOCK_MODEL_FILEPATH)
with open(SIMPLE_MOCK_MODEL_FILEPATH, 'r') as fp:
    SIMPLE_MOCK_MODEL_CONTENT = fp.read()

MOF_WITH_ERROR_FILEPATH = os.path.join(
    os.path.dirname(__file__), 'mof_with_error.mof')

QUALIFIER_FILTER_MODEL = "qualifier_filter_model.mof"

# The following lists define the help for each command in terms of particular
# parts of lines that are to be tested.
# For each list, try to include:
# 1. The usage line and in particular the argument component
# 2. The first line of the command comment (i.e. the summary sentence)
# 3. The last line CMD_OPTION_HELP_HELP_LINE
# 4. Each option including at least the long and short names

SERVER_HELP_LINES = [
    'Usage: pywbemcli [GENERAL-OPTIONS] server COMMAND [ARGS] '
    '[COMMAND-OPTIONS]',
    'Command group for WBEM servers.',
    CMD_OPTION_HELP_HELP_LINE,
    'brand             Get the brand of the server.',
    'info              Get information about the server.',
    'interop           Get the Interop namespace of the server (deprecated).',
    'namespaces        List the namespaces of the server (deprecated).',
    'add-mof           Compile MOF and add/update CIM objects in the server.',
    'remove-mof        Compile MOF and remove CIM objects from the server.',
    'schema            Get information about the server schemas.'
]

SERVER_BRAND_HELP_LINES = [
    'Usage: pywbemcli [GENERAL-OPTIONS] server brand',
    'Get the brand of the server.',
    CMD_OPTION_HELP_HELP_LINE,
]

SERVER_INFO_HELP_LINES = [
    'Usage: pywbemcli [GENERAL-OPTIONS] server info [COMMAND-OPTIONS]',
    'Get information about the server.',
    CMD_OPTION_HELP_HELP_LINE,
]

SERVER_INTEROP_HELP_LINES = [
    'Usage: pywbemcli [GENERAL-OPTIONS] server interop [COMMAND-OPTIONS]',
    'Get the Interop namespace of the server (deprecated).',
    CMD_OPTION_HELP_HELP_LINE,
]

SERVER_NAMESPACES_HELP_LINES = [
    'Usage: pywbemcli [GENERAL-OPTIONS] server namespaces [COMMAND-OPTIONS]',
    'List the namespaces of the server (deprecated)',
    CMD_OPTION_HELP_HELP_LINE,
]

SERVER_SCHEMA_HELP_LINES = [
    'Usage: pywbemcli [GENERAL-OPTIONS] server schema [COMMAND-OPTIONS]',
    'Get information about the server schemas.',
    '-n, --namespace NAMESPACE  Namespace to use for this command, instead',
    '-d, --detail               Display details about each schema in the',
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

    ['Verify server command --help response',
     '--help',
     {'stdout': SERVER_HELP_LINES,
      'test': 'innows'},
     None, OK],

    ['Verify server command -h response',
     '-h',
     {'stdout': SERVER_HELP_LINES,
      'test': 'innows'},
     None, OK],

    ['Verify server command brand  --help response',
     ['brand', '--help'],
     {'stdout': SERVER_BRAND_HELP_LINES,
      'test': 'innows'},
     None, OK],

    ['Verify server command brand  -h response',
     ['brand', '-h'],
     {'stdout': SERVER_BRAND_HELP_LINES,
      'test': 'innows'},
     None, OK],

    ['Verify server command info --help response',
     ['info', '--help'],
     {'stdout': SERVER_INFO_HELP_LINES,
      'test': 'innows'},
     None, OK],

    ['Verify server command info -h response',
     ['info', '-h'],
     {'stdout': SERVER_INFO_HELP_LINES,
      'test': 'innows'},
     None, OK],

    ['Verify server command interop --help response',
     ['interop', '--help'],
     {'stdout': SERVER_INTEROP_HELP_LINES,
      'test': 'innows'},
     None, OK],

    ['Verify server command interop -h response',
     ['interop', '-h'],
     {'stdout': SERVER_INTEROP_HELP_LINES,
      'test': 'innows'},
     None, OK],

    ['Verify server command namespaces --help response',
     ['namespaces', '--help'],
     {'stdout': SERVER_NAMESPACES_HELP_LINES,
      'test': 'innows'},
     None, OK],

    ['Verify server command namespaces -h response',
     ['namespaces', '-h'],
     {'stdout': SERVER_NAMESPACES_HELP_LINES,
      'test': 'innows'},
     None, OK],

    ['Verify server command schema --help response',
     ['schema', '--help'],
     {'stdout': SERVER_SCHEMA_HELP_LINES,
      'test': 'innows'},
     None, OK],

    ['Verify server command schema -h response',
     ['schema', '-h'],
     {'stdout': SERVER_SCHEMA_HELP_LINES,
      'test': 'innows'},
     None, OK],

    #
    #   Verify the individual commands returning data
    #
    ['Verify server command interop default output',
     {'args': ['interop'], },
     {'stdout': ['interop'],
      'rc': 0,
      'test': 'innows'},
     MOCK_SERVER_MODEL, OK],

    ['Verify server command interop',
     {'args': ['interop'],
      'general': ['-o', 'text']},
     {'stdout': ['interop'],
      'rc': 0,
      'test': 'innows'},
     MOCK_SERVER_MODEL, OK],

    ['Verify server command namespaces',
     {'args': ['namespaces'],
      'general': ['-o', 'simple']},
     {'stdout': ['Namespace Name',
                 '----------------',
                 'interop',
                 'root/cimv2'],
      'rc': 0,
      'test': 'lines'},
     MOCK_SERVER_MODEL, OK],

    ['Verify server command namespaces, text output',
     {'args': ['namespaces'],
      'general': ['-o', 'text']},
     {'stdout': ['interop', 'root/cimv2'],
      'rc': 0,
      'test': 'lines'},
     MOCK_SERVER_MODEL, OK],

    ['Verify server command namespaces with sort option',
     {'args': ['namespaces'], },
     {'stdout': ['interop'],
      'rc': 0,
      'test': 'innows'},
     MOCK_SERVER_MODEL, OK],

    ['Verify server command brand',
     {'args': ['brand'], },
     {'stdout': ['OpenPegasus'],
      'rc': 0,
      'test': 'innows'},
     MOCK_SERVER_MODEL, OK],

    ['Verify server command brand with --output table fails',
     {'args': ['brand'],
      'general': ['-o', 'simple']},
     {'stderr': ['Output format "simple" not allowed for this command'],
      'rc': 1,
      'test': 'innows'},
     MOCK_SERVER_MODEL, OK],

    ['Verify server command info with mock server',
     {'args': ['info'],
      'general': ['-o', 'simple']},
     {'stdout':
      ['Server General Information',
       'Brand        Version    Interop Namespace    Namespaces',
       '-----------  ---------  -------------------  -------------------',
       'OpenPegasus  2.15.0     interop              interop, root/cimv2'],
      'rc': 0,
      'test': 'linesnows'},
     MOCK_SERVER_MODEL, OK],

    # MOF compile commands

    ['Verify server command add-mof of same mock file fails',
     {'args': ['add-mof', SIMPLE_MOCK_MODEL_FILEPATH],
      'general': []},
     {'stdout': ["Class 'CIM_BaseRef' namespace 'root/cimv2' cannot be "
                 "modified because it has subclasses"],
      'rc': 1,
      'test': 'regex'},
     SIMPLE_MOCK_MODEL, OK],

    ['Verify server command add-mof of new mock file with abs path',
     {'args': ['add-mof', SIMPLE_MOCK_MODEL_FILEPATH],
      'general': []},
     {'stdout':
      [],
      'rc': 0,
      'test': 'innows'},
     EMPTY_MOCK_MODEL, OK],

    ['Verify server command add-mof of new mock file with rel path',
     {'args': ['add-mof', SIMPLE_MOCK_MODEL_FILEPATH_REL],
      'general': []},
     {'stdout':
      [],
      'rc': 0,
      'test': 'innows'},
     EMPTY_MOCK_MODEL, OK],

    ['Verify server command add-mof of new mock file with --include rel',
     {'args': ['add-mof', SIMPLE_MOCK_MODEL_FILEPATH, '--include', '.'],
      'general': []},
     {'stdout':
      [],
      'rc': 0,
      'test': 'innows'},
     EMPTY_MOCK_MODEL, OK],

    ['Verify server command add-mof of new mock file with --include abs',
     {'args': ['add-mof', SIMPLE_MOCK_MODEL_FILEPATH, '--include', os.getcwd()],
      'general': []},
     {'stdout':
      [],
      'rc': 0,
      'test': 'innows'},
     EMPTY_MOCK_MODEL, OK],

    ['Verify server command add-mof of same mock file with --dry-run',
     {'args': ['add-mof', SIMPLE_MOCK_MODEL_FILEPATH, '--dry-run'],
      'general': []},
     {'stdout':
      ['Executing in dry-run mode'],
      'rc': 0,
      'test': 'innows'},
     SIMPLE_MOCK_MODEL, OK],

    ['Verify server command add-mof of new mock file with --verbose',
     {'args': ['add-mof', SIMPLE_MOCK_MODEL_FILEPATH],
      'general': ['--verbose']},
     {'stdout':
      ['Setting qualifier root/cimv2:Key',
       'Creating class root/cimv2:CIM_Foo',
       'Creating instance of class root/cimv2:CIM_Foo'],
      'rc': 0,
      'test': 'innows'},
     EMPTY_MOCK_MODEL, OK],

    ['Verify server command add-mof of same mock file with --dry-run and '
     '--verbose',
     {'args': ['add-mof', SIMPLE_MOCK_MODEL_FILEPATH, '--dry-run'],
      'general': ['--verbose']},
     {'stdout':
      ['Setting qualifier root/cimv2:Key',
       'Creating class root/cimv2:CIM_Foo',
       'Creating instance of class root/cimv2:CIM_Foo'],
      'rc': 0,
      'test': 'innows'},
     SIMPLE_MOCK_MODEL, OK],

    ['Verify server command add-mof of new mock file with --verbose via '
     'stdin',
     {'args': ['server', 'add-mof', '-'],
      'general': ['--verbose'],
      'stdin': SIMPLE_MOCK_MODEL_CONTENT},
     {'stdout':
      ['Setting qualifier root/cimv2:Key',
       'Creating class root/cimv2:CIM_Foo',
       'Creating instance of class root/cimv2:CIM_Foo'],
      'rc': 0,
      'test': 'innows'},
     EMPTY_MOCK_MODEL, OK],

    ['Verify server command add-mof of invalid MOF file',
     {'args': ['add-mof', MOF_WITH_ERROR_FILEPATH],
      'general': ['--verbose']},
     {'stdout':
      ['MOF grammar error'],
      'rc': 1,
      'test': 'innows'},
     SIMPLE_MOCK_MODEL, OK],

    ['Verify server command remove-mof of same mock file with abs path',
     {'args': ['remove-mof', SIMPLE_MOCK_MODEL_FILEPATH],
      'general': []},
     {'stdout':
      [],
      'rc': 0,
      'test': 'innows'},
     SIMPLE_MOCK_MODEL, OK],

    ['Verify server command remove-mof of same mock file with rel path',
     {'args': ['remove-mof', SIMPLE_MOCK_MODEL_FILEPATH_REL],
      'general': []},
     {'stdout':
      [],
      'rc': 0,
      'test': 'innows'},
     SIMPLE_MOCK_MODEL, OK],

    ['Verify server command remove-mof of same mock file with --include rel',
     {'args': ['remove-mof', SIMPLE_MOCK_MODEL_FILEPATH, '--include', '.'],
      'general': []},
     {'stdout':
      [],
      'rc': 0,
      'test': 'innows'},
     SIMPLE_MOCK_MODEL, OK],

    ['Verify server command remove-mof of same mock file with --include abs',
     {'args': ['remove-mof', SIMPLE_MOCK_MODEL_FILEPATH, '--include',
               os.getcwd()],
      'general': []},
     {'stdout':
      [],
      'rc': 0,
      'test': 'innows'},
     SIMPLE_MOCK_MODEL, OK],

    ['Verify server command remove-mof of same mock file with --dry-run',
     {'args': ['remove-mof', SIMPLE_MOCK_MODEL_FILEPATH, '--dry-run'],
      'general': []},
     {'stdout':
      ['Executing in dry-run mode'],
      'rc': 0,
      'test': 'innows'},
     SIMPLE_MOCK_MODEL, OK],

    ['Verify server command remove-mof of same mock file with --verbose',
     {'args': ['remove-mof', SIMPLE_MOCK_MODEL_FILEPATH],
      'general': ['--verbose']},
     {'stdout':
      ['Deleting instance root/cimv2:CIM_Foo.InstanceID="CIM_Foo1"',
       'Deleting class root/cimv2:CIM_Foo'],
      'rc': 0,
      'test': 'innows'},
     SIMPLE_MOCK_MODEL, OK],

    ['Verify server command remove-mof of same mock file with --dry-run and '
     '--verbose',
     {'args': ['remove-mof', SIMPLE_MOCK_MODEL_FILEPATH, '--dry-run'],
      'general': ['--verbose']},
     {'stdout':
      ['No deletions will be shown in dry-run mode'],
      'rc': 0,
      'test': 'innows'},
     SIMPLE_MOCK_MODEL, OK],

    ['Verify server command remove-mof of same mock file with --verbose via '
     'stdin',
     {'args': ['server', 'remove-mof', '-'],
      'general': ['--verbose'],
      'stdin': SIMPLE_MOCK_MODEL_CONTENT},
     {'stdout':
      ['Deleting instance root/cimv2:CIM_Foo.InstanceID="CIM_Foo1"',
       'Deleting class root/cimv2:CIM_Foo'],
      'rc': 0,
      'test': 'innows'},
     SIMPLE_MOCK_MODEL, OK],

    ['Verify server command remove-mof of invalid MOF file',
     {'args': ['remove-mof', MOF_WITH_ERROR_FILEPATH],
      'general': ['--verbose']},
     {'stdout':
      ['MOF grammar error'],
      'rc': 1,
      'test': 'innows'},
     SIMPLE_MOCK_MODEL, OK],

    ['Verify server command schema with -n namespace of simple mock model',
     {'args': ['schema', '-n', 'root/cimv2'],
      'general': []},
     {'stdout': ['Schema information; namespaces: root/cimv2;',
                 'Namespace    schemas      classes  CIM schema  experimental',
                 '                            count  version',
                 'root/cimv2   CIM               12      ', ],
      'rc': 0,
      'test': 'innows'},
     SIMPLE_MOCK_MODEL, OK],

    ['Verify server command schema with mock_wbem_server',
     {'args': ['schema'],
      'general': []},
     {'stdout': ['Schema information; namespaces: all;',
                 'Namespace    schemas      classes  CIM schema  experimental',
                 '                            count  version',
                 'interop      CIM, PG           24  2. 45. 0   ',
                 'root/cimv2   CIM, MCK          15  2. 45. 0   '],
      'rc': 0,
      'test': 'innows'},
     MOCK_SERVER_MODEL, OK],

    ['Verify server command schema with mock_wbem_server & --namespace interop',
     {'args': ['schema'],
      'general': []},
     {'stdout': ['Schema information; namespaces: all;',
                 'Namespace    schemas      classes  CIM schema  experimental',
                 '                            count  version',
                 'interop      CIM, PG           24  2. 45. 0   ', ],
      'rc': 0,
      'test': 'innows'},
     MOCK_SERVER_MODEL, OK],

    ['Verify server command schema with mock_wbem_server and --detail',
     {'args': ['schema', '--detail'],
      'general': []},
     {'stdout': ['Schema information; detail; namespaces: all;',
                 'Namespace    schemas      classes  schema  experimental',
                 '                            count  version ',
                 'interop     CIM               23  2.45.0  ',
                 '            PG                 1      ',
                 'root/cimv2  CIM               14  2.45.0   ',
                 '            MCK                1     '],
      'rc': 0,
      'test': 'innows'},
     MOCK_SERVER_MODEL, OK],

    ['Verify server command schema with qualifier filter model',
     {'args': ['schema'],
      'general': []},
     {'stdout': ['Schema information; namespaces: all;',
                 'Namespace    schemas      classes  CIM schema  experimental',
                 '                            count  version',
                 'root/cimv2   BLA, EXP, TST  20           Experimental'],
      'rc': 0,
      'test': 'innows'},
     QUALIFIER_FILTER_MODEL, OK],

    ['Verify server command schema with qualifier filter model --detail',
     {'args': ['schema', '--detail'],
      'general': []},
     {'stdout': ['Schema information; detail; namespaces: all;',
                 'Namespace    schemas      classes  schema  experimental',
                 '                            count  version ',
                 'root/cimv2   BLA                1  2.51.0 ',
                 '             EXP                4  2.3.0    Experimental',
                 '             TST               15  2.43.0   Experimental'],
      'rc': 0,
      'test': 'innows'},
     QUALIFIER_FILTER_MODEL, OK],



]


class TestSubcmdServer(CLITestsBase):
    """
    Execute the testcases for server command variations.
    """
    command_group = 'server'

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
