# Copyright 2017 IBM Corp. All Rights Reserved.
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
from packaging.version import parse as parse_version
import pytest
from pywbem import __version__ as pywbem_version

from .cli_test_extensions import CLITestsBase, FAKEURL_STR, PYWBEM_0

from .common_options_help_lines import CMD_OPTION_NAMES_ONLY_HELP_LINE, \
    CMD_OPTION_HELP_HELP_LINE, CMD_OPTION_SUMMARY_HELP_LINE, \
    CMD_OPTION_NAMESPACE_HELP_LINE, CMD_OPTION_PROPERTYLIST_HELP_LINE, \
    CMD_OPTION_INCLUDE_CLASSORIGIN_HELP_LINE, CMD_OPTION_VERIFY_HELP_LINE, \
    CMD_OPTION_INCLUDE_QUALIFIERS_LIST_HELP_LINE, \
    CMD_OPTION_INCLUDE_QUALIFIERS_GET_HELP_LINE, \
    CMD_OPTION_FILTER_QUERY_LINE, \
    CMD_OPTION_FILTER_QUERY_LANGUAGE_LINE, \
    CMD_OPTION_LOCAL_ONLY_INSTANCE_LIST_HELP_LINE, \
    CMD_OPTION_LOCAL_ONLY_INSTANCE_GET_HELP_LINE, \
    CMD_OPTION_MULTIPLE_NAMESPACE_HELP_LINE, \
    CMD_OPTION_KEYS_HELP_LINE, \
    CMD_OPTION_ASSOCIATION_FILTER_HELP_LINE, \
    CMD_OPTION_INDICATION_FILTER_HELP_LINE, \
    CMD_OPTION_EXPERIMENTAL_FILTER_HELP_LINE, \
    CMD_OPTION_HELP_INSTANCENAME_HELP_LINE, \
    CMD_OPTION_LEAFCLASSES_FILTER_HELP_LINE


_PYWBEM_VERSION = parse_version(pywbem_version)
# pywbem 1.0.0 or later
PYWBEM_1_0_0 = _PYWBEM_VERSION.release >= (1, 0, 0)

TEST_DIR = os.path.dirname(__file__)
TEST_DIR_REL = os.path.relpath(TEST_DIR)

SIMPLE_MOCK_FILE = 'simple_mock_model.mof'
ASSOC_MOCK_FILE = 'simple_assoc_mock_model.mof'
ALLTYPES_MOCK_FILE = 'all_types.mof'
QUALIFIER_FILTER_MODEL = 'qualifier_filter_model.mof'

INVOKE_METHOD_MOCK_FILE_0 = 'simple_mock_invokemethod_v0.py'
INVOKE_METHOD_MOCK_FILE_1 = 'simple_mock_invokemethod_v1old.py'
INVOKE_METHOD_MOCK_FILE = INVOKE_METHOD_MOCK_FILE_0 if PYWBEM_0 else \
    INVOKE_METHOD_MOCK_FILE_1

COMPLEX_ASSOC_MODEL = "complex_assoc_model.mof"

MOCK_SERVER_MODEL = os.path.join(TEST_DIR, 'testmock',
                                 'wbemserver_mock_script.py')


#
# Definition of files that mock selected pywbemcli calls for tests
# These are installed in pywbemcli through a special env variable set
# before the test that is NOT one of the externally defined environment
# variables
#
def GET_TEST_PATH_STR(filename):  # pylint: disable=invalid-name
    """
    Return the string representing the relative path of the file name provided.
    """
    return (str(os.path.join(TEST_DIR_REL, filename)))


MOCK_DEFINITION_ENVVAR = 'PYWBEMCLI_STARTUP_SCRIPT'
MOCK_PROMPT_0_FILE = "mock_prompt_0.py"
MOCK_PROMPT_PICK_RESPONSE_3_FILE = 'mock_prompt_pick_response_3.py'
MOCK_PROMPT_PICK_RESPONSE_5_FILE = 'mock_prompt_pick_response_5.py'
MOCK_PROMPT_PICK_RESPONSE_11_FILE = 'mock_prompt_pick_response_11.py'
MOCK_CONFIRM_Y_FILE = "mock_confirm_y.py"
MOCK_CONFIRM_N_FILE = "mock_confirm_n.py"

ALLTYPES_INVOKEMETHOD_MOCK_FILE = 'all_types_method_mock_v0.py' if PYWBEM_0 \
    else 'all_types_method_mock_v1old.py'


#
# The following list define the help for each command in terms of particular
# parts of lines that are to be tested.
# For each test, try to include:
# 1. The usage line and in particular the argument component
# 2. The single
# 2. The last line CMD_OPTION_HELP_HELP_LINE
# Defined in alphabetical order

INSTANCE_HELP_LINES = [
    'Usage: pywbemcli [GENERAL-OPTIONS] instance COMMAND [ARGS] '
    '[COMMAND-OPTIONS]',
    'Command group for CIM instances.',
    CMD_OPTION_HELP_HELP_LINE,
    'associators   List the instances associated with an instance.',
    'count         Count the instances of each class with matching class '
    'name.',
    'create        Create an instance of a class in a namespace.',
    'delete        Delete an instance of a class.',
    'enumerate     List the instances of a class.',
    'get           Get an instance of a class.',
    'invokemethod  Invoke a method on an instance.',
    'modify        Modify properties of an instance.',
    'query         Execute a query on instances in a namespace.',
    'references    List the instances referencing an instance.',
]

INSTANCE_HELP_INSTANCENAME_LINES = [
    'An instance path is specified using the INSTANCENAME argument',
    '1. By specifying the instance path as an untyped WBEM URI',
    '2. By specifying the class path of the creation class of the instance',
    '3. By specifying the class path of the creation class of the instance',
]

INSTANCE_ASSOCIATORS_HELP_LINES = [
    # pylint: disable=line-too-long
    'Usage: pywbemcli [GENERAL-OPTIONS] instance associators INSTANCENAME [COMMAND-OPTIONS]',  # noqa: E501
    'List the instances associated with an instance.',
    '--ac, --assoc-class CLASSNAME Filter the result set by association clas',
    '--rc, --result-class CLASSNAME Filter the result set by result class',
    '-r, --role PROPERTYNAME Filter the result set by source end role',
    '--rr, --result-role PROPERTYNAME Filter the result set by far end role',
    CMD_OPTION_INCLUDE_QUALIFIERS_LIST_HELP_LINE,
    CMD_OPTION_INCLUDE_CLASSORIGIN_HELP_LINE,
    CMD_OPTION_PROPERTYLIST_HELP_LINE,
    CMD_OPTION_NAMES_ONLY_HELP_LINE,
    CMD_OPTION_NAMESPACE_HELP_LINE,
    CMD_OPTION_SUMMARY_HELP_LINE,
    CMD_OPTION_FILTER_QUERY_LINE,
    CMD_OPTION_FILTER_QUERY_LANGUAGE_LINE,
    CMD_OPTION_KEYS_HELP_LINE,
    CMD_OPTION_HELP_INSTANCENAME_HELP_LINE,
    CMD_OPTION_HELP_HELP_LINE,
]

INSTANCE_COUNT_HELP_LINES = [
    'Usage: pywbemcli [GENERAL-OPTIONS] instance count CLASSNAME-GLOB '
    '[COMMAND-OPTIONS]',
    'Count the instances of each class with matching class name.',
    '-s, --sort Sort by instance count.',
    CMD_OPTION_MULTIPLE_NAMESPACE_HELP_LINE,
    CMD_OPTION_ASSOCIATION_FILTER_HELP_LINE,
    CMD_OPTION_INDICATION_FILTER_HELP_LINE,
    CMD_OPTION_EXPERIMENTAL_FILTER_HELP_LINE,
    CMD_OPTION_HELP_HELP_LINE,
    CMD_OPTION_LEAFCLASSES_FILTER_HELP_LINE
]

INSTANCE_CREATE_HELP_LINES = [
    'Usage: pywbemcli [GENERAL-OPTIONS] instance create CLASSNAME '
    '[COMMAND-OPTIONS]',
    'Create an instance of a class in a namespace.',
    '-p, --property PROPERTYNAME=VALUE Initial property value',
    CMD_OPTION_VERIFY_HELP_LINE,
    CMD_OPTION_NAMESPACE_HELP_LINE,
    CMD_OPTION_HELP_HELP_LINE,
]

INSTANCE_DELETE_HELP_LINES = [
    'Usage: pywbemcli [GENERAL-OPTIONS] instance delete INSTANCENAME '
    '[COMMAND-OPTIONS]',
    'Delete an instance of a class.',
    CMD_OPTION_NAMESPACE_HELP_LINE,
    CMD_OPTION_KEYS_HELP_LINE,
    CMD_OPTION_HELP_INSTANCENAME_HELP_LINE,
    CMD_OPTION_HELP_HELP_LINE,
]

INSTANCE_ENUMERATE_HELP_LINES = [
    'Usage: pywbemcli [GENERAL-OPTIONS] instance enumerate CLASSNAME '
    '[COMMAND-OPTIONS]',
    'List the instances of a class.',
    CMD_OPTION_LOCAL_ONLY_INSTANCE_LIST_HELP_LINE,
    '--di, --deep-inheritance Include subclass properties in the returned',
    CMD_OPTION_INCLUDE_QUALIFIERS_LIST_HELP_LINE,
    CMD_OPTION_INCLUDE_CLASSORIGIN_HELP_LINE,
    CMD_OPTION_PROPERTYLIST_HELP_LINE,
    CMD_OPTION_NAMESPACE_HELP_LINE,
    CMD_OPTION_NAMES_ONLY_HELP_LINE,
    CMD_OPTION_SUMMARY_HELP_LINE,
    CMD_OPTION_FILTER_QUERY_LINE,
    CMD_OPTION_FILTER_QUERY_LANGUAGE_LINE,
    CMD_OPTION_HELP_HELP_LINE,
]

INSTANCE_GET_HELP_LINES = [
    'Usage: pywbemcli [GENERAL-OPTIONS] instance get INSTANCENAME '
    '[COMMAND-OPTIONS]',
    'Get an instance of a class.',
    CMD_OPTION_LOCAL_ONLY_INSTANCE_GET_HELP_LINE,
    CMD_OPTION_INCLUDE_QUALIFIERS_GET_HELP_LINE,
    CMD_OPTION_INCLUDE_CLASSORIGIN_HELP_LINE,
    CMD_OPTION_PROPERTYLIST_HELP_LINE,
    CMD_OPTION_NAMESPACE_HELP_LINE,
    CMD_OPTION_KEYS_HELP_LINE,
    CMD_OPTION_HELP_INSTANCENAME_HELP_LINE,
    CMD_OPTION_HELP_HELP_LINE,
]

INSTANCE_INVOKEMETHOD_HELP_LINES = [
    'Usage: pywbemcli [GENERAL-OPTIONS] instance invokemethod '
    'INSTANCENAME METHODNAME [COMMAND-OPTIONS]',
    'Invoke a method on an instance.',
    '-p, --parameter PARAMETERNAME=VALUE Specify a method input parameter',
    CMD_OPTION_NAMESPACE_HELP_LINE,
    CMD_OPTION_KEYS_HELP_LINE,
    CMD_OPTION_HELP_INSTANCENAME_HELP_LINE,
    CMD_OPTION_HELP_HELP_LINE,
]

INSTANCE_MODIFY_HELP_LINES = [
    'Usage: pywbemcli [GENERAL-OPTIONS] instance modify INSTANCENAME '
    '[COMMAND-OPTIONS]',
    'Modify properties of an instance.',
    '-p, --property PROPERTYNAME=VALUE Property to be modified',
    '--pl, --propertylist PROPERTYLIST Reduce the properties to be modified',
    CMD_OPTION_VERIFY_HELP_LINE,
    CMD_OPTION_NAMESPACE_HELP_LINE,
    CMD_OPTION_KEYS_HELP_LINE,
    CMD_OPTION_HELP_INSTANCENAME_HELP_LINE,
    CMD_OPTION_HELP_HELP_LINE,
]

INSTANCE_QUERY_HELP_LINES = [
    'Usage: pywbemcli [GENERAL-OPTIONS] instance query QUERY-STRING '
    '[COMMAND-OPTIONS]',
    'Execute a query on instances in a namespace.',
    '-ql, --query-language QUERY-LANGUAGE The query language to be used',
    CMD_OPTION_NAMESPACE_HELP_LINE,
    CMD_OPTION_SUMMARY_HELP_LINE,
    CMD_OPTION_HELP_HELP_LINE,
]

INSTANCE_REFERENCES_HELP_LINES = [
    'Usage: pywbemcli [GENERAL-OPTIONS] instance references INSTANCENAME '
    '[COMMAND-OPTIONS]',
    'List the instances referencing an instance.',
    '--rc, --result-class CLASSNAME Filter the result set by result class',
    '-r, --role PROPERTYNAME Filter the result set by source end role',
    CMD_OPTION_INCLUDE_QUALIFIERS_LIST_HELP_LINE,
    CMD_OPTION_INCLUDE_CLASSORIGIN_HELP_LINE,
    CMD_OPTION_PROPERTYLIST_HELP_LINE,
    CMD_OPTION_NAMES_ONLY_HELP_LINE,
    CMD_OPTION_NAMESPACE_HELP_LINE,
    CMD_OPTION_SUMMARY_HELP_LINE,
    CMD_OPTION_FILTER_QUERY_LINE,
    CMD_OPTION_FILTER_QUERY_LANGUAGE_LINE,
    CMD_OPTION_KEYS_HELP_LINE,
    CMD_OPTION_HELP_INSTANCENAME_HELP_LINE,
    CMD_OPTION_HELP_HELP_LINE,
]

INSTANCE_SHRUB_HELP_LINES = [
    'Usage: pywbemcli [GENERAL-OPTIONS] instance shrub INSTANCENAME '
    '[COMMAND-OPTIONS]',
    'Show the association shrub for INSTANCENAME.',
    '--ac, --assoc-class CLASSNAME   Filter the result set by association',
    '--rc, --result-class CLASSNAME Filter the result set by result class',
    '-r, --role PROPERTYNAME Filter the result set by source end role',
    '--rr, --result-role PROPERTYNAME',
    '-s, --summary Show only a summary (count) of the objects',
    '-f, --fullpath                  Normally the instance paths in the tree',
    CMD_OPTION_NAMESPACE_HELP_LINE,
    CMD_OPTION_HELP_HELP_LINE,
    CMD_OPTION_HELP_INSTANCENAME_HELP_LINE,
]

GET_INSTANCE_RESP = """instance of CIM_Foo {
   InstanceID = "CIM_Foo1";
   IntegerProp = 1;
};

"""
# There are two forms for this response, because pywbem 1 and earlier
# pywbems differ on returning properties with NULL in mof output

ENUM_INSTANCE_RESP = """instance of CIM_Foo {
   InstanceID = "CIM_Foo1";
   IntegerProp = 1;
};

instance of CIM_Foo {
   InstanceID = "CIM_Foo2";
   IntegerProp = 2;
};

instance of CIM_Foo {
   InstanceID = "CIM_Foo3";
};

instance of CIM_Foo {
   InstanceID = "CIM_Foo30";
};

instance of CIM_Foo {
   InstanceID = "CIM_Foo31";
};

instance of CIM_Foo_sub {
   InstanceID = "CIM_Foo_sub1";
   IntegerProp = 4;
};

instance of CIM_Foo_sub {
   InstanceID = "CIM_Foo_sub2";
   IntegerProp = 5;
};

instance of CIM_Foo_sub {
   InstanceID = "CIM_Foo_sub3";
   IntegerProp = 6;
};

instance of CIM_Foo_sub {
   InstanceID = "CIM_Foo_sub4";
   IntegerProp = 7;
};

instance of CIM_Foo_sub_sub {
   InstanceID = "CIM_Foo_sub_sub1";
   IntegerProp = 8;
};

instance of CIM_Foo_sub_sub {
   InstanceID = "CIM_Foo_sub_sub2";
   IntegerProp = 9;
};

instance of CIM_Foo_sub_sub {
   InstanceID = "CIM_Foo_sub_sub3";
   IntegerProp = 10;
};
"""

GET_INSTANCE_ALL_TYPES = """instance of PyWBEM_AllTypes {
   InstanceId = "test_instance";
   scalBool = true;
   scalUint8 = 8;
   scalSint8 = -8;
   scalUint16 = 45;
   scalSint16 = -45;
   scalUint32 = 9999;
   scalSint32 = -9999;
   scalUint64 = 99999;
   scalSint64 = -99999;
   scalReal32 = 1.9;
   scalReal64 = 1.9;
   scalString = "This is a test string";
   scalDateTime = "19991224120000.000000+360";
   arrayBool = { true, false };
   arrayUint8 = { 0, 8, 125 };
   arraySint8 = { -8 };
   arrayUint16 = { 0, 45 };
   arraySint16 = { 0, 45 };
   arrayUint32 = { 0, 9999 };
   arraySint32 = { 0, -9999 };
   arrayUint64 = { 0, 99999 };
   arraySint64 = { -99999, 0, 99999 };
   arrayReal32 = { 0.0, 1.9 };
   arrayReal64 = { 0.0, 1.9 };
   arrayString = { "This is a test string", "Second String" };
   arrayDateTime = { "19991224120000.000000+360", "19991224120000.000000+360" };
};

"""

ENUM_INSTANCE_GET_TABLE_RESP = """Instances: CIM_Foo
InstanceID      IntegerProp
------------  -------------
"CIM_Foo1"                1
"""

REF_INSTS = """instance of TST_Lineage {
   InstanceID = "MikeGabi";
   parent = "/root/cimv2:TST_Person.name=\\\"Mike\\\"";
   child = "/root/cimv2:TST_Person.name=\\\"Gabi\\\"";
};

instance of TST_Lineage {
   InstanceID = "MikeSofi";
   parent = "/root/cimv2:TST_Person.name=\\\"Mike\\\"";
   child = "/root/cimv2:TST_Person.name=\\\"Sofi\\\"";
};

instance of TST_MemberOfFamilyCollection {
   family = "/root/cimv2:TST_FamilyCollection.name=\\\"Family2\\\"";
   member = "/root/cimv2:TST_Person.name=\\\"Mike\\\"";
};
"""

ASSOC_INSTS = """instance of TST_FamilyCollection {
   name = "Family2";
};

instance of TST_Person {
   name = "Gabi";
   likes = { 2 };
   gender = 1;
};

instance of TST_Person {
   name = "Sofi";
   gender = 1;
};

"""

SIMPLE_SHRUB_TREE = """TST_Person.name="Mike"
 +-- parent(Role)
 |   +-- TST_Lineage(AssocClass)
 |       +-- child(ResultRole)
 |           +-- TST_Person(ResultClass)(2 insts)
 |               +-- /:TST_Person.name="Gabi"
 |               +-- /:TST_Person.name="Sofi"
 +-- member(Role)
     +-- TST_MemberOfFamilyCollection(AssocClass)
         +-- family(ResultRole)
             +-- TST_FamilyCollection(ResultClass)(1 insts)
                 +-- /:TST_FamilyCollection.name="Family2"
"""

SIMPLE_SHRUB_TREE_ROLE = """TST_Person.name="Mike"
 +-- parent(Role)
     +-- TST_Lineage(AssocClass)
         +-- child(ResultRole)
             +-- TST_Person(ResultClass)(2 insts)
                 +-- /:TST_Person.name="Gabi"
                 +-- /:TST_Person.name="Sofi"
"""

SIMPLE_SHRUB_TREE_ASSOC_CLASS = """TST_Person.name="Mike"
 +-- parent(Role)
     +-- TST_Lineage(AssocClass)
         +-- child(ResultRole)
             +-- TST_Person(ResultClass)(2 insts)
                 +-- /:TST_Person.name="Gabi"
                 +-- /:TST_Person.name="Sofi"
"""

SIMPLE_SHRUB_TREE_RESULT_CLASS = """TST_Person.name="Mike"
 +-- parent(Role)
 |   +-- TST_Lineage(AssocClass)
 |       +-- child(ResultRole)
 |           +-- TST_Person(ResultClass)(2 insts)
 |               +-- /:TST_Person.name="Gabi"
 |               +-- /:TST_Person.name="Sofi"
 +-- member(Role)
     +-- TST_MemberOfFamilyCollection(AssocClass)
"""

SIMPLE_SHRUB_TREE_RESULT_CLASS_NO_RTN = """TST_Person.name="Mike"
 +-- parent(Role)
 |   +-- TST_Lineage(AssocClass)
 +-- member(Role)
     +-- TST_MemberOfFamilyCollection(AssocClass)
"""

# pylint: disable=line-too-long
COMPLEX_SHRUB_TABLE = [
    'Shrub of root/cimv2:TST_EP.InstanceID=1: paths',
    'Role       AssocClass    ResultRole    ResultClass    Assoc Inst paths',
    'Initiator  TST_A3        Target        TST_EP         /:TST_EP.InstanceID=2(refinst:0)',  # noqa E501
    '                                                      /:TST_EP.InstanceID=5(refinst:1)',  # noqa E501
    '                                                      /:TST_EP.InstanceID=7(refinst:2)',  # noqa E501
    'Initiator  TST_A3        Target        TST_EP         /:TST_EP.InstanceID=2(refinst:0)',  # noqa E501
    '                                                      /:TST_EP.InstanceID=5(refinst:1)',  # noqa E501
    '                                                      /:TST_EP.InstanceID=7(refinst:2)',  # noqa E501
    'Initiator  TST_A3        Target        TST_EP         /:TST_EP.InstanceID=2(refinst:0)',  # noqa E501
    '                                                      /:TST_EP.InstanceID=5(refinst:1)',  # noqa E501
    '                                                      /:TST_EP.InstanceID=7(refinst:2)',  # noqa E501
    'Initiator  TST_A3        LogicalUnit   TST_LD         /:TST_LD.InstanceID=3(refinst:0)',  # noqa E501
    '                                                      /:TST_LD.InstanceID=6(refinst:1)',  # noqa E501
    '                                                      /:TST_LD.InstanceID=8(refinst:2)',  # noqa E501
    'Initiator  TST_A3        LogicalUnit   TST_LD         /:TST_LD.InstanceID=3(refinst:0)',  # noqa E501
    '                                                      /:TST_LD.InstanceID=6(refinst:1)',  # noqa E501
    '                                                      /:TST_LD.InstanceID=8(refinst:2)',  # noqa E501
    'Initiator  TST_A3        LogicalUnit   TST_LD         /:TST_LD.InstanceID=3(refinst:0)',  # noqa E501
    '                                                      /:TST_LD.InstanceID=6(refinst:1)',  # noqa E501
    '                                                      /:TST_LD.InstanceID=8(refinst:2)']  # noqa E501
# pylint: enable=line-too-long

COMPLEX_SHRUB_TABLE_SUMMARY = [
    'Shrub of root/cimv2:TST_EP.InstanceID=1: summary',
    'Role       AssocClass    ResultRole    ResultClass      Assoc Inst Count',
    'Initiator  TST_A3        Target        TST_EP                          3',
    'Initiator  TST_A3        Target        TST_EP                          3',
    'Initiator  TST_A3        Target        TST_EP                          3',
    'Initiator  TST_A3        LogicalUnit   TST_LD                          3',
    'Initiator  TST_A3        LogicalUnit   TST_LD                          3',
    'Initiator  TST_A3        LogicalUnit   TST_LD                          3']


COMPLEX_SHRUB_TREE = [
    'TST_EP.InstanceID=1',
    ' +-- Initiator(Role)',
    ' +-- TST_A3(AssocClass)',
    ' +-- Target(ResultRole)',
    ' +-- TST_EP(ResultClass)(3 insts)',
    ' +-- /:TST_EP.InstanceID=2(refinst:0)',
    ' +-- /:TST_EP.InstanceID=5(refinst:1)',
    ' +-- /:TST_EP.InstanceID=7(refinst:2)',
    ' +-- LogicalUnit(ResultRole)',
    ' +-- TST_LD(ResultClass)(3 insts)',
    ' +-- /:TST_LD.InstanceID=3(refinst:0)',
    ' +-- /:TST_LD.InstanceID=6(refinst:1)',
    ' +-- /:TST_LD.InstanceID=8(refinst:2)']


SIMPLE_SHRUB_TABLE1 = [
    'Shrub of root/cimv2:TST_Person.name="Mike": paths',
    'Role   AssocClass ResultRole ResultClass Assoc Inst paths',
    'parent  TST_Lineage  child  TST_Person',
    'TST_Person.',
    'name="Sofi"',
    'TST_Person.',
    'name="Gabi"',
    'member  TST_MemberOfFamilyCollection  family   TST_FamilyCollection',
    'TST_FamilyCollection.',
    'name="Family2"']


# TODO: Add tests for output format xml, repr, txt

# pylint: enable=line-too-long

OK = True     # mark tests OK when they execute correctly
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

    #
    #   instance --help
    #
    ['Verify instance command --help response',
     '--help',
     {'stdout': INSTANCE_HELP_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify instance command -h response',
     '-h',
     {'stdout': INSTANCE_HELP_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify instance command --help command order',
     ['--help'],
     {'stdout': r'Commands:'
                '.*\n  enumerate'
                '.*\n  get'
                '.*\n  delete'
                '.*\n  create'
                '.*\n  modify'
                '.*\n  associators'
                '.*\n  references'
                '.*\n  invokemethod'
                '.*\n  query'
                '.*\n  count'
                '.*\n  shrub',
      'rc': 0,
      'test': 'regex'},
     None, OK],

    #
    #  Instance Enumerate command good responses
    #
    ['Verify instance command enumerate --help response',
     ['enumerate', '--help'],
     {'stdout': INSTANCE_ENUMERATE_HELP_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify instance command enumerate -h response',
     ['enumerate', '-h'],
     {'stdout': INSTANCE_ENUMERATE_HELP_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify instance command enumerate CIM_Foo',
     ['enumerate', 'CIM_Foo'],
     {'stdout': ENUM_INSTANCE_RESP,
      'test': 'linesnows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command enumerate names CIM_Foo --no',
     ['enumerate', 'CIM_Foo', '--no'],
     {'stdout': ['root/cimv2:CIM_Foo.InstanceID="CIM_Foo1"',
                 'root/cimv2:CIM_Foo.InstanceID="CIM_Foo2"',
                 'root/cimv2:CIM_Foo.InstanceID="CIM_Foo3"',
                 'root/cimv2:CIM_Foo.InstanceID="CIM_Foo30"',
                 'root/cimv2:CIM_Foo.InstanceID="CIM_Foo31"',
                 'root/cimv2:CIM_Foo_sub.InstanceID="CIM_Foo_sub1"',
                 'root/cimv2:CIM_Foo_sub.InstanceID="CIM_Foo_sub2"',
                 'root/cimv2:CIM_Foo_sub.InstanceID="CIM_Foo_sub3"',
                 'root/cimv2:CIM_Foo_sub.InstanceID="CIM_Foo_sub4"',
                 'root/cimv2:CIM_Foo_sub_sub.InstanceID="CIM_Foo_sub_sub1"',
                 'root/cimv2:CIM_Foo_sub_sub.InstanceID="CIM_Foo_sub_sub2"',
                 'root/cimv2:CIM_Foo_sub_sub.InstanceID="CIM_Foo_sub_sub3"', ],
      'test': 'linesnows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command enumerate names CIM_Foo --no -s',
     ['enumerate', 'CIM_Foo', '--no', '--summary'],
     {'stdout': ['12 CIMInstanceName(s) returned'],
      'test': 'lines'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command enumerate names CIM_Foo --no --namespace',
     ['enumerate', 'CIM_Foo', '--no', '--namespace', 'root/cimv2'],
     {'stdout': ['root/cimv2:CIM_Foo.InstanceID="CIM_Foo1"',
                 'root/cimv2:CIM_Foo.InstanceID="CIM_Foo2"',
                 'root/cimv2:CIM_Foo.InstanceID="CIM_Foo3"',
                 'root/cimv2:CIM_Foo.InstanceID="CIM_Foo30"',
                 'root/cimv2:CIM_Foo.InstanceID="CIM_Foo31"',
                 'root/cimv2:CIM_Foo_sub.InstanceID="CIM_Foo_sub1"',
                 'root/cimv2:CIM_Foo_sub.InstanceID="CIM_Foo_sub2"',
                 'root/cimv2:CIM_Foo_sub.InstanceID="CIM_Foo_sub3"',
                 'root/cimv2:CIM_Foo_sub.InstanceID="CIM_Foo_sub4"',
                 'root/cimv2:CIM_Foo_sub_sub.InstanceID="CIM_Foo_sub_sub1"',
                 'root/cimv2:CIM_Foo_sub_sub.InstanceID="CIM_Foo_sub_sub2"',
                 'root/cimv2:CIM_Foo_sub_sub.InstanceID="CIM_Foo_sub_sub3"', ],
      'test': 'linesnows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command enumerate CIM_Foo --include-qualifiers',
     ['enumerate', 'CIM_Foo', '--include-qualifiers'],
     {'stdout': ENUM_INSTANCE_RESP,
      'test': 'linesnows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command enumerate CIM_Foo include-qualifiers and '
     ' --use-pull no',
     {'args': ['enumerate', 'CIM_Foo', '--include-qualifiers', '--di'],
      'general': ['--use-pull', 'no']},
     {'stdout': ENUM_INSTANCE_RESP,
      'test': 'linesnows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command enumerate CIM_Foo include-qualifiers and '
     ' --use-pull no',
     {'args': ['enumerate', 'CIM_Foo', '--include-qualifiers'],
      'general': ['--use-pull', 'no']},
     {'stdout': ENUM_INSTANCE_RESP,
      'test': 'linesnows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command enumerate CIM_Foo_sub2, rtns nothing,',
     {'args': ['enumerate', 'CIM_Foo_sub2'],
      'general': []},
     {'stdout': "",
      'test': 'linesnows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command enumerate CIM_Foo_sub2, w --verbose rtns msg.',
     {'args': ['enumerate', 'CIM_Foo_sub2'],
      'general': ['--verbose']},
     {'stdout': 'No objects returned',
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command enumerate CIM_Foo with --use-pull yes and '
     '--pull-max-cnt=2',
     {'args': ['enumerate', 'CIM_Foo', '--include-qualifiers'],
      'general': ['--use-pull', 'yes', '--pull-max-cnt', '2', '--log',
                  'all=stderr']},
     {'stderr': [r'PullInstancesWithPath\(pull_inst_result_tuple\(context='
                 'None, eos=True,',
                 r'PullInstancesWithPath\(MaxObjectCount=2',
                 r'OpenEnumerateInstances\(ClassName='],
      'test': 'regex'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command enumerate CIM_Foo with --use-pull yes and '
     '--pull-max-cnt=2 and --namesonly',
     {'args': ['enumerate', 'CIM_Foo', '--names-only'],
      'general': ['--use-pull', 'yes', '--pull-max-cnt', '2', '--log',
                  'all=stderr']},
     {'stderr': [r'PullInstancePaths\(pull_path_result_tuple\(context='
                 'None, eos=True,',
                 r'PullInstancePaths\(MaxObjectCount=2',
                 r'OpenEnumerateInstancePaths\(ClassName='],
      'test': 'regex'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command enumerate deep-inheritance CIM_Foo --di',
     ['enumerate', 'CIM_Foo', '--di'],
     {'stdout': ENUM_INSTANCE_RESP,
      'test': 'linesnows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command enumerate deep-inheritance CIM_Foo '
     '--deep-inheritance',
     ['enumerate', 'CIM_Foo', '--deep-inheritance'],
     {'stdout': ENUM_INSTANCE_RESP,
      'test': 'linesnows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command -o grid enumerate deep-inheritance CIM_Foo --di',
     {'args': ['enumerate', 'CIM_Foo', '--di', '--pl', 'InstanceId', '--pl',
               'IntegerProp'],
      'general': ['--output-format', 'grid']},
     {'stdout': """Instances: CIM_Foo
+--------------------+---------------+
| InstanceID         | IntegerProp   |
+====================+===============+
| "CIM_Foo1"         | 1             |
+--------------------+---------------+
| "CIM_Foo2"         | 2             |
+--------------------+---------------+
| "CIM_Foo3"         |               |
+--------------------+---------------+
| "CIM_Foo30"        |               |
+--------------------+---------------+
| "CIM_Foo31"        |               |
+--------------------+---------------+
| "CIM_Foo_sub1"     | 4             |
+--------------------+---------------+
| "CIM_Foo_sub2"     | 5             |
+--------------------+---------------+
| "CIM_Foo_sub3"     | 6             |
+--------------------+---------------+
| "CIM_Foo_sub4"     | 7             |
+--------------------+---------------+
| "CIM_Foo_sub_sub1" | 8             |
+--------------------+---------------+
| "CIM_Foo_sub_sub2" | 9             |
+--------------------+---------------+
| "CIM_Foo_sub_sub3" | 10            |
+--------------------+---------------+
""",
      'test': 'linesnows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command -o grid enumerate deep-inheritance CIM_Foo --di'
     'all properties',
     {'args': ['enumerate', 'CIM_Foo', '--di'],
      'general': ['--output-format', 'grid']},
     {'stdout': """Instances: CIM_Foo
+--------------------+---------------+
| InstanceID         | IntegerProp   |
+====================+===============+
| "CIM_Foo1"         | 1             |
+--------------------+---------------+
| "CIM_Foo2"         | 2             |
+--------------------+---------------+
| "CIM_Foo3"         |               |
+--------------------+---------------+
| "CIM_Foo30"        |               |
+--------------------+---------------+
| "CIM_Foo31"        |               |
+--------------------+---------------+
| "CIM_Foo_sub1"     | 4             |
+--------------------+---------------+
| "CIM_Foo_sub2"     | 5             |
+--------------------+---------------+
| "CIM_Foo_sub3"     | 6             |
+--------------------+---------------+
| "CIM_Foo_sub4"     | 7             |
+--------------------+---------------+
| "CIM_Foo_sub_sub1" | 8             |
+--------------------+---------------+
| "CIM_Foo_sub_sub2" | 9             |
+--------------------+---------------+
| "CIM_Foo_sub_sub3" | 10            |
+--------------------+---------------+
""",
      'test': 'linesnows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command -o grid enumerate CIM_Foo --di --no',
     {'args': ['enumerate', 'CIM_Foo', '--di', '--no'],
      'general': ['--output-format', 'grid']},
     {'stdout': """InstanceNames: CIM_Foo
+--------+-------------+-----------------+-------------------------------+
| host   | namespace   | class           | keysbindings                  |
+========+=============+=================+===============================+
|        | root/cimv2  | CIM_Foo         | InstanceID="CIM_Foo1"         |
+--------+-------------+-----------------+-------------------------------+
|        | root/cimv2  | CIM_Foo         | InstanceID="CIM_Foo2"         |
+--------+-------------+-----------------+-------------------------------+
|        | root/cimv2  | CIM_Foo         | InstanceID="CIM_Foo3"         |
+--------+-------------+-----------------+-------------------------------+
|        | root/cimv2  | CIM_Foo         | InstanceID="CIM_Foo30"        |
+--------+-------------+-----------------+-------------------------------+
|        | root/cimv2  | CIM_Foo         | InstanceID="CIM_Foo31"        |
+--------+-------------+-----------------+-------------------------------+
|        | root/cimv2  | CIM_Foo_sub     | InstanceID="CIM_Foo_sub1"     |
+--------+-------------+-----------------+-------------------------------+
|        | root/cimv2  | CIM_Foo_sub     | InstanceID="CIM_Foo_sub2"     |
+--------+-------------+-----------------+-------------------------------+
|        | root/cimv2  | CIM_Foo_sub     | InstanceID="CIM_Foo_sub3"     |
+--------+-------------+-----------------+-------------------------------+
|        | root/cimv2  | CIM_Foo_sub     | InstanceID="CIM_Foo_sub4"     |
+--------+-------------+-----------------+-------------------------------+
|        | root/cimv2  | CIM_Foo_sub_sub | InstanceID="CIM_Foo_sub_sub1" |
+--------+-------------+-----------------+-------------------------------+
|        | root/cimv2  | CIM_Foo_sub_sub | InstanceID="CIM_Foo_sub_sub2" |
+--------+-------------+-----------------+-------------------------------+
|        | root/cimv2  | CIM_Foo_sub_sub | InstanceID="CIM_Foo_sub_sub3" |
+--------+-------------+-----------------+-------------------------------+
""",
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command -o grid enumerate di CIM_Foo --di --no',
     {'args': ['enumerate', 'CIM_Foo', '--di', '--no'],
      'general': ['--output-format', 'txt']},
     {'stdout': ['root/cimv2:CIM_Foo.InstanceID="CIM_Foo1"',
                 'root/cimv2:CIM_Foo.InstanceID="CIM_Foo2"',
                 'root/cimv2:CIM_Foo.InstanceID="CIM_Foo3"',
                 'root/cimv2:CIM_Foo.InstanceID="CIM_Foo30"',
                 'root/cimv2:CIM_Foo.InstanceID="CIM_Foo31"',
                 'root/cimv2:CIM_Foo_sub.InstanceID="CIM_Foo_sub1"',
                 'root/cimv2:CIM_Foo_sub.InstanceID="CIM_Foo_sub2"',
                 'root/cimv2:CIM_Foo_sub.InstanceID="CIM_Foo_sub3"',
                 'root/cimv2:CIM_Foo_sub.InstanceID="CIM_Foo_sub4"',
                 'root/cimv2:CIM_Foo_sub_sub.InstanceID="CIM_Foo_sub_sub1"',
                 'root/cimv2:CIM_Foo_sub_sub.InstanceID="CIM_Foo_sub_sub2"',
                 'root/cimv2:CIM_Foo_sub_sub.InstanceID="CIM_Foo_sub_sub3"', ],
      'test': 'linesnows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command -o txt enumerate CIM_Foo',
     {'args': ['enumerate', 'CIM_Foo'],
      'general': ['--output-format', 'txt']},
     {'stdout': ["CIMInstance(classname='CIM_Foo', "
                 "path=CIMInstanceName(classname='CIM_Foo', "
                 "keybindings=NocaseDict({'InstanceID': 'CIM_Foo1'}), "
                 "namespace='root/cimv2', host=None), ...)",
                 "CIMInstance(classname='CIM_Foo', "
                 "path=CIMInstanceName(classname='CIM_Foo', "
                 "keybindings=NocaseDict({'InstanceID': 'CIM_Foo2'}), "
                 "namespace='root/cimv2', host=None), ...)",
                 "CIMInstance(classname='CIM_Foo', "
                 "path=CIMInstanceName(classname='CIM_Foo', "
                 "keybindings=NocaseDict({'InstanceID': 'CIM_Foo3'}), "
                 "namespace='root/cimv2', host=None), ...)",
                 "CIMInstance(classname='CIM_Foo', "
                 "path=CIMInstanceName(classname='CIM_Foo', "
                 "keybindings=NocaseDict({'InstanceID': 'CIM_Foo30'}), "
                 "namespace='root/cimv2', host=None), ...)",
                 "CIMInstance(classname='CIM_Foo', "
                 "path=CIMInstanceName(classname='CIM_Foo', "
                 "keybindings=NocaseDict({'InstanceID': 'CIM_Foo31'}), "
                 "namespace='root/cimv2', host=None), ...)",
                 "CIMInstance(classname='CIM_Foo_sub', "
                 "path=CIMInstanceName(classname='CIM_Foo_sub', "
                 "keybindings=NocaseDict({'InstanceID': 'CIM_Foo_sub1'}), "
                 "namespace='root/cimv2', host=None), ...)",
                 "CIMInstance(classname='CIM_Foo_sub', "
                 "path=CIMInstanceName(classname='CIM_Foo_sub', "
                 "keybindings=NocaseDict({'InstanceID': 'CIM_Foo_sub2'}), "
                 "namespace='root/cimv2', host=None), ...)",
                 "CIMInstance(classname='CIM_Foo_sub', "
                 "path=CIMInstanceName(classname='CIM_Foo_sub', "
                 "keybindings=NocaseDict({'InstanceID': 'CIM_Foo_sub3'}), "
                 "namespace='root/cimv2', host=None), ...)",
                 "CIMInstance(classname='CIM_Foo_sub', "
                 "path=CIMInstanceName(classname='CIM_Foo_sub', "
                 "keybindings=NocaseDict({'InstanceID': 'CIM_Foo_sub4'}), "
                 "namespace='root/cimv2', host=None), ...)",
                 "CIMInstance(classname='CIM_Foo_sub_sub', "
                 "path=CIMInstanceName(classname='CIM_Foo_sub_sub', "
                 "keybindings=NocaseDict({'InstanceID': 'CIM_Foo_sub_sub1'}), "
                 "namespace='root/cimv2', host=None), ...)",
                 "CIMInstance(classname='CIM_Foo_sub_sub', "
                 "path=CIMInstanceName(classname='CIM_Foo_sub_sub', "
                 "keybindings=NocaseDict({'InstanceID': 'CIM_Foo_sub_sub2'}), "
                 "namespace='root/cimv2', host=None), ...)",
                 "CIMInstance(classname='CIM_Foo_sub_sub', "
                 "path=CIMInstanceName(classname='CIM_Foo_sub_sub', "
                 "keybindings=NocaseDict({'InstanceID': 'CIM_Foo_sub_sub3'}), "
                 "namespace='root/cimv2', host=None), ...)"],
      'test': 'lines'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command -o grid enumerate di alltypes, datetime',
     {'args': ['enumerate', 'Pywbem_Alltypes', '--di',
               '--propertylist', 'scalDateTime', '--pl', 'scalTimeDelta'],
      'general': ['--output-format', 'grid']},
     {'stdout': ["""Instances: PyWBEM_AllTypes
+-----------------------------+
| scalDateTime                |
+=============================+
| "19991224120000.000000+360" |
+-----------------------------+
"""],
      'test': 'linesnows'},
     ALLTYPES_MOCK_FILE, OK],

    # TODO: modify this to output log and test for info in return and log

    ['Verify instance command enumerate with query.',
     ['enumerate', 'CIM_Foo', '--filter-query', 'InstanceID = 3'],
     {'stdout': ENUM_INSTANCE_RESP,
      'test': 'linesnows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command enumerate with query, traditional ops fails',
     {'args': ['enumerate', 'CIM_Foo', '--filter-query', 'InstanceID = 3'],
      'general': ['--use-pull', 'no']},
     {'stderr': ["ValueError",
                 "EnumerateInstances does not support FilterQuery"],
      'rc': 1,
      'test': 'regex'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify command enumerate with CIM_Foo inst name table output',
     {'args': ['enumerate', 'CIM_Foo', '--names-only'],
      'general': ['--output-format', 'table']},
     {'stdout': """InstanceNames: CIM_Foo
+--------+-------------+-----------------+-------------------------------+
| host   | namespace   | class           | keysbindings                  |
|--------+-------------+-----------------+-------------------------------|
|        | root/cimv2  | CIM_Foo         | InstanceID="CIM_Foo1"         |
|        | root/cimv2  | CIM_Foo         | InstanceID="CIM_Foo2"         |
|        | root/cimv2  | CIM_Foo         | InstanceID="CIM_Foo3"         |
|        | root/cimv2  | CIM_Foo         | InstanceID="CIM_Foo30"        |
|        | root/cimv2  | CIM_Foo         | InstanceID="CIM_Foo31"        |
|        | root/cimv2  | CIM_Foo_sub     | InstanceID="CIM_Foo_sub1"     |
|        | root/cimv2  | CIM_Foo_sub     | InstanceID="CIM_Foo_sub2"     |
|        | root/cimv2  | CIM_Foo_sub     | InstanceID="CIM_Foo_sub3"     |
|        | root/cimv2  | CIM_Foo_sub     | InstanceID="CIM_Foo_sub4"     |
|        | root/cimv2  | CIM_Foo_sub_sub | InstanceID="CIM_Foo_sub_sub1" |
|        | root/cimv2  | CIM_Foo_sub_sub | InstanceID="CIM_Foo_sub_sub2" |
|        | root/cimv2  | CIM_Foo_sub_sub | InstanceID="CIM_Foo_sub_sub3" |
+--------+-------------+-----------------+-------------------------------+

""",
      'rc': 0,
      'test': 'linesnows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify command enumerate with CIM_Foo summary table output',
     {'args': ['enumerate', 'CIM_Foo', '--summary'],
      'general': ['--output-format', 'table']},
     {'stdout': """Summary of CIMInstance returned
+---------+-------------+
|   Count | CIM Type    |
|---------+-------------|
|      12 | CIMInstance |
+---------+-------------+
""",
      'rc': 0,
      'test': 'linesnows'},
     SIMPLE_MOCK_FILE, OK],

    # TODO the following uses deep-inheritance because of issue in pywbem_mock
    ['Verify command enumerate with PyWBEM_AllTypes table with scalar '
     'properties returns instance with all property types',
     {'args': ['enumerate', 'PyWBEM_AllTypes', '--deep-inheritance',
               '--propertylist',
               'instanceid,scalbool,scalsint32,scaluint32'],
      'general': ['--output-format', 'grid']},
     {'stdout': """
Instances: PyWBEM_AllTypes
+-----------------+------------+--------------+--------------+
| InstanceId      | scalBool   |   scalSint32 |   scalUint32 |
+=================+============+==============+==============+
| "test_instance" | true       |        -9999 |         9999 |
+-----------------+------------+--------------+--------------+
""",
      'rc': 0,
      'test': 'linesnows'},
     ALLTYPES_MOCK_FILE, OK],

    ['Verify command enumerate with PyWBEM_AllTypes with array properties '
     'returns instance with all property types',
     {'args': ['enumerate', 'PyWBEM_AllTypes', '--deep-inheritance',
               '--propertylist',
               'instanceid,arraybool,arraysint32,arrayuint32'],
      'general': ['--output-format', 'grid']},
     {'stdout': """
Instances: PyWBEM_AllTypes
+-----------------+-------------+---------------+---------------+
| InstanceId      | arrayBool   | arraySint32   | arrayUint32   |
+=================+=============+===============+===============+
| "test_instance" | true, false | 0, -9999      | 0, 9999       |
+-----------------+-------------+---------------+---------------+

""",
      'rc': 0,
      'test': 'linesnows'},
     ALLTYPES_MOCK_FILE, OK],

    ['Verify instance command enumerate of TST_Person shows value-mapped '
     'properties in table output',
     {'args': ['enumerate', 'TST_Person', '--pl', 'name,gender,likes'],
      'general': ['--output-format', 'table']},
     {'stdout': """
Instances: TST_Person
+------------+------------+-----------------------+
| name       | gender     | likes                 |
|------------+------------+-----------------------|
| "Gabi"     | 1 (female) | 2 (movies)            |
| "Mike"     | 2 (male)   | 1 (books), 2 (movies) |
| "Saara"    | 1 (female) | 1 (books)             |
| "Sofi"     | 1 (female) |                       |
| "Gabisub"  | 1 (female) |                       |
| "Mikesub"  | 2 (male)   |                       |
| "Saarasub" | 1 (female) |                       |
| "Sofisub"  | 1 (female) |                       |
+------------+------------+-----------------------+

""",
      'rc': 0,
      'test': 'linesnows'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command enumerate of TST_Person honors property list '
     'order in table output',
     {'args': ['enumerate', 'TST_Person', '--pl', 'Name,Likes,Gender'],
      'general': ['--output-format', 'table']},
     {'stdout': """
Instances: TST_Person
+------------+-----------------------+------------+
| name       | likes                 | gender     |
|------------+-----------------------+------------|
| "Gabi"     | 2 (movies)            | 1 (female) |
| "Mike"     | 1 (books), 2 (movies) | 2 (male)   |
| "Saara"    | 1 (books)             | 1 (female) |
| "Sofi"     |                       | 1 (female) |
| "Gabisub"  |                       | 1 (female) |
| "Mikesub"  |                       | 2 (male)   |
| "Saarasub" |                       | 1 (female) |
| "Sofisub"  |                       | 1 (female) |
+------------+-----------------------+------------+

""",
      'rc': 0,
      'test': 'linesnows'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance enumerate to interop namespace as table works.',
     {'args': ['enumerate', 'CIM_Namespace', '-n', 'interop'],
      'general': ['-o', 'simple']},
     {'stdout': "CreationClassName    Name    ObjectManagerCreationClassName",
      'test': 'innows'},
     MOCK_SERVER_MODEL, OK],

    #
    # instance enumerate error returns
    #

    # Note: In pywbem 1.0, the returned status for this test changed from
    #       NOT_FOUND to INVALID_CLASS because that is the correct one for
    #       instance operations that do not find their class.
    ['Verify instance command enumerate error, invalid classname fails, '
     'pywbem 1.0',
     ['enumerate', 'CIM_Foox'],
     {'stderr': ["CIMError:", "CIM_ERR_INVALID_CLASS"],
      'rc': 1,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, PYWBEM_1_0_0],

    ['Verify instance command enumerate error, invalid classname fails, '
     'pywbem 0.x',
     ['enumerate', 'CIM_Foox'],
     {'stderr': ["CIMError:", "CIM_ERR_NOT_FOUND"],
      'rc': 1,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, not PYWBEM_1_0_0],

    ['Verify instance command enumerate error, no classname fails',
     ['enumerate'],
     {'stderr':
      ['Usage: pywbemcli [GENERAL-OPTIONS] instance enumerate CLASSNAME', ],
      'rc': 2,
      'test': 'in'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command enumerate error, invalid namespace',
     ['enumerate', 'CIM_Foo', '--namespace', 'root/blah'],
     {'stderr':
      # NOTE: Partial string becuase output formats differ starting pywbem 1.0.0
      ["(CIM_ERR_INVALID_NAMESPACE): Namespace does not exist in ", ],
      'rc': 1,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command enumerate fails invalid query language',
     ['enumerate', 'CIM_Foo', '--filter-query-language', 'blah',
      '--filter-query', 'InstanceID = 3'],
     {'stderr': ['CIMError', '14', 'CIM_ERR_QUERY_LANGUAGE_NOT_SUPPORTED'],
      'rc': 1,
      'test': 'regex'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command enumerate fails using traditional op',
     {'args': ['enumerate', 'CIM_Foo', '--filter-query', 'InstanceID = 3'],
      'general': ['--use-pull', 'no']},
     {'stderr':
      ['ValueError', 'EnumerateInstances does not support FilterQuery'],
      'rc': 1,
      'test': 'regex'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command get with -o txt fails',
     {'args': ['enumerate', 'CIM_Foo'],
      'general': ['--output-format', 'text']},
     {'stderr': ['Output format "text"', 'not allowed', 'Only CIM formats:',
                 'TABLE formats:'],
      'rc': 1,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    #
    #  Exhaustive tests for INSTANCENAME parameter (using instance get command)
    #  including variations on --namespace and --key options.
    #

    ['INSTANCENAME with one-key class and keybinding, no options',
     ['get', 'CIM_Foo.InstanceID="CIM_Foo1"'],
     {'stdout': GET_INSTANCE_RESP,
      'rc': 0,
      'test': 'linesnows'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with namespace, one-key class and keybinding, no options',
     ['get', 'root/cimv2:CIM_Foo.InstanceID="CIM_Foo1"'],
     {'stdout': GET_INSTANCE_RESP,
      'rc': 0,
      'test': 'linesnows'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with one-key class and keybinding, option --namespace',
     ['get', 'CIM_Foo.InstanceID="CIM_Foo1"', '--namespace', 'root/cimv2'],
     {'stdout': GET_INSTANCE_RESP,
      'rc': 0,
      'test': 'linesnows'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with one-key class and keybinding, option -n',
     ['get', 'CIM_Foo.InstanceID="CIM_Foo1"', '-n', 'root/cimv2'],
     {'stdout': GET_INSTANCE_RESP,
      'rc': 0,
      'test': 'linesnows'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with one-key class, option --key',
     ['get', 'CIM_Foo', '--key', 'InstanceID=CIM_Foo1'],
     {'stdout': GET_INSTANCE_RESP,
      'rc': 0,
      'test': 'linesnows'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with one-key class, option -k',
     ['get', 'CIM_Foo', '-k', 'InstanceID=CIM_Foo1'],
     {'stdout': GET_INSTANCE_RESP,
      'rc': 0,
      'test': 'linesnows'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with namespace and one-key class, option --key',
     ['get', 'root/cimv2:CIM_Foo', '--key', 'InstanceID=CIM_Foo1'],
     {'stdout': GET_INSTANCE_RESP,
      'rc': 0,
      'test': 'linesnows'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with namespace and one-key class, option -k',
     ['get', 'root/cimv2:CIM_Foo', '-k', 'InstanceID=CIM_Foo1'],
     {'stdout': GET_INSTANCE_RESP,
      'rc': 0,
      'test': 'linesnows'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with one-key class, options --namespace and --key',
     ['get', 'CIM_Foo', '--namespace', 'root/cimv2',
      '--key', 'InstanceID=CIM_Foo1'],
     {'stdout': GET_INSTANCE_RESP,
      'rc': 0,
      'test': 'linesnows'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with one-key class, options -n and -k',
     ['get', 'CIM_Foo', '-n', 'root/cimv2', '-k', 'InstanceID=CIM_Foo1'],
     {'stdout': GET_INSTANCE_RESP,
      'rc': 0,
      'test': 'linesnows'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with namespace, option --namespace with same ns (error)',
     ['get', 'root/cimv2:CIM_Foo.InstanceID="CIM_Foo1"',
      '--namespace', 'root/cimv2'],
     {'stderr': "Using the --namespace option conflicts with specifying a "
                "namespace",
      'rc': 1,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with namespace, option -n with same ns (error)',
     ['get', 'root/cimv2:CIM_Foo.InstanceID="CIM_Foo1"',
      '-n', 'root/cimv2'],
     {'stderr': "Using the --namespace option conflicts with specifying a "
                "namespace",
      'rc': 1,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with namespace, option --namespace with diff ns (error)',
     ['get', 'root/cimv2:CIM_Foo.InstanceID="CIM_Foo1"',
      '--namespace', 'test/cimv2'],
     {'stderr': "Using the --namespace option conflicts with specifying a "
                "namespace",
      'rc': 1,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with namespace, option -n with diff ns (error)',
     ['get', 'root/cimv2:CIM_Foo.InstanceID="CIM_Foo1"',
      '-n', 'test/cimv2'],
     {'stderr': "Using the --namespace option conflicts with specifying a "
                "namespace",
      'rc': 1,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with namespace, options --key and --namespace (error)',
     ['get', 'root/cimv2:CIM_Foo', '--key', 'InstanceID=CIM_Foo1',
      '--namespace', 'root/cimv2'],
     {'stderr': "Using the --namespace option conflicts with specifying a "
                "namespace",
      'rc': 1,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with keybindings, option --key with same value (error)',
     ['get', 'CIM_Foo.InstanceID="CIM_Foo1"', '--key', 'InstanceID=CIM_Foo1'],
     {'stderr': "Invalid format for a class path in WBEM URI",
      'rc': 1,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with keybindings, option -k with same value (error)',
     ['get', 'CIM_Foo.InstanceID="CIM_Foo1"', '-k', 'InstanceID=CIM_Foo1'],
     {'stderr': "Invalid format for a class path in WBEM URI",
      'rc': 1,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with keybindings, option --key with diff value (error)',
     ['get', 'CIM_Foo.InstanceID="CIM_Foo1"', '--key', 'InstanceID=CIM_Bla'],
     {'stderr': "Invalid format for a class path in WBEM URI",
      'rc': 1,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with keybindings, option -k with diff value (error)',
     ['get', 'CIM_Foo.InstanceID="CIM_Foo1"', '-k', 'InstanceID=CIM_Bla'],
     {'stderr': "Invalid format for a class path in WBEM URI",
      'rc': 1,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with non-existing namespace, no options (error)',
     ['get', 'root/bla:CIM_Foo.InstanceID="CIM_Foo1"'],
     {'stderr': "CIMError: 3 (CIM_ERR_INVALID_NAMESPACE): ",
      'rc': 1,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with non-existing namespace, --key option (error)',
     ['get', 'root/bla:CIM_Foo', '--key', 'InstanceID=CIM_Foo1'],
     {'stderr': "CIMError: 3 (CIM_ERR_INVALID_NAMESPACE): ",
      'rc': 1,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with non-existing namespace, --namespace option (error)',
     ['get', 'CIM_Foo.InstanceID="CIM_Foo1"', '--namespace', 'root/bla'],
     {'stderr': "CIMError: 3 (CIM_ERR_INVALID_NAMESPACE): ",
      'rc': 1,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with non-existing namespace, --namespace and --key options '
     '(error)',
     ['get', 'CIM_Foo', '--namespace', 'root/bla',
      '--key', 'InstanceID=CIM_Foo1'],
     {'stderr': "CIMError: 3 (CIM_ERR_INVALID_NAMESPACE): ",
      'rc': 1,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with non-existing class, no options (error)',
     ['get', 'CIM_Bla.InstanceID="CIM_Foo1"'],
     {'stderr': "CIMError: 5 (CIM_ERR_INVALID_CLASS): Class 'CIM_Bla'",
      'rc': 1,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with non-existing class, --key option (error)',
     ['get', 'CIM_Bla', '--key', 'InstanceID=CIM_Foo1'],
     {'stderr': "CIMError: 5 (CIM_ERR_INVALID_CLASS): Class 'CIM_Bla'",
      'rc': 1,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with non-existing instance, no options (error)',
     ['get', 'CIM_Foo.InstanceID="CIM_Bla"'],
     {'stderr': "CIMError: 6 (CIM_ERR_NOT_FOUND): ",
      'rc': 1,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with non-existing instance, --key option (error)',
     ['get', 'CIM_Foo', '--key', 'InstanceID=CIM_Bla'],
     {'stderr': "CIMError: 6 (CIM_ERR_NOT_FOUND): ",
      'rc': 1,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with "name=" keybinding, no options',
     ['get', 'CIM_Foo.InstanceID='],
     {'stderr': "WBEM URI has an invalid format for its keybindings",
      'rc': 1,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with no keybinding, --key option with missing VALUE',
     ['get', 'CIM_Foo', '--key', 'InstanceID='],
     {'stderr': "VALUE in --key option argument is missing",
      'rc': 1,
      'test': 'regex'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with "name" keybinding, no options',
     ['get', 'CIM_Foo.InstanceID'],
     {'stderr': "WBEM URI has an invalid format for its keybindings",
      'rc': 1,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with no keybinding, --key option with missing =VALUE',
     ['get', 'CIM_Foo', '--key', 'InstanceID'],
     {'stderr': "VALUE in --key option argument is missing",
      'rc': 1,
      'test': 'in'},
     SIMPLE_MOCK_FILE, OK],

    # In the following tests, we rely on the CIMInstanceName object being
    # printed as part of the error message that the instance was not found.
    # That allows verifying how the specified VALUE was parsed.

    ['INSTANCENAME with no keybinding, --key option with boolean true',
     ['get', 'CIM_Foo', '--key', 'InstanceID=true'],
     {'stderr': ["CIMError: 6 (CIM_ERR_NOT_FOUND): ",
                 "'InstanceID': True"],
      'rc': 1,
      'test': 'in'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with no keybinding, --key option with string true',
     ['get', 'CIM_Foo', '--key', 'InstanceID="true"'],
     {'stderr': ["CIMError: 6 (CIM_ERR_NOT_FOUND): ",
                 "'InstanceID': 'true'"],
      'rc': 1,
      'test': 'in'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with no keybinding, --key option with boolean false',
     ['get', 'CIM_Foo', '--key', 'InstanceID=false'],
     {'stderr': ["CIMError: 6 (CIM_ERR_NOT_FOUND): ",
                 "'InstanceID': False"],
      'rc': 1,
      'test': 'in'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with no keybinding, --key option with string false',
     ['get', 'CIM_Foo', '--key', 'InstanceID="false"'],
     {'stderr': ["CIMError: 6 (CIM_ERR_NOT_FOUND): ",
                 "'InstanceID': 'false'"],
      'rc': 1,
      'test': 'in'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with no keybinding, --key option with int 42',
     ['get', 'CIM_Foo', '--key', 'InstanceID=42'],
     {'stderr': ["CIMError: 6 (CIM_ERR_NOT_FOUND): ",
                 "'InstanceID': 42"],
      'rc': 1,
      'test': 'in'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with no keybinding, --key option with string 42',
     ['get', 'CIM_Foo', '--key', 'InstanceID="42"'],
     {'stderr': ["CIMError: 6 (CIM_ERR_NOT_FOUND): ",
                 "'InstanceID': '42'"],
      'rc': 1,
      'test': 'in'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with no keybinding, --key option with string with blanks',
     ['get', 'CIM_Foo', '--key', 'InstanceID="a b"'],
     {'stderr': ["CIMError: 6 (CIM_ERR_NOT_FOUND): ",
                 "'InstanceID': 'a b'"],
      'rc': 1,
      'test': 'in'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with no keybinding, --key option with string with quote '
     '(error)',
     ['get', 'CIM_Foo', '--key', 'InstanceID="a"b"'],
     {'stderr': "WBEM URI has an invalid format for its keybindings",
      'rc': 1,
      'test': 'in'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with no keybinding, two --key options',
     ['get', 'CIM_Foo', '--key', 'P1=a', '--key', 'P2=b'],
     {'stderr': ["CIMError: 6 (CIM_ERR_NOT_FOUND): ",
                 "'P1': 'a'", "'P2': 'b'"],
      'rc': 1,
      'test': 'in'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with wildcard keybinding, no options',
     {'general': [],
      'args': ['get', 'TST_Person.?'],
      'env': {MOCK_DEFINITION_ENVVAR: GET_TEST_PATH_STR(MOCK_PROMPT_0_FILE)}},
     {'stdout':
      ['Input integer between 0 and 7',
       'root/cimv2:TST_Person',
       'instance of TST_Person'],
      'rc': 0,
      'test': 'regex'},
     ASSOC_MOCK_FILE, OK],

    ['INSTANCENAME with wildcard keybinding, --key option (error)',
     {'general': [],
      'args': ['get', 'TST_Person.?', '--key', 'name=Saara'],
      'env': {MOCK_DEFINITION_ENVVAR: GET_TEST_PATH_STR(MOCK_PROMPT_0_FILE)}},
     {'stderr': "Using the --key option conflicts with specifying a "
                "wildcard keybinding",
      'rc': 1,
      'test': 'regex'},
     ASSOC_MOCK_FILE, OK],

    ['INSTANCENAME with wildcard keybinding, invalid class path (error)',
     {'general': [],
      'args': ['get', 'TST_Person.name=1.?'],
      'env': {MOCK_DEFINITION_ENVVAR: GET_TEST_PATH_STR(MOCK_PROMPT_0_FILE)}},
     {'stderr': "Invalid format for a class path in WBEM URI",
      'rc': 1,
      'test': 'regex'},
     ASSOC_MOCK_FILE, OK],

    ['INSTANCENAME with namespace and with wildcard keybinding, '
     'option --namespace with same ns (error)',
     ['get', 'root/cimv2:CIM_Foo.?', '--namespace', 'root/cimv2'],
     {'stderr': "Using the --namespace option conflicts with specifying a "
                "namespace",
      'rc': 1,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with namespace and with wildcard keybinding, '
     'option -n with same ns (error)',
     ['get', 'root/cimv2:CIM_Foo.?', '-n', 'root/cimv2'],
     {'stderr': "Using the --namespace option conflicts with specifying a "
                "namespace",
      'rc': 1,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with namespace and with wildcard keybinding, '
     'option --namespace with diff ns (error)',
     ['get', 'root/cimv2:CIM_Foo.?', '--namespace', 'test/cimv2'],
     {'stderr': "Using the --namespace option conflicts with specifying a "
                "namespace",
      'rc': 1,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    ['INSTANCENAME with namespace and with wildcard keybinding, '
     'option -n with diff ns (error)',
     ['get', 'root/cimv2:CIM_Foo.?', '-n', 'test/cimv2'],
     {'stderr': "Using the --namespace option conflicts with specifying a "
                "namespace",
      'rc': 1,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    #
    #  instance get command
    #

    ['Verify instance command get --help response',
     ['get', '--help'],
     {'stdout': INSTANCE_GET_HELP_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify instance command get -h response',
     ['get', '-h'],
     {'stdout': INSTANCE_GET_HELP_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify instance command get --help-instancename response',
     ['get', '--help-instancename'],
     {'stdout': INSTANCE_HELP_INSTANCENAME_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify instance command get --hi response',
     ['get', '--hi'],
     {'stdout': INSTANCE_HELP_INSTANCENAME_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify instance command get with instancename local_only returns data',
     ['get', 'CIM_Foo.InstanceID="CIM_Foo1"', '--lo'],
     {'stdout': GET_INSTANCE_RESP,
      'rc': 0,
      'test': 'linesnows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command get with instancename --local-only returns '
     ' data',
     ['get', 'CIM_Foo.InstanceID="CIM_Foo1"', '--local-only'],
     {'stdout': GET_INSTANCE_RESP,
      'rc': 0,
      'test': 'linesnows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command get with instancename --include-qualifiers '
     'returns data',
     ['get', 'CIM_Foo.InstanceID="CIM_Foo1"', '--include-qualifiers'],
     {'stdout': GET_INSTANCE_RESP,
      'rc': 0,
      'test': 'linesnows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command get with instancename --include-qualifiers '
     'and general --use-pull returns data',
     {'args': ['get', 'CIM_Foo.InstanceID="CIM_Foo1"', '--iq'],
      'general': ['--use-pull', 'no']},
     {'stdout': GET_INSTANCE_RESP,
      'rc': 0,
      'test': 'linesnows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command get with instancename prop list -p returns '
     'one property',
     ['get', 'CIM_Foo.InstanceID="CIM_Foo1"', '--pl', 'InstanceID'],
     {'stdout': ['instance of CIM_Foo {',
                 'InstanceID = "CIM_Foo1";',
                 '};',
                 ''],
      'rc': 0,
      'test': 'linesnows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command get with instancename prop list '
     '--propertylist returns property',
     ['get', 'CIM_Foo.InstanceID="CIM_Foo1"', '--propertylist', 'InstanceID'],
     {'stdout': ['instance of CIM_Foo {',
                 'InstanceID = "CIM_Foo1";',
                 '};',
                 ''],
      'rc': 0,
      'test': 'linesnows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command get with instancename prop list -p  '
     ' InstanceID,IntegerProp returns 2 properties',
     ['get', 'CIM_Foo.InstanceID="CIM_Foo1"', '--pl', 'InstanceID,IntegerProp'],
     {'stdout': GET_INSTANCE_RESP,
      'rc': 0,
      'test': 'linesnows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command get with instancename prop list -p '
     ' multiple instances of option returns 2 properties',
     ['get', 'CIM_Foo.InstanceID="CIM_Foo1"', '--pl', 'InstanceID',
      '--pl', 'IntegerProp'],
     {'stdout': GET_INSTANCE_RESP,
      'rc': 0,
      'test': 'linesnows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command get with instancename empty  prop list '
     'returns  empty instance',
     ['get', 'CIM_Foo.InstanceID="CIM_Foo1"', '--pl', '""'],
     {'stdout': ['instance of CIM_Foo {',
                 '};',
                 ''],
      'rc': 0,
      'test': 'lines'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command get with instancename PyWBEM_AllTypes'
     ' returns instance with all property types',
     ['get', 'PyWBEM_AllTypes.InstanceID="test_instance"'],
     {'stdout': GET_INSTANCE_ALL_TYPES,
      'rc': 0,
      'test': 'lines'},
     ALLTYPES_MOCK_FILE, OK],

    ['Verify instance command -o grid get CIM_Foo',
     {'args': ['get', 'CIM_Foo.InstanceID="CIM_Foo1"'],
      'general': ['-o', 'simple']},
     {'stdout': ENUM_INSTANCE_GET_TABLE_RESP,
      'test': 'lines'},
     SIMPLE_MOCK_FILE, OK],

    # Cannot insure order of the pick and we are using an integer to
    # pick so result is very general
    ['Verify instance command get with wildcard keybinding',
     {'general': [],
      'args': ['get', 'TST_Person.?'],
      'env': {MOCK_DEFINITION_ENVVAR: GET_TEST_PATH_STR(MOCK_PROMPT_0_FILE)}},
     {'stdout':
      ['Input integer between 0 and 7',
       'root/cimv2:TST_Person',
       'instance of TST_Person'],
      'rc': 0,
      'test': 'regex'},
     ASSOC_MOCK_FILE, OK],

    #
    #  instance get command errors
    #
    ['instance command get error. no classname',
     ['get'],
     {'stderr':
      ['Usage: pywbemcli [GENERAL-OPTIONS] instance get INSTANCENAME', ],
      'rc': 2,
      'test': 'in'},
     SIMPLE_MOCK_FILE, OK],

    ['instance command get error. instance name invalid',
     ['get', "blah"],
     {'stderr':
      ['Invalid format for an instance path in WBEM URI', ],
      'rc': 1,
      'test': 'in'},
     SIMPLE_MOCK_FILE, OK],

    ['instance command get error. invalid namespace',
     ['get', 'CIM_Foo.InstanceID="CIM_Foo1"',
      '--namespace', 'root/invalidnamespace'],
     {'stderr':
      # NOTE: cut out pieces of message because of pywbem 1.0.0 word difference
      ['CIMError:', '3', '(CIM_ERR_INVALID_NAMESPACE):',
       'Namespace does not exist in',
       "repository: 'root/invalidnamespace'"],
      'rc': 1,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command get with none existentinstancename',
     ['get', 'CIM_Foo.InstanceID="CIM_NOTEXIST"'],
     # Output format diff starting pywbem 1.0.0, words cim repository
     {'stderr': ['CIMError:', '6', '(CIM_ERR_NOT_FOUND):',
                 'Instance not found in ',
                 "namespace 'root/cimv2'. Path=CIMInstanceName("
                 "classname='CIM_Foo', keybindings=NocaseDict({'InstanceID': "
                 "'CIM_NOTEXIST'}), namespace='root/cimv2', host=None)"],
      'rc': 1,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command get with -o txt fails',
     {'args': ['get', 'CIM_Foo.InstanceID="CIM_Foo1"', '--lo'],
      'general': ['--output-format', 'text']},
     {'stderr': ['Output format "text"', 'not allowed', 'Only CIM formats:',
                 'TABLE formats:'],
      'rc': 1,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    #
    #  instance create command
    #
    ['Verify instance command create --help response',
     ['create', '--help'],
     {'stdout': INSTANCE_CREATE_HELP_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify instance command create -h response',
     ['create', '-h'],
     {'stdout': INSTANCE_CREATE_HELP_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify instance command create, new instance of CIM_Foo one property',
     ['create', 'CIM_Foo', '-p', 'InstanceID=blah'],
     {'stdout': 'root/cimv2:CIM_Foo.InstanceID="blah"',
      'rc': 0,
      'test': 'lines'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command create, new instance of CIM_Foo one '
     'property and verify yes',
     {'general': [],
      'args': ['create', 'CIM_Foo', '-p', 'InstanceID=blah', '--verify'],
      'env': {MOCK_DEFINITION_ENVVAR: GET_TEST_PATH_STR(MOCK_CONFIRM_Y_FILE)}},
     {'stdout': ['instance of CIM_Foo {',
                 'InstanceID = "blah";',
                 '};',
                 'Execute CreateInstance',
                 'root/cimv2:CIM_Foo.InstanceID="blah"'],
      'rc': 0,
      'test': 'in'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command create, new instance of CIM_Foo one '
     'property and verify no',
     {'general': [],
      'args': ['create', 'CIM_Foo', '-p', 'InstanceID=blah', '--verify'],
      'env': {MOCK_DEFINITION_ENVVAR: GET_TEST_PATH_STR(MOCK_CONFIRM_N_FILE)}},
     {'stdout': ['instance of CIM_Foo {',
                 'InstanceID = "blah";',
                 '};',
                 'Execute CreateInstance',
                 'Request aborted'],
      'rc': 0,
      'test': 'in'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command create, new instance of CIM_Foo, '
     'one property, explicit namespace definition',
     ['create', 'CIM_Foo', '-p', 'InstanceID=blah', '-n', 'root/cimv2'],
     {'stdout': "",
      'rc': 0,
      'test': 'regex'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify get and delete with wildcard keybinding with stdin',
     {'env': {MOCK_DEFINITION_ENVVAR:
              GET_TEST_PATH_STR(MOCK_PROMPT_PICK_RESPONSE_3_FILE)},
      'stdin': ['instance get CIM_Foo.?',
                'instance delete CIM_Foo.?']},
     {'stdout': ['CIM_Foo',
                 'instance of CIM_Foo',
                 'InstanceID = "CIM_Foo30"'],
      'rc': 0,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify multiple creates verify with enum summary with stdin',
     {'stdin': ['instance create CIM_Foo -p InstanceID=blah1',
                'instance enumerate CIM_Foo -s',
                'instance create CIM_Foo -p InstanceID=blah2',
                'instance enumerate CIM_Foo -s']},
     {'stdout': ['13 CIMInstance',
                 '14 CIMInstance'],
      'rc': 0,
      'test': 'innows'},
     [SIMPLE_MOCK_FILE], OK],

    ['Verify create, get, delete works with stdin using --key to define path',
     {'stdin': ['instance create CIM_Foo -p InstanceID=blah',
                'instance get CIM_Foo -k InstanceID=blah',
                'instance delete CIM_Foo -k InstanceID=blah']},
     {'stdout': ['CIM_Foo',
                 'instance of CIM_Foo',
                 'InstanceID ="blah"'],
      'rc': 0,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify create, get, delete works with stdin using instancepath',
     {'stdin': ['instance create CIM_Foo -p InstanceID=blah',
                'instance get CIM_Foo.InstanceID=\\"blah\\"',
                'instance delete CIM_Foo."InstanceID=\\"blah\\""']},
     {'stdout': ['CIM_Foo',
                 'instance of CIM_Foo',
                 'InstanceID ="blah"'],
      'rc': 0,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify create, get with wildcard keybindin and delete with wildcard '
     'keybinding, with stdin',
     {'env': {MOCK_DEFINITION_ENVVAR:
              GET_TEST_PATH_STR(MOCK_PROMPT_PICK_RESPONSE_5_FILE)},
      'stdin': ['instance create CIM_Foo -p InstanceID=blah',
                'instance get CIM_Foo.?',
                'instance delete CIM_Foo.?']},
     {'stdout': ['CIM_Foo',
                 'instance of CIM_Foo',
                 'InstanceID = "blah"'],
      'rc': 0,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command create, new instance of all_types '
     'with scalar types',
     ['create', 'PyWBEM_AllTypes',
      '-p', 'InstanceID=BunchOfValues',
      '-p', 'scalBool=true', '-p', 'scalUint8=1',
      '-p', 'scalUint16=9', '-p', 'scalSint16=-9',
      '-p', 'scalUint32=999', '-p', 'scalSint32=-999',
      '-p', 'scalSint64=-9999',
      '-p', 'scalUint64=9999',
      '-p', 'scalString="test\"embedded\"quote"',
      '-p', 'scalDateTime=19991224120000.000000+360'],
     {'stdout': 'root/cimv2:PyWBEM_AllTypes.InstanceId="BunchOfValues"',
      'rc': 0,
      'test': 'lines'},
     ALLTYPES_MOCK_FILE, OK],

    ['Verify instance command create, new instance of all_types '
     "with array values",
     ['create', 'PyWBEM_AllTypes',
      '-p', 'InstanceID=blah',
      '-p', 'arrayBool=true,false',
      '-p', 'arrayUint8=1,2,3',
      '-p', 'arraySint8=-1,-2,-3',
      '-p', 'arrayUint16=9,19',
      '-p', 'arrayUint32=0,99,999', '-p', 'arraySint32=0,-999,-999',
      '-p', 'arrayUint64=0,999,9999', '-p', 'arraySint64=-9999,0,9999',
      '-p', 'scalString="abc", "def", "jhijk"'],
     {'stdout': 'root/cimv2:PyWBEM_AllTypes.InstanceId="blah"',
      'rc': 0,
      'test': 'lines'},
     ALLTYPES_MOCK_FILE, OK],

    ['Verify instance command create, new instance Error in Property Type with'
     " array values",
     ['create', 'PyWBEM_AllTypes', '-p', 'InstanceID=blah',
      '-p', 'arrayBool=8,9',
      '-p', 'arrayUint8=1,2,3',
      '-p', 'arraySint8=-1,-2,-3',
      '-p', 'arrayUint16=9,19',
      '-p', 'arrayUint32=0,99,999', '-p', 'arraySint32=0,-999,-999',
      '-p', 'arrayUint64=0,999,9999', '-p', 'arraySint64=-9999,0,9999',
      '-p', 'scalString="abc", "def", "jhijk"'],
     {'stderr': "Error: Type mismatch property 'arrayBool' between expected "
                "type='boolean', array=True and input value='8,9'. "
                'Exception: Invalid boolean value: "8"',
      'rc': 1,
      'test': 'innows'},
     ALLTYPES_MOCK_FILE, OK],

    ['Verify instance command create, new instance already exists',
     ['create', 'PyWBEM_AllTypes', '-p', 'InstanceID=test_instance'],
     {'stderr': ['CIMClass: "PyWBEM_AllTypes" does not exist in ',
                 'namespace "root/cimv2" in WEB server: FakedWBEMConnection'],
      'rc': 1,
      'test': 'regex'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command create, new instance invalid ns',
     ['create', 'PyWBEM_AllTypes', '-p', 'InstanceID=test_instance', '-n',
      'blah'],
     {'stderr': ['CIMError', '3', 'CIM_ERR_INVALID_NAMESPACE'],
      'rc': 1,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command create, new instance invalid class',
     ['create', 'CIM_blah', '-p', 'InstanceID=test_instance'],
     {'stderr': ["CIMClass"],
      'rc': 1,
      'test': 'in'},
     SIMPLE_MOCK_FILE, OK],
    # NOTE: Since the instance creation logic is the same for modify and
    # create instance. The error tests in modify also test the error logic.
    # We have not repeated a bunch of those in for the CreateInstance

    #
    #  instance modify command
    #
    ['Verify instance command modify --help response',
     ['modify', '--help'],
     {'stdout': INSTANCE_MODIFY_HELP_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify instance command modify -h response',
     ['modify', '-h'],
     {'stdout': INSTANCE_MODIFY_HELP_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify instance command modify --help-instancename response',
     ['modify', '--help-instancename'],
     {'stdout': INSTANCE_HELP_INSTANCENAME_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify instance command modify --hi response',
     ['modify', '--hi'],
     {'stdout': INSTANCE_HELP_INSTANCENAME_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify instance command modify, single good change',
     ['modify', 'PyWBEM_AllTypes.InstanceID="test_instance"',
      '-p', 'scalBool=False'],
     {'stdout': "",
      'rc': 0,
      'test': 'linesnows'},
     ALLTYPES_MOCK_FILE, OK],

    ['Verify instance modify, --verbose',
     {'args': ['modify', 'PyWBEM_AllTypes.InstanceID="test_instance"',
               '-p', 'scalBool=False'],
      'general': ['--verbose']},
     {'stdout': ['Modified'],
      'rc': 0,
      'test': 'innows'},
     ALLTYPES_MOCK_FILE, OK],

    ['Verify instance command modify with --key, single good change',
     ['modify', 'PyWBEM_AllTypes', '--key', 'InstanceID=test_instance',
      '-p', 'scalBool=False'],
     {'stdout': "",
      'rc': 0,
      'test': 'linesnows'},
     ALLTYPES_MOCK_FILE, OK],

    ['Verify instance command modify, single good change with verify yes',
     ['modify', 'PyWBEM_AllTypes.InstanceID="test_instance"',
      '-p', 'scalBool=False', '--verify'],
     {'stdout': ['instance of PyWBEM_AllTypes {',
                 'scalBool = false;',
                 '};',
                 'Execute ModifyInstance'],
      'rc': 0,
      'test': 'regex'},
     [ALLTYPES_MOCK_FILE, MOCK_CONFIRM_Y_FILE], OK],

    ['Verify instance command modify, single good change with verify no',
     ['modify', 'PyWBEM_AllTypes.InstanceID="test_instance"',
      '-p', 'scalBool=False', '--verify'],
     {'stdout': ['instance of PyWBEM_AllTypes {',
                 'scalBool = false;',
                 '};',
                 'Execute ModifyInstance',
                 'Request aborted'],
      'rc': 0,
      'test': 'regex'},
     [ALLTYPES_MOCK_FILE, MOCK_CONFIRM_N_FILE], OK],

    ['Verify instance command modify, single good change, explicit --n',
     ['modify', 'PyWBEM_AllTypes.InstanceID="test_instance"', '-n',
      'root/cimv2', '-p', 'scalBool=False'],
     {'stdout': "",
      'rc': 0,
      'test': 'lines'},
     ALLTYPES_MOCK_FILE, OK],

    ['Verify instance command modify, single good change, explicit --namespace',
     ['modify', 'PyWBEM_AllTypes.InstanceID="test_instance"', '--namespace',
      'root/cimv2', '--property', 'scalBool=False'],
     {'stdout': "",
      'rc': 0,
      'test': 'lines'},
     ALLTYPES_MOCK_FILE, OK],

    ['Verify instance command modify, multiple good change',
     ['modify', 'PyWBEM_AllTypes.InstanceID="test_instance"',
      '-p', 'scalBool=False',
      '-p', 'arrayBool=true,false,true',
      '-p', 'arrayUint32=0,99,999, 3', '-p', 'arraySint32=0,-999,-999,9',
      '-p', 'arrayUint64=0,999,9999,3000', '-p', 'arraySint64=-9999,0,9999,4',
      '-p', 'scalString="abc", "def", "jhijk"'],
     {'stdout': "",
      'rc': 0,
      'test': 'lines'},
     ALLTYPES_MOCK_FILE, OK],

    #
    # Instance modify errors
    #
    ['Verify instance command modify, invalid class',
     ['modify', 'PyWBEM_AllTypesxxx.InstanceID="test_instance"',
      '-p', 'scalBool=9'],
     {'stderr': ["CIMClass:", "PyWBEM_AllTypesxxx",
                 "does not exist in WEB server",
                 "FakedUrl"],
      'rc': 1,
      'test': 'regex'},
     ALLTYPES_MOCK_FILE, OK],

    ['Verify instance command modify, single property, Type Error bool',
     ['modify', 'PyWBEM_AllTypes.InstanceID="test_instance"',
      '-p', 'scalBool=9'],
     {'stderr': "Error: Type mismatch property 'scalBool' between expected "
                "type='boolean', array=False and input value='9'. "
                'Exception: Invalid boolean value: "9"',
      'rc': 1,
      'test': 'innows'},
     ALLTYPES_MOCK_FILE, OK],

    ['Verify instance command modify, single property, Fail modifies key',
     ['modify', 'PyWBEM_AllTypes.InstanceId="test_instance"',
      '-p', 'InstanceId=9'],
     {'stderr': ['Server Error modifying instance',
                 'Exception: CIMError:',
                 '4',
                 'CIM_ERR_INVALID_PARAMETER',
                 "'InstanceId'"],
      'rc': 1,
      'test': 'innows'},
     ALLTYPES_MOCK_FILE, OK],

    ['Verify instance command modify, single property, Type Error uint32. '
     'Uses regex because Exception msg different between python 2 and 3',
     ['modify', 'PyWBEM_AllTypes.InstanceID="test_instance"',
      '-p', 'scalUint32=Fred'],
     {'stderr': ["Error: Type mismatch property 'scalUint32' between expected ",
                 "type='uint32', array=False and input value='Fred'. ",
                 "Exception: invalid literal for", "with base 10: 'Fred'"],
      'rc': 1,
      'test': 'regex'},
     ALLTYPES_MOCK_FILE, OK],

    ['Verify instance command modify, single Property arrayness error',
     ['modify', 'PyWBEM_AllTypes.InstanceID="test_instance"',
      '-p', 'scalBool=False,True'],
     {'stderr': "Error: Type mismatch property 'scalBool' between expected "
                "type='boolean', array=False and input value='False,True'. "
                'Exception: Invalid boolean value: "False,True"',
      'rc': 1,
      'test': 'innows'},
     ALLTYPES_MOCK_FILE, OK],

    ['Verify instance command modify, Error value types mismatch with array',
     ['modify', 'PyWBEM_AllTypes.InstanceID="test_instance"',
      '-p', 'arrayBool=9,8'],
     {'stderr': "Error: Type mismatch property 'arrayBool' between expected "
                "type='boolean', array=True and input value='9,8'. "
                'Exception: Invalid boolean value: "9"',
      'rc': 1,
      'test': 'innows'},
     ALLTYPES_MOCK_FILE, OK],

    ['Verify instance command modify, Error different value types',
     ['modify', 'PyWBEM_AllTypes.InstanceID="test_instance"',
      '-p', 'arrayBool=true,8'],
     {'stderr': "Error: Type mismatch property 'arrayBool' between expected "
                "type='boolean', array=True and input value='true,8'. "
                'Exception: Invalid boolean value: "8"',
      'rc': 1,
      'test': 'innows'},
     ALLTYPES_MOCK_FILE, OK],

    ['Verify instance command modify, Error integer out of range',
     ['modify', 'PyWBEM_AllTypes.InstanceID="test_instance"',
      '-p', 'arrayUint32=99999999999999999999999'],
     {'stderr': "Error: Type mismatch property 'arrayUint32' between expected "
                "type='uint32', array=True and input "
                "value='99999999999999999999999'. "
                "Exception: Integer value 99999999999999999999999 is out of "
                "range for CIM datatype uint32",
      'rc': 1,
      'test': 'innows'},
     ALLTYPES_MOCK_FILE, OK],

    ['Verify instance command modify, Error property not in class',
     ['modify', 'PyWBEM_AllTypes.InstanceID="test_instance"',
      '-p', 'blah=9'],
     {'stderr': 'Error: Property name "blah" not in class "PyWBEM_AllTypes".',
      'rc': 1,
      'test': 'innows'},
     ALLTYPES_MOCK_FILE, OK],

    # TODO additional modify error tests required

    #
    #  instance delete command
    #
    ['Verify instance command delete --help response',
     ['delete', '--help'],
     {'stdout': INSTANCE_DELETE_HELP_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify instance command delete -h response',
     ['delete', '-h'],
     {'stdout': INSTANCE_DELETE_HELP_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify instance command delete --help-instancename response',
     ['delete', '--help-instancename'],
     {'stdout': INSTANCE_HELP_INSTANCENAME_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify instance command delete --hi response',
     ['delete', '--hi'],
     {'stdout': INSTANCE_HELP_INSTANCENAME_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify instance command delete, valid delete',
     ['delete', 'CIM_Foo.InstanceID="CIM_Foo1"'],
     {'stdout': '',
      'rc': 0,
      'test': 'lines'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command delete with --key, valid delete',
     ['delete', 'CIM_Foo', '--key', 'InstanceID=CIM_Foo1'],
     {'stdout': '',
      'rc': 0,
      'test': 'lines'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command delete with --key, valid delete, --verbose',
     {'args': ['delete', 'CIM_Foo', '--key', 'InstanceID=CIM_Foo1'],
      'general': ['--verbose']},
     {'stdout': ['Deleted'],
      'rc': 0,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command delete, valid delete, explicit ns',
     ['delete', 'CIM_Foo.InstanceID="CIM_Foo1"', '-n', 'root/cimv2'],
     {'stdout': '',
      'rc': 0,
      'test': 'lines'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command delete, valid delete, explicit ns',
     ['delete', 'CIM_Foo.InstanceID="CIM_Foo1"', '--namespace', 'root/cimv2'],
     {'stdout': '',
      'rc': 0,
      'test': 'lines'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command delete with wildcard keybinding',
     {'general': [],
      'args': ['delete', 'TST_Person.?'],
      'env': {MOCK_DEFINITION_ENVVAR: GET_TEST_PATH_STR(MOCK_PROMPT_0_FILE)}},
     {'stdout':
      ['root/cimv2:TST_Person.name="Mike"'],
      'rc': 0,
      'test': 'in'},
     ASSOC_MOCK_FILE, OK],

    #
    # Delete command error tests
    #
    ['Verify instance command delete, missing instance name',
     ['delete'],
     {'stderr':
      ['Usage: pywbemcli [GENERAL-OPTIONS] instance delete INSTANCENAME', ],
      'rc': 2,
      'test': 'in'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command delete, instance name invalid',
     ['delete', "blah"],
     {'stderr':
      ['Invalid format for an instance path in WBEM URI', ],
      'rc': 1,
      'test': 'in'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command delete, instance name not in repo',
     ['delete', 'CIM_Foo.InstanceID="xxxxx"', '--namespace', 'root/cimv2'],
     {'stderr':
      ["CIMError", "6", "CIM_ERR_NOT_FOUND"],
      'rc': 1,
      'test': 'in'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command delete, namespace not in repo',
     ['delete', 'CIM_Foo.InstanceID=1', '--namespace', 'Argh'],
     {'stderr':
      ["CIMError", "3", "CIM_ERR_INVALID_NAMESPACE"],
      'rc': 1,
      'test': 'in'},
     SIMPLE_MOCK_FILE, OK],

    #
    #  instance references command
    #
    ['Verify instance command references --help response',
     ['references', '--help'],
     {'stdout': INSTANCE_REFERENCES_HELP_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify instance command references -h response',
     ['references', '-h'],
     {'stdout': INSTANCE_REFERENCES_HELP_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify instance command references --help-instancename response',
     ['references', '--help-instancename'],
     {'stdout': INSTANCE_HELP_INSTANCENAME_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify instance command references --hi response',
     ['references', '--hi'],
     {'stdout': INSTANCE_HELP_INSTANCENAME_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify instance command references, returns instances',
     ['references', 'TST_Person.name="Mike"'],
     {'stdout': REF_INSTS,
      'rc': 0,
      'test': 'linesnows'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command references with --key, returns instances',
     ['references', 'TST_Person', '--key', 'name=Mike'],
     {'stdout': REF_INSTS,
      'rc': 0,
      'test': 'linesnows'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command references, returns instances, explicit ns',
     ['references', 'TST_Person.name="Mike"', '-n', 'root/cimv2'],
     {'stdout': REF_INSTS,
      'rc': 0,
      'test': 'linesnows'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command references --no, returns paths',
     ['references', 'TST_Person.name="Mike"', '--no'],
     {'stdout': ['"root/cimv2:TST_FamilyCollection.name=\\"Family2\\"",member',
                 '=\"root/cimv2:TST_Person.name=\\"Mike\\""',
                 FAKEURL_STR + '/root/cimv2:TST_Lineage.InstanceID="MikeSofi"',
                 FAKEURL_STR + '/root/cimv2:TST_Lineage.InstanceID="MikeGabi"',
                 FAKEURL_STR + '/root/cimv2:TST_MemberOfFamilyCollection.family'
                 ],
      'rc': 0,
      'test': 'in'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command references --no, returns paths with result '
     'class valid returns paths',
     ['references', 'TST_Person.name="Mike"', '--no',
      '--result-class', 'TST_Lineage'],
     {'stdout': [FAKEURL_STR + '/root/cimv2:TST_Lineage.InstanceID="MikeSofi"',
                 FAKEURL_STR + '/root/cimv2:TST_Lineage.InstanceID="MikeGabi"'],
      'rc': 0,
      'test': 'in'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command references CIM_Foo with --use-pull yes '
     'and --pull-max-cnt=1',
     {'args': ['references', 'TST_Person.name="Mike"'],
      'general': ['--use-pull', 'yes', '--pull-max-cnt', '1', '--log',
                  'all=stderr']},
     {'stderr': [r'PullInstancesWithPath\(MaxObjectCount=1',
                 r'OpenReferenceInstances\(pull_inst_result_tuple\('
                 'context=',
                 r'TST_MemberOfFamilyCollection',
                 r'TST_Lineage'],
      'test': 'regex'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command reference paths CIM_Foo with --use-pull '
     'yes and --pull-max-cnt=1 and --names-only',
     {'args': ['references', 'TST_Person.name="Mike"', '--names-only'],
      'general': ['--use-pull', 'yes', '--pull-max-cnt', '1', '--log',
                  'all=stderr']},
     {'stderr': [r'PullInstancePaths\(MaxObjectCount=1',
                 r'OpenReferenceInstancePaths\(pull_path_result_tuple\('
                 'context=',
                 r'TST_MemberOfFamilyCollection',
                 r'TST_Lineage'],
      'test': 'regex'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command references -o, returns paths with result '
     'class valid returns paths sorted',
     ['references', 'TST_Person.name="Mike"', '--no',
      '--result-class', 'TST_Lineage'],
     {'stdout': [FAKEURL_STR + '/root/cimv2:TST_Lineage.InstanceID="MikeGabi"',
                 FAKEURL_STR + '/root/cimv2:TST_Lineage.InstanceID="MikeSofi"'],
      'rc': 0,
      'test': 'in'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command references -o, returns paths with result '
     'class short form valid returns paths',
     ['references', 'TST_Person.name="Mike"', '--no',
      '--rc', 'TST_Lineage'],
     {'stdout': [FAKEURL_STR + '/root/cimv2:TST_Lineage.InstanceID="MikeSofi"',
                 FAKEURL_STR + '/root/cimv2:TST_Lineage.InstanceID="MikeGabi"'],
      'rc': 0,
      'test': 'in'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command references --no, returns paths with result '
     'class short form valid returns paths',
     ['references', 'TST_Person.name="Mike"', '--no', '--summary',
      '--rc', 'TST_Lineage'],
     {'stdout': ['2 CIMInstanceName(s) returned'],
      'rc': 0,
      'test': 'lines'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command references --no, returns paths with result '
     'class short form valid returns paths',
     {'args': ['references', 'TST_Person.name="Mike"', '--no', '--summary',
               '--rc', 'TST_Lineage'],
      'general': ['--output-format', 'table']},
     {'stdout': ["""Summary of CIMInstanceName returned
+---------+-----------------+
|   Count | CIM Type        |
|---------+-----------------|
|       2 | CIMInstanceName |
+---------+-----------------+
"""],
      'rc': 0,
      'test': 'linesnows'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command references -s, returns paths with result '
     'class short form valid returns paths',
     ['references', 'TST_Person.name="Mike"', '-s',
      '--rc', 'TST_Lineage'],
     {'stdout': ['2 CIMInstance(s) returned'],
      'rc': 0,
      'test': 'lines'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command references --include-qualifiers',
     ['references', 'TST_Person.name="Mike"', '--include-qualifiers'],
     {'stdout': REF_INSTS,
      'test': 'linesnows'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command references include-qualifiers and '
     ' --use-pull no',
     {'args': ['references', 'TST_Person.name="Mike"', '--include-qualifiers'],
      'general': ['--use-pull', 'no']},
     {'stdout': REF_INSTS,
      'test': 'linesnows'},
     ASSOC_MOCK_FILE, OK],

    # Behavior changed pywbem 0.15.0 to exception rtn
    ['Verify instance command references -o, returns paths with result '
     'class not a real ref returns no paths',
     ['references', 'TST_Person.name="Mike"', '--no',
      '--result-class', 'TST_Lineagex'],
     {'stderr': ["CIMError: 4 (CIM_ERR_INVALID_PARAMETER):",
                 "Class 'TST_Lineagex'"],
      'rc': 1,
      'test': 'innows'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command references with --pl in sorted order',
     {'args': ['references', 'TST_Person.name="Mike"',
               '--rc', 'TST_Lineage', '--pl', 'instanceid,Parent'],
      'general': ['--output-format', 'table']},
     {'stdout': ["""Instances: TST_Lineage
+--------------+----------------------------------------+
| InstanceID   | parent                                 |
|--------------+----------------------------------------|
| "MikeGabi"   | "/root/cimv2:TST_Person.name=\\"Mike\\"" |
| "MikeSofi"   | "/root/cimv2:TST_Person.name=\\"Mike\\"" |
+--------------+----------------------------------------+
"""],
      'rc': 0,
      'test': 'linesnows'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command references with --pl in unsorted order',
     {'args': ['references', 'TST_Person.name="Mike"',
               '--rc', 'TST_Lineage', '--pl', 'Parent,instanceid'],
      'general': ['--output-format', 'table']},
     {'stdout': ["""Instances: TST_Lineage
+----------------------------------------+--------------+
| parent                                 | InstanceID   |
|----------------------------------------+--------------|
| "/root/cimv2:TST_Person.name=\\"Mike\\"" | "MikeGabi"   |
| "/root/cimv2:TST_Person.name=\\"Mike\\"" | "MikeSofi"   |
+----------------------------------------+--------------+
"""],
      'rc': 0,
      'test': 'linesnows'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command references, no instance name',
     ['references'],
     {'stderr': ['Usage: pywbemcli [GENERAL-OPTIONS] instance references '
                 'INSTANCENAME', ],
      'rc': 2,
      'test': 'in'},
     ASSOC_MOCK_FILE, OK],

    # Behavior changed pywbem 0.15.0 to exception rtn
    ['Verify instance command references, invalid instance name',
     ['references', 'TST_Blah.blah="abc"'],
     {'stderr': "",
      'rc': 1,
      'test': 'innows'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command references with wildcard keybinding',
     {'general': [],
      'args': ['references', 'TST_Person.?'],
      'env': {MOCK_DEFINITION_ENVVAR: GET_TEST_PATH_STR(MOCK_PROMPT_0_FILE)}},
     {'stdout':
      ['root/cimv2:TST_Person.name="Mike"',
       'instance of TST_Lineage {',
       'InstanceID = "MikeGabi";',
       'instance of TST_MemberOfFamilyCollection {'],
      'rc': 0,
      'test': 'innows'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command references with query',
     ['references', 'TST_Person.name="Mike"', '--filter-query',
      'InstanceID = 3'],
     {'stdout': REF_INSTS,
      'test': 'linesnows'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command references with query, traditional ops fails',
     {'args': ['references', 'TST_Person.name="Mike"', '--filter-query',
               'InstanceID = 3'],
      'general': ['--use-pull', 'no']},
     {'stderr': ["ValueError:",
                 "References does not support FilterQuery"],
      'rc': 1,
      'test': 'regex'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command references with --output-format text',
     {'args': ['references', 'CIM_Foo.InstanceID="CIM_Foo1"'],
      'general': ['--output-format', 'text']},
     {'stderr': ['Output format "text"', 'not allowed', 'Only CIM formats:',
                 'TABLE formats:'],
      'rc': 1,
      'test': 'innows'},
     SIMPLE_MOCK_FILE, OK],

    # TODO add more invalid references tests

    #
    #  instance associators command
    #
    ['Verify instance command associators --help response',
     ['associators', '--help'],
     {'stdout': INSTANCE_ASSOCIATORS_HELP_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify instance command associators -h response',
     ['associators', '-h'],
     {'stdout': INSTANCE_ASSOCIATORS_HELP_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify instance command associators --help-instancename response',
     ['associators', '--help-instancename'],
     {'stdout': INSTANCE_HELP_INSTANCENAME_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify instance command associators --hi response',
     ['associators', '--hi'],
     {'stdout': INSTANCE_HELP_INSTANCENAME_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify instance command associators, returns instances',
     ['associators', 'TST_Person.name="Mike"'],
     {'stdout': ASSOC_INSTS,
      'rc': 0,
      'test': 'lines'},
     ASSOC_MOCK_FILE, OK],  # returning different property set

    ['Verify instance command associators with --key, returns instances',
     ['associators', 'TST_Person', '--key', 'name=Mike'],
     {'stdout': ASSOC_INSTS,
      'rc': 0,
      'test': 'lines'},
     ASSOC_MOCK_FILE, OK],  # returning different property set

    ['Verify instance command associators, --include-qualifiers',
     ['associators', 'TST_Person.name="Mike"', '--include-qualifiers'],
     {'stdout': ASSOC_INSTS,
      'rc': 0,
      'test': 'lines'},
     ASSOC_MOCK_FILE, OK],  # returning different property set

    ['Verify instance command associators, --include-qualifiers wo pull',
     {'general': ['--use-pull', 'no'],
      'args': ['associators', 'TST_Person.name="Mike"',
               '--include-qualifiers']},
     {'stdout': ASSOC_INSTS,
      'rc': 0,
      'test': 'lines'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command associators -o, returns data',
     ['associators', 'TST_Person.name="Mike"', '--no'],
     {'stdout': [FAKEURL_STR +
                 '/root/cimv2:TST_FamilyCollection.name="Family2"',
                 FAKEURL_STR + '/root/cimv2:TST_Person.name="Gabi"',
                 FAKEURL_STR + '/root/cimv2:TST_Person.name="Sofi"'],
      'rc': 0,
      'test': 'linesnows'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command associators with --pl in sorted order',
     {'args': ['associators', 'TST_Person.name="Mike"',
               '--pl', 'Name,Gender,Likes'],
      'general': ['--output-format', 'table']},
     {'stdout': ["""Instances: TST_FamilyCollection
+-----------+------------+------------+
| name      | gender     | likes      |
|-----------+------------+------------|
| "Family2" |            |            |
| "Gabi"    | 1 (female) | 2 (movies) |
| "Sofi"    | 1 (female) |            |
+-----------+------------+------------+
"""],
      'rc': 0,
      'test': 'linesnows'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command associators with --pl in unsorted order',
     {'args': ['associators', 'TST_Person.name="Mike"',
               '--pl', 'Name,Likes,Gender'],
      'general': ['--output-format', 'table']},
     {'stdout': ["""Instances: TST_FamilyCollection
+-----------+------------+------------+
| name      | likes      | gender     |
|-----------+------------+------------|
| "Family2" |            |            |
| "Gabi"    | 2 (movies) | 1 (female) |
| "Sofi"    |            | 1 (female) |
+-----------+------------+------------+
"""],
      'rc': 0,
      'test': 'linesnows'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command associators CIM_Foo with --use-pull yes '
     'and --pull-max-cnt=1',
     {'args': ['associators', 'TST_Person.name="Mike"'],
      'general': ['--use-pull', 'yes', '--pull-max-cnt', '1', '--log',
                  'all=stderr']},
     {'stderr': [r'PullInstancesWithPath\(MaxObjectCount=1',
                 r'OpenAssociatorInstances\(pull_inst_result_tuple\('
                 'context=',
                 r'TST_Person'],
      'test': 'regex'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command associator paths CIM_Foo with --use-pull '
     'yes and --pull-max-cnt=1 and --names-only',
     {'args': ['associators', 'TST_Person.name="Mike"', '--names-only'],
      'general': ['--use-pull', 'yes', '--pull-max-cnt', '1', '--log',
                  'all=stderr']},
     {'stderr': [r'PullInstancePaths\(MaxObjectCount=1',
                 r'OpenAssociatorInstancePaths\(pull_path_result_tuple\('
                 'context=',
                 r'TST_Person'],
      'test': 'regex'},
     ASSOC_MOCK_FILE, OK],

    # Invalid associators tests

    ['Verify instance command associators, no instance name',
     ['associators'],
     {'stderr': ['Usage: pywbemcli [GENERAL-OPTIONS] instance associators '
                 'INSTANCENAME', ],
      'rc': 2,
      'test': 'in'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command associators with wildcard keybinding',
     ['associators', 'TST_Person.?'],
     {'stdout':
      ['root/cimv2:TST_Person.name="Mike"',
       'instance of TST_FamilyCollection {',
       'name = "family1";',
       '};',
       'instance of TST_Person {',
       'name = "Mike";',
       'likes = { 1, 2 };',
       'gender = 2;',
       '};'],
      'rc': 0,
      'test': 'innows'},
     [ASSOC_MOCK_FILE, MOCK_PROMPT_0_FILE], OK],

    ['Verify instance command associators with query.',
     ['associators', 'TST_Person.name="Mike"', '--filter-query',
      'InstanceID = 3'],
     {'stdout': ASSOC_INSTS,
      'test': 'linesnows'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command associators with query, traditional ops',
     {'args': ['associators', 'TST_Person.name="Mike"', '--filter-query',
               'InstanceID = 3'],
      'general': ['--use-pull', 'no']},
     {'stderr': ["ValueError:",
                 "Associators does not support FilterQuery"],
      'rc': 1,
      'test': 'regex'},
     ASSOC_MOCK_FILE, OK],

    # TODO add more associators error tests

    #
    #  instance count command
    #
    ['Verify instance command count --help response',
     ['count', '--help'],
     {'stdout': INSTANCE_COUNT_HELP_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify instance command count -h response',
     ['count', '-h'],
     {'stdout': INSTANCE_COUNT_HELP_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    # The following use interop ns to avoid warning about namespaces.

    ['Verify instance command count CIM_* sorted, simple model, format table',
     {'args': ['count', 'CIM_*', '--sort'],
      'general': ['--output-format', 'table',
                  '--default-namespace', 'interop']},
     {'stdout': """Count of instances per class
+-------------+-----------------+---------+
| Namespace   | Class           |   count |
|-------------+-----------------+---------|
| interop     | CIM_FooAssoc    |       1 |
| interop     | CIM_FooRef1     |       1 |
| interop     | CIM_FooRef2     |       1 |
| interop     | CIM_Foo_sub_sub |       3 |
| interop     | CIM_Foo_sub     |       4 |
| interop     | CIM_Foo         |       5 |
+-------------+-----------------+---------+
""",
      'rc': 0,
      'test': 'linesnows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command count CIM_*, simple model, format table',
     {'args': ['count', 'CIM_*'],
      'general': ['--output-format', 'table',
                  '--default-namespace', 'interop']},
     {'stdout': """Count of instances per class
+-------------+-----------------+---------+
| Namespace   | Class           |   count |
|-------------+-----------------+---------|
| interop     | CIM_Foo         |       5 |
| interop     | CIM_FooAssoc    |       1 |
| interop     | CIM_FooRef1     |       1 |
| interop     | CIM_FooRef2     |       1 |
| interop     | CIM_Foo_sub     |       4 |
| interop     | CIM_Foo_sub_sub |       3 |
+-------------+-----------------+---------+
""",
      'rc': 0,
      'test': 'linesnows'},
     SIMPLE_MOCK_FILE, OK],

    ['Verify instance command count *, assoc model, format plain',
     {'args': ['count', '*'],
      'general': ['--default-namespace', 'interop', '--output-format',
                  'plain']},
     {'stdout': """Count of instances per class
Namespace    Class                           count
interop      TST_FamilyCollection                2
interop      TST_Lineage                         3
interop      TST_MemberOfFamilyCollection        3
interop      TST_Person                          4
interop      TST_Personsub                       4
""",
      'rc': 0,
      'test': 'linesnows'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command count *Person*, assoc model, default format',
     {'args': ['count', '*Person*'],
      'general': ['--default-namespace', 'interop']},
     {'stdout': """Count of instances per class
Namespace    Class            count
-----------  -------------  -------
interop      TST_Person           4
interop      TST_Personsub        4
""",
      'rc': 0,
      'test': 'linesnows'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command count *TST_* with --association',
     {'args': ['count', '*TST_*', '--association'],
      'general': ['--default-namespace', 'interop', '--output-format',
                  'plain']},
     {'stdout': """Count of instances per class
Namespace    Class            count
interop      TST_Lineage          3
interop      TST_MemberOfFamilyCollection  3
interop      TST_MemberOfFamilyCollectionExp 1
""",
      'rc': 0,
      'test': 'linesnows'},
     QUALIFIER_FILTER_MODEL, OK],

    ['Verify instance command count *TST_* with --experimental',
     {'args': ['count', '*TST_*', '--experimental'],
      'general': ['--default-namespace', 'interop', '--output-format',
                  'plain']},
     {'stdout': """Count of instances per class
Namespace    Class            count
interop      TST_MemberOfFamilyCollectionExp 1
interop      TST_PersonExp        4
""",
      'rc': 0,
      'test': 'linesnows'},
     QUALIFIER_FILTER_MODEL, OK],

    ['Verify instance command count *TST_*,--no-indication, --association',
     {'args': ['count', '*TST_*', '--no-indication', '--association'],
      'general': ['--default-namespace', 'interop', '--output-format',
                  'plain']},
     {'stdout': ['Count of instances per class',
                 'Namespace    Class            count',
                 'interop      TST_Lineage          3',
                 'interop      TST_FamilyCollection  2',
                 'interop      TST_MemberOfFamilyCollection  3',
                 'interop      TST_MemberOfFamilyCollectionExp        1',
                 'interop      TST_Person       4',
                 'interop      TST_PersonExp    4'],
      'rc': 0,
      'test': 'innows'},
     QUALIFIER_FILTER_MODEL, OK],

    #
    #  instance invokemethod tests
    #

    ['Verify instance command invokemethod --help response',
     ['invokemethod', '--help'],
     {'stdout': INSTANCE_INVOKEMETHOD_HELP_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify instance command invokemethod -h response',
     ['invokemethod', '-h'],
     {'stdout': INSTANCE_INVOKEMETHOD_HELP_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify instance command invokemethod --help-instancename response',
     ['invokemethod', '--help-instancename'],
     {'stdout': INSTANCE_HELP_INSTANCENAME_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify instance command invokemethod --hi response',
     ['invokemethod', '--hi'],
     {'stdout': INSTANCE_HELP_INSTANCENAME_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify instance command invokemethod, returnvalue = 0',
     ['invokemethod', ':CIM_Foo.InstanceID="CIM_Foo1"', 'Fuzzy'],
     {'stdout': ['ReturnValue=0'],
      'rc': 0,
      'test': 'lines'},
     [SIMPLE_MOCK_FILE, INVOKE_METHOD_MOCK_FILE], OK],

    ['Verify instance command invokemethod with --key, returnvalue = 0',
     ['invokemethod', 'CIM_Foo', 'Fuzzy', '--key', 'InstanceID=CIM_Foo1'],
     {'stdout': ['ReturnValue=0'],
      'rc': 0,
      'test': 'lines'},
     [SIMPLE_MOCK_FILE, INVOKE_METHOD_MOCK_FILE], OK],

    ['Verify instance command invokemethod with multiple scalar params',
     ['invokemethod', 'CIM_Foo.InstanceID="CIM_Foo1"', 'Fuzzy',
      '-p', 'TestInOutParameter="blah"',
      '-p', 'TestRef=CIM_Foo.InstanceID="CIM_Foo1"'],
     {'stdout': ['ReturnValue=0',
                 'TestInOutParameter=', 'blah',
                 'TestRef=', 'CIM_Foo.InstanceID=', 'CIM_Foo1'],
      'rc': 0,
      'test': 'innows'},
     [SIMPLE_MOCK_FILE, INVOKE_METHOD_MOCK_FILE], OK],

    ['Verify instance command invokemethod with all_types method',
     ['invokemethod', 'Pywbem_Alltypes.InstanceID="test_instance"',
      'AllTypesMethod',
      '-p', 'scalBool=true',
      '-p', 'arrBool=false,true',
      '-p', 'scalUint32=9',
      '-p', 'arrUint32=9,3,255',
      '-p', 'scalString=abcdefjh',
      '-p', 'arrString="abc","def"',
      '-p', 'scalRef=PyWBEM_AllTypes.InstanceID="1"'],
     {'stdout': ['ReturnValue=0',
                 'scalBool=true',
                 'arrBool=false, true',
                 'scalUint32=9',
                 'arrUint32=9, 3, 255',
                 'scalString="abcdefjh"',
                 'arrString=', 'abc', 'def',
                 'scalRef=', 'PyWBEM_AllTypes.InstanceID='],
      'rc': 0,
      'test': 'innows'},
     [ALLTYPES_MOCK_FILE, ALLTYPES_INVOKEMETHOD_MOCK_FILE], OK],

    ['Verify instance command invokemethod fails Invalid Class',
     ['invokemethod', 'CIM_Foox.InstanceID="CIM_Foo1"', 'Fuzzy', '-p',
      'TestInOutParameter="blah"'],
     {'stderr': ["Error: CIMError: 6"],
      'rc': 1,
      'test': 'regex'},
     [SIMPLE_MOCK_FILE, INVOKE_METHOD_MOCK_FILE], OK],

    ['Verify instance command invokemethod fails Method not registered',
     ['invokemethod', 'CIM_Foo.InstanceID="CIM_Foo1"', 'Fuzzy', '-p',
      'TestInOutParameter=blah'],
     {'stderr': ["Error: CIMError: 17"],
      'rc': 1,
      'test': 'in'},
     [SIMPLE_MOCK_FILE], OK],  # pywbem 1.0.0 reports Error 16

    # TODO expand the number of invokemethod tests to include all options
    # in classnametests
    # TODO: Create new method that has all param types and options

    #
    #  instance query command. We have not implemented this command
    #
    ['Verify instance command query --help response',
     ['query', '--help'],
     {'stdout': INSTANCE_QUERY_HELP_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify instance command query -h response',
     ['query', '-h'],
     {'stdout': INSTANCE_QUERY_HELP_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify instance command query execution. Returns error because mock does '
     'not support query',
     ['query', 'Select blah from blah'],
     {'stderr': ['Error: CIMError: 14 (CIM_ERR_QUERY_LANGUAGE_NOT_SUPPORTED): ',
                 "FilterQueryLanguage 'DMTF:CQL' not supported"],
      'rc': 1,
      'test': 'innows'},
     [SIMPLE_MOCK_FILE], OK],

    #
    #   Test the shrub subcommand
    #
    ['Verify instance command shrub, --help response',
     ['shrub', '--help'],
     {'stdout': INSTANCE_SHRUB_HELP_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify instance command shrub, -h response',
     ['shrub', '-h'],
     {'stdout': INSTANCE_SHRUB_HELP_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify instance command shrub --help-instancename response',
     ['shrub', '--help-instancename'],
     {'stdout': INSTANCE_HELP_INSTANCENAME_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    ['Verify instance command shrub --hi response',
     ['shrub', '--hi'],
     {'stdout': INSTANCE_HELP_INSTANCENAME_LINES,
      'rc': 0,
      'test': 'innows'},
     None, OK],

    # Test simple mock association with namespace and host in INSTANCENAME
    ['Verify instance command shrub, INSTANCENAME with host and namespace',
     ['shrub', '//FakedUrl/root/cimv2:TST_Person.name="Mike"', '--fullpath'],
     {'stdout': SIMPLE_SHRUB_TREE,
      'rc': 0,
      'test': 'innows'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command shrub, simple tree, namespace in INSTNAME',
     ['shrub', 'root/cimv2:TST_Person.name="Mike"', '--fullpath'],
     {'stdout': SIMPLE_SHRUB_TREE,
      'rc': 0,
      'test': 'innows'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command shrub, simple tree no namepace',
     ['shrub', 'TST_Person.name="Mike"', '--fullpath'],
     {'stdout': SIMPLE_SHRUB_TREE,
      'rc': 0,
      'test': 'innows'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command shrub, simple tree no namepace. short path',
     ['shrub', 'TST_Person.name="Mike"'],
     {'stdout': SIMPLE_SHRUB_TREE,
      'rc': 0,
      'test': 'innows'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command shrub, simple tree with --role option 1',
     ['shrub', 'TST_Person.name="Mike"', '--role', 'parent'],
     {'stdout': SIMPLE_SHRUB_TREE_ROLE,
      'rc': 0,
      'test': 'innows'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command shrub, simple tree with --role option 2',
     ['shrub', 'TST_Person.name="Mike"', '--role', 'Parent'],
     {'stdout': SIMPLE_SHRUB_TREE_ROLE,
      'rc': 0,
      'test': 'innows'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command shrub, simple tree with --role option err',
     ['shrub', 'TST_Person.name="Mike"', '--role', 'parentx'],
     {'stderr': 'WARNING: Option --role (parentx) not found in roles: '
                '(parent, member). Ignored',
      'stdout': SIMPLE_SHRUB_TREE,
      'rc': 0,
      'test': 'innows'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command shrub, simple tree with --assoc-class option1',
     ['shrub', 'TST_Person.name="Mike"', '--assoc-class', 'TST_Lineage'],
     {'stdout': SIMPLE_SHRUB_TREE_ASSOC_CLASS,
      'rc': 0,
      'test': 'innows'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command shrub, simple tree with --assoc-class option2',
     ['shrub', 'TST_Person.name="Mike"', '--assoc-class', 'tst_lineage'],
     {'stdout': SIMPLE_SHRUB_TREE_ASSOC_CLASS,
      'rc': 0,
      'test': 'innows'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command shrub, simple tree with --assoc-class option err',
     ['shrub', 'TST_Person.name="Mike"', '--assoc-class', 'TST_Lineagex'],
     {'stdout': SIMPLE_SHRUB_TREE,
      'stderr': "WARNING",
      'rc': 0,
      'test': 'innows'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command shrub, simple tree with --result-class option1',
     ['shrub', 'TST_Person.name="Mike"', '--result-class', 'TST_Person'],
     {'stdout': SIMPLE_SHRUB_TREE_RESULT_CLASS,
      'rc': 0,
      'test': 'innows'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command shrub, simple tree with --assoc-class option2',
     ['shrub', 'TST_Person.name="Mike"', '--result-class', 'tst_person'],
     {'stdout': SIMPLE_SHRUB_TREE_RESULT_CLASS,
      'rc': 0,
      'test': 'innows'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command shrub, simple tree with --assoc-class error',
     ['shrub', 'TST_Person.name="Mike"', '--result-class', 'TST_Personx'],
     {'stdout': SIMPLE_SHRUB_TREE_RESULT_CLASS_NO_RTN,
      'rc': 0,
      'test': 'innows'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command shrub, simple table request w ns',
     {'args': ['shrub', 'root/cimv2:TST_Person.name="Mike"',
               '--fullpath'],
      'general': ['--output-format', 'plain']},
     {'stdout': SIMPLE_SHRUB_TABLE1,
      'rc': 0,
      'test': 'innows'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command shrub, simple table; ns in request',
     {'args': ['shrub', 'root/cimv2:TST_Person.name="Mike"'],
      'general': ['--output-format', 'plain']},
     {'stdout': SIMPLE_SHRUB_TABLE1,
      'rc': 0,
      'test': 'innows'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command shrub, simple table; ns/host in request',
     {'args': ['shrub', '//FakedUrl/root/cimv2:TST_Person.name="Mike"'],
      'general': ['--output-format', 'plain']},
     {'stdout': SIMPLE_SHRUB_TABLE1,
      'rc': 0,
      'test': 'innows'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command shrub, simple tree with namespace',
     ['shrub', 'TST_Person.name="Mike"', '--fullpath'],
     {'stdout': SIMPLE_SHRUB_TREE,
      'rc': 0,
      'test': 'innows'},
     ASSOC_MOCK_FILE, OK],

    ['Verify instance command shrub, simple tree without namespace',
     ['shrub', 'TST_Person.name="Mike"', '--fullpath'],
     {'stdout': SIMPLE_SHRUB_TREE,
      'rc': 0,
      'test': 'innows'},
     ASSOC_MOCK_FILE, OK],

    # Test with a complex (ternary) association

    ['Verify instance command shrub, complex table',
     {'args': ['shrub', '/root/cimv2:TST_EP', '--key', 'InstanceID=1',
               '--fullpath'],
      'general': ['--output-format', 'plain']},
     {'stdout': COMPLEX_SHRUB_TABLE,
      'rc': 0,
      'test': 'innows'},
     COMPLEX_ASSOC_MODEL, OK],

    ['Verify instance command shrub, complex table, summary',
     {'args': ['shrub', '/root/cimv2:TST_EP', '--key', 'InstanceID=1',
               '--fullpath', '--summary'],
      'general': ['--output-format', 'plain']},
     {'stdout': COMPLEX_SHRUB_TABLE_SUMMARY,
      'rc': 0,
      'test': 'innows'},
     COMPLEX_ASSOC_MODEL, OK],

    ['Verify instance command shrub, complex tree',
     {'args': ['shrub', 'TST_EP.InstanceID=1', '--fullpath'],
      'general': []},
     {'stdout': COMPLEX_SHRUB_TREE,
      'rc': 0,
      'test': 'innows'},
     COMPLEX_ASSOC_MODEL, OK],

    ['Verify instance command shrub, with reduced terminal width to trigger '
     'path folding',
     {'args': ['shrub', 'root/cimv2:TST_Person.name="Mike"', '--fullpath'],
      'general': ['--output-format', 'plain'],
      'env': {'PYWBEMTOOLS_TERMWIDTH': '80'}},
     {'stdout': SIMPLE_SHRUB_TABLE1,
      'rc': 0,
      'test': 'innows'},
     ASSOC_MOCK_FILE, OK],

    # TODO test results if we have keys that get hidden.  This will require
    # a more complex model with CreationClassName, etc. in paths.

]


class TestSubcmd(CLITestsBase):  # pylint: disable=too-few-public-methods
    """
    Test all of the instance command variations.
    """
    command_group = 'instance'

    @pytest.mark.parametrize(
        "desc, inputs, exp_response, mock, condition", TEST_CASES)
    def test_execute_pywbemcli(self, desc, inputs, exp_response, mock,
                               condition):
        """
        Execute pybemcli with the defined input and test output.
        """
        self.command_test(desc, self.command_group, inputs, exp_response,
                          mock, condition)
