# (C) Copyright 2020 IBM Corp.
# (C) Copyright 2020 Inova Development Inc.
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
Unit tests for _pywbemcli_operations module.
"""

from __future__ import absolute_import, print_function

import sys
import os
import glob
import re
import pytest
import pywbem

from pywbemtools.pywbemcli._pywbemcli_operations import PYWBEMCLIFakedConnection
from pywbemtools.pywbemcli._utils import _ensure_unicode, \
    DEFAULT_CONNECTIONS_FILE
from pywbemtools.pywbemcli.mockscripts import DeprecatedSetupWarning, \
    SetupNotSupportedError

from .pytest_extensions import simplified_test_function
from .utils import captured_output

OK = True
FAIL = False
PDB = "pdb"

# Click (as of 7.1.2) raises UnsupportedOperation in click.echo() when
# the pytest capsys fixture is used. That happens only on Windows.
# See Click issue https://github.com/pallets/click/issues/1590. This
# run condition skips the testcases on Windows.
CLICK_ISSUE_1590 = sys.platform == 'win32'

SCRIPT_DIR = os.path.dirname(__file__)
USER_CONNECTIONS_FILE = os.path.join(SCRIPT_DIR, '.test_connections_file.yaml')

# Backup of default connections file
DEFAULT_CONNECTIONS_FILE_BAK = DEFAULT_CONNECTIONS_FILE + \
    '.test_pywbemcli_operations.bak'

# Flag indicating that the new-style setup approach() with a setup() function
# is supported.
NEWSTYLE_SUPPORTED = sys.version_info[0:2] >= (3, 5)


def save_default_connections_file():
    """
    Save the default connections file.
    """
    if os.path.exists(DEFAULT_CONNECTIONS_FILE):
        if os.path.exists(DEFAULT_CONNECTIONS_FILE_BAK):
            os.remove(DEFAULT_CONNECTIONS_FILE_BAK)
        os.rename(DEFAULT_CONNECTIONS_FILE, DEFAULT_CONNECTIONS_FILE_BAK)


def restore_default_connections_file():
    """
    Restore the default connections file.
    """
    if os.path.exists(DEFAULT_CONNECTIONS_FILE_BAK):
        if os.path.exists(DEFAULT_CONNECTIONS_FILE):
            os.remove(DEFAULT_CONNECTIONS_FILE)
        os.rename(DEFAULT_CONNECTIONS_FILE_BAK, DEFAULT_CONNECTIONS_FILE)


def get_mockcache_dir(connection_name):
    """
    Return mock cache directory path for a connection name.

    We assume the connection name is unique across all connection files.
    """
    mockcache_rootdir = os.path.join(os.path.expanduser('~'),
                                     '.pywbemcli_mockcache')
    if os.path.isdir(mockcache_rootdir):
        for _dir in os.listdir(mockcache_rootdir):
            if _dir.endswith('.' + connection_name):
                dir_path = os.path.join(mockcache_rootdir, _dir)
                return dir_path
    raise ValueError


def remove_mockcache(connection_name):
    """
    Remove mock cache for a connection name.
    """
    try:
        mockcache_dir = get_mockcache_dir(connection_name)
    except ValueError:
        return
    file_list = glob.glob(os.path.join(mockcache_dir, '*'))
    for _file in file_list:
        os.remove(_file)
    os.rmdir(mockcache_dir)


# Testcase parameters for simple model with old-style method provider
SIMPLE_V1_OLD_NAMESPACE = pywbem.DEFAULT_NAMESPACE
SIMPLE_V1_OLD_MOCK_FILES = [
    'tests/unit/simple_mock_model.mof',
    'tests/unit/simple_mock_invokemethod_v1old.py',
]
SIMPLE_V1_OLD_EXP_CLASSES = [
    (SIMPLE_V1_OLD_NAMESPACE, 'CIM_Foo'),
    (SIMPLE_V1_OLD_NAMESPACE, 'CIM_Foo_sub'),
    (SIMPLE_V1_OLD_NAMESPACE, 'CIM_Foo_sub_sub'),
    (SIMPLE_V1_OLD_NAMESPACE, 'CIM_Foo_sub2'),
]
SIMPLE_V1_OLD_EXP_PROVIDERS = [
    (SIMPLE_V1_OLD_NAMESPACE, 'CIM_Foo', 'method', 'CIM_FooMethodProvider'),
]

# Testcase parameters for simple model with new-style method provider
SIMPLE_V1_NEW_NAMESPACE = pywbem.DEFAULT_NAMESPACE
SIMPLE_V1_NEW_MOCK_FILES = [
    'tests/unit/simple_mock_model.mof',
    'tests/unit/simple_mock_invokemethod_v1new.py',
]
SIMPLE_V1_NEW_EXP_CLASSES = [
    (SIMPLE_V1_NEW_NAMESPACE, 'CIM_Foo'),
    (SIMPLE_V1_NEW_NAMESPACE, 'CIM_Foo_sub'),
    (SIMPLE_V1_NEW_NAMESPACE, 'CIM_Foo_sub_sub'),
    (SIMPLE_V1_NEW_NAMESPACE, 'CIM_Foo_sub2'),
]
SIMPLE_V1_NEW_EXP_PROVIDERS = [
    (SIMPLE_V1_NEW_NAMESPACE, 'CIM_Foo', 'method', 'CIM_FooMethodProvider'),
]


TESTCASES_BUILD_MOCKENV = [
    # TESTCASES for BuildMockenvMixin.build_mockenv()
    #
    # Each list item is a testcase tuple with these items:
    # * desc: Short testcase description.
    # * kwargs: Keyword arguments for the test function and response:
    #   * test_mode: Test mode, with the following values:
    #     - build: Test build of non-existing cache
    #     - load: Test load of up-to-date cache
    #     - load_rebuild_missing_pklfile: Test load resulting in rebuild due to
    #       missing pkl file
    #     - load_rebuild_missing_md5file: Test load resulting in rebuild due to
    #       missing md5 file
    #     - load_rebuild_changed_moffile: Test load resulting in rebuild due to
    #       changed MOF file
    #     - load_rebuild_changed_pyfile: Test load resulting in rebuild due to
    #       missing mock script
    #   * verbose: verbose flag to be used in test.
    #   * connections_file: Path name of connections file to use.
    #   * default_namespace: Default namespace for the mock connection.
    #   * mock_files: List of file paths of mock scripts and MOF files.
    #   * exp_classes: List of expected classes in mock environment, as
    #     tuple(namespace, classname).
    #   * exp_providers: List of expected providers in mock environment, as
    #     tuple(namespace, classname, provider_type, provider_classname).
    #   * exp_stdout_lines: List of lines expected to be written to stdout
    #     during execution of the code to be tested. Each line is a regexp.
    #   * exp_stderr_lines: List of lines expected to be written to stderr
    #     during execution of the code to be tested. Each line is a regexp.
    # * exp_exc_types: Expected exception type(s), or None.
    # * exp_warn_types: Expected warning type(s), or None.
    # * condition: Boolean condition for testcase to run, or 'pdb' for debugger

    # Testcases with verbose disabled.
    (
        "Mock env with MOF file and old-style mock script, "
        "cache does not exist",
        dict(
            test_mode='build',
            verbose=False,
            connections_file=DEFAULT_CONNECTIONS_FILE,
            default_namespace=SIMPLE_V1_OLD_NAMESPACE,
            mock_files=SIMPLE_V1_OLD_MOCK_FILES,
            exp_classes=SIMPLE_V1_OLD_EXP_CLASSES,
            exp_providers=SIMPLE_V1_OLD_EXP_PROVIDERS,
            exp_stdout_lines=[],
            exp_stderr_lines=[],
        ),
        None, DeprecatedSetupWarning, OK
    ),
    (
        "Mock env with MOF file and old-style mock script, "
        "cache exists, and load succeeds",
        dict(
            test_mode='load',
            verbose=False,
            connections_file=DEFAULT_CONNECTIONS_FILE,
            default_namespace=SIMPLE_V1_OLD_NAMESPACE,
            mock_files=SIMPLE_V1_OLD_MOCK_FILES,
            exp_classes=SIMPLE_V1_OLD_EXP_CLASSES,
            exp_providers=SIMPLE_V1_OLD_EXP_PROVIDERS,
            exp_stdout_lines=[],
            exp_stderr_lines=[],
        ),
        None, DeprecatedSetupWarning, OK
    ),
    (
        "Mock env with MOF file and old-style mock script, "
        "cache exists, but load results in rebuild due to missing pkl file",
        dict(
            test_mode='load_rebuild_missing_pklfile',
            verbose=False,
            connections_file=DEFAULT_CONNECTIONS_FILE,
            default_namespace=SIMPLE_V1_OLD_NAMESPACE,
            mock_files=SIMPLE_V1_OLD_MOCK_FILES,
            exp_classes=SIMPLE_V1_OLD_EXP_CLASSES,
            exp_providers=SIMPLE_V1_OLD_EXP_PROVIDERS,
            exp_stdout_lines=[],
            exp_stderr_lines=[],
        ),
        # This testcase removes the pkl file from the mock cache as a
        # preparation for executing the code to be tested. If the mock env is
        # not cached, there is no pkl file that can be removed, so this
        # testcase is skipped when the mock env cannot be cached.
        None, DeprecatedSetupWarning, NEWSTYLE_SUPPORTED
    ),
    (
        "Mock env with MOF file and old-style mock script, "
        "cache exists, but load results in rebuild due to missing md5 file",
        dict(
            test_mode='load_rebuild_missing_md5file',
            verbose=False,
            connections_file=DEFAULT_CONNECTIONS_FILE,
            default_namespace=SIMPLE_V1_OLD_NAMESPACE,
            mock_files=SIMPLE_V1_OLD_MOCK_FILES,
            exp_classes=SIMPLE_V1_OLD_EXP_CLASSES,
            exp_providers=SIMPLE_V1_OLD_EXP_PROVIDERS,
            exp_stdout_lines=[],
            exp_stderr_lines=[],
        ),
        # This testcase removes the md5 file from the mock cache as a
        # preparation for executing the code to be tested. If the mock env is
        # not cached, there is no md5 file that can be removed, so this
        # testcase is skipped when the mock env cannot be cached.
        None, DeprecatedSetupWarning, NEWSTYLE_SUPPORTED
    ),
    (
        "Mock env with MOF file and old-style mock script, "
        "cache exists, but load results in rebuild due to changed MOF file",
        dict(
            test_mode='load_rebuild_changed_moffile',
            verbose=False,
            connections_file=DEFAULT_CONNECTIONS_FILE,
            default_namespace=SIMPLE_V1_OLD_NAMESPACE,
            mock_files=SIMPLE_V1_OLD_MOCK_FILES,
            exp_classes=SIMPLE_V1_OLD_EXP_CLASSES,
            exp_providers=SIMPLE_V1_OLD_EXP_PROVIDERS,
            exp_stdout_lines=[],
            exp_stderr_lines=[],
        ),
        None, DeprecatedSetupWarning, OK
    ),
    (
        "Mock env with MOF file and old-style mock script, "
        "cache exists, but load results in rebuild due to changed .py file",
        dict(
            test_mode='load_rebuild_changed_pyfile',
            verbose=False,
            connections_file=DEFAULT_CONNECTIONS_FILE,
            default_namespace=SIMPLE_V1_OLD_NAMESPACE,
            mock_files=SIMPLE_V1_OLD_MOCK_FILES,
            exp_classes=SIMPLE_V1_OLD_EXP_CLASSES,
            exp_providers=SIMPLE_V1_OLD_EXP_PROVIDERS,
            exp_stdout_lines=[],
            exp_stderr_lines=[],
        ),
        None, DeprecatedSetupWarning, OK
    ),
    (
        "Mock env with MOF file and new-style mock script, "
        "cache does not exist",
        dict(
            test_mode='build',
            verbose=False,
            connections_file=DEFAULT_CONNECTIONS_FILE,
            default_namespace=SIMPLE_V1_NEW_NAMESPACE,
            mock_files=SIMPLE_V1_NEW_MOCK_FILES,
            exp_classes=SIMPLE_V1_NEW_EXP_CLASSES,
            exp_providers=SIMPLE_V1_NEW_EXP_PROVIDERS,
            exp_stdout_lines=[],
            exp_stderr_lines=[],
        ),
        None if NEWSTYLE_SUPPORTED else SetupNotSupportedError, None, OK
    ),
    (
        "Mock env with MOF file and new-style mock script, "
        "cache exists, and load succeeds",
        dict(
            test_mode='load',
            verbose=False,
            connections_file=DEFAULT_CONNECTIONS_FILE,
            default_namespace=SIMPLE_V1_NEW_NAMESPACE,
            mock_files=SIMPLE_V1_NEW_MOCK_FILES,
            exp_classes=SIMPLE_V1_NEW_EXP_CLASSES,
            exp_providers=SIMPLE_V1_NEW_EXP_PROVIDERS,
            exp_stdout_lines=[],
            exp_stderr_lines=[],
        ),
        None if NEWSTYLE_SUPPORTED else SetupNotSupportedError, None, OK
    ),
    (
        "Mock env with MOF file and new-style mock script, "
        "cache exists, but load results in rebuild due to missing pkl file",
        dict(
            test_mode='load_rebuild_missing_pklfile',
            verbose=False,
            connections_file=DEFAULT_CONNECTIONS_FILE,
            default_namespace=SIMPLE_V1_NEW_NAMESPACE,
            mock_files=SIMPLE_V1_NEW_MOCK_FILES,
            exp_classes=SIMPLE_V1_NEW_EXP_CLASSES,
            exp_providers=SIMPLE_V1_NEW_EXP_PROVIDERS,
            exp_stdout_lines=[],
            exp_stderr_lines=[],
        ),
        None if NEWSTYLE_SUPPORTED else SetupNotSupportedError, None, OK
    ),
    (
        "Mock env with MOF file and new-style mock script, "
        "cache exists, but load results in rebuild due to missing md5 file",
        dict(
            test_mode='load_rebuild_missing_md5file',
            verbose=False,
            connections_file=DEFAULT_CONNECTIONS_FILE,
            default_namespace=SIMPLE_V1_NEW_NAMESPACE,
            mock_files=SIMPLE_V1_NEW_MOCK_FILES,
            exp_classes=SIMPLE_V1_NEW_EXP_CLASSES,
            exp_providers=SIMPLE_V1_NEW_EXP_PROVIDERS,
            exp_stdout_lines=[],
            exp_stderr_lines=[],
        ),
        None if NEWSTYLE_SUPPORTED else SetupNotSupportedError, None, OK
    ),
    (
        "Mock env with MOF file and new-style mock script, "
        "cache exists, but load results in rebuild due to changed MOF file",
        dict(
            test_mode='load_rebuild_changed_moffile',
            verbose=False,
            connections_file=DEFAULT_CONNECTIONS_FILE,
            default_namespace=SIMPLE_V1_NEW_NAMESPACE,
            mock_files=SIMPLE_V1_NEW_MOCK_FILES,
            exp_classes=SIMPLE_V1_NEW_EXP_CLASSES,
            exp_providers=SIMPLE_V1_NEW_EXP_PROVIDERS,
            exp_stdout_lines=[],
            exp_stderr_lines=[],
        ),
        None if NEWSTYLE_SUPPORTED else SetupNotSupportedError, None, OK
    ),
    (
        "Mock env with MOF file and new-style mock script, "
        "cache exists, but load results in rebuild due to changed .py file",
        dict(
            test_mode='load_rebuild_changed_pyfile',
            verbose=False,
            connections_file=DEFAULT_CONNECTIONS_FILE,
            default_namespace=SIMPLE_V1_NEW_NAMESPACE,
            mock_files=SIMPLE_V1_NEW_MOCK_FILES,
            exp_classes=SIMPLE_V1_NEW_EXP_CLASSES,
            exp_providers=SIMPLE_V1_NEW_EXP_PROVIDERS,
            exp_stdout_lines=[],
            exp_stderr_lines=[],
        ),
        None if NEWSTYLE_SUPPORTED else SetupNotSupportedError, None, OK
    ),

    # Testcases with verbose enabled.
    (
        "Mock env with MOF file and old-style mock script, "
        "cache does not exist",
        dict(
            test_mode='build',
            verbose=True,
            connections_file=DEFAULT_CONNECTIONS_FILE,
            default_namespace=SIMPLE_V1_OLD_NAMESPACE,
            mock_files=SIMPLE_V1_OLD_MOCK_FILES,
            exp_classes=SIMPLE_V1_OLD_EXP_CLASSES,
            exp_providers=SIMPLE_V1_OLD_EXP_PROVIDERS,
            exp_stdout_lines=[
                b"Mock environment .* will be built because it was not cached.",
                b"Mock environment .* has been written to cache.",
            ] if NEWSTYLE_SUPPORTED else [
                b"Mock environment .* will be built because it was not cached.",
                b"Mock environment .* will be built because it is not "
                b"cacheable",
            ],
            exp_stderr_lines=[],
        ),
        None, DeprecatedSetupWarning, not CLICK_ISSUE_1590
    ),
    (
        "Mock env with MOF file and old-style mock script, "
        "cache exists, and load succeeds",
        dict(
            test_mode='load',
            verbose=True,
            connections_file=DEFAULT_CONNECTIONS_FILE,
            default_namespace=SIMPLE_V1_OLD_NAMESPACE,
            mock_files=SIMPLE_V1_OLD_MOCK_FILES,
            exp_classes=SIMPLE_V1_OLD_EXP_CLASSES,
            exp_providers=SIMPLE_V1_OLD_EXP_PROVIDERS,
            exp_stdout_lines=[
                b"Mock environment .* will be rebuilt because it is not "
                b"cacheable",
            ] if NEWSTYLE_SUPPORTED else [
                b"Mock environment .* will be built because it was not cached.",
                b"Mock environment .* will be built because it is not "
                b"cacheable",
            ],
            exp_stderr_lines=[],
        ),
        None, DeprecatedSetupWarning, not CLICK_ISSUE_1590
    ),
    (
        "Mock env with MOF file and old-style mock script, "
        "cache exists, but load results in rebuild due to missing pkl file",
        dict(
            test_mode='load_rebuild_missing_pklfile',
            verbose=True,
            connections_file=DEFAULT_CONNECTIONS_FILE,
            default_namespace=SIMPLE_V1_OLD_NAMESPACE,
            mock_files=SIMPLE_V1_OLD_MOCK_FILES,
            exp_classes=SIMPLE_V1_OLD_EXP_CLASSES,
            exp_providers=SIMPLE_V1_OLD_EXP_PROVIDERS,
            exp_stdout_lines=[  # Only NEWSTYLE_SUPPORTED
                b"Mock environment .* will be built because it was not cached.",
                b"Mock environment .* has been written to cache.",
            ],
            exp_stderr_lines=[],
        ),
        # This testcase removes the pkl file from the mock cache as a
        # preparation for executing the code to be tested. If the mock env is
        # not cached, there is no pkl file that can be removed, so this
        # testcase is skipped when the mock env cannot be cached.
        None, DeprecatedSetupWarning,
        NEWSTYLE_SUPPORTED and not CLICK_ISSUE_1590
    ),
    (
        "Mock env with MOF file and old-style mock script, "
        "cache exists, but load results in rebuild due to missing md5 file",
        dict(
            test_mode='load_rebuild_missing_md5file',
            verbose=True,
            connections_file=DEFAULT_CONNECTIONS_FILE,
            default_namespace=SIMPLE_V1_OLD_NAMESPACE,
            mock_files=SIMPLE_V1_OLD_MOCK_FILES,
            exp_classes=SIMPLE_V1_OLD_EXP_CLASSES,
            exp_providers=SIMPLE_V1_OLD_EXP_PROVIDERS,
            exp_stdout_lines=[  # Only NEWSTYLE_SUPPORTED
                b"Mock environment .* will be built because it was not cached.",
                b"Mock environment .* has been written to cache.",
            ],
            exp_stderr_lines=[],
        ),
        # This testcase removes the md5 file from the mock cache as a
        # preparation for executing the code to be tested. If the mock env is
        # not cached, there is no md5 file that can be removed, so this
        # testcase is skipped when the mock env cannot be cached.
        None, DeprecatedSetupWarning,
        NEWSTYLE_SUPPORTED and not CLICK_ISSUE_1590
    ),
    (
        "Mock env with MOF file and old-style mock script, "
        "cache exists, but load results in rebuild due to changed MOF file",
        dict(
            test_mode='load_rebuild_changed_moffile',
            verbose=True,
            connections_file=DEFAULT_CONNECTIONS_FILE,
            default_namespace=SIMPLE_V1_OLD_NAMESPACE,
            mock_files=SIMPLE_V1_OLD_MOCK_FILES,
            exp_classes=SIMPLE_V1_OLD_EXP_CLASSES,
            exp_providers=SIMPLE_V1_OLD_EXP_PROVIDERS,
            exp_stdout_lines=[
                b"Mock environment .* will be rebuilt because the mock files "
                b"have changed.",
                b"Mock environment .* has been written to cache.",
            ] if NEWSTYLE_SUPPORTED else [
                b"Mock environment .* will be built because it was not cached.",
                b"Mock environment .* will be built because it is not "
                b"cacheable",
            ],
            exp_stderr_lines=[],
        ),
        None, DeprecatedSetupWarning, not CLICK_ISSUE_1590
    ),
    (
        "Mock env with MOF file and old-style mock script, "
        "cache exists, but load results in rebuild due to changed .py file",
        dict(
            test_mode='load_rebuild_changed_pyfile',
            verbose=True,
            connections_file=DEFAULT_CONNECTIONS_FILE,
            default_namespace=SIMPLE_V1_OLD_NAMESPACE,
            mock_files=SIMPLE_V1_OLD_MOCK_FILES,
            exp_classes=SIMPLE_V1_OLD_EXP_CLASSES,
            exp_providers=SIMPLE_V1_OLD_EXP_PROVIDERS,
            exp_stdout_lines=[
                b"Mock environment .* will be rebuilt because the mock files "
                b"have changed.",
                b"Mock environment .* has been written to cache.",
            ] if NEWSTYLE_SUPPORTED else [
                b"Mock environment .* will be built because it was not cached.",
                b"Mock environment .* will be built because it is not "
                b"cacheable",
            ],
            exp_stderr_lines=[],
        ),
        None, DeprecatedSetupWarning, not CLICK_ISSUE_1590
    ),
    (
        "Mock env with MOF file and new-style mock script, "
        "cache does not exist",
        dict(
            test_mode='build',
            verbose=True,
            connections_file=DEFAULT_CONNECTIONS_FILE,
            default_namespace=SIMPLE_V1_NEW_NAMESPACE,
            mock_files=SIMPLE_V1_NEW_MOCK_FILES,
            exp_classes=SIMPLE_V1_NEW_EXP_CLASSES,
            exp_providers=SIMPLE_V1_NEW_EXP_PROVIDERS,
            exp_stdout_lines=[
                b"Mock environment .* will be built because it was not cached.",
                b"Mock environment .* has been written to cache.",
            ],
            exp_stderr_lines=[],
        ),
        None if NEWSTYLE_SUPPORTED else SetupNotSupportedError, None,
        not CLICK_ISSUE_1590

    ),
    (
        "Mock env with MOF file and new-style mock script, "
        "cache exists, and load succeeds",
        dict(
            test_mode='load',
            verbose=True,
            connections_file=DEFAULT_CONNECTIONS_FILE,
            default_namespace=SIMPLE_V1_NEW_NAMESPACE,
            mock_files=SIMPLE_V1_NEW_MOCK_FILES,
            exp_classes=SIMPLE_V1_NEW_EXP_CLASSES,
            exp_providers=SIMPLE_V1_NEW_EXP_PROVIDERS,
            exp_stdout_lines=[  # Only NEWSTYLE_SUPPORTED
                b"Mock environment .* has been loaded from cache.",
            ],
            exp_stderr_lines=[],
        ),
        None if NEWSTYLE_SUPPORTED else SetupNotSupportedError, None,
        not CLICK_ISSUE_1590
    ),
    (
        "Mock env with MOF file and new-style mock script, "
        "cache exists, but load results in rebuild due to missing pkl file",
        dict(
            test_mode='load_rebuild_missing_pklfile',
            verbose=True,
            connections_file=DEFAULT_CONNECTIONS_FILE,
            default_namespace=SIMPLE_V1_NEW_NAMESPACE,
            mock_files=SIMPLE_V1_NEW_MOCK_FILES,
            exp_classes=SIMPLE_V1_NEW_EXP_CLASSES,
            exp_providers=SIMPLE_V1_NEW_EXP_PROVIDERS,
            exp_stdout_lines=[  # Only NEWSTYLE_SUPPORTED
                b"Mock environment .* will be built because it was not cached.",
                b"Mock environment .* has been written to cache.",
            ],
            exp_stderr_lines=[],
        ),
        None if NEWSTYLE_SUPPORTED else SetupNotSupportedError, None,
        not CLICK_ISSUE_1590
    ),
    (
        "Mock env with MOF file and new-style mock script, "
        "cache exists, but load results in rebuild due to missing md5 file",
        dict(
            test_mode='load_rebuild_missing_md5file',
            verbose=True,
            connections_file=DEFAULT_CONNECTIONS_FILE,
            default_namespace=SIMPLE_V1_NEW_NAMESPACE,
            mock_files=SIMPLE_V1_NEW_MOCK_FILES,
            exp_classes=SIMPLE_V1_NEW_EXP_CLASSES,
            exp_providers=SIMPLE_V1_NEW_EXP_PROVIDERS,
            exp_stdout_lines=[  # Only NEWSTYLE_SUPPORTED
                b"Mock environment .* will be built because it was not cached.",
                b"Mock environment .* has been written to cache.",
            ],
            exp_stderr_lines=[],
        ),
        None if NEWSTYLE_SUPPORTED else SetupNotSupportedError, None,
        not CLICK_ISSUE_1590
    ),
    (
        "Mock env with MOF file and new-style mock script, "
        "cache exists, but load results in rebuild due to changed MOF file",
        dict(
            test_mode='load_rebuild_changed_moffile',
            verbose=True,
            connections_file=DEFAULT_CONNECTIONS_FILE,
            default_namespace=SIMPLE_V1_NEW_NAMESPACE,
            mock_files=SIMPLE_V1_NEW_MOCK_FILES,
            exp_classes=SIMPLE_V1_NEW_EXP_CLASSES,
            exp_providers=SIMPLE_V1_NEW_EXP_PROVIDERS,
            exp_stdout_lines=[  # Only NEWSTYLE_SUPPORTED
                b"Mock environment .* will be rebuilt because the mock files "
                b"have changed.",
                b"Mock environment .* has been written to cache.",
            ],
            exp_stderr_lines=[],
        ),
        None if NEWSTYLE_SUPPORTED else SetupNotSupportedError, None,
        not CLICK_ISSUE_1590
    ),
    (
        "Mock env with MOF file and new-style mock script, "
        "cache exists, but load results in rebuild due to changed .py file",
        dict(
            test_mode='load_rebuild_changed_pyfile',
            verbose=True,
            connections_file=DEFAULT_CONNECTIONS_FILE,
            default_namespace=SIMPLE_V1_NEW_NAMESPACE,
            mock_files=SIMPLE_V1_NEW_MOCK_FILES,
            exp_classes=SIMPLE_V1_NEW_EXP_CLASSES,
            exp_providers=SIMPLE_V1_NEW_EXP_PROVIDERS,
            exp_stdout_lines=[  # Only NEWSTYLE_SUPPORTED
                b"Mock environment .* will be rebuilt because the mock files "
                b"have changed.",
                b"Mock environment .* has been written to cache.",
            ],
            exp_stderr_lines=[],
        ),
        None if NEWSTYLE_SUPPORTED else SetupNotSupportedError, None,
        not CLICK_ISSUE_1590
    ),

    # Testcases with non-cacheable user-specified connections file
    (
        "Mock env with user-specified connections file",
        dict(
            test_mode='build',
            verbose=True,
            connections_file=USER_CONNECTIONS_FILE,
            default_namespace=SIMPLE_V1_OLD_NAMESPACE,
            mock_files=SIMPLE_V1_OLD_MOCK_FILES,
            exp_classes=SIMPLE_V1_OLD_EXP_CLASSES,
            exp_providers=SIMPLE_V1_OLD_EXP_PROVIDERS,
            exp_stdout_lines=[
                b"Mock environment .* will be built because user-specified "
                b"connections files are not cached",
            ] if NEWSTYLE_SUPPORTED else [
                b"Mock environment .* will be built because user-specified "
                b"connections files are not cached",
                b"Mock environment .* will be built because it is not "
                b"cacheable",
            ],
            exp_stderr_lines=[],
        ),
        None, None, not CLICK_ISSUE_1590
    ),
]


@pytest.mark.parametrize(
    "desc, kwargs, exp_exc_types, exp_warn_types, condition",
    TESTCASES_BUILD_MOCKENV)
@simplified_test_function
def test_build_mockenv(testcase, test_mode, verbose, connections_file,
                       default_namespace, mock_files, exp_classes,
                       exp_providers, exp_stdout_lines, exp_stderr_lines):
    """
    Test function for BuildMockenvMixin.build_mockenv().
    """

    # The connections file is used by PywbemServer() and its build_mockenv()
    # method only as a file path, and is never actually created or accessed.
    connection_name = 'test_build_mockenv'

    # Make sure the mock cache does not exist
    remove_mockcache(connection_name)

    if connections_file == DEFAULT_CONNECTIONS_FILE:
        save_default_connections_file()

    try:

        if test_mode == 'build':

            conn = PYWBEMCLIFakedConnection(default_namespace=default_namespace)
            server = pywbem.WBEMServer(conn)

            with captured_output() as captured:

                # The code to be tested
                conn.build_mockenv(server, mock_files, connections_file,
                                   connection_name, verbose)

            if NEWSTYLE_SUPPORTED and \
                    connections_file == DEFAULT_CONNECTIONS_FILE:
                mockcache_dir = get_mockcache_dir(connection_name)
                assert os.path.isdir(mockcache_dir)

        elif test_mode == 'load':

            # This test only makes sense when caching is possible
            assert connections_file == DEFAULT_CONNECTIONS_FILE

            conn = PYWBEMCLIFakedConnection(default_namespace=default_namespace)
            server = pywbem.WBEMServer(conn)
            conn.build_mockenv(server, mock_files, connections_file,
                               connection_name, False)

            conn = PYWBEMCLIFakedConnection(default_namespace=default_namespace)
            server = pywbem.WBEMServer(conn)

            with captured_output() as captured:

                # The code to be tested
                conn.build_mockenv(server, mock_files, connections_file,
                                   connection_name, verbose)

        elif test_mode == 'load_rebuild_missing_pklfile':

            # This test only makes sense when caching is possible
            assert connections_file == DEFAULT_CONNECTIONS_FILE

            conn = PYWBEMCLIFakedConnection(default_namespace=default_namespace)
            server = pywbem.WBEMServer(conn)
            conn.build_mockenv(server, mock_files, connections_file,
                               connection_name, False)

            mockcache_dir = get_mockcache_dir(connection_name)
            pkl_file = os.path.join(mockcache_dir, 'mockenv.pkl')
            os.remove(pkl_file)

            conn = PYWBEMCLIFakedConnection(default_namespace=default_namespace)
            server = pywbem.WBEMServer(conn)

            with captured_output() as captured:

                # The code to be tested
                conn.build_mockenv(server, mock_files, connections_file,
                                   connection_name, verbose)

        elif test_mode == 'load_rebuild_missing_md5file':

            # This test only makes sense when caching is possible
            assert connections_file == DEFAULT_CONNECTIONS_FILE

            conn = PYWBEMCLIFakedConnection(default_namespace=default_namespace)
            server = pywbem.WBEMServer(conn)
            conn.build_mockenv(server, mock_files, connections_file,
                               connection_name, False)

            mockcache_dir = get_mockcache_dir(connection_name)
            md5_file = os.path.join(mockcache_dir, 'mockfiles.md5')
            os.remove(md5_file)

            conn = PYWBEMCLIFakedConnection(default_namespace=default_namespace)
            server = pywbem.WBEMServer(conn)

            with captured_output() as captured:

                # The code to be tested
                conn.build_mockenv(server, mock_files, connections_file,
                                   connection_name, verbose)

        elif test_mode == 'load_rebuild_changed_moffile':

            # This test only makes sense when caching is possible
            assert connections_file == DEFAULT_CONNECTIONS_FILE

            conn = PYWBEMCLIFakedConnection(default_namespace=default_namespace)
            server = pywbem.WBEMServer(conn)
            conn.build_mockenv(server, mock_files, connections_file,
                               connection_name, False)

            # Change the MOF file
            mof_file = [mf for mf in mock_files if mf.endswith('.mof')][0]
            mof_size = os.stat(mof_file).st_size
            with open(mof_file, 'a') as fp:
                fp.write('\n// test_build_mockenv: Dummy line\n')

            conn = PYWBEMCLIFakedConnection(default_namespace=default_namespace)
            server = pywbem.WBEMServer(conn)
            try:
                with captured_output() as captured:

                    # The code to be tested
                    conn.build_mockenv(server, mock_files, connections_file,
                                       connection_name, verbose)

            finally:
                # Undo change to the MOF file
                with open(mof_file, 'ab') as fp:
                    fp.truncate(mof_size)

        elif test_mode == 'load_rebuild_changed_pyfile':

            # This test only makes sense when caching is possible
            assert connections_file == DEFAULT_CONNECTIONS_FILE

            conn = PYWBEMCLIFakedConnection(default_namespace=default_namespace)
            server = pywbem.WBEMServer(conn)
            conn.build_mockenv(server, mock_files, connections_file,
                               connection_name, False)

            # Change the mock script file
            py_file = [mf for mf in mock_files if mf.endswith('.py')][0]
            py_size = os.stat(py_file).st_size
            with open(py_file, 'a') as fp:
                fp.write('\n# test_build_mockenv: Dummy line\n')

            conn = PYWBEMCLIFakedConnection(default_namespace=default_namespace)
            server = pywbem.WBEMServer(conn)
            try:
                with captured_output() as captured:

                    # The code to be tested
                    conn.build_mockenv(server, mock_files, connections_file,
                                       connection_name, verbose)

            finally:
                # Undo change to the mock script file
                with open(py_file, 'ab') as fp:
                    fp.truncate(py_size)

    finally:
        # Clean up the mock cache
        remove_mockcache(connection_name)

        if connections_file == DEFAULT_CONNECTIONS_FILE:
            restore_default_connections_file()

    # Ensure that exceptions raised in the remainder of this function
    # are not mistaken as expected exceptions
    assert testcase.exp_exc_types is None

    for ns, cln in exp_classes:
        class_store = conn.cimrepository.get_class_store(ns)
        assert class_store.object_exists(cln)

    for ns, cln, pt, _ in exp_providers:
        # pylint: disable=protected-access
        assert conn._provider_registry.get_registered_provider(ns, pt, cln)

    if captured.stdout == b'':
        stdout_lines = []
    else:
        stdout_lines = captured.stdout.strip(b'\n').split(b'\n')
    assert len(stdout_lines) == len(exp_stdout_lines), \
        "Unexpected number of lines on stdout:\n" \
        "Testcase: {}\n" \
        "---- Actually: {} lines:\n{}" \
        "---- Expected: {} lines (regexp):\n{}" \
        "---- End\n". \
        format(testcase.desc,
               len(stdout_lines),
               ''.join([_ensure_unicode(ln) + '\n'
                        for ln in stdout_lines]),
               len(exp_stdout_lines),
               ''.join([_ensure_unicode(ln) + '\n'
                        for ln in exp_stdout_lines]))
    for i, regexp in enumerate(exp_stdout_lines):
        line = stdout_lines[i]
        assert re.search(regexp, line), \
            "Unexpected line #{} on stdout:\n" \
            "Testcase: {}\n" \
            "---- Actually:\n" \
            "{}\n" \
            "---- Expected (regexp):\n" \
            "{}\n" \
            "---- End\n". \
            format(i + 1, testcase.desc, line, regexp)

    if captured.stderr == b'':
        stderr_lines = []
    else:
        stderr_lines = captured.stderr.strip(b'\n').split(b'\n')
    assert len(stderr_lines) == len(exp_stderr_lines), \
        "Unexpected number of lines on stderr:\n" \
        "Testcase: {}\n" \
        "---- Actually: {} lines:\n{}" \
        "---- Expected: {} lines (regexp):\n{}" \
        "---- End\n". \
        format(testcase.desc,
               len(stderr_lines),
               ''.join([_ensure_unicode(ln) + '\n'
                        for ln in stderr_lines]),
               len(exp_stderr_lines),
               ''.join([_ensure_unicode(ln) + '\n'
                        for ln in exp_stderr_lines]))
    for i, regexp in enumerate(exp_stderr_lines):
        line = stderr_lines[i]
        assert re.search(regexp, line), \
            "Unexpected line #{} on stderr:\n" \
            "Testcase: {}\n" \
            "---- Actually:\n" \
            "{}\n" \
            "---- Expected (regexp):\n" \
            "{}\n" \
            "---- End\n". \
            format(i + 1, testcase.desc, line, regexp)
