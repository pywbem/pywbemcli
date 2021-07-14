"""
Test mock script that installs the pywbem provided namespace provider
CIMNamespaceProvider and the simple Interop and user namespace model
defined in simple_interop_mock_model.mof and then sets the pywbem_mock
server to disable pull operations. This script is used to test the
general options around enabling and disabling pull operations

This mock script sets up a mock_environment with an interop namespace
and a user namespace populaed with the simple_mock_model but with pull
operations disabled so any execution of a pull operation
directly returns a NOT_SUPPORTED error. It is used to test the operation
of the pywbemcli client on servers where pull does not exist.

This mock script uses 'new-style' setup for Python >=3.5 and 'old-style' setup
otherwise, and is therefore useable for all supported Python versions.
On Python <3.5, the tests using this script must be run from the repo main
directory.
"""

import sys
import os
import six
import pywbem_mock

# interop namespace used by this mock environment
INTEROP_NAMESPACE = 'interop'


def register_dependents(conn, this_file_path, dependent_file_names):
    """
    Register a dependent file name with the pywbemcli dependent file api.
    This insures that any change to a dependent file will cause the
    script to be recompiled.
    """
    if isinstance(dependent_file_names, six.string_types):
        dependent_file_names = [dependent_file_names]

    for fn in dependent_file_names:
        dep_path = os.path.join(os.path.dirname(this_file_path), fn)
        conn.provider_dependent_registry.add_dependents(this_file_path,
                                                        dep_path)


def _setup(conn, server, verbose):
    # pylint: disable=unused-argument
    """
    Setup for this mock script.

    Parameters:
      conn (FakedWBEMConnection): Connection
      server (PywbemServer): Server
      verbose (bool): Verbose flag
    """

    if INTEROP_NAMESPACE not in conn.cimrepository.namespaces:
        conn.add_namespace(INTEROP_NAMESPACE)

    conn.disable_pull_operations  # pylint: disable=pointless-statement

    if sys.version_info >= (3, 5):
        this_file_path = __file__
    else:
        # Unfortunately, it does not seem to be possible to find the file path
        # of the current script when it is executed using exec(), so we hard
        # code the file path. This requires that the tests are run from the
        # repo main directory.
        this_file_path = 'tests/unit/pywbemcli/simple_interop_mock_script.py'
        assert os.path.exists(this_file_path)

    mof_file = 'simple_interop_mock_model.mof'
    dependent_files = [mof_file,
                       'mock_interop.mof',
                       'simple_mock_model.mof']
    mof_path = os.path.join(os.path.dirname(this_file_path), mof_file)
    conn.compile_mof_file(mof_path, namespace=None)

    # Disable the pull operations for this test
    conn.disable_pull_operations = True

    register_dependents(conn, this_file_path, dependent_files)
    ns_provider = pywbem_mock.CIMNamespaceProvider(conn.cimrepository)
    conn.register_provider(ns_provider, INTEROP_NAMESPACE, verbose=verbose)


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
