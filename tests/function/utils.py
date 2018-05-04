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
Utilities to exercise pywbemcli both as a separate executable and in line with
a direct call.
"""

from __future__ import absolute_import, print_function

import sys
import os
import re
import tempfile
from copy import copy
from subprocess import Popen, PIPE
import six

from pywbemcli.pywbemcli import cli


def execute_pywbemcli(args, env=None):
    """
    Invoke the 'pywbemcli' command as a child process.

    This requires that the 'pywbemcli' command is installed in the current
    Python environment.

    Parameters:

      args (iterable of :term:`string`): Command line arguments, without the
        command name.
        Each single argument must be its own item in the iterable; combining
        the arguments into a string does not work.
        The arguments may be binary strings encoded in UTF-8, or unicode
        strings.

      env (dict): Environment variables to be put into the environment when
        calling the command. May be `None`. Dict key is the variable name as a
        :term:`string`; dict value is the variable value as a :term:`string`
        (without any shell escaping needed).

    Returns:

      tuple(rc, stdout, stderr): Output of the command, where:

        * rc(int): Exit code of the command.
        * stdout(:term:`unicode string`): Standard output of the command,
          as a unicode string with newlines represented as '\\n'.
          An empty string, if there was no data.
        * stderr(:term:`unicode string`): Standard error of the command,
          as a unicode string with newlines represented as '\\n'.
          An empty string, if there was no data.
    """

    cli_cmd = u'pywbemcli'

    if env is None:
        env = {}
    else:
        env = copy(env)

    # Unset pywbemcli env variables
    if 'PYWBEMCLI_HOST' not in env:
        env['PYWBEMCLI_HOST'] = None

    env['PYTHONPATH'] = '.'  # Use local files
    env['PYTHONWARNINGS'] = ''  # Disable for parsing output

    # Put the env vars into the environment of the current Python process,
    # from where they will be inherited into its child processes (-> shell ->
    # cli command).
    for name in env:
        value = env[name]
        if value is None:
            if name in os.environ:
                del os.environ[name]
        else:
            os.environ[name] = value

    assert isinstance(args, (list, tuple))
    cmd_args = [cli_cmd]
    for arg in args:
        if not isinstance(arg, six.text_type):
            arg = arg.decode('utf-8')
        cmd_args.append(arg)

    # print('cmd_args %s' % cmd_args)

    # Note that the click package on Windows writes '\n' at the Python level
    # as '\r\n' at the level of the shell. Some other layer (presumably the
    # Windows shell) contriubutes another such translation, so we end up with
    # '\r\r\n' for each '\n'. Using universal_newlines=True undoes all of that.
    proc = Popen(cmd_args, shell=False, stdout=PIPE, stderr=PIPE,
                 universal_newlines=True)
    stdout_str, stderr_str = proc.communicate()
    rc = proc.returncode

    if isinstance(stdout_str, six.binary_type):
        stdout_str = stdout_str.decode('utf-8')
    if isinstance(stderr_str, six.binary_type):
        stderr_str = stderr_str.decode('utf-8')

    return rc, stdout_str, stderr_str


def call_pywbemcli_inline(args, env=None):
    """
    Invoke the Python code of the `pywbemcli` command in the current Python
    process.

    Does not require that the `pywbemcli` command is installed in the
    current Python environment.

    Parameters:

      args (iterable of :term:`string`): Command line arguments, without the
        command name.
        Each single argument must be its own item in the iterable; combining
        the arguments into a string as a single argument does not work.

        ex. pywbemcli -s http://localhost class get CIM_blah becomes:
            ['-s' 'http://fred', '-t', '1', 'class', 'get',  'CIM_blah']

        The arguments may be binary strings encoded in UTF-8, or unicode
        strings.

      env (dict): Environment variables to be put into the environment when
        calling the command. May be `None`. Dict key is the variable name as a
        :term:`string`; dict value is the variable value as a :term:`string`,
        (without any shell escaping needed).

    Returns:

      tuple(rc, stdout, stderr): Output of the command, where:

        * rc(int): Exit code of the command.
        * stdout(:term:`unicode string`): Standard output of the command,
          as a unicode string with newlines represented as '\\n'.
          An empty string, if there was no data.
        * stderr(:term:`unicode string`): Standard error of the command,
          as a unicode string with newlines represented as '\\n'.
          An empty string, if there was no data.
    """

    cli_cmd = u'pywbemcli'

    if env is None:
        env = {}
    else:
        env = copy(env)

    env['PYTHONPATH'] = '.'  # Use local files
    env['PYTHONWARNINGS'] = ''  # Disable for parsing output

    # Put the env vars into the environment of the current Python process.
    # The cli command code runs in the current Python process.
    for name in env:
        value = env[name]
        if value is None:
            if name in os.environ:
                del os.environ[name]
        else:
            os.environ[name] = value

    assert isinstance(args, (list, tuple))
    sys.argv = [cli_cmd]
    for arg in args:
        if not isinstance(arg, six.text_type):
            arg = arg.decode('utf-8')
        sys.argv.append(arg)

    # print('sys.argv %s' % sys.argv)

    # In Python 3.6, the string type must match the file mode
    # (bytes/binary and str/text). sys.std* is open in text mode,
    # so we need to open the temp file also in text mode.
    with tempfile.TemporaryFile(mode='w+t') as tmp_stdout:
        saved_stdout = sys.stdout
        sys.stdout = tmp_stdout

        with tempfile.TemporaryFile(mode='w+t') as tmp_stderr:
            saved_stderr = sys.stderr
            sys.stderr = tmp_stderr

            exit_rcs = []  # Mutable object for storing sys.exit() rcs.

            def local_exit(rc):
                exit_rcs.append(rc)

            saved_exit = sys.exit
            sys.exit = local_exit

            cli_rc = cli()

            if len(exit_rcs) > 0:
                # The click command function called sys.exit(). This should
                # always be the case for pywbemcli.

                # When --help is specified, click invokes the specified
                # subcommand without args when run in py.test (for whatever
                # reason...). As a consequence, sys.exit() is called an extra
                # time. We use the rc passed into the first invocation.
                rc = exit_rcs[0]
            else:
                # The click command function returned and did not call
                # sys.exit(). That can be done with click, but should not be
                # the case with pywbemcli. We still handle that, just in case.
                rc = cli_rc

            sys.exit = saved_exit

            sys.stderr = saved_stderr
            tmp_stderr.flush()
            tmp_stderr.seek(0)
            stderr_str = tmp_stderr.read()

        sys.stdout = saved_stdout
        tmp_stdout.flush()
        tmp_stdout.seek(0)
        stdout_str = tmp_stdout.read()

    if isinstance(stdout_str, six.binary_type):
        stdout_str = stdout_str.decode('utf-8')
    if isinstance(stderr_str, six.binary_type):
        stderr_str = stderr_str.decode('utf-8')

    # Note that the click package on Windows writes '\n' at the Python level
    # as '\r\n' at the level of the shell, so we need to undo that.
    stdout_str = stdout_str.replace('\r\n', '\n')
    stderr_str = stderr_str.replace('\r\n', '\n')

    return rc, stdout_str, stderr_str


def assert_rc(exp_rc, rc, stdout, stderr):
    """
    Assert that the specified return code is as expected.

    The actual return code is compared with the expected return code,
    and if they don't match, stdout and stderr are displayed as a means
    to help debugging the issue.

    Parameters:

      exp_rc (int): expected return code.

      rc (int): actual return code.

      stdout (string): stdout of the command, for debugging purposes.

      stderr (string): stderr of the command, for debugging purposes.
    """

    assert exp_rc == rc, \
        "Unexpected exit code (expected {}, got {})\n" \
        "  stdout:\n" \
        "{}\n" \
        "  stderr:\n" \
        "{}". \
        format(exp_rc, rc, stdout, stderr)


def assert_patterns(exp_patterns, lines, meaning):
    """
    Assert that the specified lines match the specified patterns.

    The patterns are matched against the complete line from begin to end,
    even if no begin and end markers are specified in the patterns.

    Parameters:

      exp_patterns (iterable of string): regexp patterns defining the expected
        value for each line.

      lines (iterable of string): the lines to be matched.

      meaning (string): A short descriptive text that identifies the meaning
        of the lines that are matched, e.g. 'stderr'.
    """

    assert len(lines) == len(exp_patterns), \
        "Unexpected number of lines in {}:\n" \
        "  expected patterns:\n" \
        "{}\n" \
        "  actual lines:\n" \
        "{}\n". \
        format(meaning,
               '\n'.join(exp_patterns),
               '\n'.join(lines))

    for i, line in enumerate(lines):
        pattern = exp_patterns[i]
        if not pattern.endswith('$'):
            pattern += '$'
        assert re.match(pattern, line), \
            "Unexpected line {} in {}:\n" \
            "  expected pattern:\n" \
            "{}\n" \
            "  actual line:\n" \
            "{}\n". \
            format(i, meaning, pattern, line)
