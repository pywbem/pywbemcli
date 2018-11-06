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
Click command definition for the pywbemcli command, the top level command for
the pywbemcli click tool
"""
from __future__ import absolute_import

import os
import click_repl
import click
from prompt_toolkit.history import FileHistory

from pywbem import DEFAULT_CA_CERT_PATHS, LOGGER_SIMPLE_NAMES, \
    LOG_DESTINATIONS, DEFAULT_LOG_DESTINATION, LOG_DETAIL_LEVELS, \
    DEFAULT_LOG_DETAIL_LEVEL

from ._context_obj import ContextObj
from ._common import GENERAL_OPTIONS_METAVAR, OUTPUT_FORMATS
from ._pywbem_server import PywbemServer
from .config import DEFAULT_OUTPUT_FORMAT, DEFAULT_NAMESPACE, \
    PYWBEMCLI_PROMPT, PYWBEMCLI_HISTORY_FILE, DEFAULT_MAXPULLCNT, \
    DEFAULT_CONNECTION_TIMEOUT, MAX_TIMEOUT

from ._connection_repository import get_pywbemcli_servers


__all__ = ['cli']

# Defaults for some options
DEFAULT_TIMESTATS = False
# enable -h as additional help option
CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


# pylint: disable=bad-continuation
@click.group(invoke_without_command=True,
             context_settings=CONTEXT_SETTINGS,
             options_metavar=GENERAL_OPTIONS_METAVAR)
@click.option('-s', '--server', type=str, envvar=PywbemServer.server_envvar,
              help='Hostname or IP address with scheme of the WBEMServer in '
                   ' format [{scheme}://]{host}[:{port}]. Scheme must be '
                   ' "https" or "http" (Default: "https"). Host defines a '
                   ' short or fully qualified DNS hostname, a literal '
                   ' IPV4 address (dotted) or a literal IPV6 address'
                   ' Port (optional) defines a '
                   ' WBEM server protocol to be used (Defaults 5988(HTTP) and '
                   ' 5989 (HTTPS). ' +  # noqa: W504
                   '(EnvVar: {ev}).'.format(ev=PywbemServer.server_envvar))
@click.option('-N', '--name', type=str,
              help='Optional name for the connection.  If the name option '
                   'is not set, the name "default" is used. If the name '
                   'option exists and the server option does not exist '
                   'pywbemcli attempts to retrieve the connection information '
                   'from persistent storage. If the server option exists '
                   'that is used as the connection name')
@click.option('-d', '--default_namespace', type=str,
              envvar=PywbemServer.defaultnamespace_envvar,
              help="Default Namespace to use in the target WBEMServer if no "
                   "namespace is defined in the subcommand"
                   "(EnvVar: PYWBEMCLI_DEFAULT_NAMESPACE)."
                   " " + "(Default: {of}).".format(of=DEFAULT_NAMESPACE))
@click.option('-u', '--user', type=str, envvar=PywbemServer.user_envvar,
              help="User name for the WBEM Server connection. "
                   "(EnvVar: PYWBEMCLI_USER).")
@click.option('-p', '--password', type=str,
              envvar=PywbemServer.password_envvar,
              help="Password for the WBEM Server. Will be requested as part "
                   " of initialization if user name exists and it is not "
                   " provided by this option."
                   "(EnvVar: PYWBEMCLI_PASSWORD ).")
@click.option('-t', '--timeout', type=click.IntRange(0, MAX_TIMEOUT),
              envvar=PywbemServer.timeout_envvar,
              help="Operation timeout for the WBEM Server in seconds. "
                   "(EnvVar: PYWBEMCLI_TIMEOUT). "
                   "Default: " + "%s" % DEFAULT_CONNECTION_TIMEOUT)
@click.option('-n', '--noverify', is_flag=True,
              envvar=PywbemServer.noverify_envvar,
              help='If set, client does not verify server certificate.')
@click.option('-c', '--certfile', type=str, envvar=PywbemServer.certfile_envvar,
              help="Server certfile. Ignored if noverify flag set. "
                   "(EnvVar: PYWBEMCLI_CERTFILE).")
@click.option('-k', '--keyfile', type=str, envvar=PywbemServer.keyfile_envvar,
              help="Client private key file. "
                   "(EnvVar: PYWBEMCLI_KEYFILE).")
@click.option('--ca_certs', type=str, envvar=PywbemServer.ca_certs_envvar,
              help='File or directory containing certificates that will be '
                   'matched against a certificate received from the WBEM '
                   'server. Set the --no-verify-cert option to bypass '
                   'client verification of the WBEM server certificate. '
                   ' (EnvVar: PYWBEMCLI_CA_CERTS).'
                   'Default: Searches for matching certificates in the '
                   'following system directories:'
                   ' ' + ("\n".join("%s" % p for p in DEFAULT_CA_CERT_PATHS)))
@click.option('-o', '--output-format',
              type=click.Choice(OUTPUT_FORMATS),
              help='Output format (Default: {of}). pywbemcli may override '
                   'the format choice depending on the operation since not '
                   'all formats apply to all output data types. For CIM'
                   'structured objects (ex. CIMInstance), the default output '
                   'format is mof'
              .format(of=DEFAULT_OUTPUT_FORMAT))
@click.option('--use-pull_ops', envvar=PywbemServer.use_pull_envvar,
              type=click.Choice(['yes', 'no', 'either']),
              default='either',
              help='Determines whether the pull operations are used for'
                   'the EnumerateInstances, associatorinstances,'
                   'referenceinstances, and ExecQuery operations. '
                   'yes means that pull will be used and if the server '
                   'does not support pull, the operation will fail. '
                   'No choice forces pywbemcli to try only the '
                   'traditional non-pull operations. '
                   'either allows pywbem to try both pull and then '
                   ' traditional operations. '
                   'This choice is acomplished by using the Iter... operations '
                   'as the underlying pywbem api call. '
                   ' The default is either.')
@click.option('--pull-max-cnt', type=int,
              envvar=PywbemServer.pull_max_cnt_envvar,
              default=DEFAULT_MAXPULLCNT,
              help='MaxObjectCount of objects to be returned if pull '
                   'operations are used. This must be  a positive non-zero '
                   'integer. Default is {moc}.'.format(moc=DEFAULT_MAXPULLCNT))
@click.option('-T', '--timestats', is_flag=True,
              help='Show time statistics of WBEM server operations after '
                   ' each command execution.')
@ click.option('-l', '--log', type=str, metavar='COMP=DEST:DETAIL,...',
               envvar=PywbemServer.log_envvar,
               help='Enable logging of CIM Operations and set a component to '
                    'a log level, destination, and detail level\n'
                    '(COMP: [{c}], Default: {cd}) '
                    'DEST: [{d}], Default: {dd}) '
                    'DETAIL:[{dl}], Default: {dll})'
                    .format(c='|'.join(LOGGER_SIMPLE_NAMES),
                            cd='all',
                            d='|'.join(LOG_DESTINATIONS),
                            dd=DEFAULT_LOG_DESTINATION,
                            dl='|'.join(LOG_DETAIL_LEVELS),
                            dll=DEFAULT_LOG_DETAIL_LEVEL))
@click.option('-v', '--verbose', is_flag=True,
              help='Display extra information about the processing.')
@click.option('-m', '--mock-server', type=str, multiple=True,
              # envvar=PywbemServer.mock_server_envvar,
              metavar="FILENAME",
              help='If this option is defined, a mock WBEM server is '
                   'constructed as the target WBEM server and the option value '
                   'defines a MOF or Python file to be used to populate the '
                   'mock repository. This option may be used multiple times '
                   'where each use defines a single file or file_path.'
                   'See the pywbemcli documentation for more information.')
@click.version_option(help="Show the version of this command and exit.")
@click.pass_context
def cli(ctx, server, name, default_namespace, user, password, timeout, noverify,
        certfile, keyfile, ca_certs, output_format, use_pull_ops, pull_max_cnt,
        verbose, mock_server, pywbem_server=None, timestats=None, log=None):
    """
    Command line browser for WBEM Servers. This cli tool implements the
    CIM/XML client APIs as defined in pywbem to make requests to a WBEM
    server. This browser uses subcommands to:

    \b
        * Explore the characteristics of WBEM Servers based on using the
          pywbem client APIs.  It can manage/inspect CIM_Classes and
          CIM_instanceson the server.

    \b
        * In addition it can inspect namespaces and other server information
          and inspect and manage WBEM indication subscriptions.

    The options shown above that can also be specified on any of the
    (sub-)commands as well as the command line.
    """

    # In interactive mode, global options specified in cmd line are used as
    # defaults for interactive commands.
    # This requires being able to determine for each option whether it has been
    # specified and is why global options don't define defaults in the
    # decorators that define them.

    # TODO: ks This should be lazy load.
    pywbemcli_servers = get_pywbemcli_servers()

    if ctx.obj is None:
        # In command mode or processing the command line options in
        # interactive mode. Apply the documented option defaults.
        # Default for output_format is applied in processing since it depends
        # on request (ex. mof for get class vs table for many)
        if default_namespace is None:
            default_namespace = DEFAULT_NAMESPACE

        if timestats is None:
            timestats = DEFAULT_TIMESTATS

        if mock_server:
            assert isinstance(mock_server, tuple)
            new_mock_server = []
            # allow relative or absolute paths
            for fn in mock_server:
                if fn == os.path.basename(fn):
                    new_mock_server.append(os.path.join(os.getcwd(), fn))
                else:
                    new_mock_server.append(fn)
            mock_server = new_mock_server

        if use_pull_ops == 'either':
            use_pull_ops = None
        elif use_pull_ops == 'yes':
            use_pull_ops = True
        elif use_pull_ops == 'no':
            use_pull_ops = False
        else:
            raise click.ClickException('Invalid choice for use_pull_ops %s' %
                                       use_pull_ops)
        if pull_max_cnt is None:
            pull_max_cnt = DEFAULT_MAXPULLCNT

        # Create the PywbemServer object (this contains all of the info
        # for the connection defined by the cmd line input)
        if server or mock_server:
            if not name:
                name = 'default'
            pywbem_server = PywbemServer(server,
                                         default_namespace,
                                         name=name,
                                         user=user,
                                         password=password,
                                         timeout=timeout,
                                         noverify=noverify,
                                         certfile=certfile,
                                         keyfile=keyfile,
                                         ca_certs=ca_certs,
                                         use_pull_ops=use_pull_ops,
                                         pull_max_cnt=pull_max_cnt,
                                         stats_enabled=timestats,
                                         verbose=verbose,
                                         mock_server=mock_server,
                                         log=log)
        else:  # no server and mock_server are None
            if name:
                if name in pywbemcli_servers:
                    pywbem_server = pywbemcli_servers[name]
                else:
                    raise click.ClickException('%s named connection does not '
                                               'exist' % name)
            elif 'default' in pywbemcli_servers:
                pywbem_server = pywbemcli_servers['default']
            else:
                # If no server defined, set None. This allows subcmds that do
                # not require a server executed without the server defined.
                pywbem_server = None

    else:  # ctx.obj exists. Processing an interactive command.
        # Apply the option defaults from the command line options.
        if pywbem_server is None:
            pywbem_server = ctx.obj.pywbem_server
        if output_format is None:
            output_format = ctx.obj.output_format
        if verbose is None:
            verbose = ctx.obj.verbose
        if timestats is None:
            timestats = ctx.obj.timestats

    # Create a command context for each command: An interactive command has
    # its own command context different from the command context for the
    # command line.

    ctx.obj = ContextObj(pywbem_server, output_format, use_pull_ops,
                         pull_max_cnt, timestats, verbose)

    # Invoke default command
    if ctx.invoked_subcommand is None:
        ctx.invoke(repl)


@cli.command('help')
@click.pass_context
def repl_help(ctx):  # pylint: disable=unused-argument
    """
    Show help message for interactive mode.
    """
    print("""
The following can be entered in interactive mode:

  <pywbemcli-cmd>             Execute pywbemcli command <pywbemcli-cmd>.
  !<shell-cmd>                Execute shell command <shell-cmd>.

  <CTRL-D>, :q, :quit, :exit  Exit interactive mode.

  <TAB>                       Tab completion (can be used anywhere).
  -h, --help                  Show pywbemcli general help message, including a
                              list of pywbemcli commands.
  <pywbemcli-cmd> --help      Show help message for pywbemcli command
                              <pywbemcli-cmd>.
  help                        Show this help message.
  :?, :h, :help               Show help message about interactive mode.
  <up-arrow, down-arrow>      View pwbemcli command history:
""")


@cli.command('repl')
@click.pass_context
def repl(ctx):
    """
    Enter interactive (REPL) mode (default).

    Enters the interactive mode where subcommands can be entered interactively
    and load the command history file.

    If no options are specified on the command line,  the interactive mode
    is entered. The prompt is changed to `pywbemcli>' in the interactive
    mode.

    Pywbemcli may be terminated form this mode by entering
    <CTRL-D>, :q, :quit, :exit

    Parameters:

      ctx (:class:`click.Context`): The click context object. Created by the
        ``@click.pass_context`` decorator.
    """

    history_file = PYWBEMCLI_HISTORY_FILE
    if history_file.startswith('~'):
        history_file = os.path.expanduser(history_file)

    print("Enter 'help' for help, <CTRL-D> or ':q' to exit pywbemcli.")

    prompt_kwargs = {
        'message': PYWBEMCLI_PROMPT,
        'history': FileHistory(history_file),
    }
    click_repl.repl(ctx, prompt_kwargs=prompt_kwargs)
