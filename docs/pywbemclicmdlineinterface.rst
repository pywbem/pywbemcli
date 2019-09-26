.. Copyright  2017 IBM Corp. and Inova Development Inc.
..
.. Licensed under the Apache License, Version 2.0 (the "License");
.. you may not use this file except in compliance with the License.
.. You may obtain a copy of the License at
..
..    http://www.apache.org/licenses/LICENSE-2.0
..
.. Unless required by applicable law or agreed to in writing, software
.. distributed under the License is distributed on an "AS IS" BASIS,
.. WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
.. See the License for the specific language governing permissions and
.. limitations under the License.
..

.. _`Pywbemcli command line interface`:

Pywbemcli command line interface
================================

This section describes the command line interface of the pywbemcli command
within the pywbemtools package.

Pywbemcli provides a command line interface(CLI) interaction with WBEM servers.

The command line can contain the following components:

* **GENERAL-OPTIONS** - General options; they apply to all commands.
  See :ref:`Using the pywbemcli command line general options` for information
  on the pywbemcli general options.
* **COMMAND-GROUP** - A name of a group of commands.
  See :ref:`Pywbemcli command groups and commands`
* **COMMAND** - A name of a command, normally within a command group.
  There are however some special commands (``repl`` and ``help``) that are not
  in any command group.
* **COMMAND-OPTIONS** - Command options; they apply only to a particular
  command.
* **ARGS** - Arguments for a command.

Options are prefixed with the characters ``-`` for the short form or ``--`` for
the long form (ex. ``-n`` or ``--namespace``). The other components do not
begin with ``-``.

Command groups are named after the objects the commands operate on
(ex. ``class``, ``instance``, ``qualifier``, ``server``).
Commands are named after actions on these objects
(ex. ``get``, ``create``, ``delete``).

For example, the command:

.. code-block:: text

    $ pywbemcli --output-format mof class get CIM_ManagedElement --namespace interop

gets class ``CIM_ManagedElement`` in namespace ``interop`` and displays it in
the MOF output format. The option ``--output-format`` is a general option
and ``--namespace`` is a command option.


.. _`Modes of operation`:

Modes of operation
------------------

Pywbemcli supports two modes of operation:

* `Command mode`_: Executing standalone non-interactive commands.
* `Interactive mode`_: Invoking an interactive pywbemcli shell for typing
  pywbemcli commands.


.. _`Command mode`:

Command mode
------------

In command mode, the pywbemcli command performs its task and terminates
like any other standalone non-interactive command.

This mode is used when the pywbemcli command is invoked with a command or
command group name and arguments/options:

.. code-block:: text

    $ pywbemcli [GENERAL-OPTIONS] [COMMAND-GROUP] COMMAND [COMMAND-OPTIONS] [ARGS]

The following example enumerates classes in the ``root/cimv2`` namespace of the
WBEM server on ``localhost``:

.. code-block:: text

    $ pywbemcli --server http://localhost --default-namespace root/cimv2 --user username class enumerate
    Enter password: <password>
    . . .
    <Returns MOF for the enumerated classes>

In command mode, tab completion is also supported for some command shells, but
must be enabled specifically for each shell.

For example, with a bash shell, enter the following to enable tab completion of
pywbemcli:

.. code-block:: text

    $ eval "$(_PYWBEMCLI_COMPLETE=source pywbemcli)"

Bash tab completion for ``pywbemcli`` is used like any other bash tab
completion:

.. code-block:: text

    $ pywbemcli --<TAB><TAB>
    ... <shows the general options to select from>

    $ pywbemcli <TAB><TAB>
    ... <shows the command groups to select from>

    $ pywbemcli class <TAB><TAB>
    ... <shows the class commands to select from>

Pywbemcli uses the Python
`click package <https://click.palletsprojects.com/en/7.x/>`_
for its command line handling. See
`Bash Complete in the Click documentation <https://click.palletsprojects.com/en/7.x/bashcomplete/>`_
for additional features of the Bash tab completion of pywbemcli.


.. _`Interactive mode`:

Interactive mode
----------------

In interactive mode (also known as :term:`REPL` mode), pywbem provides an
interactive shell environment that allows typing pywbemcli commands, internal
commands (for operating the pywbemcli shell), and external commands (that are
executed in the standard shell of the user).

This pywbemcli shell is started when the ``pywbemcli`` command is invoked
without specifying any command group or command:

.. code-block:: text

    $ pywbemcli [GENERAL-OPTIONS]
    pywbemcli> _

Alternatively, the pywbemcli shell can also be started by specifying the ``repl``
command:

.. code-block:: text

    $ pywbemcli [GENERAL-OPTIONS] repl
    pywbemcli> _

The pywbemcli shell uses the prompt ``pywbemcli>``. The cursor is shown in
the examples above as an underscore (``_``).

The commands and options that can be typed in the pywbemcli shell are the rest
of the command line that would follow the ``pywbemcli`` command in
`command mode`_, as well as internal commands (for operating the pywbemcli
shell), and external commands (that are executed in the standard shell of the
user):

.. code-block:: text

    pywbemcli> [GENERAL-OPTIONS] [COMMAND-GROUP] COMMAND [COMMAND-OPTIONS] [ARGS]

    pywbemcli> :INTERNAL-COMMAND

    pywbemcli> !EXTERNAL-COMMAND

The following example starts a pywbemcli shell in interactive mode,
executes several commands, and exits the shell:

.. code-block:: text

    $ pywbemcli -s http://localhost -d root/cimv2 -u username

    pywbemcli> class enumerate --no
    . . . <Enumeration of class names in the default namespace>

    pywbemcli> class get CIM_System
    . . . <Class CIM_System in the default namespace in MOF format>

    pywbemcli> :q

The pywbemcli shell command ``class get CIM_System`` in the example
above has the same effect as the standalone command:

.. code-block:: text

    $ pywbemcli -s http://localhost -d root/cimv2 -u username class get CIM_System
    . . . <Class CIM_System in the default namespace in MOF format>

The internal commands ``:?``, ``:h``, or ``:help`` display general help
information for external and internal commands:

.. code-block:: text

    > :help
    REPL help:

      External Commands:
        prefix external commands with "!"

      Internal Commands:
        prefix internal commands with ":"
        :?, :h, :help     displays general help information
        :exit, :q, :quit  exits the REPL

In addition to using one of the internal exit commands shown in the help text
above, you can also exit the pywbemcli shell by typing `Ctrl-D` (on Linux,
OS-X and UNIX-like environments on Windows), or `Ctrl-C` (on native Windows).

Typing ``--help`` or ``-h`` in the pywbemcli shell displays general help
information for the pywbemcli commands which includes general options and a
list of the supported command groups and commands without command group.

.. code-block:: text

    $ pywbemcli
    pywbemcli> --help
    Usage: pywbemcli [GENERAL-OPTIONS] COMMAND [ARGS]...
    . . .

    Options:
      -n, --name NAME                 Use the WBEM server ...
      . . .

    Commands:
      class       Command group for CIM classes.
      connection  Command group for WBEM connection definitions.
      . . .

The usage line in this help text shows the usage in command mode. In
interactive mode, the ``pywbemcli`` word is omitted.

Typing ``COMMAND-GROUP --help``,  or ``COMMAND-GROUP -h`` in the pywbemcli shell
displays help information for the specified pywbemcli command group, for
example:

.. code-block:: text

    pywbemcli> class --help
    Usage: pywbemcli class [COMMAND-OPTIONS] COMMAND [ARGS]...
    . . .

    Options:
      -h, --help  Show this message and exit.

    Commands:
      associators   List the classes associated with a class.
      . . .

The pywbemcli shell in the interactive mode supports popup help text
while typing, where the valid choices are shown based upon what was typed so
far, and where an item from the popup list can be picked with <TAB> or with the
cursor keys. It can be used to select from the list of general options. In the
following examples, an underscore ``_`` is shown as the cursor:

.. code-block:: text

    pywbemcli> --_
    --name               Use the WBEM server defined by the WBEM connection ...
    --mock-server        Use a mock WBEM server that is automatically ...
    --server             Use the WBEM server at the specified URL with ...
    . . .

    pywbemcli> cl_
                  class

The pywbemcli shell supports history across multiple invocations of the shell
using <UP-ARROW>, <DOWN-ARROW>.
The pywbemcli history is stored in ``~/.pywbemcli_history``.


.. _`Error handling`:

Error handling
--------------

Pywbemcli terminates with one of the following program exit codes:

* **0 - Success**: The pywbemcli command has succeeded.

* **1 - Error**: In such cases, pywbemcli aborts the requested operation and
  displays one or more human readable error messages on standard error.

  If this happens for a command entered in interactive mode, the pywbemcli shell
  is not terminated; only the command that failed is terminated.

  Examples for errors reported that way:

  * Local system issues, e.g. pywbemcli history file or connections file cannot
    be written to.

  * WBEM server access issues, e.g. pywbemcli cannot connect to or authenticate
    with the WBEM server. This includes CIM errors about failed authentication
    returned by the server.

  * WBEM server operation issues, e.g. pywbemcli attempts to retrieve an
    instance that does not exist, or the WBEM server encountered an internal
    error. This will mostly be caused by CIM errors returned by the server,
    but can also be caused by the pywbemcli code itself.

  * Programming errors in mock Python scripts (see: :ref:`Mock support overview`);
    the error message includes a Python traceback of the error.

* **1 - Python traceback**: In such cases, pywbemcli terminates during its
  processing, and displays the Python stack traceback on standard error.

  If this happens for a command entered in interactive mode, the pywbemcli shell
  also terminates with a program exit code of 1.

  These Python tracebacks should never happen and are always considered a
  reason to open a bug in the
  `pywbemtools issue tracker <https://github.com/pywbem/pywbemtools/issues>`_`.

  Note that an error message with a traceback from a mock Python script does
  not fall into this category and is an issue in that Python script and not
  in pywbemcli.

* **2 - User error**: In such cases, pywbemcli terminates without even
  attempting to perform the requested operation, and displays one or more human
  readable error messages on standard error.

  If this happens for a command entered in interactive mode, the pywbemcli shell
  is not terminated; only the command that failed is terminated.

  Examples for user errors are a missing required command argument, the use of
  an invalid option, or an invalid option argument.

* **2 - Help**: When help is requested (``--help``/``-h`` option or
  ``help command``), pywbemcli displays the requested help text on standard
  output and terminates.

  If this happens for a command entered in interactive mode, the pywbemcli shell
  is not terminated; only the command that displayed the help is terminated.
