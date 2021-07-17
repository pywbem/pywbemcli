
.. _`Change log`:

Change log
==========


pywbemtools 1.0.0.dev1
----------------------

This version contains all fixes up to version 0.9.x.

Released: not yet

**Incompatible changes:**

* The PYWBEMCLI_TERMWIDTH environment variable was renamed to
  PYWBEMTOOLS_TERMWIDTH since it is common to all pywbemtools commands.

**Deprecations:**

**Bug fixes:**

* Test: Fixed that test_utils.py changed the PYWBEMCLI_TERMWIDTH env var
  for testing purposes without restoring it.

* Fixes issue where the command:
  ``class invokemethod <class> <method> -n <namespace>``
  ignores the command namespace option (-n) and usedsthe default
  namespace. (see issue #990)

* Fix issue where an exception occurs if the user tries to display
  cim instances as a table but the class for the instances returned are not in the
  default namespace and an alternate namespace is defined for the command.
  The function display_cim_objects(...) uses valuemapping_for_property() but
  specifies the default namespace as the target.  (See issue #995)

* Fixed issues raised by new Pylint version 2.9.

**Enhancements:**

* Added a 'pywbemlistener' command for running and managing WBEM listeners.
  (issues #430, #479, #948)

* Implement server schema command that returns information about the schemas
  for each namespace including: 5. the DMTF schemas, 2. schema version, 3. whether
  any classes in the schema/namespace are experimental, and 4) the number of
  classes in this schema, and 5. the DMTF schemas (characters before the `_` in
  the namespace). (see issue #444)


**Cleanup:**

* Prepared the development environment for having more than one pywbemtools
  command. As part of that, moved a number of utility functions from the
  'pywbemtools/pywbemcli' subdirectory to the common 'pywbemtools' directory.

* Moved the environment variable names from being class attributes on the
  PywbemServer class to become constants in the config module. (issue #658)

* Cleanup the test code used as pywbemcli scripts.  Named all of them
  with the last part of the name  _script.py and modified them to use the
  setup initialization with Python 3.6 and greater as well as the old
  script interface.

**Known issues:**

* See `list of open issues`_.

.. _`list of open issues`: https://github.com/pywbem/pywbemtools/issues


pywbemtools 0.9.0
-----------------

This version contains all fixes up to pywbemtools 0.8.1.

Released: 2021-05-03

**Incompatible changes:**

* Modified the --timestats general option from boolean to choice with 3
  choices for when statistics are displayed (after each command or via a
  command). See   issue #588)

**Deprecations:**

* Deprecated the 'server namespaces' and 'server interop' commands. Use the
  new commands 'namespace list' and 'namespace interop', respectively.
  (issue #877)

* The '--force' / '-f' option of the 'class delete' command has been deprecated
  because its name does not sufficiently make it clear that other inhibitors
  than existing instances of the class (such as existing subclasses, or
  referencing classes) will still cause rejection of the command.
  Use the new '--include-instances' option instead. (issue #885)

**Bug fixes:**

* Fixed a ValueError on Windows that was raised when the connections file was
  not on the home drive.

* Limit click package to < 8.0 because of a) incompatibility with python 2.7,
  b) incompatibility between click 8.0 and clicl-repl.
  (see issues #816 and #817)

* Limit mock package to lt 4.0.3 to avoid issue issue that causes test failure.
  (see #822)

* Fix issue caused by mock package version 4.0.3 by creating replacements for
  warnings.warn and warnings.warn_explicit functions  and removing the use of
  the patch decorator in pywbemcli.py before the definition of the cli
  function.  (see issue #822)

* Fixes issue where in pywbemcli the --timeout and --use-pull general
  options were not always correctly included in the new object context in
  interactive mode if they were specified on the interactive mode cmd line.

* Fixed issue in tests with use of stdin and inputting the instance path
  for instance get and instance delete. This was a test setup issue and not
  a code issue. (see issue # 387)

* Mitigated the coveralls HTTP status 422 by pinning coveralls-python to
  <3.0.0.

* Fix issue where documentation index disappeared when we changed the
  documentation theme (see issue #868)

* Test: Fixed behavior of 'pdb' test condition, which is supposed to stop
  in the pdb debugger before executing the command function, but did immediately
  leave the debugger again because of redirections of the standard streams.
  The debugger now properly comes up when 'pdb' is specified as a condition.

* Test: Fixed restoring of environment variables that are modified by testcases,
  and displaying of PYWBEMCLI environment variables during testing in verbose
  mode.

* Change MOFCompiler.add_mof/remove_mof() to only display exceptions received
  if not MOFCompileError since the MOF compiler logs all MOFCompileError
  exceptions. (see issue #395)

**Enhancements:**

* Increased the minimum pywbem version to 1.2.0.

* Add new option to class find command (--summary) to display a summary of
  the counts of classes found instead of the full list of the classes to make
  the command more useful for real servers that may return many classes for
  a class find. (see issue #810)

* Extend the class tree command to optionally provide extra information about
  each class in the tree including 1) the value of the Version qualifier
  if it exists and whether the class is Abstract, an Association, or an
  Indication class. (see. # 817)

* Migrated from Travis and Appveyor to GitHub Actions. This required several
  changes in package dependencies for development.

* The verbose option ('-v' / '--verbose') now also displays the objects that
  are compiled into a mock environment when setting it up.

* Added 'qualifier delete' command. (see #884)

* Enabled the tests for Python 3.4 on Windows again - this required
  some changes in the Makefile and constraints files.

* Added a 'namespace' command group that allows listing, creating and deleting
  CIM namespaces, and showing the Interop namespace. The 'server namespaces'
  and 'server interop' commands that provide a subset of that functionality
  have been deprecated. (issue #877)

* Added commands 'add-mof' and 'remove-mof' for compiling MOF to the 'server'
  command group. (issue #886)

* Test: Added end2end test capability using the OpenPegasus container image
  on Docker Hub.

* Added new command group ('statistics') that contols use of statistics. See
  issue #588)

* Implement command to get statistics from server and present as a table #895)

* Test: Added a unit test module for _utils.py.

* Added an '--include-instances' option to the 'class delete' command that
  replaces the deprecated '--force' / '-f' option. (issue #885)

* Added an '--include-objects' option to the 'namespace delete' command that
  causes the deletion of instances, classes and qualifier types in the targeted
  namespace before the namespace itself is deleted. The objects in the namespace
  are deleted in the correct order of dependencies so that no dangling
  dependencies exist at any point in the operation. (issue #885)

* Added a ''--dry-run' option to the 'class delete' and 'namespace delete'
  commands. If used, it displays the message about each deletion with a
  'Dry run:' prefix and does not perform the actual deletion. (issue #911)

**Cleanup:**

* Cleaned up the circumvention for Click issue #1231 by upgrading the minimum
  Click version to 7.1.1, where possible. The circumvention is still required
  on Python 2.7 and 3.4 on Windows.

* Clarified in the help text of general option '--pdb' that it will be ignored
  in interactive mode but can be specified on each interactive command.

* Test: Added a check that rejects the use of the 'pdb' test condition when the
  test specifies stdin for the test, because the 'pdb' test condition disables
  the stdin/stdout/stderr redirection.


pywbemtools 0.8.0
-----------------

This version contains all fixes up to pywbemtools 0.7.3.

Released: 2020-10-13

**Incompatible changes:**

* Moving the commands "server profiles" and "serve centralinsts" to the
  new group profiles with the commmand names "profile list" and
  "profile centralinsts" added a command group and removed 2 commands
  from the server command group. (See issue #612)

* The `--deprecation-warnings` / `--no-deprecation-warnings` general option
  has been remamed to `--warn` / `--no-warn`, and it now controls the
  display of all Python warnings.

**Bug fixes:**

* Order display of instance names when the .? is used to pick an instance
  name so the same order of instance names is displayed for all versions of
  Python. (See issue #458 and #459)

* Pinned prompt-toolkit to <3.0 on Python 3.8 on Windows to avoid WinError 995.
  (See issue #690)

* Fixed exception when command entered in interactive mode, on Python 2.
  (See issue #224)

* Test: Default connection file does not get restored in some cases during test.
  (See issue #680)

* AssociationShrub produces instancename slightly different table output in
  some cases for pywbem 1 vs previous versions(inclusion of "/:" prefix).
  (see issue #704)

* Test: Fixed attempt in test_class_cmds.py to invoke a non-static method on a
  class object. (see issue #707)

* Fix help message for "--deprecated" to be unicode so python 2.7 help does not
  fail. (see issue #725). This error was added with issue #678

* Upgraded nocasedict and nocaselist packages to pick up fixes.

* Error in test defintion for qualdecl Indication causes failure with pywbem
  i.1.0 where mocker validates qualifiers scopes. (see issue #766)

* Test: Preventive fix for potential issue with virtualenv raising
  AttributeError during installtest on Python 3.4. (see issue #775)

* Test: Added checking for no expected warning. (see issue #774)

* Fixed incorrect property order in instance table output, where key properties
  were not ordered before non-key properties but ordered along with them.
  (see issue #782)

* Docs/Test: Fixed failing install of Jinja2 on Python 3.4 by adding it
  to dev-requirements.txt and pinning it to <2.11 for Python 3.4.

* Test: Aligned qualifier definitions in test MOF with CIM Schema.
  (related to issue #788)

* Upgraded pywbem to 1.1.1 to pick up fixes and enhancements.
  (see issues #749, #183)

**Enhancements:**

* Introduced caching of the mock environment used by connection definitions in
  order to speed up the loading of the connection definition. The mock
  environments are stored in directory ~/.pywbemcli_mockcache and are
  automatically managed. The pywbemcli --verbose general option can be used
  to show messages about the cache management. (See issue #689)

* A new approach for the setup of mock scripts has been introduced: The mock
  script defines a `setup(conn, server, verbose)` function that is called when
  the mock environment is built. It is not called when the mock environment
  is reinstantiated from the cache.
  The old approach with setting global variables CONN, SERVER, VERBOSE is still
  supported, but the mock environment cannot be cached and will be built every
  time when mock scripts with that setup approach are used.
  On Python <3.5, mock scripts with the `setup()` function are rejected, because
  the functionality to import them is not available, and the compile+exec
  approach does not allow executing the setup() function. (See issue #689)

* Modify general help to display the full path of the default connections file.
  (See issue #660)

* Move the commands associated with WBEM management profiles from the server
  group to a new profile group. (See issue #612). See also Incompatible changes.

* Add --deprecated/-no-deprecated as a new qualifier filter for the class
  enumerate, class find, and instance count commands. Extend the behavior so
  that for each of the possible filters it looks for the qualifier on all
  of the elements (property, method, parameter) in addition to the class
  itself.  See issue #678)

* Test: Enabled coveralls to run on all Python versions in the Travis CI,
  resulting in a combined coverage for all Python versions.

* For instance display in table format, added the display of
  the units of properties to the table headers. If a property
  in the class has a PUnit or Units qualifier set, the unit
  is translated to a human readable SI unit using the pywbem.siunit_obj()
  function, and appended to the property name in square brackets.
  (See issue #727)

* Consolidated the warnings control, such that the deprecation messages were
  changed to be issued as Python warnings, and the `--warn` / `--no-warn`
  general options now control the display of all Python warnings. If `--warn`
  is used, all Python warnings are shown once. If `--no-warn` is used (default),
  the `PYTHONWARNINGS` environment variable determines which warnings are shown.
  If that variable is not set, no warnings are shown. (See issue #723)
  Added the 'mock' package and for Python 2.7, the 'funcsigs' package as new
  dependencies.

* Specifying a property list (--pl option) on instance commands with table
  output formats now uses the order of properties as specified in the property
  list in the output table, instead of sorting them. (See issue #702)

* Allow unsetting general options. Originally the general options could be
  either set specifically by defining them on the command line or the
  default would be enabled. However, in interactive mode the need may arise
  to set an option back to its default value (i.e. the equivalent of not
  including it on the command line). This fixes the options so that there is
  an alternative that will will set them to the default value. (see issue
  #350)

* Converted remaining unittest testcases to pytest. (See issue #91)

* Test: When testing with latest package levels, the package versions of
  indirect dependencies are now also upgraded to the latest compatible
  version from Pypi. (see issue #784)

**Cleanup**

* Remove unused NocaseList from __common.py

* Moved the general option --pull_max_cnt to become part of the persistent
  server definition rather than transient.  This means that this
  parameter is part of the data maintained in the server definitionfile and
  applies to just the server defined.  (See issue #694)

* Docs: Improved the description and help texts of the connections file and the
  --connections-file general option in various places, for consistency.
  (Related to issue #708)

* Move code associated with display_cimobjects() to a separate module. This
  is part of creating table representation of classes (See issue #249)

* Resolved remaining Pylint issues and enforced clean pylint checks.
  (See issue #668)

* Renamed the default connections file in the user's home directory from
  `pywbemcli_connection_definitions.yaml` to `.pywbemcli_connections.yaml`,
  because it is really an internal file not meant for being edited.
  An existing file with the old name is migrated automatically.
  (See issue #716)

* Refactor error handling for connections file handlingif there are problems
  with the YAML file or loading the file. Created new exceptions for the
  Connections File and created a unit test and function error test.
  (see issue #661)

* Separate code to execute test files (ex. setup up mock of prompt) from
  the process of executing files defined by the --mock-server general option.
  The new capability is controled by an environment variable
  "PYWBEMCLI_STARTUP_SCRIPT" that is considered intenal to pywbemcli testing.

* Refactor statistics display to present information consistent with the
  display in pywbem. (see issue # 724)

* Refactor connections show command and clean up its documentation.  (see
  issue #732)

* Remove use of pydicti dictionary package in favor of NocaseDict.

* set pylint disable on all uses of pdb.set_trace(). This is an issue between
  the add-on package pdbpp and lint, not pdb.  (see issue # 751)

* Docs: Changed Sphinx theme to sphinx_rtd_theme. (see issue #792)

* Modified the class WbemServerMock in tests/unit/testmock to define a
  WBEM server configuration that includes multiple namespaces, a user and
  an interop namespace to test cross-namespace mock. (see issue #183)


pywbemtools 0.7.0
-----------------

This version contains all fixes up to pywbemtools 0.6.1.

Released: 2020-07-12

**Incompatible changes:**

* The default location for the connections file (pywbemcli_connection_definitions.yaml)
  has been moved from the users current directory to the users home directory.
  A general option (``connections_file``) allows the user to set other directories
  and file names for this file. (See issue #596)

**Deprecations:**

* Deprecated support for Python 2.7 and 3.4, because these Python versions have
  reached their end of life. A future version of pywbemtools will remove support
  for Python 2.7 and 3.4. (see issue #630).

**Bug fixes:**

* Fixed incorrect connection list output in readme files (see issue #593).

* Fixed yaml.RepresenterError during 'connection save' command. This introduced
  a dependency on the yamlloader package. (see issue #603).

* Fixed possible issue where the `connection test` command would fail on a
  server that did not support class operations.  (See issue #606)

* Pinned version of colorama to <0.4.0 for Python <=3.4.

* Adjusted to changes in the pywbem mock support for method providers, in the
  sample method provider simple_mock_invokemethod_pywbem_V1.py. (See issue #646)

* Fix issue with MOF compile in pywbem_mock to account for changes to
  pywbem.FakedWBEMConnection in pywbem 1.0.0.  Because the pywbem
  mocker stopped displaying compile error messages, this change modifies the
  code to display the compile errors as exceptions for pywbem 1.0 and use the
  original display for pre 1.0 pywbem version.  With pywbem 1.0.0 it also
  outputs the compile error message and exception to stderr whereas before
  the compile error text was routed to stdout. (See issue #637)

* Fixed an issue where displaying instances in a table format missed properties
  if the list of instances had different sets of properties. (See issue #650)

* Change the table output for outputformat html to output the title parameter
  as an html caption entity instead of as a paragraph.  This allows html
  tables to be subtabled and also presents the table title better.
  (see issue #721)

**Enhancements:**

* Enabled installation using 'setup.py install' from unpacked source distribution
  archive, and added install tests for various installation methods including
  this one. (see issues #590, #591).

* Enhance output formats to allow an additional format group TEXT with
  a single format ``text``. This format outputs the command result as a
  text string to the console and is use for simple commands like
  ``server interop`` that only output one piece of data. (see issue #594)

* Extended the command `connection test` so that it will also test for existence
  of the DMTF pull operations.  It tests for all of the operations and
  reports success or failure on each operation.

* Added value-mapped strings to properties in instance table output.
  For integer-typed (scalar or array) properties that have a ValueMap qualifier,
  the output of instances in table format now includes the value of the Values
  qualifier in parenthesis, in addition to the integer value. (See issue #634)

* The order of properties when displaying instances in a table format is now
  predictable: First the sorted key properties, then the sorted non-key
  properties. (Part of fix for issue #650)

* Modify connections file location functionality so that the default file
  location is the users home directory. Any other directory and filename can
  be specified using the general option ``connections_file`` which has a
  corresponding environment variable.  (See issue #596)

**Cleanup**

* Adds command to test connection for existence of  the pull operations
  (connection test-pull)

* Refactored display_class_tree() and other functions in _displaytree.py  and
  _cmd_class.py cmd_class_tree function to eliminate boundary conditions, and
  clarify code.

* Extended parameter type testing in class PywbemServer so that all
  constructor parameters are value tested.  This specifically fixes issue
  where we were depending on WBEMConnection to test types of ca_certs
  and invalid data types could get into the connections file. (See issue
  #663).

* Added a function test test module test_misc_errors.py that tests for some
  common exceptions that apply to many commands (ex. connection error).


pywbemtools 0.6.0
-----------------

This version contains all fixes up to pywbemtools 0.5.1.

Released: 2020-04-10

**Bug fixes:**

* Fix issue with mixed old and new formats on click.echo statement.
  (See issue #419)

* Fixed missing Python 3.7 in supported environments shown on Pypi.
  (See issue #416)

* Fixed that the 'class find' command showed the --namespace option twice
  (see issue #417)

* Added PyYAML>=5.1 as a prerequisite package for pywbemtools for installation.
  So far, it was pulled in indirectly via pywbem.

* Fixed case sensitive matching of class names in instance modify by
  picking up the fix in pywbem 0.14.6. (See issue #429).

* Fixed issue where extra diagnostic information about click was being displayed
  when the general option --verbose was defined.

* Fixed issue with x509 parameter of WBEMConnection. (See issue #468)

* Fixed issue with class find command not returning connection error when
  cannot connect to server.

* Added documentation for the --version general option.

* Increased pywbem minimum version to 0.16.0 to accomodate install issues
  on Python 3.4, and to pick up other fixes.

* Test: Accomodated new formatting of error messages in Click 7.1.1, and
  excluded Click 7.1 due to bug.

* Test: Fixed dependency to Python development packages on CygWin platform
  in Appveyor CI.

* Pygments 2.4.0 and readme-renderer 25.0 have removed support for Python 3.4
  and have therefore been pinned to below these versions on Python 3.4.

* Fix bug where order of commands listed in help output was different for
  different versions of Python. (See issue #510)

* Increased minimum version of pluggy package from 0.12.0 to 0.13.0
  because it failed during loading of pytest plugins on Python 3.8.
  (See issue #494)

* Test: Changed testcases that check the CIM-XML generated with output format
  'xml' to tolerate the different order of XML attributes that happens on
  Python 3.8 (See issue #494)

* Fixed several badges on the README page.

* Remove use of pywbem internal functions from pywbemcli. This removes use of
  NocaseDict, _to_unicode, _ensure_unicode, _format from pywbemcli. (See
  issue #489)

* Corrected issue with use-pull general option that causes issues with using
  the 'either' option with servers that do not have pull. (See issue #530)

* Pinned dparse to <0.5.0 on Python 2.7 due to an issue.

* Test: Fixed incorrect coverage reported at the end of the pytest run,
  by increasing the minimum version of the coverage package to 4.5.2.
  (See issue #547)

* Test: Fixed bug with detection of invalid test validation values, and fixed
  testcases in turn (See issue #553).

* Fixed issues in README and README_PYPI file (See issue #555)

* Improvements and bug fixes in the way the INSTANCENAME parameter of pywbemcli
  commands is processed. (See issue #528)

* Increased minimum versions of some packages used for development to address
  security issues reported by the pyup.io safety tool: twine, bleach, urllib3.

**Enhancements:**

* Promoted development status of pywbemtools from Alpha to Beta.
  (See issue #476)

* Add capability to reorder commands in the help for each group.  The commands
  in all groups except for the top group (pywbemcli -h) are ordered in the
  help list by their order in their source file. The display of commands in
  the top level group is alphabetical except that connection, help, and repl
  are reordered to the bottom of the list. (See issue #466)

* Define alternatives for creating INSTANCENAME input parameter since the
  original form using, WBEMURI is error prone with quote marks.
  (see issue #390)

* Add prompt-toolkit auto-suggest.  This extends the command completion
  capability in the repl mode (interactive mode) to make suggestions on
  command line input based on the history file.  Usually auto-suggest completion
  will be shown as gray text behind the current input. Auto-suggest is not
  available in command line mode.

* Add ability to filter results of 'class enumerate', 'class find', and
  'instance count' commands for selected class qualifiers.  This ability
  is based on 3 new options for each of the above commands '--association',
  '--indication', and '--experimental' each of which has a corresponding
  'no-...'. The user can filter to find classes with combinations of these
  options returning only classes that meet the option criteria.  Thus,
  '--association' returns classes that are associations and '--no-association'
  returns only classes that are not associations.  See issue #447

* Added support for disabling the spinner that is displayed by default during
  any ongoing activities, by setting the env var PYWBEM_SPINNER to 'false',
  '0', or the empty string. This is useful when debugging.  See issue #465.

* Modified the response handling on commands that may return nothing with
  successful response to display a message if the general option --verbose
  is defined and display nothing if --verbose not set.  This includes
  class/instance delete, instance modify and the commands that display
  cim objects. (See issue #123)

* Changed the `--ca-certs` general option to support the changes as of
  pywbem version 1.0.0 (new values 'system' and 'certifi', and default changed
  from a fixed set of directories to 'certifi'). The pywbem version is
  determined at run time and pywbem versions before 1.0.0 are still supported.

* Test: Improved assertion messages in tests.

* Output of "pywbemcli server profiles" command is now reliably sorted by
  version in addition to org and name. (See issue #500)

* Added support for a new `--pdb` general option and corresponding
  `PYWBEMCLI_PDB` environment variable that causes the pywbemcli command
  to come up with the pdb debugger before invoking the specified command.
  This is a debug feature that is expected to be used mainly by the
  developers of pywbemcli. (See issue #505)

* Test: Added support for entering the pdb debugger from specific unit testcases
  by setting the condition parameter of the testcase to the string 'pdb'.
  This causes pywbemcli to be invoked with the new --pdb option for that
  testcase. (See issue #505)

* Removed usage of the "pbr" package. It was used for automatic versioning
  of the pywbemtools package, but it had too many drawbacks for that small
  benefit (See issue #178):

  - Getting the minor version increased in a development version (instead of
    the patch version) by means of markers in the commit message never worked.
  - The package needed to be tagged twice during the release process.
  - If the last tag was too far in the past of the commit history, the
    shallow git checkout used by Travis failed and its depth needed to be
    adjusted. At some point this defeats the purpose of a shallow checkout.

* Test: Added support for testing on Python 3.8 in Travis, Appveyor and Tox.
  (See issue #494)

* Added support for adjusting the width of any help output to the terminal
  width. The width can be set using the PYWBEMCLI_TERMWIDTH env var.
  (See issues #518 and #542)

* Docs: Increased the width of the help text to 120 (See issue #548).

* Modified the help usage to better reflect the required and optional
  components of the command line. This includes showing the location
  in the cmd line for general options where before it was called
  [COMMAND-OPTIONS] and showing the positioning of both arguments and
  command arguments. (See issue #446)

* Increased minimum version of pywbem to 0.17.0 (See issue #571)

* Add option `--full` to `connection list` to create both a brief table
  output that only has 3 columns (name, server, mock-server) as default but
  when the option is set all of the columns currently in the report. We did
  this because it appears that the most frequent use of this command is to just
  get the name of the various servers defined within an 80 column display.
  This also now shows empty columns where the original report hid any columns
  that were empty. (See issue #556)

**Cleanup:**

* Test: Enabled Python warning suppression for PendingDeprecationWarning
  and ResourceWarning (py3 only), and fixed incorrect make variable for that.

* Test: Removed testfixtures from minimum constraints file, as it is not used.

* Test: Increased minimum version of pytest from 3.3.0 to 4.3.1 because
  it fixed an issue that surfaced with pywbem minimum package levels
  on Python 3.7.

* Code: refactor code to use only the .format formatter and remove all use
  of the % formatter.

* Test: Added missing indirectly referenced prerequisite packages to
  minimum-constraints.txt, for a defined package level when testing with
  PACKAGE_LEVEL=minimum.

* Clean up test mock files by merging mock_simple_model_ext.mof into
  mock_simple_model.mof

* Changed some tests to account for behavior difference with pywbem 0.15.0
  references and associations with invalid class, role.

* Changed minimun version of pywbem to 0.15.0 because of test differences
  that resulted from differences between pywbem 0.14.6 and 0.15.0. The
  differences are in pywbem_mock where the code was changed to return errors
  for invalid classnames and roles in association and reference operations
  where it previously return empty, ignoring the invalid classname.

* Added tests of all command groups and commands for server connection error.

* Removed a circumvention for a pywbem bug related to colons in WBEM URIs
  that was fixed in pywbem 0.13.0. (See issue #131)

* Added the general option `--use-pull` to the the PywbemServer() class so that
  it is persisted in the connection file and to the display of connection
  information (`connection show` and `connection list`). This means that
  `--use-pull` can now be set for a particular server permanently.(See issues
  #529 and #534).

* Added table formatted output for connection show and removed original
  free-form output format. (See issue #572)

* Added documentation on incremental search option to search the command
  history file in interactive mode. (See issue #595)

* Added documentation index entries for commands, command groups, etc. (see
  issue #598)



pywbemtools 0.5.0
-----------------

Released: 2019-09-29

This is the initial release of pywbemtools.
