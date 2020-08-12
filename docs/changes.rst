
.. _`Change log`:

Change log
==========


pywbemtools 0.8.0
-----------------

This version is currently in development and is shown as |version|.

This version contains all fixes up to pywbemtools 0.7.x.

Released: not yet

**Incompatible changes:**

* Moving the commands "server profiles" and "serve centralinsts" to the
  new group profiles with the commmand names "profile list" and
  "profile centralinsts" added a command group and removed 2 commands
  from the server command group. (See issue #612)

**Deprecations:**

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

**Enhancements:**

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

**Known issues:**

* See `list of open issues`_.

.. _`list of open issues`: https://github.com/pywbem/pywbemtools/issues


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
