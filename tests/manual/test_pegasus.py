#!/usr/bin/env python

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
    Execute and test the validity of the help output from pywbemcli
"""

from __future__ import print_function, absolute_import

import unittest
import re
from subprocess import Popen, PIPE
import six


class ClientTest(unittest.TestCase):
    """Top level container. Performs any setup and teardown"""

    def setUp(self):
        """Setup the test
        """
        self.host = 'http://localhost'
        self.verbose = False


class TestsContainer(ClientTest):
    """Container class for all tests"""

    def execute_cmd(self, cmd_str):  # pylint: disable=no-self-use
        """Execute the command defined by cmd_str and return results."""
        if self.verbose:
            print('cmd %s' % cmd_str)
        # Disable python warnings for pywbemcli call.See issue #42
        command = 'export PYTHONWARNINGS="" && %s' % cmd_str
        proc = Popen(command, shell=True, stdout=PIPE, stderr=PIPE)
        std_out, std_err = proc.communicate()
        exitcode = proc.returncode
        if six.PY3:
            std_out = std_out.decode()
            std_err = std_err.decode()
        if self.verbose:
            print('rtn %s\n%s\n%s' % (std_out, std_err, exitcode))

        # return tuple of exitcode, stdout, stderr
        return exitcode, std_out, std_err

    def assert_not_found(self, regex, test_str):
        """ Test of find regex on multiline string.
        If regex is a list each entry is tested.
        """
        if isinstance(regex, list):
            for i in regex:
                self.assert_not_found(i, test_str)
        else:
            match = re.search(regex, test_str)
            if match:
                self.fail('Found in error search regex %s, str %s' %
                          (regex, test_str))

    def assert_found(self, regex, test_str):
        """ Test of find regex on multiline string.
        If regex is a list each entry is tested.
        """
        if isinstance(regex, list):
            for i in regex:
                self.assert_found(i, test_str)
        else:
            match = re.search(regex, test_str)
            if match is None:
                self.fail('Failed search regex %s, str %s' % (regex, test_str))

    def assertRegexp(self, regex, test_str):
        """
        This function eliminates the issue between the unittest assertRegex
        and assertRegexpMatches functions between unittiest in python 2 and 3
        """
        if six.PY3:
            # pylint: disable=no-member
            return self.assertRegex(test_str, regex)

        # pylint: disable=no-member, deprecated-method
        return self.assertRegexpMatches(test_str,
                                        regex)  # pylint: disable=no-member


class ClassTests(TestsContainer):
    """Test operations in the class group"""

    def class_cmd(self, params):
        """Adds the cmd name prefix and executes"""
        cmd = 'pywbemcli -s %s class %s' % (self.host, params)
        exitcode, std_out_str, std_err_str = self.execute_cmd(cmd)
        return exitcode, std_out_str, std_err_str

    def test_get_simple(self):
        """Test a get of CIM_ManagedElement"""
        exitcode, out, err = self.class_cmd('get CIM_ManagedElement')

        self.assertEqual(exitcode, 0)
        self.assertEqual(err, '', 'Expect no std_err. Found %s' % err)
        self.assert_found('CIM_ManagedElement', out)

    def test__get_localonly(self):
        """Test class get --local-only"""
        exitcode, out, err = self.class_cmd('get CIM_ManagedElement -l')

        self.assertEqual(exitcode, 0)
        self.assertEqual(err, "")
        self.assert_found('CIM_ManagedElement', out)

        exitcode, out, err = self.class_cmd(
            'get CIM_ManagedElement --local-only')

        self.assertEqual(exitcode, 0)
        self.assert_found('CIM_ManagedElement', out)

    def test_get_no_includequalifiers(self):
        """ """
        exitcode, out, err = self.class_cmd(
            'get CIM_ManagedElement --no-qualifiers')

        self.assertEqual(exitcode, 0)
        self.assert_found('CIM_ManagedElement', out)

    def test_propertylist(self):
        """Test property list on the get"""
        exitcode, out, err = self.class_cmd(
            'get CIM_ManagedElement -p InstanceID')
        self.assertEqual(exitcode, 0)
        self.assert_found(['class CIM_ManagedElement', 'InstanceID'], out)

        exitcode, out, err = self.class_cmd(
            'get CIM_ManagedElement -p InstanceID -p Caption')
        self.assertEqual(exitcode, 0)
        self.assert_found('class CIM_ManagedElement', out)
        self.assert_found('InstanceID', out)
        self.assert_found('Caption', out)

        exitcode, out, err = self.class_cmd(
            'get CIM_ManagedElement -p ""')
        self.assertEqual(exitcode, 0)
        self.assert_found('class CIM_ManagedElement', out)
        self.assert_not_found(['InstanceID', 'Caption'], out)

    def test_simple_invoke(self):
        """Execute simple invoke method defined in pegasus"""
        exitcode, out, err = self.class_cmd(
            'invokemethod Test_IndicationProviderClass '
            'SendTestIndicationsCount -p indicationSendCount=0 '
            ' -n test/TestProvider')
        self.assertEqual(exitcode, 0)


# TODO finish this based on the test_ops in the tools directory

# cmd "class get CIM_ManagedElement -c"
# cmd "class get CIM_ManagedElement --include-classorigin"
# cmd "class get CIM_ManagedElement --namespace root/PG_Interop"
# cmd "class get CIM_ManagedElement - root/PG_Interop"

# TODO create tests for qualifier, server

class InstanceTests(TestsContainer):
    """Test operations in the instance group"""

    def instance_cmd(self, params):
        """Adds the instance cmd name prefix and executes"""
        cmd = 'pywbemcli -s %s instance %s' % (self.host, params)
        exitcode, std_out_str, std_err_str = self.execute_cmd(cmd)
        return exitcode, std_out_str, std_err_str

    def test_enumerate_simple(self):
        """ """
        exitcode, out, err = self.instance_cmd('enumerate PyWBEM_Person')

        self.assertEqual(exitcode, 0)
        self.assert_found('instance of PyWBEM_Person', out)

    def test_enumerate_proplist(self):
        """ """
        exitcode, out, err = self.instance_cmd('enumerate PyWBEM_Person '
                                               '-p Name')

        self.assertEqual(exitcode, 0)
        self.assert_found(['instance of PyWBEM_Person', 'Name'], out)
        self.assert_not_found('CreationClassName', out)

    def test_get_simple(self):
        """Execute simple get of known instance """
        exitcode, out, err = self.instance_cmd(
            'get PyWBEM_Person.CreationClassname=PyWBEM_Person,Name=Bob')

        self.assertEqual(exitcode, 0)
        self.assert_found('PyWBEM_Person', out)

    def test_create_simple(self):
        """
        Test create a simple instance. To be complete this must both
        create and delete the instance since tests are not ordered and each
        test should leave the repository in the same state in which it
        was before the test.
        """
        exitcode, out, err = self.instance_cmd(
            'create PyWBEM_Person --property name=Fred '
            '--property CreationClassname=PyWBEM_Person')
        self.assertEqual(exitcode, 0)

        exitcode, out, err = self.instance_cmd(
            'delete PyWBEM_Person.Name=Fred,CreationClassName=PyWBEM_Person')
        self.assertEqual(exitcode, 0)
        self.assert_found(['Deleted', 'Fred'], out)

    def test_create_array_prop(self):
        """Create an instance of an array property"""

        exitcode, out, err = self.instance_cmd(
            'create pywbem_alltypes --property InstanceId=ArrayBool '
            '--property arrayBool=True,False')

        self.assertEqual(exitcode, 0, "Failed create test")
        exitcode, out, err = self.instance_cmd(
            'get pywbem_alltypes.InstanceId=ArrayBool')

        self.assert_found(["instance of PyWBEM_AllTypes", 'ArrayBool',
                           "{True, False}"], out)

        exitcode, out, err = self.instance_cmd(
            'delete PyWBEM_AllTypes.InstanceId=ArrayBool')
        self.assertEqual(exitcode, 0)
        self.assert_found(['Deleted', 'ArrayBool'], out)

    def test_create_alltypes(self):
        """
        Create an instance of a class with all types
        """

        exitcode, out, err = self.instance_cmd(
            'create PyWBEM_AllTypes --property InstanceId=ScalarTest1 '
            '--property scalBool=True '
            '--property scalUint8=8 '
            '--property scalSint8=-8 '
            '--property scalUint32=9999 '
            '--property scalSint32=-9999 '
            '--property scalUint64=12345678 '
            '--property scalSint64=-12345678 '
            '--property scalReal32=5678.32 '
            '--property scalReal64=345876.3 '
            '--property scalDateTime="19991224120000.000000+360" '
            '--property scalString="A string value" ')
        self.assertEqual(exitcode, 0, 'Expected good response. Rcvd '
                         ' code %s err %s' % (exitcode, err))
        self.assertEqual(exitcode, 0, 'Create instance of Pywbem_AllTypes '
                         'failed. exitcode %s, err %s' % (exitcode, err))

        exitcode, out, err = self.instance_cmd(
            'delete PyWBEM_AllTypes.InstanceId=ScalarTest1')
        self.assertEqual(exitcode, 0)
        self.assert_found(['Deleted', 'ScalarTest1'], out)

    def test_property_notexist(self):
        """
        Validate the error when property does not exist in class
        """
        exitcode, out, err = self.instance_cmd(
            'create pywbem_alltypes --property InstanceId=ArrayBool '
            '--property BlahBool=True,False')
        print('err %s' % err)
        self.assertEqual(exitcode, 1)

    def test_references(self):
        exitcode, out, err = self.instance_cmd(
            'references PyWBEM_Person.CreationClassname=PyWBEM_Person,'
            'Name=Bob')

        self.assertEqual(exitcode, 0)
        self.assert_found('instance of PyWBEM_MemberOfPersonCollection', out)

    def test_reference_paths(self):
        exitcode, out, err = self.instance_cmd(
            'references PyWBEM_Person.CreationClassname=PyWBEM_Person,'
            'Name=Bob -o')

        self.assertEqual(exitcode, 0)
        self.assert_found(':PyWBEM_MemberOfPersonCollection.Member', out)

    def test_associators(self):
        exitcode, out, err = self.instance_cmd(
            'associators PyWBEM_Person.CreationClassname=PyWBEM_Person,'
            'Name=Bob')

        self.assertEqual(exitcode, 0)
        self.assert_found('instance of PyWBEM_PersonCollection', out)

    def test_associator_paths(self):
        exitcode, out, err = self.instance_cmd(
            'associators PyWBEM_Person.CreationClassname=PyWBEM_Person,'
            'Name=Bob -o')

        self.assertEqual(exitcode, 0)
        self.assert_found(':PyWBEM_PersonCollection.InstanceID', out)


if __name__ == '__main__':
    unittest.main()
