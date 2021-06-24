# Copyright 2021 IBM Corp. All Rights Reserved.
# (C) Copyright 2021 Inova Development Inc.
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
    Define the classes and instances to mock a WEMServer as the basis for
    test mocks.

    This model is defined in a single multi-level dictionary and the
    WbemServerMock class uses that dictionary to populate the mock
    cim_repository with qualifiers, classes, and instances for the model

    This was modified from an equivalent test tool in pywbem

    NOTE: There is a version of this functionality wbemserver_mock_v0.py
    that is used to run tests against python versions < 3 because the
    mock script using setup does not exist for these version of python.

    This file defines the class that implements building the mock wbem
    server from a dictionary and a default dictionary to build the WBEM
    server.

    It requires a class such as the wbemserver_mock.py class to actually
    call this class to define a complete pywbemcli mock startup script.

    This class does not incluede the script startup method to all users to
    define alternate wbem server dictionaries than the default and build
    the corresponding mock WBEM server for tests.
"""

from __future__ import print_function, absolute_import

import os

from pywbem import ValueMapping, CIMInstance, CIMInstanceName, CIMError, \
    CIM_ERR_ALREADY_EXISTS
from pywbem_mock import FakedWBEMConnection, DMTFCIMSchema, \
    CIMNamespaceProvider, CIMIndicationFilterProvider, \
    CIMListenerDestinationProvider, CIMIndicationSubscriptionProvider

DMTF_TEST_SCHEMA_VER = (2, 49, 0)


# Location of DMTF schema directory used by all tests.
# This directory is permanent and should not be removed.
TESTSUITE_SCHEMA_DIR = os.path.join('tests', 'schema')

# The following dictionary represents the data required to build a
# set of classes and instances for a mock WbemServer. This dictionary defines
# the following elements of a wbem server:
#
#  dmtf_schema: The DMTF schema version (ex (2, 49, 0) of the schema that
#  will be installed and the directory into which it will be installed
#
#  system_name: The name of the system (used by the CIM_ObjectManager)
#
#  object_manager: A dictionary that defines variable element for the
#  CIM_ObjectManager class.
#
#  interop_namespace: The interop namespace. Note that that if the interop
#  namespace is defined in the WbemServerMock init method that overrides any
#  value in this dictionary
#
#  class-names: Lists of leaf classes origanized by namespace that are to
#  be used as the basis to build classes in the mock CIM repository
#
#  class_mof: element that defines specific classes that are to be included
#  in the model.  This is largely to allow building trivial sublcasses for
#  components of profiles
#
#  registered_profiles: The Organization, profile name, profile version for any
#  registered profiles that are to be built
#
#  referenced_profiles: Definition of CIM_ReferencedProfile associations
#  between CIM_RegisteredProfiles. This is used to test get_central_instances
#
#  central-instances: Specific central intances that are built
#
#  element-conforms-to: Set of relations that define the associations between
#  the registered profiles and central classes.#
#
DEFAULT_WBEM_SERVER_MOCK_DEFAULT_DICT = {
    # Defines the DMTF schema from which qualifier declarations and classes
    # are to be retrieved.
    'dmtf_schema': {'version': DMTF_TEST_SCHEMA_VER,
                    'dir': TESTSUITE_SCHEMA_DIR},

    # TODO: Relook at this since it is just a class compile based on a mof file
    # Other schema definitions and the mof from them to be inserted.
    # This is used just to intall one piece of mof today.
    'pg_schema': {'interop':
                  {'dir': os.path.join(TESTSUITE_SCHEMA_DIR, 'OpenPegasus'),
                   'files': ['PG_Namespace.mof']}},

    # Definition of the interop namespace name.
    'interop-namspace': 'interop',

    # Class names for leaf classes from the dmtf_schema to be installed in the
    # mockserver organized by namespace. The namespaces will be built if they
    # do not already exist before the build_class method is called.
    'class-names': {'interop': ['CIM_Namespace',
                                'CIM_ObjectManager',
                                'CIM_RegisteredProfile',
                                'CIM_ElementConformsToProfile',
                                'CIM_ReferencedProfile',
                                'CIM_ComputerSystem',
                                'CIM_CIMOMStatisticalData',
                                'CIM_ListenerDestinationCIMXML',
                                'CIM_IndicationFilter',
                                'CIM_IndicationSubscription'],

                    'root/cimv2': ['CIM_ElementConformsToProfile',
                                   'CIM_ComputerSystem']},

    # class MOF that must be compiled in the environment by namespace
    'class-mof': {'root/cimv2': ["class MCK_StorageComputerSystem: "
                                 "CIM_ComputerSystem{};", ]},

    # A name for the system and properties for the object namager that
    # will be used to build the object manager instance
    'system_name': 'Mock_WBEMServerTest',
    'object_manager': {'Name': 'FakeObjectManager',
                       'ElementName': 'Pegasus',
                       'Description': 'Pegasus CIM Server Version 2.15.0'
                                      ' Released',
                       'GatherStatisticalData': False},

    # User providers that are to be registered.
    'user_providers': ['namespaceprovider',
                       'subscriptionproviders'],

    'registered_profiles': [('DMTF', 'Indications', '1.1.0'),
                            ('DMTF', 'Profile Registration', '1.0.0'),
                            ('SNIA', 'Server', '1.2.0'),
                            ('SNIA', 'Server', '1.1.0'),
                            ('SNIA', 'SMI-S', '1.2.0'),
                            ('SNIA', 'Array', '1.4.0'),
                            ('SNIA', 'Software', '1.4.0'),
                            ('DMTF', 'Component', '1.4.0'), ],

    'referenced_profiles': [
        (('SNIA', 'Server', '1.2.0'), ('DMTF', 'Indications', '1.1.0')),
        (('SNIA', 'Server', '1.2.0'), ('SNIA', 'Array', '1.4.0')),
        (('SNIA', 'Array', '1.4.0'), ('DMTF', 'Component', '1.4.0')),
        (('SNIA', 'Array', '1.4.0'), ('SNIA', 'Software', '1.4.0')),
    ],

    # List of CIMInstances to install by namespace. Each entry is a CIM
    # instance with classname,and properties. All properties required to build
    # the path must be defined. No other properties are required for this test.
    # (namespace, instance)
    'central-instances': {
        'interop': [],  # TODO add CIMComputerSystem profile
        'root/cimv2':
            [CIMInstance(
                'MCK_StorageComputerSystem',
                properties={'Name': "10.1.2.3",
                            'CreationClassName': "MCK_StorageComputerSystem",
                            'NameFormat': "IP"})]},

    # TODO/Future: Add definition of scoping instance path
    'scoping-instances': [],


    # Define the relationships between a central instance and a specific
    # profile by namespace where the namespace is the location of the
    # central instance.
    # Two elements in list for each element conforms to definition.
    # 1. a specific profile including org, name, and version
    # 2. Components to define an instance including:
    #    Classname,
    #    Keybindings of CIMInstance name
    'element_conforms_to_profile':
        {'interop': [],
         'root/cimv2': [
             (('SNIA', 'Server', '1.2.0'),
              ("MCK_StorageComputerSystem", {'Name': "10.1.2.3",
                                             'CreationClassName':
                                             "MCK_StorageComputerSystem"})), ],
         },
}


class WbemServerMock(object):
    # pylint: disable=useless-object-inheritance, too-many-instance-attributes
    """
    Class that mocks the classes and methods used by the pywbem
    WBEMServer class so that the WBEMServer class will produce valid data
    for the server CIM_ObjectManager, CIM_Namespace, CIM_RegisteredProfile
    instances.

    This can be used to test the WbemServer class but is also required for
    other tests such as the Subscription manager since that class is based
    on getting data from the WbemServer class (ex. namespace)

    It allows building a the instance data for a particular server either
    from user defined input or from standard data predefined for pywbem
    tests
    """

    def __init__(self, conn, server, interop_ns=None, server_mock_data=None,
                 verbose=None):
        # pylint: disable=too-many-arguments, too-many-locals
        """
        Build the mock repository with the classes and instances defined for
        the WBEM server in accord with the dictionary defined in
        server_mock_data or in the default mock configuration dictionary
        DEFAULT_WBEM_SERVER_MOCK_DEFAULT_DICT.

        Parameters:

          conn (:class:`~pywbem.WBEMConnection`):
            The connection already defined by pywbemcli

          server (:class:`pywbem.WBEMServer`):
            The WBEM server instance already defined by pywbemcli. This
            is normally provided by the initiating call from pywbemcli
            to execute this script

          interop_ns (:term:`string):
            Interop namespace. Overrides the interop namespace defined in
            the server_mock_data dictionary if it exists. This
            is normally provided by the initiating call from pywbemcli
            to execute this script

          server_mock_data (:class:`py:dict`):
            Dictionary that defines the characteristics of the mock. The
            default is DEFAULT_WBEM_SERVER_MOCK_DEFAULT_DICT defined above.

          verbose
        """
        self.verbose = verbose
        self.conn = conn
        self.wbem_server = server

        # default to the config dictionary defined in
        # DEFAULT_WBEM_SERVER_MOCK_DEFAULTDICT above.
        self.server_mock_data = server_mock_data or \
            DEFAULT_WBEM_SERVER_MOCK_DEFAULT_DICT

        FakedWBEMConnection._reset_logging_config()

        # Step 0: establish the interop namespace.
        self.interop_ns = interop_ns or \
            self.server_mock_data['interop-namspace']

        # Step 1: build classes for all namespaces based on class-names dict
        class_names = self.server_mock_data['class-names']
        for namespace, clns in class_names.items():
            self.build_classes(clns, namespace)

        self.display("Built classes")

        # Step 2: install user providers
        # TODO/Future: Install user providers from configuration definition
        # For now, install the Namespace provider. The issue is knowing
        # exactly what input parameters are required for each user provider.
        for provider in self.server_mock_data['user_providers']:
            if provider == "namespaceprovider":
                ns_provider = CIMNamespaceProvider(conn.cimrepository)
                conn.register_provider(ns_provider, namespaces=self.interop_ns)
            elif provider == 'subscriptionproviders':
                reg_provider = CIMIndicationFilterProvider(conn.cimrepository)
                conn.register_provider(reg_provider, namespaces=self.interop_ns)
                reg_provider = CIMListenerDestinationProvider(
                    conn.cimrepository)
                conn.register_provider(reg_provider, namespaces=self.interop_ns)
                reg_provider = CIMIndicationSubscriptionProvider(
                    conn.cimrepository)
                conn.register_provider(reg_provider, namespaces=self.interop_ns)
        # NOTE: The wbemserver is not usable until the instances for at
        # least object manager and namespaces have been inserted. Any attempt
        # to display the instance objects before that will fail because the
        # enumerate namespaces will be inconsistent.

        # Step 3: build the object manager.
        # Build CIM_ObjectManager instance into the interop namespace since
        # this is required to build namespace instances

        # # build the dictionary of values for the CIM_ObjectManager
        # TODO: Move this so definition is completely in hands of the
        # dictionary
        object_mgr_data = self.server_mock_data['object_manager']
        omdict = {
            "SystemCreationClassName": "CIM_ComputerSystem",
            "CreationClassName": "CIM_ObjectManager",
            "SystemName": self.server_mock_data['system_name'],
            "Name": object_mgr_data['Name'],
            "ElementName": object_mgr_data['ElementName'],
            "Description": object_mgr_data['Description'],
            "GatherStatisticalData": object_mgr_data['GatherStatisticalData']}
        self.build_obj_mgr_inst(omdict)

        self.display("Built object manager object")

        # Step 4: Build the registered profile and referenced_profile instances
        self.build_reg_profile_insts(
            self.server_mock_data['registered_profiles'])
        self.build_referenced_profile_insts(
            self.server_mock_data['referenced_profiles'])

        self.display("Built profile instances")

        # Step 5: build the defined central instances
        for ns, insts in self.server_mock_data['central-instances'].items():
            self.build_central_instances(ns, insts)

        # Step 6: build the defined element-conforms-to-profile associations
        # build element_conforms_to_profile insts from dictionary
        for ns, items in self.server_mock_data[
                'element_conforms_to_profile'].items():
            for item in items:
                profile_name = item[0]
                central_inst_path = CIMInstanceName(
                    item[1][0],
                    keybindings=item[1][1],
                    host=conn.host,
                    namespace=ns)
                prof_insts = self.wbem_server.get_selected_profiles(
                    registered_org=profile_name[0],
                    registered_name=profile_name[1],
                    registered_version=profile_name[2])
                assert len(prof_insts) == 1

                self.build_ECTP_inst(prof_insts[0].path, central_inst_path)

        self.display("Built central instances and element_conforms_to_Profile")

    def __str__(self):
        return 'object_manager_name={!r}, interop_ns={!r}, system_name=' \
            '{!r}, dmtf_schema_ver={!r}, schema_dir={!r}, wbem_server={}' \
            .format(self.server_mock_data['object_manager']['Name'],
                    self.interop_ns,
                    self.server_mock_data['system_name'],
                    self.server_mock_data['dmtf_schema']['version'],
                    self.server_mock_data['dmtf_schema']['dir'],
                    getattr(self, 'wbem_server', None))

    def __repr__(self):
        """
        Return a representation of the class object
        with all attributes, that is suitable for debugging.
        """
        return 'WBEMServerMock(object_manager_name={!r}, interop_ns={!r}, ' \
            'system_name={!r}, dmtf_schema_ver={!r}, schema_dir={!r}, ' \
            'wbem_server={!r}, registered_profiles={!r})' \
            .format(self.server_mock_data['object_manager']['Name'],
                    self.interop_ns,
                    self.server_mock_data['system_name'],
                    self.server_mock_data['dmtf_schema']['version'],
                    self.server_mock_data['dmtf_schema']['dir'],
                    getattr(self, 'wbem_server', None),
                    self.server_mock_data['registered_profiles'])

    def display(self, txt):
        """Display the txt and current repository. Diagnostic only"""
        if self.verbose:
            print(txt)
            self.conn.display_repository()

    def build_classes(self, classes, namespace):
        """
        Build the schema qualifier declarations, and the class objects in the
        defined namespace of the CIM repository from a DMTF schema.
        This requires only that the leaf objects be defined in a mof
        include file since the compiler finds the files for qualifiers
        and dependent classes.
        """
        try:
            self.conn.add_namespace(namespace)
        except CIMError as er:
            if er.status_code != CIM_ERR_ALREADY_EXISTS:
                pass

        # Compile the leaf classes into the CIM repositor
        # This test not required to use the class in the test environment.
        # However, if it is ever used as template for code that could
        # execute on pywbem version 0.x, this test is required.
        if hasattr(self.conn, 'compile_schema_classes'):
            # Using pywbem 1.x
            schema = DMTFCIMSchema(
                self.server_mock_data['dmtf_schema']['version'],
                self.server_mock_data['dmtf_schema']['dir'],
                use_experimental=False,
                verbose=self.verbose)
            # pylint: disable=no-member
            self.conn.compile_schema_classes(
                classes,
                schema.schema_pragma_file,
                namespace=namespace,
                verbose=self.verbose)
        else:
            # Using pywbem 0.x
            self.conn.compile_dmtf_schema(
                self.server_mock_data['dmtf_schema']['version'],
                self.server_mock_data['dmtf_schema']['dir'],
                class_names=classes,
                namespace=namespace,
                verbose=self.verbose)

        # Build the pg_schema elements
        # TODO: This should be separate method.
        if namespace in self.server_mock_data['pg_schema']:
            pg_schema_ns = self.server_mock_data['pg_schema'][namespace]
            filenames = pg_schema_ns['files']
            pg_dir = pg_schema_ns['dir']
            for fn in filenames:
                filepath = os.path.join(pg_dir, fn)
                self.conn.compile_mof_file(
                    filepath, namespace=namespace,
                    search_paths=[pg_dir],
                    verbose=self.verbose)

        # Compile the mof defined in the 'class-mof definitions
        if namespace in self.server_mock_data['class-mof']:
            mofs = self.server_mock_data['class-mof'][namespace]
            for mof in mofs:
                self.conn.compile_mof_string(mof, namespace=namespace,
                                             verbose=self.verbose)

    def inst_from_classname(self, class_name, namespace=None,
                            property_list=None,
                            property_values=None,
                            include_missing_properties=True,
                            include_path=True):
        # pylint: disable=too-many-arguments
        """
        Build instance from classname using class_name property to get class
        from a repository.
        """
        cls = self.conn.GetClass(class_name,
                                 namespace=namespace,
                                 LocalOnly=False,
                                 IncludeQualifiers=True,
                                 IncludeClassOrigin=True,
                                 PropertyList=property_list)

        return CIMInstance.from_class(
            cls,
            namespace=namespace,
            property_values=property_values,
            include_missing_properties=include_missing_properties,
            include_path=include_path)

    def add_inst_from_def(self, class_name, namespace=None,
                          property_values=None,
                          include_missing_properties=True,
                          include_path=True):
        """
        Build and insert into the environment a complete instance given the
        classname and a dictionary defining the properties of the instance.

        """
        # pylint: disable=too-many-arguments
        new_inst = self.inst_from_classname(
            class_name,
            namespace=namespace,
            property_values=property_values,
            include_missing_properties=include_missing_properties,
            include_path=include_path)

        self.conn.CreateInstance(new_inst, namespace=namespace)

        return new_inst

    def build_obj_mgr_inst(self, object_manager_values_dict):
        """
        Build a CIMObjectManager instance for the mock wbem server using
        fixed data defined in this method and data from the init parameter
        mock data. Add this instance to the repository
        """
        ominst = self.add_inst_from_def(
            "CIM_ObjectManager",
            namespace=self.interop_ns,
            property_values=object_manager_values_dict,
            include_missing_properties=False,
            include_path=True)

        rtn_ominsts = self.conn.EnumerateInstances("CIM_ObjectManager",
                                                   namespace=self.interop_ns)
        assert len(rtn_ominsts) == 1, \
            "Expected 1 ObjetManager instance, got {!r}".format(rtn_ominsts)

        return ominst

    def build_reg_profile_insts(self, profiles):
        """
        Build and install in repository the registered profiles defined by
        the profiles parameter. A dictionary of tuples where each tuple
        contains RegisteredOrganization, RegisteredName, RegisteredVersion

        Parameters:
          conn:
          profiles (dict of lists where each list contains org, name, version
             for a profiles)
        """
        # Map ValueMap to Value
        org_vm = ValueMapping.for_property(self.conn, self.interop_ns,
                                           'CIM_RegisteredProfile',
                                           'RegisteredOrganization')

        # This is a workaround hack to get ValueMap from Value
        org_vm_dict = {}   # reverse mapping dictionary (valueMap from Value)
        for value in range(0, 22):
            org_vm_dict[org_vm.tovalues(value)] = value

        for profile in profiles:
            instance_id = '{}+{}+{}'.format(profile[0], profile[1], profile[2])
            reg_prof_dict = {'RegisteredOrganization': org_vm_dict[profile[0]],
                             'RegisteredName': profile[1],
                             'RegisteredVersion': profile[2],
                             'InstanceID': instance_id}

            self.add_inst_from_def("CIM_RegisteredProfile",
                                   namespace=self.interop_ns,
                                   property_values=reg_prof_dict,
                                   include_missing_properties=False,
                                   include_path=True)

        rtn_rpinsts = self.conn.EnumerateInstances("CIM_RegisteredProfile",
                                                   namespace=self.interop_ns)
        assert rtn_rpinsts, \
            "Expected 1 or more RegisteredProfile instances, got none"

    def build_ECTP_inst(self, profile_path, element_path):
        """
        Build an instance of CIM_ElementConformsToProfile and insert into
        repository
        """
        class_name = 'CIM_ElementConformsToProfile'
        element_conforms_dict = {'ConformantStandard': profile_path,
                                 'ManagedElement': element_path}

        inst = self.add_inst_from_def(class_name,
                                      namespace=self.interop_ns,
                                      property_values=element_conforms_dict,
                                      include_missing_properties=False,
                                      include_path=True)

        assert self.conn.EnumerateInstances(class_name,
                                            namespace=self.interop_ns)
        assert self.conn.GetInstance(inst.path)

    def build_referenced_profile_insts(self, referenced_profiles):
        """
        Build and install in repository the referemced profile instances
        defined by the referemces parameter. A dictionary of tuples where each
        tuple contains Antecedent and Dependent reference in terms of the
        profile name as a tuple (org, name, version).

        Parameters:
          profiles (dict of tuples where each tuple defines the antecedent
          and dependent)
        """
        class_name = 'CIM_ReferencedProfile'
        for profile_name in referenced_profiles:
            antecedent = profile_name[0]
            dependent = profile_name[1]
            antecedent_inst = self.wbem_server.get_selected_profiles(
                registered_org=antecedent[0],
                registered_name=antecedent[1],
                registered_version=antecedent[2])
            dependent_inst = self.wbem_server.get_selected_profiles(
                registered_org=dependent[0],
                registered_name=dependent[1],
                registered_version=dependent[2])

            assert len(antecedent_inst) == 1, \
                "Antecedent: {0}".format(antecedent)
            assert len(dependent_inst) == 1, \
                "Dependent: {0}".format(dependent)

            ref_profile_dict = {'Antecedent': antecedent_inst[0].path,
                                'Dependent': dependent_inst[0].path}

            inst = self.add_inst_from_def(class_name,
                                          namespace=self.interop_ns,
                                          property_values=ref_profile_dict,
                                          include_missing_properties=False,
                                          include_path=True)

            assert self.conn.EnumerateInstances(class_name,
                                                namespace=self.interop_ns)
            assert self.conn.GetInstance(inst.path)

    def build_central_instances(self, namespace, central_instances):
        """
        Build the central_instances from the definitions provided in the list
        central_instance where each definition is a python CIMInstance object
        and add them to the repository. This method adds the path to each
        """
        for inst in central_instances:
            cls = self.conn.GetClass(inst.classname, namespace=namespace,
                                     LocalOnly=False, IncludeQualifiers=True,
                                     IncludeClassOrigin=True)
            inst.path = CIMInstanceName.from_instance(
                cls, inst, namespace=namespace, strict=True)

            self.conn.CreateInstance(inst, namespace=namespace)
