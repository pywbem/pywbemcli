"""
mock_pywbem test script that installs a method callback to be executed. This is
based on the CIM_Foo class in the simple_mock_model.mof test file

"""

import six
from pywbem_mock import MethodProvider

from pywbem import CIM_ERR_METHOD_NOT_AVAILABLE, CIMError, CIM_ERR_NOT_FOUND

# test that GLOBALS exist
assert "CONN" in globals()
assert 'SERVER' in globals()
assert 'VERBOSE' in globals()
global CONN  # pylint: disable=global-at-module-level


class CIM_AllTypesMethodProvider(MethodProvider):
    """
    User test provider for InvokeMethod using CIM_Foo and method1.
    This is basis for testing passing of input parameters correctly and
    generating some exceptions.  It uses only one input parameter where the
    value defines the test and one return parameter that provides data from the
    provider, normally the value of the parameter defined with the input
    parameter. Test for existence of method named method1
    """

    provider_classnames = 'PyWBEM_AllTypes'

    def __init__(self, cimrepository):
        super(CIM_AllTypesMethodProvider, self).__init__(cimrepository)

    def InvokeMethod(self, namespace, MethodName, ObjectName, Params):
        """
        Simplistic test method. Validates methodname, objectname, Params
        and returns rtn value 0 and one parameter

        The parameters and return for Invoke method are defined in
        :meth:`~pywbem_mock.MethodProvider.InvokeMethod`
        """
        # validate namespace using method in BaseProvider
        self.validate_namespace(namespace)

        # get classname and validate. This provider uses only one class
        if isinstance(ObjectName, six.string_types):
            classname = ObjectName
        else:
            classname = ObjectName.classname

        assert classname.lower() == self.provider_classnames.lower()

        if MethodName != 'AllTypesMethod':
            raise CIMError(CIM_ERR_METHOD_NOT_AVAILABLE)

        # Test if class exists.
        if not self.class_exists(namespace, classname):
            raise CIMError(
                CIM_ERR_NOT_FOUND,
                "class {0} does not exist in CIM repository, "
                "namespace {1}".format(classname, namespace))

        # Return the input parameters and returnvalue == 0
        return (0, Params)


# Add the the callback to the mock repository
# pylint: disable=undefined-variable
CONN.register_provider(  # noqa: F821
    CIM_AllTypesMethodProvider(CONN.cimrepository),  # noqa: F821
    CONN.default_namespace,  # noqa: F821
    verbose=False)