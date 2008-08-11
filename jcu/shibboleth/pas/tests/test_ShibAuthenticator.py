import unittest
import os
import base
from base import ShibbolethTestCase

class ShibAuthenticator(ShibbolethTestCase):
    def afterSetUp(self):
        from jcu.shibboleth.pas.plugin import ShibbolethHelper
        shib = ShibbolethHelper('shib', 'Shibboleth Helper')
        self.folder.acl_users['shib'] = shib
        self.uf = self.folder.acl_users

    def testAttributeAuthorityHeaders(self):
        path = os.path.dirname(base.__file__)

        Attributes = [u'HTTP_SHIB_EP_AFFILIATION', u'HTTP_SHIB_EP_UNSCOPEDAFFILIATION', u'HTTP_REMOTE_USER', u'HTTP_SHIB_EP_ENTITLEMENT', u'HTTP_SHIB_TARGETEDID', u'HTTP_SHIB_TARGETEDID', u'HTTP_SHIB_EP_PRIMARYAFFILIATION', u'HTTP_SHIB_EP_PRIMARYORGUNITDN', u'HTTP_SHIB_EP_ORGUNITDN', u'HTTP_SHIB_EP_ORGDN', u'HTTP_SHIB_PERSON_COMMONNAME', u'HTTP_SHIB_PERSON_SURNAME', u'HTTP_SHIB_INETORGPERSON_MAIL', u'HTTP_SHIB_PERSON_TELEPHONENUMBER', u'HTTP_SHIB_ORGPERSON_TITLE', u'HTTP_SHIB_INETORGPERSON_INITIALS', u'HTTP_SHIB_PERSON_DESCRIPTION', u'HTTP_SHIB_INETORGPERSON_CARLICENSE', u'HTTP_SHIB_INETORGPERSON_DEPTNUM', u'HTTP_SHIB_INETORGPERSON_DISPLAYNAME', u'HTTP_SHIB_INETORGPERSON_EMPLOYEENUM', u'HTTP_SHIB_INETORGPERSON_EMPLOYEETYPE', u'HTTP_SHIB_INETORGPERSON_PREFLANG', u'HTTP_SHIB_INETORGPERSON_MANAGER', u'HTTP_SHIB_INETORGPERSON_ROOMNUM', u'HTTP_SHIB_ORGPERSON_SEEALSO', u'HTTP_SHIB_ORGPERSON_FAX', u'HTTP_SHIB_ORGPERSON_STREET', u'HTTP_SHIB_ORGPERSON_POBOX', u'HTTP_SHIB_ORGPERSON_POSTALCODE', u'HTTP_SHIB_ORGPERSON_STATE', u'HTTP_SHIB_INETORGPERSON_GIVENNAME', u'HTTP_SHIB_ORGPERSON_LOCALITY', u'HTTP_SHIB_INETORGPERSON_BUSINESSCAT', u'HTTP_SHIB_ORGPERSON_ORGUNIT', u'HTTP_SHIB_ORGPERSON_OFFICENAME']
        self.assert_(self.uf.shib.getProperty("Shibboleth_Config_Dir"))
        for a in self.uf.shib.getPossibleAttributes(path + "/AAP.xml"):
            self.assert_(a in Attributes)
        self.uf.shib.manage_changeProperties({"Shibboleth_Config_Dir":path})
        self.assert_(self.uf.shib.configfileExists())
        self.assert_(self.uf.shib.getPossibleAttributes())


def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(ShibAuthenticator))
    return suite

