import unittest
import os

from zope.testing import doctestunit
from zope.component import testing
from Testing import ZopeTestCase as ztc

from Products.Five import zcml
from Products.Five import fiveconfigure
from Products.PloneTestCase import PloneTestCase as ptc
from Products.PloneTestCase.layer import PloneSite
from zope.publisher.browser import TestRequest
from zope.component import getMultiAdapter
from AccessControl.Permissions import manage_users

import jcu.shibboleth.pas

from Testing import ZopeTestCase
from Testing.ZopeTestCase import user_name, user_password
from Testing.ZopeTestCase.ZopeLite import installPackage
from Products.PloneTestCase import layer
import Products.PluggableAuthService

class TestCase(ZopeTestCase.Functional, ZopeTestCase.ZopeTestCase):

    _setup_fixture = 1

    def afterSetUp(self):
        # Upgrade the UserFolder to a PAS
        from Products.PluggableAuthService.Extensions.upgrade import replace_acl_users
        replace_acl_users(self.app.test_folder_1_)
        from Products.PluggableAuthService.interfaces.plugins import IGroupsPlugin, IGroupEnumerationPlugin
        self.uf = self.app.test_folder_1_.acl_users
        self.uf.roles.assignRoleToPrincipal('Manager', user_name)
        if not self.uf.hasObject('groups'):
            factory = self.uf.manage_addProduct['PluggableAuthService']
            factory.addZODBGroupManager('groups')
            plugins = self.uf.plugins
            plugins.activatePlugin(IGroupsPlugin, 'groups')
            plugins.activatePlugin(IGroupEnumerationPlugin, 'groups')

        zcml.load_site()
        installPackage('jcu.shibboleth.pas')

        # Add the session objects
        ZopeTestCase.utils.setupCoreSessions(self.app)

        #self.setRoles(manage_users, user_name)

        #from ipdb import set_trace; set_trace()


def test_suite():
    return unittest.TestSuite([

        ztc.FunctionalDocFileSuite(
            'configuration_functional.txt', package='jcu.shibboleth.pas.tests',
            test_class=TestCase),

        ])

if __name__ == '__main__':
    unittest.main(defaultTest='test_suite')

