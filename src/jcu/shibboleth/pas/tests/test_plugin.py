import unittest
import os

from zope.component import testing
from Testing import ZopeTestCase as ztc

from Products.Five import zcml
from Products.Five import fiveconfigure
from Products.PloneTestCase import PloneTestCase as ptc
from Products.PloneTestCase.layer import PloneSite
from zope.publisher.browser import TestRequest
from zope.component import getMultiAdapter

import jcu.shibboleth.pas

from Testing import ZopeTestCase
from Products.PloneTestCase import layer
import Products.PluggableAuthService

class TestCase(ZopeTestCase.ZopeTestCase):

    _setup_fixture = 0

    def afterSetUp(self):
        # Upgrade the UserFolder to a PAS
        from Products.PluggableAuthService.Extensions.upgrade import replace_acl_users
        replace_acl_users(self.app)
        from Products.PluggableAuthService.interfaces.plugins import IGroupsPlugin, IGroupEnumerationPlugin
        self.uf = self.app.acl_users
        if not self.uf.hasObject('groups'):
            factory = self.uf.manage_addProduct['PluggableAuthService']
            factory.addZODBGroupManager('groups')
            plugins = self.uf.plugins
            plugins.activatePlugin(IGroupsPlugin, 'groups')
            plugins.activatePlugin(IGroupEnumerationPlugin, 'groups')


        # Add the session objects
        ZopeTestCase.utils.setupCoreSessions(self.app)

        from jcu.shibboleth.pas.plugin import ShibbolethHelper
        shib = ShibbolethHelper('shib', 'Shibboleth Helper')
        self.app.acl_users.acl_users['shib'] = shib

        # Setup AAP resolver
        path = os.path.dirname(jcu.shibboleth.pas.__file__)
        self.uf.shib.shibboleth_config_dir = path + os.sep + 'tests'

        self.shib = self.app.acl_users.shib
        #from ipdb import set_trace; set_trace()

def test_suite():
    return unittest.TestSuite([

        ztc.ZopeDocTestSuite(
            module='jcu.shibboleth.pas.plugin',
            test_class=TestCase),
        ])


if __name__ == '__main__':
    unittest.main(defaultTest='test_suite')

