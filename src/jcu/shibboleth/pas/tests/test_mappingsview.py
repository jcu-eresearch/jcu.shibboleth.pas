import unittest
import os
import base

from zope.testing import doctestunit
from zope.component import testing
from Testing import ZopeTestCase as ztc

from Products.Five import zcml
from Products.Five import fiveconfigure
from Products.PloneTestCase import PloneTestCase as ptc
from Products.PloneTestCase.layer import PloneSite
from zope.publisher.browser import TestRequest
from zope.component import getMultiAdapter

import jcu.shibboleth.pas
from base import ShibbolethTestCase

class TestCase(ShibbolethTestCase):
    class layer(PloneSite):
        @classmethod
        def setUp(cls):
            fiveconfigure.debug_mode = True
            zcml.load_config('configure.zcml',
                             jcu.shibboleth.pas)
            fiveconfigure.debug_mode = False
        @classmethod
        def tearDown(cls):
            pass

    def afterSetUp(self):
        from jcu.shibboleth.pas.plugin import ShibbolethHelper
        shib = ShibbolethHelper('shib', 'Shibboleth Helper')
        self.folder.acl_users['shib'] = shib
        self.uf = self.folder.acl_users

        # Setup attribute map resolver
        path = os.path.dirname(jcu.shibboleth.pas.__file__)
        self.uf.shib.shibboleth_config_dir = os.path.join(path, 'tests', 'shib2')

        self.shib = self.folder.acl_users.shib


def test_suite():
    return unittest.TestSuite([

        ztc.FunctionalDocTestSuite(
            module='jcu.shibboleth.pas.browser.mappings',
            test_class=TestCase),

        ])


if __name__ == '__main__':
    unittest.main(defaultTest='test_suite')

