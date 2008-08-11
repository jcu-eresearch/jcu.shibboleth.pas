import unittest

from zope.testing import doctestunit
from zope.component import testing
from Testing import ZopeTestCase as ztc

from Products.Five import zcml
from Products.Five import fiveconfigure

import jcu.shibboleth.pas
from base import ShibbolethTestCase


def test_suite():
    return unittest.TestSuite([

        ztc.FunctionalDocFileSuite(
            'README.txt', package='jcu.shibboleth.pas',
            test_class=ShibbolethTestCase),

        ])

if __name__ == '__main__':
    unittest.main(defaultTest='test_suite')

