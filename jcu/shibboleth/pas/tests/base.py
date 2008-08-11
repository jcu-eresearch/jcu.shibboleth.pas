import unittest
from zope.testing import doctest

from Testing import ZopeTestCase
from Products.PluggableAuthService.tests.pastc import PASTestCase

ZopeTestCase.installProduct('PluggableAuthService')

class ShibbolethTestCase(PASTestCase):
    """Base class for integration tests for the 'Shibboleth' product.
    """


