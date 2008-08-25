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
        from Products.PluggableAuthService.interfaces.plugins import IGroupsPlugin, IGroupEnumerationPlugin, IUserEnumerationPlugin, IAuthenticationPlugin, IRolesPlugin
        from Products.PluggableAuthService.interfaces.plugins import ICredentialsUpdatePlugin, ICredentialsResetPlugin, IExtractionPlugin, IChallengePlugin
        self.uf = self.app.test_folder_1_.acl_users
        self.uf.roles.assignRoleToPrincipal('Manager', user_name)
        plugins = self.uf.plugins
        factory = self.uf.manage_addProduct['PluggableAuthService']
        if not self.uf.hasObject('groups'):
            factory.addZODBGroupManager('groups')
            plugins.activatePlugin(IGroupsPlugin, 'groups')
            plugins.activatePlugin(IGroupEnumerationPlugin, 'groups')
        if not self.uf.hasObject('cookies'):
            factory.addCookieAuthHelper('cookies')
            #plugins.activatePlugin(ICredentialsUpdatePlugin, 'cookies')
            #plugins.activatePlugin(ICredentialsResetPlugin, 'cookies')
            plugins.activatePlugin(IExtractionPlugin, 'cookies')
        if not self.uf.hasObject('basic_auth'):
            factory.addHTTPBasicAuthHelper('basic_auth')
            #plugins.activatePlugin(ICredentialsUpdatePlugin, 'cookies')
            #plugins.activatePlugin(ICredentialsResetPlugin, 'cookies')
            plugins.activatePlugin(IExtractionPlugin, 'basic_auth')
            plugins.activatePlugin(IChallengePlugin, 'basic_auth')

        zcml.load_site()
        #zcml.load_config('configure.zcml', jcu.shibboleth.pas)
        installPackage('jcu.shibboleth.pas')

        # Add the session objects
        ZopeTestCase.utils.setupCoreSessions(self.app)

        from jcu.shibboleth.pas.plugin import ShibbolethHelper
        shib = ShibbolethHelper('shib', 'Shibboleth Helper')
        self.app.test_folder_1_.acl_users['shib'] = shib
        plugins.activatePlugin(IExtractionPlugin, 'shib')
        plugins.activatePlugin(IAuthenticationPlugin, 'shib')
        plugins.activatePlugin(IChallengePlugin, 'shib')
        plugins.activatePlugin(IRolesPlugin, 'shib')
        plugins.activatePlugin(IUserEnumerationPlugin, 'shib')
        #plugins.activatePlugin(IChallengePlugin, 'basic_auth')

        # Setup AAP resolver
        path = os.path.dirname(jcu.shibboleth.pas.__file__)
        self.app.test_folder_1_.acl_users.shib.manage_changeProperties({"Shibboleth_Config_Dir":path + os.sep +  'tests'})


import unittest
from Products.PluggableAuthService.tests.conformance \
        import IAuthenticationPlugin_conformance
from Products.PluggableAuthService.tests.conformance \
        import IRolesPlugin_conformance
from Products.PluggableAuthService.tests.conformance \
        import IGroupsPlugin_conformance
from Products.PluggableAuthService.tests.conformance \
        import IUserEnumerationPlugin_conformance
from Products.PluggableAuthService.tests.conformance \
        import IChallengePlugin_conformance
from Products.PluggableAuthService.tests.conformance \
        import ILoginPasswordExtractionPlugin_conformance

from Products.PluggableAuthService.tests.test_PluggableAuthService \
     import FauxRequest, FauxResponse, FauxObject, FauxRoot, FauxContainer


class FauxSettableRequest(FauxRequest):

    def __init__(self, *args, **kw):
        super(FauxSettableRequest, self).__init__(*args, **kw)
        self.cookies = {}
        self.SESSION = {}

    def set(self, name, value):
        self._dict[name] = value


class FauxCookieResponse(FauxResponse):

    def __init__(self):
        self.cookies = {}
        self.redirected = False
        self.status = '200'
        self.headers = {}

    def setCookie(self, cookie_name, cookie_value, path):
        self.cookies[(cookie_name, path)] = cookie_value

    def expireCookie(self, cookie_name, path):
        if (cookie_name, path) in self.cookies:
            del self.cookies[(cookie_name, path)]

    def redirect(self, location, status=302, lock=0):
        self.status = status
        self.headers['Location'] = location


class ConformanceTestCase(unittest.TestCase,
                          IAuthenticationPlugin_conformance,
                          IRolesPlugin_conformance,
                          IGroupsPlugin_conformance,
                          IUserEnumerationPlugin_conformance,
                          IChallengePlugin_conformance,
                          ILoginPasswordExtractionPlugin_conformance):
    def _getTargetClass(self):

        from jcu.shibboleth.pas.plugin import ShibbolethHelper

        return ShibbolethHelper

    def _makeOne(self, id='test', *args, **kw):

        return self._getTargetClass()(id=id, *args, **kw)

    def test_extractCredentials_no_creds(self):

        helper = self._makeOne()
        response = FauxCookieResponse()
        request = FauxSettableRequest(RESPONSE=response)

        self.assertEqual(helper.extractCredentials(request), {})

    def test_enumerateUsers_no_criteria(self):

        from Products.PluggableAuthService.tests.test_PluggableAuthService \
            import FauxRoot

        root = FauxRoot()
        shib = self._makeOne( id='no_crit' ).__of__( root )

        ID_LIST = ( 'foo', 'bar', 'baz', 'bam' )

        for id in ID_LIST:

            shib.store[id] =  {u'HTTP_REMOTE_USER': id, 'SHIB_PERSON_MAIL':'%s@example.com' % id }

        info_list = shib.enumerateUsers()

        self.assertEqual( len( info_list ), len( ID_LIST ) )

        sorted = list( ID_LIST )
        sorted.sort()

        for i in range( len( sorted ) ):

            self.assertEqual( info_list[ i ][ 'id' ], sorted[ i ] )
            # Currently the ID is the same as the Login
            #self.assertEqual( info_list[ i ][ 'login' ]
            #                , '%s@example.com' % sorted[ i ] )
            self.assertEqual( info_list[ i ][ 'pluginid' ], 'no_crit' )
            self.assertEqual( info_list[ i ][ 'editurl' ]
                            , 'no_crit/manage_users?user_id=%s' % sorted[ i ])


    def test_enumerateUsers_exact( self ):

        from Products.PluggableAuthService.tests.test_PluggableAuthService \
            import FauxRoot

        root = FauxRoot()
        shib = self._makeOne( id='exact' ).__of__( root )

        ID_LIST = ( 'foo', 'bar', 'baz', 'bam' )

        for id in ID_LIST:

            shib.store[id] =  {u'HTTP_REMOTE_USER': id, 'SHIB_PERSON_MAIL':'%s@example.com' % id }

        info_list = shib.enumerateUsers( id='bar', exact_match=True )

        self.assertEqual( len( info_list ), 1 )
        info = info_list[ 0 ]

        self.assertEqual( info[ 'id' ], 'bar' )
        # Currently the ID is the same as the Login
        #self.assertEqual( info[ 'login' ], 'bar@example.com' )
        self.assertEqual( info[ 'pluginid' ], 'exact' )
        self.assertEqual( info[ 'editurl' ]
                        , 'exact/manage_users?user_id=bar' )



    def test_enumerateUsers_partial( self ):

        from Products.PluggableAuthService.tests.test_PluggableAuthService \
            import FauxRoot

        root = FauxRoot()
        shib = self._makeOne( id='partial' ).__of__( root )

        ID_LIST = ( 'foo', 'bar', 'baz', 'bam' )

        for id in ID_LIST:

            shib.store[id] =  {u'HTTP_REMOTE_USER': id, 'SHIB_PERSON_MAIL':'%s@example.com' % id }

        info_list = shib.enumerateUsers( id=['a','o'], exact_match=False )

        self.assertEqual( len( info_list ), len( ID_LIST ) ) # all match

        sorted = list( ID_LIST )
        sorted.sort()

        for i in range( len( sorted ) ):

            self.assertEqual( info_list[ i ][ 'id' ], sorted[ i ] )
            #self.assertEqual( info_list[ i ][ 'login' ]
            #                , '%s@example.com' % sorted[ i ] )
            self.assertEqual( info_list[ i ][ 'pluginid' ], 'partial' )
            self.assertEqual( info_list[ i ][ 'editurl' ]
                            , 'partial/manage_users?user_id=%s' % sorted[ i ])

        info_list = shib.enumerateUsers( id='ba', exact_match=False )

        self.assertEqual( len( info_list ), len( ID_LIST ) - 1 ) # no 'foo'

        sorted = list( ID_LIST )
        sorted.sort()

        for i in range( len( sorted ) - 1 ):

            self.assertEqual( info_list[ i ][ 'id' ], sorted[ i ] )
            #self.assertEqual( info_list[ i ][ 'login' ]
            #                , '%s@example.com' % sorted[ i ] )
            self.assertEqual( info_list[ i ][ 'pluginid' ], 'partial' )
            self.assertEqual( info_list[ i ][ 'editurl' ]
                            , 'partial/manage_users?user_id=%s' % sorted[ i ])


    def test_enumerateUsers_other_criteria( self ):

        from Products.PluggableAuthService.tests.test_PluggableAuthService \
            import FauxRoot

        root = FauxRoot()
        shib = self._makeOne( id='partial' ).__of__( root )

        ID_LIST = ( 'foo', 'bar', 'baz', 'bam' )

        for id in ID_LIST:

            shib.store[id] =  {u'HTTP_REMOTE_USER': id, 'SHIB_PERSON_MAIL':'%s@example.com' % id }

        info_list = shib.enumerateUsers( email='bar@example.com',
                                        exact_match=False )
        self.assertEqual( len( info_list ), 0 )

    def test_enumerateUsers_unicode( self ):

        from Products.PluggableAuthService.tests.test_PluggableAuthService \
            import FauxRoot

        root = FauxRoot()
        shib = self._makeOne( id='partial' ).__of__( root )

        ID_LIST = ( 'foo', 'bar', 'baz', 'bam' )

        for id in ID_LIST:

            shib.store[id] =  {u'HTTP_REMOTE_USER': id, 'SHIB_PERSON_MAIL':'%s@example.com' % id }

        info_list = shib.enumerateUsers( id = u'abc',
                                        exact_match=False )
        self.assertEqual( len( info_list ), 0 )


    def test_enumerateUsers_exact_nonesuch( self ):

        from Products.PluggableAuthService.tests.test_PluggableAuthService \
            import FauxRoot

        root = FauxRoot()
        shib = self._makeOne( id='exact_nonesuch' ).__of__( root )

        ID_LIST = ( 'foo', 'bar', 'baz', 'bam' )

        for id in ID_LIST:

            shib.store[id] =  {u'HTTP_REMOTE_USER': id, 'SHIB_PERSON_MAIL':'%s@example.com' % id }

        self.assertEquals( shib.enumerateUsers( id='qux', exact_match=True )
                         , () )


    def test_enumerateUsers_multiple_logins( self ):

        from Products.PluggableAuthService.tests.test_PluggableAuthService \
            import FauxRoot

        root = FauxRoot()
        shib = self._makeOne( id='partial' ).__of__( root )

        ID_LIST = ( 'foo', 'bar', 'baz', 'bam' )
        LOGIN_LIST = [ '%s@example.com' % x for x in ID_LIST ]

        for i in range( len( ID_LIST ) ):

            shib.store[ID_LIST[i]] =  {u'HTTP_REMOTE_USER': ID_LIST[i], 'SHIB_PERSON_MAIL':'%s' % LOGIN_LIST[i] }

        info_list = shib.enumerateUsers( login=ID_LIST )

        self.assertEqual( len( info_list ), len( ID_LIST ) )

        for info in info_list:
            self.failUnless( info[ 'id' ] in ID_LIST )
            self.failUnless( info[ 'login' ] in ID_LIST )

        SUBSET_IDS = ID_LIST[:3]

        info_list = shib.enumerateUsers( login=SUBSET_IDS )

        self.assertEqual( len( info_list ), len( SUBSET_IDS ) )

        for info in info_list:
            self.failUnless( info[ 'id' ] in SUBSET_IDS )
            self.failUnless( info[ 'login' ] in SUBSET_IDS )



def test_suite():
    return unittest.TestSuite([

        ztc.FunctionalDocFileSuite(
            'intergration_shibboleth.txt', package='jcu.shibboleth.pas.tests',
            test_class=TestCase),

        unittest.makeSuite(ConformanceTestCase),

        ])

if __name__ == '__main__':
    unittest.main(defaultTest='test_suite')

