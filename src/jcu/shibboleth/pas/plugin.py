'''Class: PasHelper
'''
import logging, StringIO, traceback, re, pickle, base64, md5
from logging import DEBUG, ERROR, INFO
from os import path

import Constants as Constants
import interface
from BTrees.OOBTree import OOBTree
from AccessControl.SecurityInfo import ClassSecurityInfo
from App.class_init import default__class_init__ as InitializeClass
from Products.PluggableAuthService.interfaces.plugins import IRoleEnumerationPlugin
from Products.PluggableAuthService.permissions import ManageUsers
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PluggableAuthService.utils import classImplements
from Products.PluggableAuthService.UserPropertySheet import UserPropertySheet
from persistent.mapping import PersistentMapping


def isStringType(data):
    return isinstance(data, str) or isinstance(data, unicode)


log = logging.getLogger("jcu.shibboleth.pas")

class ShibbolethHelper(BasePlugin):
    '''Multi-plugin Shibboleth

    '''

    meta_type = 'Shibboleth Helper'

    security = ClassSecurityInfo()

    manage_options = ( BasePlugin.manage_options +
                       ( { 'label': 'Configuration',
                           'action': 'manage_shibbolethhelper',
                           'help':('jcu.shibboleth.pas','manage_shibbolethhelper.stx')}
                         ,
                       ) +
                       ( { 'label': 'Map Roles',
                           'action': 'manage_roles',
                           'help':('jcu.shibboleth.pas','manage_mapping.stx')}
                         ,
                       ) +
                       ( { 'label': 'Map Groups',
                           'action': 'manage_groups',
                           'help':('jcu.shibboleth.pas','manage_mapping.stx')}
                         ,
                       ) +
                       ( { 'label': 'Import/Export',
                           'action': 'manage_importexport',
                           'help':('jcu.shibboleth.pas','manage_mapping.stx')}
                         ,
                       )
                     )

    _op_switch = None

    def __init__(self, id, title=None, total_shib=False):
        super(ShibbolethHelper, self).__init__()
        self._id = self.id = id
        self.title = title
        self.total_shib = total_shib
        self.log(INFO,'Initilizing Shibboleth Authentication.')
        self.login_path = "login"
        self.role_mapping =  PersistentMapping()
        self.log(INFO,'Role Mapping. %s' % self.role_mapping)
        self.group_mapping =  PersistentMapping()
        self.log(INFO,'Group Mapping. %s' % self.group_mapping)
        self._mapping_map = {Constants.RoleM: self.role_mapping, Constants.GroupM:self.group_mapping}
        self.__setup_compiled_func_map()

        # Shibboleth attributes store
        self.store = OOBTree()

        # Shibboleth attributes map
        self.attr_map = OOBTree()
        self.rattr_map = OOBTree()

        # Default Values for attribute map
        self.attr_map['HTTP_DISPLAYNAME'] = 'fullname'
        self.attr_map['HTTP_MAIL'] = 'email'
        self.rattr_map['fullname'] = 'HTTP_DISPLAYNAME'
        self.rattr_map['fullname_fallback'] = 'HTTP_CN'
        self.rattr_map['email'] = 'HTTP_MAIL'

        #Properties for the Property Manager.
        self.max_brackets = 6
        self.userid_attribute = 'HTTP_SHARED_TOKEN'
        self.idp_attribute = 'HTTP_SHIB_IDENTITY_PROVIDER'
        self.shibboleth_config_dir = '/etc/shibboleth'
        self.sso_url = '/Shibboleth.sso/DS'


    def __setup_compiled_func_map(self):
        self._v_compiled_mapping_func_map = {}
        for i in self._mapping_map:
            self._v_compiled_mapping_func_map[i] = {}

    #
    #   IAuthenticationPlugin implementation
    #
    security.declarePrivate('authenticateCredentials')
    def authenticateCredentials(self, credentials):
        """Authenticate Credentials
        """
        if not credentials.has_key('shibboleth.session'):
            log.debug("Will only authenticate Shibboleth credentials.")
            return None

        session_id = credentials.get('shibboleth.session')
        log.debug('Authentication Requested.')
        url = self.getLoginURL()
        request = self.REQUEST
        log.debug("URLS: %s, %s" % (request.URL, url))
        if request.URL == url:
            log.debug("Not attempting to authenticate login request.")
            return None

        if credentials['shibboleth.id'] == credentials['shibboleth.session']:
            login = "Pseudo-Anonymous: %s" % credentials['shibboleth.id']
            return (self.prefix + session_id, login)

        login = credentials.get('shibboleth.id')
        return (self.prefix + login, login)


    #
    #   IChallengePlugin implementation
    #
    security.declarePrivate('challenge')
    def challenge(self, request, response):
        """The Challange
        """
        req = self.REQUEST
        resp = req['RESPONSE']

        self.log(INFO, "Challange.")
        url = self.getLoginURL()
        came_from = req.get('URL', '')
        query = req.get('QUERY_STRING')
        if query:
            if not query.startswith('?'):
                query = '?' + query
            came_from = came_from + query

        shibSessionId = self.__getShibbolethSessionId(request)
        if not shibSessionId:
            resp.redirect("%s?came_from=%s" % (url, came_from), lock=1)
            return True

        return False

    #
    #    ICredentialsResetPlugin implementation
    #
    security.declarePrivate('extractCredentials')
    def resetCredentials(self, request, response):
        """
            >>> from Products.PluggableAuthService.interfaces.plugins import \
                    ICredentialsResetPlugin
            >>> plugins = self.uf.plugins
            >>> plugins.activatePlugin(ICredentialsResetPlugin, 'shib')

            >>> print self.shib

        Expire the _shibsession_XXX cookie here to enable users to log
        out correctly.
        """
        for cookie in request.cookies:
            if 'shibsession' in cookie:
                response.expireCookie(cookie, path='/')

    #
    #    IDeleteCapability implementation
    #
    security.declarePublic('allowDeletePrincipal')
    def allowDeletePrincipal(self, principal_id):
        """
            >>> self.shib.store = {'B_0-_88s2CiUXmJx-PYW_8TugZI': {
            ...     u'HTTP_SHARED_TOKEN': 'B_0-_88s2CiUXmJx-PYW_8TugZI',
            ...     u'HTTP_CN': 'David B',
            ...     u'HTTP_MAIL': 'david@jcu.edu.au',
            ...     u'HTTP_REMOTE_USER':'david',
            ...     }
            ... }
            >>> self.shib.allowDeletePrincipal('B_0-_88s2CiUXmJx-PYW_8TugZI')
            1

        True iff this plugin can delete a certain user/group.
        This is true if this plugin manages the user.
        """
        if principal_id in self.store:
            return 1
        return 0

    #
    #   IUserManagement implementation
    #
    security.declarePrivate('doChangeUser')
    def doChangeUser(self, principal_id, password, **kw):
        """We don't change users.
        """
        pass

    security.declarePrivate('doDeleteUser')
    def doDeleteUser(self, principal_id):
        """
            >>> from Products.PluggableAuthService.interfaces.plugins import \
                    IPropertiesPlugin, IUserEnumerationPlugin
            >>> from Products.PlonePAS.interfaces.plugins import \
                    IUserManagement
            >>> plugins = self.uf.plugins
            >>> plugins.activatePlugin(IPropertiesPlugin, 'shib')
            >>> plugins.activatePlugin(IUserEnumerationPlugin, 'shib')
            >>> plugins.activatePlugin(IUserManagement, 'shib')

            >>> self.shib.store = {'B_0-_88s2CiUXmJx-PYW_8TugZI': {
            ...     u'HTTP_SHARED_TOKEN': 'B_0-_88s2CiUXmJx-PYW_8TugZI',
            ...     u'HTTP_CN': 'David B',
            ...     u'HTTP_MAIL': 'david@jcu.edu.au',
            ...     u'HTTP_REMOTE_USER':'david',
            ...     }
            ... }
            >>> u = self.app.acl_users.getUser('B_0-_88s2CiUXmJx-PYW_8TugZI')
            >>> print u
            B_0-_88s2CiUXmJx-PYW_8TugZI

            >>> self.app.acl_users.doDeleteUser('B_0-_88s2CiUXmJx-PYW_8TugZI')

            >>> 'B_0-_88s2CiUXmJx-PYW_8TugZI' in self.shib.store

        Given a Shibboleth ID (shared token, typically), delete that user
        """
        if not self.allowDeletePrincipal(principal_id):
            raise KeyError, 'Invalid user ID: %s' % principal_id

        del self.store[principal_id]
        return True

    #
    #    IExtractionPlugin implementation
    #
    security.declarePrivate('extractCredentials')
    def extractCredentials(self, request):
        """Extract the credentials
        """
        session = request.SESSION
        if session.has_key('shibboleth.session') and session.has_key('shibboleth.id'):
            return {"shibboleth.session": session.get('shibboleth.session'),
                    "shibboleth.id": session.get('shibboleth.id')}

        session_id = self.__getShibbolethSessionId(request)
        self.log(DEBUG, "extractCredentials: %s" % session_id)
        if not session_id:
            self.log(DEBUG, "extractCredentials: Not Shib")
            return {}

        id, attributes = self.__extract_shib_data(request)
        session['shibboleth.id'] = id
        # if not Pseudo-Anonymous then store the users details
        if not id == session_id:
            # Store the users attribute in the tool and in the users session
            self.store[id] = attributes

        # set session level variables so that we won't need to keep authing
        session.set('shibboleth.session', session_id)
        session.set('shibboleth.id', id)

        # Doesn't return login/password because no other tool can help authentication
        return {"shibboleth.session": session_id, "shibboleth.id": id}


    #
    #    IRolesPlugin implementation
    #
    security.declarePrivate('getRolesForPrincipal')
    def getRolesForPrincipal(self, principal, request=None):
        """

            >>> from zope.publisher.browser import TestRequest
            >>> shib_headers = { \
              'HTTP_REMOTE_USER': 'russell@vpac.org', \
              'HTTP_SHIB_SESSION_ID' : "_9c86b438e92e1de9b378a23f4838a959", }
            >>> request = TestRequest(**shib_headers)
            >>> request.SESSION = self.app.session_data_manager.getSessionData()
            >>> self.app.acl_users.shib.REQUEST.environ.update({'HTTP_REMOTE_USER': 'russell@vpac.org'})
            >>> self.shib.REQUEST.SESSION = self.app.session_data_manager.getSessionData()
            >>> from Products.PluggableAuthService.plugins.tests.helpers import DummyUser
            >>> self.shib.getRolesForPrincipal(DummyUser('russell@vpac.org'), request)
            ()
        """
        self.log(INFO, "Principal: %s"%principal)
        if not hasattr(self,'_v_compiled_mapping_func_map'):
            self.__compileMappings()
        return self.__caculateMapping(principal.getId(), self._v_compiled_mapping_func_map[Constants.RoleM])


    #
    #    IGroupsPlugin implementation
    #
    security.declarePrivate('getRolesForPrincipal')
    def getGroupsForPrincipal(self, principal, request=None):
        """

            >>> from zope.publisher.browser import TestRequest
            >>> shib_headers = { \
              'HTTP_REMOTE_USER': 'russell@vpac.org', \
              'HTTP_SHIB_SESSION_ID' : "_9c86b438e92e1de9b378a23f4838a959", }
            >>> request = TestRequest(**shib_headers)
            >>> request.SESSION = self.app.session_data_manager.getSessionData()
            >>> self.app.acl_users.shib.REQUEST.environ.update({'HTTP_REMOTE_USER': 'russell@vpac.org'})
            >>> self.shib.REQUEST.SESSION = self.app.session_data_manager.getSessionData()
            >>> from Products.PluggableAuthService.plugins.tests.helpers import DummyUser
            >>> self.shib.getGroupsForPrincipal(DummyUser('russell@vpac.org'), request)
            ()
        """
        if not hasattr(self,'_v_compiled_mapping_func_map'):
            self.__compileMappings()
        return self.__caculateMapping(principal.getId(), self._v_compiled_mapping_func_map[Constants.GroupM])


    #
    #   IUserEnumerationPlugin implementation
    #
    security.declarePrivate('enumerateUsers')
    def enumerateUsers(self, id=None, login=None, exact_match=False, sort_by=None, max_results=None, **kw):
        """ See IUserEnumerationPlugin.
        """
        user_info = []
        user_ids = []
        plugin_id = self.getId()

        if isinstance( id, basestring ):
            id = [id]

        if isinstance( login, basestring ):
            login = [login]

        if not user_ids:
            user_ids = self.listUserIds()
            user_filter = _ShibUserFilter(id, login, exact_match, self.rattr_map, **kw)

        if not id and not login and not kw:
            user_filter = None

        for user_id in user_ids:
            data = self.store.get(user_id)
            if data:
                e_url = '%s/manage_users' % self.getId()
                qs = 'user_id=%s' % user_id

                fullname = data.get(self.rattr_map.get('fullname')) \
                        or data.get(self.rattr_map.get('fullname_fallback'), \
                                                       user_id)
                info = { 'id' : self.prefix + user_id
                       , 'login' : user_id
                       , 'pluginid' : plugin_id
                       , 'email' : data.get(self.rattr_map.get('email'), '')
                       , 'title' : fullname
                       , 'description' : fullname
                       , 'editurl' : '%s?%s' % (e_url, qs)
                       }
                if not user_filter or user_filter(user_id, user_id, data):
                    user_info.append(info)

        return tuple(user_info)


    #
    #   IPropertiesPlugin implementation
    #
    security.declarePrivate('getPropertiesForUser')
    def getPropertiesForUser(self, user, request=None ):
        """return the immutabel shibboleth properties of a user

            >>> from Products.PluggableAuthService.interfaces.plugins import \
                    IPropertiesPlugin, IUserEnumerationPlugin
            >>> plugins = self.uf.plugins
            >>> plugins.activatePlugin(IPropertiesPlugin, 'shib')
            >>> plugins.activatePlugin(IUserEnumerationPlugin, 'shib')

            >>> self.shib.store = {'matthew': {u'HTTP_DISPLAYNAME': 'Matthew Morgan', u'HTTP_MAIL': 'matthew.morgan@jcu.edu.au', u'HTTP_REMOTE_USER': 'matthew',}}
            >>> u = self.app.acl_users.getUser('matthew')
            >>> u.listPropertysheets()
            ['shib']
            >>> prop = u.getPropertysheet('shib')
            >>> print prop.propertyItems()
            [('email', 'matthew.morgan@jcu.edu.au'), ('fullname', 'Matthew Morgan'), ('location', None)]

            Test for an instance where IdP doesn't provide our display name

            >>> self.shib.store = {'david': {
            ...     u'HTTP_CN': 'David B',
            ...     u'HTTP_MAIL': 'david@jcu.edu.au',
            ...     u'HTTP_REMOTE_USER':'david',
            ...     }
            ... }
            >>> u = self.app.acl_users.getUser('david')
            >>> u.listPropertysheets()
            ['shib']
            >>> prop = u.getPropertysheet('shib')
            >>> print prop.propertyItems()
            [('email', 'david@jcu.edu.au'), ('fullname', 'David B'), ('location', None)]

            Test for instance where our display name should take precedence

            >>> self.shib.store = {'david': {
            ...     u'HTTP_DISPLAYNAME': 'Real Name',
            ...     u'HTTP_CN': 'Override me',
            ...     u'HTTP_MAIL': 'david@jcu.edu.au',
            ...     u'HTTP_REMOTE_USER':'david',
            ...     }
            ... }
            >>> u = self.app.acl_users.getUser('david')
            >>> u.listPropertysheets()
            ['shib']
            >>> prop = u.getPropertysheet('shib')
            >>> print prop.propertyItems()
            [('email', 'david@jcu.edu.au'), ('fullname', 'Real Name'), ('location', None)]

            Test for the situation where there aren't any names defined at all.
            >>> self.shib.store = {'david': {
            ...     u'HTTP_MAIL': 'david@jcu.edu.au',
            ...     u'HTTP_REMOTE_USER':'david',
            ...     }
            ... }
            >>> u = self.app.acl_users.getUser('david')
            >>> prop = u.getPropertysheet('shib')
            >>> print prop.propertyItems()
            [('email', 'david@jcu.edu.au'), ('fullname', 'Unknown (Name not supplied)'), ('location', None)]


            test missing shibboleth attribute

            >>> self.shib.store = {'matthew': {u'HTTP_MAIL': 'matthew.morgan@jcu.edu.au', u'HTTP_REMOTE_USER': 'matthew', u'HTTP_DISPLAYNAME': 'Matthew Morgan'}}
            >>> u = self.app.acl_users.getUser('matthew')
            >>> u.listPropertysheets()
            ['shib']
        """
        userdata = self.store.get(user.getId())
        schema = [('email', 'string'),
                  ('fullname', 'string'),
                  ('location', 'string'),
                 ]
        data = {}
        if not userdata:
            return None
        for k, v in self.attr_map.items():
            if userdata.has_key(k):
                data[v] = userdata[k]
            elif v == 'fullname':
                data[v] = userdata.get('HTTP_CN', \
                                       'Unknown (Name not supplied)')

        return UserPropertySheet(self.id, schema=schema, **data)


    #
    # IUserIntrospection implementation
    #

    def getUserIds(self):
        """
        Return a list of user ids
        """
        return self.listUserIds()

    def getUserNames(self):
        """
        Return a list of usernames
        """
        return [x['login_name'] for x in self.listUserInfo()]

    def getUsers(self):
        """
        Return a list of users
        """
        uf = self.acl_users
        return [uf.getUserById(x) for x in self.getUserIds()]


    security.declarePrivate('getLoginURL')
    def getLoginURL(self):
        """ Where to send people for logging in """
        if self.login_path.startswith('/'):
            return self.login_path
        elif self.login_path != '':
            return '%s/%s' % (self.absolute_url(), self.login_path)
        else:
            return None


    #
    #   (notional)IZODBUserManager interface
    #
    security.declareProtected(ManageUsers, 'listUserIds')
    def listUserIds(self):

        """ -> ( user_id_1, ... user_id_n )
        """
        return self.store.keys()


    security.declarePrivate('__extract_shib_data')
    def __extract_shib_data(self, request):
        """
        Extracts Shibboleth information for the headers. Return a tuple containing the unique identifier of the user and dict of other shibboleth headers.

            >>> from zope.publisher.browser import TestRequest
            >>> shib_headers = { 'HTTP_SHIB_APPLICATION_ID' : "default", \
              'HTTP_SHIB_AUTHENTICATION_INSTANT' : "2010-02-18T22:46:12.140Z", \
              'HTTP_SHIB_AUTHENTICATION_METHOD' : "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport", \
              'HTTP_SHIB_AUTHNCONTEXT_CLASS' : "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport", \
              'HTTP_SHIB_IDENTITY_PROVIDER' : "https://idp.test.org/idp/shibboleth", \
              'HTTP_SHIB_SESSION_ID' : "_9c86b438e92e1de9b378a23f4838a959", \
              'HTTP_AFFILIATION' : "staff@vpac.org", \
              'HTTP_ASSURANCE' : "2", \
              'HTTP_CN' : "Russell Sim", \
              'HTTP_DISPLAYNAME' : "Russell Sim", \
              'HTTP_EPPN' : "russell@vpac.org", \
              'HTTP_GIVENNAME' : "Russell", \
              'HTTP_HOMEORGANIZATION' : "vpac.org", \
              'HTTP_HOMEORGANIZATIONTYPE' : "urn:mace:aaf.edu.au:marcs", \
              'HTTP_L' : "AU", \
              'HTTP_MAIL' : "russell@vpac.org", \
              'HTTP_O' : "VPAC", \
              'HTTP_PERSISTENT_ID' : "https://idp.test.org/idp/shibboleth!https://testhost.com/shibboleth!P4o6lbbg41Q=", \
              'HTTP_SHARED_TOKEN' : "B_0-_88s2CiUXmJx-PYW_8TugZI", \
              'HTTP_SN' : "Sim", \
              'HTTP_UNSCOPED_AFFILIATION' : "staff", }
            >>> request = TestRequest(**shib_headers)
            >>> self.shib._ShibbolethHelper__extract_shib_data(request)
              ('B_0-_88s2CiUXmJx-PYW_8TugZI', \
              {u'HTTP_PERSISTENT_ID': 'https://idp.test.org/idp/shibboleth!https://testhost.com/shibboleth!P4o6lbbg41Q=', \
              u'HTTP_SN': 'Sim', \
              u'HTTP_MAIL': 'russell@vpac.org', \
              u'HTTP_SHIB_APPLICATION_ID': 'default', \
              u'HTTP_EPPN': 'russell@vpac.org', \
              u'HTTP_GIVENNAME': 'Russell', \
              u'HTTP_SHIB_AUTHNCONTEXT_CLASS': 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport', \
              u'HTTP_CN': 'Russell Sim', \
              u'HTTP_O': 'VPAC', \
              u'HTTP_L': 'AU', \
              u'HTTP_UNSCOPED_AFFILIATION': 'staff', \
              u'HTTP_DISPLAYNAME': 'Russell Sim', \
              u'HTTP_AFFILIATION': 'staff@vpac.org', \
              u'HTTP_SHIB_AUTHENTICATION_INSTANT': '2010-02-18T22:46:12.140Z'})

            >>> shib_headers = { 'HTTP_SHIB_APPLICATION_ID' : "default", \
              'HTTP_SHIB_AUTHENTICATION_INSTANT' : "2010-02-18T22:46:12.140Z", \
              'HTTP_SHIB_AUTHENTICATION_METHOD' : "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport", \
              'HTTP_SHIB_AUTHNCONTEXT_CLASS' : "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport", \
              'HTTP_SHIB_IDENTITY_PROVIDER' : "https://idp.test.org/idp/shibboleth", \
              'HTTP_SHIB_SESSION_ID' : "_9c86b438e92e1de9b378a23f4838a959", \
              'HTTP_PERSISTENT_ID' : "https://idp.test.org/idp/shibboleth!https://testhost.com/shibboleth!P4o6lbbg41Q=", \
              'HTTP_DISPLAYNAME' : "Russell Sim", \
              'HTTP_REMOTE_USER': 'russell@vpac.org'}
            >>> request = TestRequest(**shib_headers)
            >>> self.shib._ShibbolethHelper__extract_shib_data(request)
              ('_9c86b438e92e1de9b378a23f4838a959', \
              {u'HTTP_PERSISTENT_ID': 'https://idp.test.org/idp/shibboleth!https://testhost.com/shibboleth!P4o6lbbg41Q=', \
              u'HTTP_REMOTE_USER': 'russell@vpac.org', \
              u'HTTP_SHIB_APPLICATION_ID': 'default', \
              u'HTTP_SHIB_AUTHNCONTEXT_CLASS': 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport', \
              u'HTTP_DISPLAYNAME': 'Russell Sim', \
              u'HTTP_SHIB_AUTHENTICATION_INSTANT': '2010-02-18T22:46:12.140Z'})
        """
        attributes={}

        for k in self.getPossibleAttributes():
            v = request.get(k, None)
            if v:
                attributes[k] = v

        uid_attr = self.userid_attribute
        if uid_attr.strip():
            if not (uid_attr in request.keys()):
                id = str(self.__getShibbolethSessionId(request))
                log.debug("User UID not supplied using handle: %s, from provider: %s." % (id, request[self.idp_attribute]))
            else:
                log.debug('id: %s, %s' % (uid_attr, request[uid_attr]))
                id = request[uid_attr]
        else:
            log.error("userid_attribute is not set to anything.")
        return id, attributes


    security.declarePrivate('__getShibbolethSessionId')
    def __getShibbolethSessionId(self, request):
        """
        Gets the Shibboleth Session ID from the Request

            >>> shib_headers = { 'HTTP_SHIB_SESSION_ID' : "_9c86b438e92e1de9b378a23f4838a959", }
            >>> self.app.acl_users.shib.REQUEST.environ.update(shib_headers)
            >>> self.shib._ShibbolethHelper__getShibbolethSessionId(self.shib.REQUEST)
            '_9c86b438e92e1de9b378a23f4838a959'
        """
        return request.get('HTTP_SHIB_SESSION_ID', None)


    security.declarePrivate('__validShibSession')
    def __validShibSession(self, request):
        """
        Check that the request shib session id matches the one in the session manager.

            >>> from zope.publisher.browser import TestRequest
            >>> shib_headers = { 'HTTP_SHIB_SESSION_ID' : "_9c86b438e92e1de9b378a23f4838a959", }
            >>> request = TestRequest(**shib_headers)
            >>> request.SESSION = self.app.session_data_manager.getSessionData()
            >>> self.shib._ShibbolethHelper__validShibSession(request)
            False

            >>> request.SESSION = self.app.session_data_manager.getSessionData()
            >>> request.SESSION['shibboleth.session'] = '_9c86b438e92e1de9b378a23f4838a959'
            >>> self.shib._ShibbolethHelper__validShibSession(request)
            True
        """

        sesid = self.__getShibbolethSessionId(request)
        if request.SESSION.has_key('shibboleth.session'):
            return request.SESSION['shibboleth.session'] == sesid
        return False



    security.declarePrivate('__getIPAddress')
    def __getIPAddress(self, request):
        """
        Get the IP Address

            >>> from ZPublisher.HTTPRequest import HTTPRequest
            >>> from StringIO import StringIO
            >>> request = HTTPRequest(StringIO(), {'REQUEST_METHOD': 'GET', \
              'SERVER_NAME': 'localhost', \
              'SERVER_PORT': '80', \
              'REMOTE_ADDR':'137.219.45.111', \
              'HTTP_X_FORWARDED_FOR': ''}, None)
            >>> self.shib._ShibbolethHelper__getIPAddress(request)
            '137.219.45.111'

            >>> from zope.publisher.browser import TestRequest
            >>> request = TestRequest(**{'HTTP_X_FORWARDED_FOR': '137.219.45.217'})
            >>> self.shib._ShibbolethHelper__getIPAddress(request)
            '137.219.45.217'
        """
        self.log(DEBUG, "__getIPAddress: %s" % request)
        # TODO probably should advise the user about untrusted proxies
        toRet = request['HTTP_X_FORWARDED_FOR']
        if not toRet:
            toRet = request.getClientAddr()
        self.log(DEBUG, "__getIPAddress: %s" % toRet)
        return toRet


    security.declarePrivate('log')
    def log(self, level, message):
        """
        Log a message for this object.
        """
        log.log(level, ": "+ str(message))


    security.declarePrivate('__caculateMapping')
    def __caculateMapping(self, principal, funcs):
        self.log(DEBUG, "__caculateMapping: %s, %s" % (principal, funcs))
        toRet = []
        attrs = self.store.get(principal, {})
        assign_targets = funcs
        for role in assign_targets:
            try:
                if assign_targets[role](attrs): toRet.append(role)
            except Exception, e:
                self.log(INFO,"Error occoured whilst assiging target: %s" % role)
        self.log(DEBUG, "__caculateMapping: %s" % toRet)
        return tuple(toRet)


    def __setup_op_switch(self):
        """Setups up the operation dictionary for use by manage_mappings"""
        def add_item(REQUEST, map):
            map[REQUEST.form[Constants.mapping_item]] = [[0, '', 0, '', 0, 0]]
            return False

        def del_item(REQUEST, map):
            self.log(DEBUG, "Deleting %s %s." %
                     (REQUEST.form[Constants.mapping],
                      REQUEST.form[Constants.mapping_item]))
            map.__delitem__(REQUEST.form[Constants.mapping_item])
            return False

        def manage_item(REQUEST, map):
            form = REQUEST.form
            role = map[form[Constants.mapping_item]]

            #Saves the current state.
            for x in form:
                if x.startswith(Constants.opening_bracket_element):
                    role[int(x.split(':')[1])][Constants.OBPos] = int(form[x])
                elif x.startswith(Constants.closing_bracket_element):
                    role[int(x.split(':')[1])][Constants.CBPos] = int(form[x])
                elif x.startswith(Constants.op_type_value_element):
                    role[int(x.split(':')[1])][Constants.OTPos] = int(form[x])
                elif x.startswith(Constants.bool_row_op_element):
                    role[int(x.split(':')[1])][Constants.BOTPos] = int(form[x])
                elif x.startswith(Constants.var_name_element):
                    role[int(x.split(':')[1])][Constants.SVNPos] = form[x]
                elif x.startswith(Constants.var_value_element):
                    role[int(x.split(':')[1])][Constants.SVVPos] = form[x]

            #Remove deleted items.
            if form.has_key(Constants.del_row_element):
                toDel = form[Constants.del_row_element]
                if not isinstance(toDel, list):
                    toDel = [toDel]
                for i in toDel:
                    role[int(i)] = None
                while None in role: role.remove(None)

            #Add new rows.
            if form.has_key(Constants.add_row_element):
                try:
                    new_row_count = int(form[Constants.add_row_count_element])
                except ValueError, v:
                    new_row_count = 1
                for c in range(0, new_row_count):
                    role.append([0, '', 0, '', 0, 0])

            #To insure the PersistantMap object is properly updated.
            map[form[Constants.mapping_item]] = role
            return False

        def export_mapping(REQUEST, map):
            hasher = md5.new()
            hasher.update(str(map))
            to_export = REQUEST.form[Constants.mapping]
            response = REQUEST.RESPONSE
            response.setHeader('Content-Type','application/octet-stream')
            response.setHeader('Content-Disposition', 'attachment; filename=%s.b64' % to_export)
            response.setBody(base64.encodestring(pickle.dumps([to_export, map, hasher.hexdigest()])))
            return True

        def import_mapping(REQUEST, map):
            form = REQUEST.form
            def doRedr(message):
                uri = "%s?%s=%s" % (REQUEST['HTTP_REFERER'].split("?")[0],Constants.message_element, message)
                self.log(INFO, "URI: %s" % uri)
                return REQUEST.RESPONSE.redirect(uri)

            #Decode the data.
            try:
                print form[Constants.uploaded_file_element]
                data = pickle.loads(base64.decodestring(form[Constants.uploaded_file_element].read()))
            except Exception, e:
                self.log(ERROR, e)
                doRedr("Could not decode the data. It may be corrupted.")
                return True

            #Check that the hash matches.
            if not form.has_key(Constants.ignore_hash_element):
                hasher = md5.new()
                hasher.update(str(data[1]))
                if hasher.hexdigest() != data[2]:
                    doRedr("The hash did not match.")
                    return True

            #Check that the mapping name matches.
            if not form.has_key(Constants.ignore_name_element):
                if not data[0] == form[Constants.mapping]:
                    doRedr("The Name did not match.")
                    return True

            #Store the newly imported mappings in the map.
            map.clear()
            for mapping in data[1]:
                map[mapping] = data[1][mapping]

            doRedr("Import Successful.")
            return True

        self.__class__._op_switch = {Constants.op_add_item : add_item,
                                     Constants.op_del_item : del_item,
                                     Constants.op_manage_item : manage_item,
                                     Constants.op_export_mapping : export_mapping,
                                     Constants.op_import_mapping : import_mapping}


    security.declareProtected( ManageUsers, 'manage_mappings')
    def manage_mappings(self, op_type, mapping, REQUEST=None):
        """
        This method is called by the mapping/import export pages to carry out there operations.


            >>> import UserDict
            >>> class RESPONSE:
            ...     def redirect(self, *args):
            ...         pass
            >>> class FuxRequest(UserDict.UserDict):
            ...     form = {}
            ...     RESPONSE = RESPONSE()
            ...
            >>> request = FuxRequest({'item': 'Manager', 'mapping': 'Role', 'op_type': 'add_item', 'URL1': 'http://localhost'})
            >>> request.form = {'item': 'Manager', 'mapping': 'Role', 'op_type': 'add_item'}
            >>> self.shib.manage_mappings('add_item', 'Role', request)
            >>> self.shib.getMap('Role')
            {'Manager': [[0, '', 0, '', 0, 0]]}

            >>> request = FuxRequest({'add_row_count': '1', 'brop:0': '0', 'closing_bracket:0': '0', 'item': 'Manager', 'mapping': 'Role', 'op_type': 'manage_item', 'opening_bracket:0': '0', 'opp_type:0': '0', 'save_map': 'Save Role Map', 'var_name:0': 'HTTP_REMOTE_USER', 'var_value:0': 'testuser1', 'URL1': 'http://localhost'})
            >>> request.form = {'opening_bracket:0': '0', 'closing_bracket:0': '0', 'mapping': 'Role', 'var_value:0': 'testuser1', 'item': 'Manager', 'brop:0': '0', 'opp_type:0': '0', 'op_type': 'manage_item', 'save_map': 'Save Role Map', 'add_row_count': '1', 'var_name:0': 'HTTP_REMOTE_USER'}
            >>> self.shib.manage_mappings('manage_item', 'Role', request)
            >>> self.shib.getMap('Role')
            {'Manager': [[0, 'HTTP_REMOTE_USER', 0, 'testuser1', 0, 0]]}
        """
        if self._op_switch is None: self.__setup_op_switch()
        if self._mapping_map.has_key(mapping):
            map = self._mapping_map[mapping]
        else:
            map = None
        if REQUEST:
            if self._op_switch.has_key(op_type):
                if not self._op_switch[op_type](REQUEST, map):
                    if mapping == "Role":
                        return REQUEST.RESPONSE.redirect(REQUEST['URL1'] + '/manage_roles')
                    if mapping == "Group":
                        return REQUEST.RESPONSE.redirect(REQUEST['URL1'] + '/manage_roles')
                    return REQUEST.RESPONSE.redirect(REQUEST['HTTP_REFERER'])


    security.declareProtected( ManageUsers, 'compileItem')
    def compileItem(self, map, item, mapping):
        """
        Compiles a mapping element, and stores it for use.

            >>> self.shib.compileItem({'Anonymous': [[0, 'HTTP_REMOTE_USER', 0, 'test', 0, 1]]}, 'Anonymous', 'Role')
            (None, "def assign_target(attributes):\\n  import re\\n  if  attributes['HTTP_REMOTE_USER'] == 'test' : return True\\n  return False\\n", <function assign_target at ...>)

            >>> self.shib.compileItem({'Owner': [[0, 'HTTP_REMOTE_USER', 0, 'matthew', 0, 0]]}, 'Owner', 'Role')
            (None, "def assign_target(attributes):\\n  import re\\n  if  attributes['HTTP_REMOTE_USER'] == 'matthew' : return True\\n  return False\\n", <function assign_target at ...>)
        """
        self.log(DEBUG, "compileItem: %s, %s, %s" % (map, item, mapping))
        if not hasattr(self,'_v_compiled_mapping_func_map'):
            self.__setup_compiled_func_map()
        results =  self.__compileItem(item, map[item])
        error, code, function = results
        if error is None:
            self.log(DEBUG, "compileItem: %s, %s = %s" % (mapping, item, function))
            self._v_compiled_mapping_func_map[mapping][item] = function
        self.log(DEBUG, "compileItem: %s" % str(results))
        return results


    security.declarePrivate('__compileMapping')
    def __compileMappings(self):
        """
        Compiles all mappings and there items.

            >>> self.shib._ShibbolethHelper__compileMappings()

        """
        self.log(DEBUG, "__compileMappings")
        if not hasattr(self,'_v_compiled_mapping_func_map'):
            self.__setup_compiled_func_map()
        for mapping in self._mapping_map:
            self.log(DEBUG, "__compileMappings: MAPPING %s" % mapping)
            for item in self._mapping_map[mapping]:
                self.log(DEBUG, "__compileMappings: ITEM %s" % item)
                self.compileItem(self._mapping_map[mapping], item, mapping)


    security.declarePrivate('__compileItem')
    def __compileItem(self, name, map):
        """
        Does the actual compiling of a mapping item (called by compileItem).

            >>> self.shib._ShibbolethHelper__compileItem('Anonymous', [[0, 'HTTP_REMOTE_USER', 0, 'test', 0, 1]])
            (None, "def assign_target(attributes):\\n  import re\\n  if  attributes['HTTP_REMOTE_USER'] == 'test' : return True\\n  return False\\n", <function assign_target at ...>)

            >>> self.shib._ShibbolethHelper__compileItem('Owner', [[0, 'HTTP_REMOTE_USER', 0, 'matthew', 0, 0]])
            (None, "def assign_target(attributes):\\n  import re\\n  if  attributes['HTTP_REMOTE_USER'] == 'matthew' : return True\\n  return False\\n", <function assign_target at ...>)
        """
        self.log(DEBUG, "Compiling: %s, %s" % (name, map))
        code="def assign_target(attributes):\n  import re\n  if "
        lines = []
        expression = "%s"
        regex = []
        if map.__len__() == 0:
            code += "False"
        else:
            for i in range(0, map.__len__()):
                item = map[i]
                value = None

                #Determin if the value is numerical or a string.
                #Is this step nessecary? Will there ever be a numerical value here?
                try:
                    float(item[Constants.SVVPos])
                    value = item[Constants.SVVPos]
                except ValueError, e:
                    value = str((item[Constants.SVVPos]).decode('unicode-escape', 'ignore')).__repr__()

                #Create the expression for a single line.
                lines.append( (item[Constants.OBPos]*'(') +
                    Constants.EXP_CODE[item[Constants.OTPos]] % {'1': (item[Constants.SVNPos].__repr__()),
                    '2':value} + ""+ (item[Constants.CBPos]*')'))

                #Create the boolean expressions betweens the lines.
                if(i < (map.__len__()-1)): expression = Constants.BOOL_CODE[item[Constants.BOTPos]] % (expression, '%s')

                #Gather the regular expression patterns for validation later.
                if item[Constants.OTPos] in Constants.REGEX_EXP:
                    self.log(DEBUG, "Pattern: "+(str(value)[1:-1]))
                    regex.append(value)

            #Merge the lines with the boolean expression.
            code += expression % tuple(lines)

        code +=": return True\n  return False\n"

        #Compile the code. If it contains errors return the stack trace.
        try:
            exec(code)
        except Exception, e:
            f = StringIO.StringIO()
            traceback.print_exc(file=f)
            return (f.getvalue(), code, None)

        #Compile the regular expression patterns to ensure they are valid.
        #If they fail return the combined stacktrace.
        regex_error = ''
        regex_compile_error = False
        for expr in regex:
            try:
                re.compile(expr[1:-1])
            except Exception, e:
                regex_compile_error = True
                f = StringIO.StringIO()
                traceback.print_exc(file=f)
                regex_error += '*' * 50
                regex_error += '\n%s\n%s' % ("Pattern: %s" % expr[1:-1],f.getvalue())
        self.log(DEBUG, "Errors?: %s" % regex_compile_error)
        if regex_compile_error:
            return (regex_error, code, None)

        self.log(DEBUG, "__compileItem: %s, %s, %s" % (None, code, assign_target))
        return (None, code, assign_target)

    security.declareProtected(ManageUsers, 'valid_groups')
    def valid_groups(self):
        """
        Return the valid groups

            >>> self.shib.valid_groups()
            []
            >>> self.app.acl_users.groups.addGroup('Another Group')
            >>> self.app.acl_users.groups.addGroup('and Another Group')
            >>> self.shib.valid_groups()
            ['Another Group', 'and Another Group']
        """
        self.log(DEBUG, "valid_groups: %s" % [group['id'] for group in self.searchGroups()])
        mapped_groups = self.getMap('Group').keys()
        return [group['id'] for group in self.searchGroups() if group['id'] not in mapped_groups]


    security.declareProtected(ManageUsers, 'valid_mappings')
    def valid_mappings(self):
        """
            >>> self.shib.valid_mappings()
            ['Group', 'Role']

        """
        self.log(DEBUG, "valid_mappings: %s" % self._mapping_map.keys())
        return self._mapping_map.keys()


    def valid_roles(self):
        """
        Return the valid roles

            >>> self.shib.valid_roles()
            ['Owner', 'Manager']
            >>> self.app.acl_users.roles.addRole('Another Role')
            >>> self.app.acl_users.shib.valid_roles()
            ['Owner', 'Manager', 'Another Role']
        """
        roles = []
        for plugin in self.plugins.listPlugins(IRoleEnumerationPlugin):
            roles += [role['id'] for role in plugin[1].enumerateRoles()]
        mapped_roles = self.getMap('Role').keys()
        return [r for r in set(roles) if r not in mapped_roles]


#    security.declareProtected(ManageUsers, 'do_encode')
#    def do_encode(self, toEncode):
#       return string.join([("&#%s;"%ord(x))  for x in list(toEncode)],'')


    def getMap(self, name):
        """
        Return the map of the mappings
            >>> print self.shib.getMap('Group')
            {}
            >>> print self.shib.getMap('Role')
            {}
        """
        return dict(self._mapping_map[name])

    #
    # Shibboleth XML file reader
    #
    def configFile(self):
        """
        Return a tuple containing the location and the search path for the
        attributes.
            >>> self.app.acl_users.shib.configFile()
            (... 'Attribute/@id')
        """
        dir = self.shibboleth_config_dir
        if path.exists(path.join(dir, "attribute-map.xml")):
            shib2 = [u'HTTP_REMOTE_USER', u'HTTP_SHIB_PERSON_MAIL',
                     u'HTTP_SHIB_AUTHENTICATION_INSTANT', u'HTTP_SHIB_APPLICATION_ID',
                     u'HTTP_SHIB_AUTHNCONTEXT_CLASS', u'HTTP_SHIB_AUTHNCONTEXT_DECL']
            return (path.join(dir, "attribute-map.xml"), shib2, 'Attribute/@id')
        return False

    def getPossibleAttributes(self):
        """
        Return the possible shibboleth attributes which are found in the AAP xml file

            >>> Attributes = [u'HTTP_SHIB_APPLICATION_ID', \
                              u'HTTP_SHIB_PERSON_MAIL']
            >>> len(self.uf.shib.getPossibleAttributes()) == 47
            True
            >>> for a in Attributes:
            ...     if a in self.uf.shib.getPossibleAttributes():
            ...         continue
            ...     print "Missing Attribute %s" % a

        """
        # TODO should exit cleanly if it can't find the config file, currently causes server error when called from extractshibHeaders function
        from xml.dom.ext.reader import Sax2
        from xml import xpath
        #TODO Should read the shibboleth.xml to figureout where the AAP is
        try:
            filename, extra_attributes, attribute_path = self.configFile()
        except TypeError:
            return []
        doc = Sax2.Reader().fromStream(open(filename))
        nodes = [n for n in xpath.Evaluate(attribute_path, doc.documentElement)]
        # TODO the following attributes are missing for an unknown reason
        attributes = list(set(['HTTP_' + n._get_value().upper().replace('-','_')
                               for n in nodes])) + extra_attributes
        attributes.sort()
        return attributes



classImplements(ShibbolethHelper, interface.IShibbolethHelper)

InitializeClass( ShibbolethHelper )


class _ShibUserFilter:

    def __init__( self
                , id=None
                , login=None
                , exact_match=False
                , rattr_map={}
                , **kw
                ):

        self._filter_ids = id
        self._filter_logins = login
        self._filter_keywords = kw
        self.exact_match = exact_match
        self.rattr_map = rattr_map


    def __call__(self, id=None, login=None, user_info={}):
        if self._filter_ids:
            for filter_id in self._filter_ids:
                if self.match(id, filter_id):
                    return True

        if self._filter_logins:
            for filter_login in self._filter_logins:
                if self.match(login, filter_login):
                    return True

        for (key, value) in self._filter_keywords.items():
            testvalue=user_info.get(self.rattr_map.get(key), None)
            if self.match(testvalue, value):
                return True

        return False

    def match(self, testvalue, value):
        if testvalue is None:
            return False

        if isStringType(testvalue):
            testvalue = testvalue.lower()
        if isStringType(value):
            value = value.lower()

        if self.exact_match:
            if value != testvalue:
                return False
        else:
            try:
                if value not in testvalue:
                    return False
            except TypeError:
                # Fall back to exact match if we can check for sub-component
                if value != testvalue:
                    return False

        return True
