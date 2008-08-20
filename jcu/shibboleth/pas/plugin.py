'''Class: PasHelper
'''

from os import path
from AccessControl.SecurityInfo import ClassSecurityInfo
from App.class_init import default__class_init__ as InitializeClass

from Products.PluggableAuthService.interfaces.plugins import IRoleEnumerationPlugin
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PluggableAuthService.utils import classImplements
from Products.PluggableAuthService.permissions import ManageUsers

from ConstantsPageTemplateFile import mypt
import Constants as Constants

from logging import  DEBUG, ERROR, INFO, WARNING, CRITICAL, FATAL
import logging, StringIO, traceback, re, pickle, base64, md5

from persistent.mapping import PersistentMapping
import interface
import plugins

LOG = logging.getLogger("jcu.shibboleth.pas")

class ShibbolethHelper(BasePlugin):
    '''Multi-plugin Shibboleth

    '''

    meta_type = 'Shibboleth Helper'

    security = ClassSecurityInfo()

    manage_options = ( BasePlugin.manage_options +
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

    _properties = BasePlugin._properties + \
                  ({'label': 'Shibboleth Provider Attribute',
                    'id': Constants.idp_identifier_attribute,
                    'type': 'string',
                    'mode': 'w',},
                   {'label':'User Common Name Attribute',
                    'id': Constants.user_cn_attribute,
                    'type': 'string',
                    'mode':'w'},
                   {'label':'User ID Attribute',
                    'id': 'userid_attribute',
                    'type': 'string',
                    'mode':'w'},
                   {'label':'Maxium Brackets To Display',
                    'id': 'max_brackets',
                    'type': 'int',
                    'mode':'w'},
                   {'label':'Shibboleth SP configuration dir',
                    'id': Constants.shib_config_dir,
                    'type': 'string',
                    'mode':'w'})


    _op_switch = None

    def __init__(self, id, title=None, total_shib=False):
        """
            >>> from jcu.shibboleth.pas.plugin import ShibbolethHelper
            >>> newshib = ShibbolethHelper('newshib')
            >>> newshib.getProperty('max_brackets')
            6
            >>> newshib.getProperty('userid_attribute')
            'HTTP_REMOTE_USER'
            >>> newshib.getProperty('User_Common_Name_Attribute')
            'HTTP_SHIB_PERSON_COMMONNAME'
            >>> newshib.getProperty('IDP_Attribute')
            'HTTP_SHIB_IDENTITY_PROVIDER'
            >>> newshib.getProperty('Shibboleth_Config_Dir')
            '/etc/shibboleth'
            >>> del newshib
        """
        super(ShibbolethHelper, self).__init__()
        self._id = self.id = id
        self.title = title
        self.total_shib = total_shib
        self.log(INFO,'Initilizing Shibboleth Authentication.')
        self.__login_location = "login"
        self.role_mapping =  PersistentMapping()
        self.log(INFO,'Role Mapping. %s' % self.role_mapping)
        self.group_mapping =  PersistentMapping()
        self.log(INFO,'Group Mapping. %s' % self.group_mapping)
        self._mapping_map = {Constants.RoleM: self.role_mapping, Constants.GroupM:self.group_mapping}
        self.__setup_compiled_func_map()

        #Properties for the Property Manager.
        self.max_brackets = 6
        self.__dict__[Constants.user_cn_attribute] = Constants.default_user_cn_attribute_value
        self.userid_attribute = 'HTTP_REMOTE_USER'
        self.__dict__[Constants.shib_config_dir] = Constants.default_shib_config_dir
        self.__dict__[Constants.idp_identifier_attribute] = Constants.default_idp_identifier_attribute_value

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
        if credentials['extractor'] != self.getId():
           self.log(INFO, "Will only authenticate Shibboleth credentials.")
           return None
        session = self.REQUEST.SESSION
        self.log(INFO, 'Authentication Requested.')
        url = "%s/%s"%(self.absolute_url(), self.__login_location)
        request = self.REQUEST
        self.log(INFO, "URLS: %s, %s"%(request.URL, url))
        if request.URL == url:
            self.log(INFO, "Not attempting to authenticate login request.")
            return None
        shibSessionId = self.__getShibbolethSessionId(request)
        #self.log(INFO, 'Session ID: %s'%(shibSessionId,))
        #self.log(INFO, 'Credentials: %s'%(str(credentials),))

        #if not self.__validShibSession(shibSessionId, self.__getIPAddress(request)) or (not session.has_key(credentials['login'])):
        if not self.__validShibSession(request): # or (not session.has_key(credentials['login'])):
            self.log(INFO, 'Invalid Session')
            if shibSessionId != None:
                self.challenge(self.REQUEST, self.REQUEST['RESPONSE'])
            return None

        data = session[credentials['shibboleth.session']]
        if not data.has_key(self.getProperty(Constants.user_cn_attribute)):
               principle_name = "Pseudo-Anonymous: %s"%shibSessionId
        else:
               principle_name = data[self.getProperty(Constants.user_cn_attribute)]
        return (data['login'], principle_name)


    #
    #   IChallengePlugin implementation
    #
    security.declarePrivate('challenge')
    def challenge(self, request, response ):
        """The Challange
        """
        req = self.REQUEST
        resp = req['RESPONSE']

        self.log(INFO, "Challange.")
        url = "%s/%s"%(self.absolute_url(), self.__login_location)
        came_from = req.get('URL', '')
        query = req.get('QUERY_STRING')
        if query:
            if not query.startswith('?'):
                query = '?' + query
            came_from = came_from + query

        shibSessionId = self.__getShibbolethSessionId(request)
        if not shibSessionId:
                resp.redirect("%s?came_from=%s"%(url, came_from), lock=1)
                return True

        #if not self.__validShibSession(shibSessionId, self.__getIPAddress(request)):
        if not self.__validShibSession(request):
                self.log(INFO, "Not a valid Request")
                resp.redirect("%s?came_from=%s"%(url, came_from))

        session = self.REQUEST.SESSION
        if shibSessionId and not session.has_key(shibSessionId):
           resp.redirect("%s?came_from=%s"%(url, came_from))

        return True


    #
    #    ILoginPasswordExtractionPlugin implementation
    #
    security.declarePrivate('extractCredentials')
    def extractCredentials(self, request ):
        """Extract the credentials
        """
        shibsession = self.__getShibbolethSessionId(request)
        self.log(DEBUG, "extractCredentials: %s" % shibsession)
        if not shibsession:
            self.log(DEBUG, "extractCredentials: Not Shib")
            return {}
        return {"shibboleth.session": shibsession}


    #
    #    IRolesPlugin implementation
    #
    security.declarePrivate('getRolesForPrincipal')
    def getRolesForPrincipal( self, principal, request=None ):
        """

            >>> from zope.publisher.browser import TestRequest
            >>> shib_headers = {'HTTP_COOKIE': '_saml_idp=aHR0cHM6Ly9nbG9idXMtbWF0dGhldy5ocGMuamN1LmVkdS5hdS9zaGliYm9sZXRo; _shibstate_5dc97d035cb931c8123d34c999e481deb8e5204c=https%3A%2F%2Fglobus-matthew.hpc.jcu.edu.au%2Fmattotea%2Facl_users%2Fshib%2Flogin; _shibsession_5dc97d035cb931c8123d34c999e481deb8e5204c=_44847aa19938b0ff3dbb0505b50f7251; _ZopeId="59459141A3fUP2UyaZk"', 'HTTP_SHIB_REMOTE_USER': 'matthew'}
            >>> request = TestRequest(**shib_headers)
            >>> request.SESSION = self.app.session_data_manager.getSessionData()
            >>> self.app.acl_users.shib.REQUEST.environ.update({'HTTP_SHIB_REMOTE_USER': 'matthew'})
            >>> self.shib.REQUEST.SESSION = self.app.session_data_manager.getSessionData()
            >>> ignore = self.shib.login()
            >>> self.shib.getRolesForPrincipal('matthew', request)
            ()
        """
        self.log(INFO, "Principle: %s"%principal)
        if not hasattr(self,'_v_compiled_mapping_func_map'):
           self.__compileMappings()
        return self.__caculateMapping(self.REQUEST, self._v_compiled_mapping_func_map[Constants.RoleM])


    #
    #    IGroupsPlugin implementation
    #
    security.declarePrivate('getRolesForPrincipal')
    def getGroupsForPrincipal( self, principal, request=None ):
        """

            >>> from zope.publisher.browser import TestRequest
            >>> shib_headers = {'HTTP_COOKIE': '_saml_idp=aHR0cHM6Ly9nbG9idXMtbWF0dGhldy5ocGMuamN1LmVkdS5hdS9zaGliYm9sZXRo; _shibstate_5dc97d035cb931c8123d34c999e481deb8e5204c=https%3A%2F%2Fglobus-matthew.hpc.jcu.edu.au%2Fmattotea%2Facl_users%2Fshib%2Flogin; _shibsession_5dc97d035cb931c8123d34c999e481deb8e5204c=_44847aa19938b0ff3dbb0505b50f7251; _ZopeId="59459141A3fUP2UyaZk"', 'HTTP_SHIB_REMOTE_USER': 'matthew'}
            >>> request = TestRequest(**shib_headers)
            >>> request.SESSION = self.app.session_data_manager.getSessionData()
            >>> self.app.acl_users.shib.REQUEST.environ.update({'HTTP_SHIB_REMOTE_USER': 'matthew'})
            >>> self.shib.REQUEST.SESSION = self.app.session_data_manager.getSessionData()
            >>> ignore = self.shib.login()
            >>> self.shib.getGroupsForPrincipal('matthew', request)
            ()
        """
        if not hasattr(self,'_v_compiled_mapping_func_map'):
           self.__compileMappings()
        return self.__caculateMapping(self.REQUEST, self._v_compiled_mapping_func_map[Constants.GroupM])


    #
    #   IUserEnumerationPlugin implementation
    #
    security.declarePrivate('enumerateUsers')
    def enumerateUsers(self, id=None, login=None, exact_match=False, sort_by=None, max_results=None, **kw):
        """

            >>> from zope.publisher.browser import TestRequest
            >>> shib_headers = {'HTTP_COOKIE': '_saml_idp=aHR0cHM6Ly9nbG9idXMtbWF0dGhldy5ocGMuamN1LmVkdS5hdS9zaGliYm9sZXRo; _shibstate_5dc97d035cb931c8123d34c999e481deb8e5204c=https%3A%2F%2Fglobus-matthew.hpc.jcu.edu.au%2Fmattotea%2Facl_users%2Fshib%2Flogin; _shibsession_5dc97d035cb931c8123d34c999e481deb8e5204c=_44847aa19938b0ff3dbb0505b50f7251; _ZopeId="59459141A3fUP2UyaZk"', 'HTTP_SHIB_REMOTE_USER': 'matthew'}
            >>> request = TestRequest(**shib_headers)
            >>> request.SESSION = self.app.session_data_manager.getSessionData()
            >>> self.app.acl_users.shib.REQUEST.environ.update({'HTTP_SHIB_REMOTE_USER': 'matthew'})
            >>> self.shib.REQUEST.SESSION = self.app.session_data_manager.getSessionData()
            >>> self.shib.enumerateUsers(id='matthew', exact_match=True)


            >>> self.shib.enumerateUsers()

        """
        self.log(INFO,"Trying to enumerate users.")
        self.log(INFO, "ID: %s, Login: %s, Exact Match: %s, Sort By: %s, Max Results: %s"%(id,login,exact_match,sort_by,max_results))
        request = self.REQUEST
        session = request.SESSION
        if not exact_match:
            self.log(INFO, "Sorry, Exact Match Enumerations Only.")
            return None
        session_id = self.__getShibbolethSessionId(request)
        if not session_id:
            self.log(INFO, "Not a Shib request, so won't try to enumerateUsers.")
            return None

        #This stopes an exception that happens after a user is redirected by
        #A challange, but the request continues to be processed.
        if not session.has_key(session_id): return None
#               __validShibSession(request)

        if session[session_id]['login'] == session_id:
           self.log(INFO, "User ID not provided by IDP, will not enumerateUsers (because what is the point?).")
           return None
        #for key in session.keys():
        if isinstance(session[session_id],dict) and session[session_id]['login'] is id:
            self.log(INFO,str({'id':session[session_id]['login'],'login':session[session_id][self.getProperty('userid_attribute')],'pluginid':self.getId()}))
            return ({'id':session[session_id]['login'],'login':session[session_id][self.getProperty('userid_attribute')],'pluginid':self.getId()},)
        self.log(INFO, "Not Found.")
        return None


    security.declarePublic('login')
    def login(self):
        """The Login Method
            >>> from zope.publisher.browser import TestRequest
            >>> shib_headers = {'BASE1': 'https://globus-matthew.hpc.jcu.edu.au/mattotea',\
              'BASE2': 'https://globus-matthew.hpc.jcu.edu.au/mattotea/acl_users',\
              'HTTP_COOKIE': '_saml_idp=aHR0cHM6Ly9nbG9idXMtbWF0dGhldy5ocGMuamN1LmVkdS5hdS9zaGliYm9sZXRo; _shibstate_5dc97d035cb931c8123d34c999e481deb8e5204c=https%3A%2F%2Fglobus-matthew.hpc.jcu.edu.au%2Fmattotea%2Facl_users%2Fshib%2Flogin; _shibsession_5dc97d035cb931c8123d34c999e481deb8e5204c=_44847aa19938b0ff3dbb0505b50f7251; _ZopeId="59459141A3fUP2UyaZk"',\
              'HTTP_HOST': 'localhost:8380',\
              'HTTP_REFERER': 'https://globus-matthew.hpc.jcu.edu.au/mattotea',\
              'HTTP_SHIB_APPLICATION_ID': 'default',\
              'HTTP_SHIB_AUTHENTICATION_METHOD': 'urn:oasis:names:tc:SAML:1.0:am:unspecified',\
              'HTTP_SHIB_EP_UNSCOPEDAFFILIATION': 'member;student',\
              'HTTP_SHIB_IDENTITY_PROVIDER': 'https://globus-matthew.hpc.jcu.edu.au/shibboleth',\
              'HTTP_SHIB_INETORGPERSON_GIVENNAME': 'Matthew',\
              'HTTP_SHIB_ORIGIN_SITE': 'https://globus-matthew.hpc.jcu.edu.au/shibboleth',\
              'HTTP_SHIB_PERSON_COMMONNAME': 'Matthew Morgan',\
              'HTTP_SHIB_PERSON_MAIL': 'matthew.morgan@jcu.edu.au',\
              'HTTP_SHIB_PERSON_SURNAME': 'Morgan',\
              'HTTP_X_FORWARDED_FOR': '137.219.45.217',\
              'HTTP_X_FORWARDED_HOST': 'globus-matthew.hpc.jcu.edu.au',\
              'HTTP_X_FORWARDED_SERVER': 'globus-matthew.hpc.jcu.edu.au',}
            >>> self.app.acl_users.shib.REQUEST.environ.update(shib_headers)
            >>> self.shib.REQUEST.SESSION = self.app.session_data_manager.getSessionData()
            >>> self.shib.REQUEST.BASE2 = shib_headers['BASE2']
            >>> cookies = self.shib.REQUEST.cookies
            >>> for c in shib_headers['HTTP_COOKIE'].split(';'):
            ...     c = c.split('=')
            ...     cookies[c[0].strip()] = unicode(c[1])
            >>> self.shib.login()
            'https://globus-matthew.hpc.jcu.edu.au/mattotea/acl_users'

            >>> self.app.acl_users.shib.REQUEST.environ.update({'HTTP_REMOTE_USER': 'matthew'})
            >>> self.shib.login()
            'https://globus-matthew.hpc.jcu.edu.au/mattotea/acl_users/login_form?form.submitted=1'

            >>> self.app.acl_users.shib.REQUEST.set('came_from', 'https://globus-matthew.hpc.jcu.edu.au/mattotea/')
            >>> self.shib.login()
            'https://globus-matthew.hpc.jcu.edu.au/mattotea/'

        """
        self.log(INFO, "Login Requested.")
        request = self.REQUEST
        response = request['RESPONSE']
        came_from = request.get('came_from')
#       if not came_from:
#           came_from = request['HTTP_REFERER']
#       if not came_from:
#           #came_from = "http://pandora.jcu.edu.au/shib"
#           self.log(INFO, "came_from  not specified, using: %s"%request.BASE2)
#           came_from = request.BASE2+"/login_form?form.submitted=1"

        session_id = self.__getShibbolethSessionId(request)
        if not session_id: return False

#       if not self.total_shib :
        session = self.REQUEST.SESSION
        session[Constants.session_id] = session_id
        session[session_id] = self.__extract_shib_data(request)
        if not came_from:
            self.log(INFO, "came_from  not specified, using: %s"%request.BASE2)
            if not session[session_id].has_key(self.getProperty('userid_attribute')):
                came_from = request.BASE2
            else:
                came_from = request.BASE2+"/login_form?form.submitted=1"

        return response.redirect(came_from)


#    security.declarePublic('listManageOptions')
#    def listManageOptions(self, REQUEST=None):
#        "Hello"
#        #self.roleview.REQUEST = self.REQUEST
#       print "//////////////////////////////////////////////"
#       print self.roleview is None
#        return self.roleview(self, self.REQUEST)


#    security.declarePublic('sessionInfo')
#    def sessionInfo(self):
#        """Get The Session Info For Debuging
#       """
#       #self.__setupProperties()
#       return str(self.REQUEST)


#    security.declarePublic('rolemapInfo')
#    def rolemapInfo(self):
#        """Get The Session Info For Debuging
#       """
#       print self.role_mapping
#        return str(self.role_mapping)


    security.declarePrivate('__extract_shib_data')
    def __extract_shib_data(self, request):
        """
        Extracts Credentials

            >>> from zope.publisher.browser import TestRequest
            >>> shib_headers = { 'HTTP_SHIB_APPLICATION_ID': 'default', \
              'HTTP_COOKIE': '_saml_idp=aHR0cHM6Ly9nbG9idXMtbWF0dGhldy5ocGMuamN1LmVkdS5hdS9zaGliYm9sZXRo; _shibstate_5dc97d035cb931c8123d34c999e481deb8e5204c=https%3A%2F%2Fglobus-matthew.hpc.jcu.edu.au%2Fmattotea%2Facl_users%2Fshib%2Flogin; _shibsession_5dc97d035cb931c8123d34c999e481deb8e5204c=_44847aa19938b0ff3dbb0505b50f7251; _ZopeId="59459141A3fUP2UyaZk"', \
              'HTTP_SHIB_AUTHENTICATION_METHOD': 'urn:oasis:names:tc:SAML:1.0:am:unspecified', \
              'HTTP_SHIB_EP_UNSCOPEDAFFILIATION': 'member;student', \
              'HTTP_SHIB_IDENTITY_PROVIDER': 'https://globus-matthew.hpc.jcu.edu.au/shibboleth', \
              'HTTP_SHIB_INETORGPERSON_GIVENNAME': 'Matthew', \
              'HTTP_SHIB_ORIGIN_SITE': 'https://globus-matthew.hpc.jcu.edu.au/shibboleth', \
              'HTTP_SHIB_PERSON_COMMONNAME': 'Matthew Morgan', \
              'HTTP_SHIB_PERSON_MAIL': 'matthew.morgan@jcu.edu.au', \
              'HTTP_SHIB_PERSON_SURNAME': 'Morgan'}
            >>> request = TestRequest(**shib_headers)
            >>> self.shib._ShibbolethHelper__extract_shib_data(request)
            {'HTTP_SHIB_PERSON_COMMONNAME': 'Matthew Morgan', \
              'HTTP_SHIB_IDENTITY_PROVIDER': 'https://globus-matthew.hpc.jcu.edu.au/shibboleth', \
              'HTTP_COOKIE': '_saml_idp=aHR0cHM6Ly9nbG9idXMtbWF0dGhldy5ocGMuamN1LmVkdS5hdS9zaGliYm9sZXRo; _shibstate_5dc97d035cb931c8123d34c999e481deb8e5204c=https%3A%2F%2Fglobus-matthew.hpc.jcu.edu.au%2Fmattotea%2Facl_users%2Fshib%2Flogin; _shibsession_5dc97d035cb931c8123d34c999e481deb8e5204c=_44847aa19938b0ff3dbb0505b50f7251; _ZopeId="59459141A3fUP2UyaZk"', \
              'HTTP_SHIB_PERSON_SURNAME': 'Morgan', \
              'HTTP_SHIB_APPLICATION_ID': 'default', \
              'HTTP_SHIB_INETORGPERSON_GIVENNAME': 'Matthew', \
              'HTTP_SHIB_EP_UNSCOPEDAFFILIATION': 'member;student', \
              'HTTP_HOST': '127.0.0.1', \
              'HTTP_SHIB_ORIGIN_SITE': 'https://globus-matthew.hpc.jcu.edu.au/shibboleth', \
              'HTTP_SHIB_PERSON_MAIL': 'matthew.morgan@jcu.edu.au', \
              'login': u'_44847aa19938b0ff3dbb0505b50f7251', \
              'HTTP_SHIB_AUTHENTICATION_METHOD': 'urn:oasis:names:tc:SAML:1.0:am:unspecified'}

            >>> shib_headers = {'HTTP_ACCEPT': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', \
              'HTTP_ACCEPT_CHARSET': 'ISO-8859-1,utf-8;q=0.7,*;q=0.7', \
              'HTTP_ACCEPT_ENCODING': 'gzip,deflate', \
              'HTTP_ACCEPT_LANGUAGE': 'en-au,en;q=0.5', \
              'HTTP_COOKIE': '_saml_idp=aHR0cHM6Ly9nbG9idXMtbWF0dGhldy5ocGMuamN1LmVkdS5hdS9zaGliYm9sZXRo; _shibstate_5dc97d035cb931c8123d34c999e481deb8e5204c=https%3A%2F%2Fglobus-matthew.hpc.jcu.edu.au%2Fmattotea%2Facl_users%2Fshib%2Flogin; _shibsession_5dc97d035cb931c8123d34c999e481deb8e5204c=_44847aa19938b0ff3dbb0505b50f7251; _ZopeId="59459141A3fUP2UyaZk"', \
              'HTTP_HOST': 'localhost:8380', \
              'HTTP_MAX_FORWARDS': '10', \
              'HTTP_REFERER': 'https://globus-matthew.hpc.jcu.edu.au/mattotea', \
              'HTTP_SHIB_APPLICATION_ID': 'default', \
              'HTTP_SHIB_AUTHENTICATION_METHOD': 'urn:oasis:names:tc:SAML:1.0:am:unspecified', \
              'HTTP_SHIB_EP_UNSCOPEDAFFILIATION': 'member;student', \
              'HTTP_SHIB_IDENTITY_PROVIDER': 'https://globus-matthew.hpc.jcu.edu.au/shibboleth', \
              'HTTP_SHIB_INETORGPERSON_GIVENNAME': 'Matthew', \
              'HTTP_SHIB_ORIGIN_SITE': 'https://globus-matthew.hpc.jcu.edu.au/shibboleth', \
              'HTTP_SHIB_PERSON_COMMONNAME': 'Matthew Morgan', \
              'HTTP_SHIB_PERSON_MAIL': 'matthew.morgan@jcu.edu.au', \
              'HTTP_SHIB_PERSON_SURNAME': 'Morgan', \
              'HTTP_USER_AGENT': 'Mozilla/5.0 (X11; U; Linux i686; en; rv:1.9.0.1) Gecko/20080528 Epiphany/2.22 Firefox/3.0', 'HTTP_VIA': '1.1 globus-matthew.hpc.jcu.edu.au', \
              'HTTP_X_FORWARDED_FOR': '137.219.45.217', \
              'HTTP_X_FORWARDED_HOST': 'globus-matthew.hpc.jcu.edu.au', \
              'HTTP_X_FORWARDED_SERVER': 'globus-matthew.hpc.jcu.edu.au',}
            >>> request = TestRequest(**shib_headers)
            >>> self.shib._ShibbolethHelper__extract_shib_data(request)
            {'HTTP_SHIB_IDENTITY_PROVIDER': 'https://globus-matthew.hpc.jcu.edu.au/shibboleth', \
              'HTTP_MAX_FORWARDS': '10', \
              'HTTP_COOKIE': '_saml_idp=aHR0cHM6Ly9nbG9idXMtbWF0dGhldy5ocGMuamN1LmVkdS5hdS9zaGliYm9sZXRo; _shibstate_5dc97d035cb931c8123d34c999e481deb8e5204c=https%3A%2F%2Fglobus-matthew.hpc.jcu.edu.au%2Fmattotea%2Facl_users%2Fshib%2Flogin; _shibsession_5dc97d035cb931c8123d34c999e481deb8e5204c=_44847aa19938b0ff3dbb0505b50f7251; _ZopeId="59459141A3fUP2UyaZk"', \
              'HTTP_ACCEPT_LANGUAGE': 'en-au,en;q=0.5', \
              'HTTP_SHIB_APPLICATION_ID': 'default', \
              'HTTP_X_FORWARDED_SERVER': 'globus-matthew.hpc.jcu.edu.au', \
              'HTTP_ACCEPT_CHARSET': 'ISO-8859-1,utf-8;q=0.7,*;q=0.7', \
              'HTTP_USER_AGENT': 'Mozilla/5.0 (X11; U; Linux i686; en; rv:1.9.0.1) Gecko/20080528 Epiphany/2.22 Firefox/3.0', \
              'HTTP_REFERER': 'https://globus-matthew.hpc.jcu.edu.au/mattotea', \
              'HTTP_SHIB_PERSON_SURNAME': 'Morgan', \
              'HTTP_SHIB_INETORGPERSON_GIVENNAME': 'Matthew', \
              'HTTP_SHIB_EP_UNSCOPEDAFFILIATION': 'member;student', \
              'HTTP_VIA': '1.1 globus-matthew.hpc.jcu.edu.au', \
              'HTTP_HOST': 'localhost:8380', \
              'HTTP_SHIB_ORIGIN_SITE': 'https://globus-matthew.hpc.jcu.edu.au/shibboleth', \
              'HTTP_SHIB_AUTHENTICATION_METHOD': 'urn:oasis:names:tc:SAML:1.0:am:unspecified', \
              'HTTP_ACCEPT': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', \
              'HTTP_SHIB_PERSON_COMMONNAME': 'Matthew Morgan', \
              'HTTP_X_FORWARDED_FOR': '137.219.45.217', \
              'HTTP_X_FORWARDED_HOST': 'globus-matthew.hpc.jcu.edu.au', \
              'HTTP_SHIB_PERSON_MAIL': 'matthew.morgan@jcu.edu.au', \
              'login': u'_44847aa19938b0ff3dbb0505b50f7251', \
              'HTTP_ACCEPT_ENCODING': 'gzip,deflate'}

        """
        toRet={}
        keys = request.keys()
        for key in keys:
            if key.startswith("HTTP_"):
                toRet[key] = request[key];
        #toRet["login"] = request['HTTP_SHIB_PERSON_UID']
        uid_attr = self.getProperty('userid_attribute')
        if uid_attr.strip().__len__() > 0:
             if not (uid_attr in request.keys()):
                  toRet["login"] = self.__getShibbolethSessionId(request)
                  self.log(INFO, "User UID not supplied using handle: %s, from provider: %s."%(toRet["login"], request[self.getProperty(Constants.idp_identifier_attribute)]))
             else:
                  self.log(INFO, 'Login: %s, %s'%(uid_attr,request[uid_attr]))
                  toRet["login"] = request[uid_attr]
        else:
            self.log(ERROR, "%s property is not set to anything."%('userid_attribute',))
        self.log(INFO, "Extracted Values: %s"%str(toRet))
        return toRet


    security.declarePrivate('__getShibbolethSessionId')
    def __getShibbolethSessionId(self, request):
        """
        Gets the Shibboleth Session ID from the Request

            >>> shib_headers = {'HTTP_COOKIE': '_saml_idp=aHR0cHM6Ly9nbG9idXMtbWF0dGhldy5ocGMuamN1LmVkdS5hdS9zaGliYm9sZXRo; \
              _shibstate_5dc97d035cb931c8123d34c999e481deb8e5204c=https%3A%2F%2Fglobus-matthew.hpc.jcu.edu.au%2Fmattotea%2Facl_users%2Fshib%2Flogin; \
              _shibsession_5dc97d035cb931c8123d34c999e481deb8e5204c=_44847aa19938b0ff3dbb0505b50f7251; \
              _ZopeId="59459141A3fUP2UyaZk"'}
            >>> cookies = self.shib.REQUEST.cookies
            >>> for c in shib_headers['HTTP_COOKIE'].split(';'):
            ...     c = c.split('=')
            ...     cookies[c[0].strip()] = unicode(c[1])
            >>> self.app.acl_users.shib.REQUEST.environ.update(shib_headers)
            >>> self.shib._ShibbolethHelper__getShibbolethSessionId(self.shib.REQUEST)
            u'_44847aa19938b0ff3dbb0505b50f7251'

            >>> from zope.publisher.browser import TestRequest
            >>> shib_headers = {'HTTP_COOKIE': '_saml_idp=aHR0cHM6Ly9nbG9idXMtbWF0dGhldy5ocGMuamN1LmVkdS5hdS9zaGliYm9sZXRo; \
              _shibstate_5dc97d035cb931c8123d34c999e481deb8e5204c=https%3A%2F%2Fglobus-matthew.hpc.jcu.edu.au%2Fmattotea%2Facl_users%2Fshib%2Flogin; \
              _shibsession_5dc97d035cb931c8123d34c999e481deb8e5204c=_44847aa19938b0ff3dbb0505b50f7251; \
              _ZopeId="59459141A3fUP2UyaZk"'}
            >>> request = TestRequest(**shib_headers)
            >>> self.shib._ShibbolethHelper__getShibbolethSessionId(request)
            u'_44847aa19938b0ff3dbb0505b50f7251'
        """
        for key in request.cookies.keys():
                if key.startswith("_shibsession_"):
                        self.log(DEBUG, "__getShibbolethSessionId: %s" % request.cookies[key])
                        return request.cookies[key]
        return None

#    security.declarePrivate('__validShibSession')
#    def __validShibSession(self, shibSessionId, ip):
#        """Checks weather the Shibboleth session cookie is valid.
#        """
#       toRet = False
#       ses = None
#        if shibSessionId == None:
#           shibSessionId=''
#        try:
#                ses = self.lisn.getSession(self.app, shibSessionId, ip)
#                toRet = True
#
#        except pyShibTarget.SAMLException:
#                toRet = False
#        except Exception, e:
#               self.log(INFO,e)
#
#        self.log(INFO, "Validating Session, is valid: %s."%toRet)
#        del ses
#        #f not toRet and
#        return toRet

    security.declarePrivate('__validShibSession')
    def __validShibSession(self, request):
        """
        Check that the request shib session id matches the one in the session manager.

            >>> from zope.publisher.browser import TestRequest
            >>> shib_headers = {'HTTP_COOKIE': '_saml_idp=aHR0cHM6Ly9nbG9idXMtbWF0dGhldy5ocGMuamN1LmVkdS5hdS9zaGliYm9sZXRo; _shibstate_5dc97d035cb931c8123d34c999e481deb8e5204c=https%3A%2F%2Fglobus-matthew.hpc.jcu.edu.au%2Fmattotea%2Facl_users%2Fshib%2Flogin; _shibsession_5dc97d035cb931c8123d34c999e481deb8e5204c=_44847aa19938b0ff3dbb0505b50f7251; _ZopeId="59459141A3fUP2UyaZk"'}
            >>> request = TestRequest(**shib_headers)
            >>> request.SESSION = self.app.session_data_manager.getSessionData()
            >>> self.shib._ShibbolethHelper__validShibSession(request)
            False

            >>> request.SESSION = self.app.session_data_manager.getSessionData()
            >>> request.SESSION['session_id'] = u'_44847aa19938b0ff3dbb0505b50f7251'
            >>> self.shib._ShibbolethHelper__validShibSession(request)
            True
        """

        sesid = self.__getShibbolethSessionId(request)
        if request.SESSION.has_key(Constants.session_id):
            #self.log(INFO, request.SESSION[Constants.session_id])
            #self.log(INFO, request.SESSION[Constants.session_id] == sesid)
            return  request.SESSION[Constants.session_id] == sesid
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
        LOG.log(level, ": "+ str(message))


    security.declarePrivate('__caculateMapping')
    def __caculateMapping(self, request, funcs):
        self.log(DEBUG, "__caculateMapping: %s, %s" % (request, funcs))
        toRet = []
        sesid = self.__getShibbolethSessionId(request)
        session = self.REQUEST.SESSION
        if not sesid: return tuple()
        if not session.has_key(sesid): return tuple()
        attrs = session[sesid]
        assign_targets = funcs
        for role in assign_targets:
          try:
              if assign_targets[role](attrs): toRet.append(role)
          except Exception, e:
              self.log(INFO, "Error occoured whilst assiging target: %s"%role)
        self.log(DEBUG, "__caculateMapping: %s" % toRet)
        return tuple(toRet)


    def __setup_op_switch(self):
        """Setups up the operation dictionary for use by manage_mappings"""
        def add_item(REQUEST, map):
            map[REQUEST.form[Constants.mapping_item]] = [[0, '', 0, '', 0, 0]]
            return False

        def del_item(REQUEST, map):
            self.log(DEBUG, "Deleting %s %s."%(REQUEST.form[Constants.mapping], REQUEST.form[Constants.mapping_item]))
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
            response.setHeader('Content-Disposition', 'attachment; filename=%s.b64'%to_export)
            response.setBody(base64.encodestring(pickle.dumps([to_export, map, hasher.hexdigest()])))
            return True

        def import_mapping(REQUEST, map):
            form = REQUEST.form
            def doRedr(message):
                uri = "%s?%s=%s"%(REQUEST['HTTP_REFERER'].split("?")[0],Constants.message_element, message)
                self.log(INFO, "URI: %s"%uri)
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
                    Constants.EXP_CODE[item[Constants.OTPos]]%{'1': (item[Constants.SVNPos].__repr__()),
                    '2':value} + ""+ (item[Constants.CBPos]*')'))

                #Create the boolean expressions betweens the lines.
                if(i < (map.__len__()-1)): expression = Constants.BOOL_CODE[item[Constants.BOTPos]]%(expression, '%s')

                #Gather the regular expression patterns for validation later.
                if item[Constants.OTPos] in Constants.REGEX_EXP:
                   self.log(DEBUG, "Pattern: "+(str(value)[1:-1]))
                   regex.append(value)

            #Merge the lines with the boolean expression.
            code += expression%tuple(lines)

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
            regex_error += '\n%s\n%s'%("Pattern: %s"%expr[1:-1],f.getvalue())
        self.log(DEBUG, "Errors?: %s"%regex_compile_error)
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
    def configfileExists(self):
        """
        Return true if the AAP.xml config file exists.
        This is a prereq for getPossibleAttributes.
            >>> self.app.acl_users.shib.configfileExists()
            True
        """
        return path.exists(path.join(self.getProperty(Constants.shib_config_dir), "AAP.xml"))

    def getPossibleAttributes(self, file=None):
        """
        Return the possible shibboleth attributes which are found in the AAP xml file

            >>> Attributes = [u'HTTP_SHIB_EP_AFFILIATION', \
              u'HTTP_SHIB_EP_UNSCOPEDAFFILIATION', u'HTTP_REMOTE_USER', u'HTTP_SHIB_EP_ENTITLEMENT', \
              u'HTTP_SHIB_TARGETEDID', u'HTTP_SHIB_EP_PRIMARYAFFILIATION', \
              u'HTTP_SHIB_EP_PRIMARYORGUNITDN', u'HTTP_SHIB_EP_ORGUNITDN', u'HTTP_SHIB_EP_ORGDN', \
              u'HTTP_SHIB_PERSON_COMMONNAME', u'HTTP_SHIB_PERSON_SURNAME', u'HTTP_SHIB_INETORGPERSON_MAIL', \
              u'HTTP_SHIB_PERSON_TELEPHONENUMBER', u'HTTP_SHIB_ORGPERSON_TITLE', u'HTTP_SHIB_INETORGPERSON_INITIALS', \
              u'HTTP_SHIB_PERSON_DESCRIPTION', u'HTTP_SHIB_INETORGPERSON_CARLICENSE', \
              u'HTTP_SHIB_INETORGPERSON_DEPTNUM', u'HTTP_SHIB_INETORGPERSON_DISPLAYNAME', \
              u'HTTP_SHIB_INETORGPERSON_EMPLOYEENUM', u'HTTP_SHIB_INETORGPERSON_EMPLOYEETYPE', \
              u'HTTP_SHIB_INETORGPERSON_PREFLANG', u'HTTP_SHIB_INETORGPERSON_MANAGER', u'HTTP_SHIB_INETORGPERSON_ROOMNUM', \
              u'HTTP_SHIB_ORGPERSON_SEEALSO', u'HTTP_SHIB_ORGPERSON_FAX', u'HTTP_SHIB_ORGPERSON_STREET', \
              u'HTTP_SHIB_ORGPERSON_POBOX', u'HTTP_SHIB_ORGPERSON_POSTALCODE', u'HTTP_SHIB_ORGPERSON_STATE', \
              u'HTTP_SHIB_INETORGPERSON_GIVENNAME', u'HTTP_SHIB_ORGPERSON_LOCALITY', \
              u'HTTP_SHIB_INETORGPERSON_BUSINESSCAT', u'HTTP_SHIB_ORGPERSON_ORGUNIT', u'HTTP_SHIB_ORGPERSON_OFFICENAME', \
              u'HTTP_SHIB_IDENTITY_PROVIDER', u'HTTP_SHIB_ORIGIN_SITE', u'HTTP_SHIB_AUTHENTICATION_METHOD']
            >>> for a in Attributes:
            ...     if a in self.uf.shib.getPossibleAttributes():
            ...         continue
            ...     print "Missing Attribute %s" % a

        """
        from xml.dom.ext.reader import Sax2
        from xml import xpath
        #TODO Should read the shibboleth.xml to figureout where the AAP is
        #doc = Sax2.Reader().fromStream(open(self.getProperty(Constants.shib_config_dir)))
        #AAPConf = xpath.Evaluate('/SPConfig/Applications/AAPProvider/@uri', doc.documentElement)[0]
        #file = AAPConf._get_value()
        if not file:
            file = path.join(self.getProperty(Constants.shib_config_dir), "AAP.xml")
        doc = Sax2.Reader().fromStream(open(file))
        nodes = [n for n in xpath.Evaluate('AttributeRule/@Header', doc.documentElement)]
        attributes = list(set(['HTTP_' + n._get_value().upper().replace('-','_') for n in nodes])) + [u'HTTP_SHIB_AUTHENTICATION_METHOD', u'HTTP_SHIB_ORIGIN_SITE',  u'HTTP_SHIB_IDENTITY_PROVIDER']
        attributes.sort()
        return attributes



classImplements(ShibbolethHelper, interface.IShibbolethHelper)

InitializeClass( ShibbolethHelper )
