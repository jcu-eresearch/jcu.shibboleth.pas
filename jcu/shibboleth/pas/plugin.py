'''Class: PasHelper
'''

from AccessControl.SecurityInfo import ClassSecurityInfo
from App.class_init import default__class_init__ as InitializeClass

from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PluggableAuthService.utils import classImplements

import interface
import plugins

from Products.PluggableAuthService.permissions import ManageUsers

from ConstantsPageTemplateFile import mypt
import Constants as Constants

from logging import  DEBUG, ERROR, INFO, WARNING, CRITICAL, FATAL
import logging, StringIO, traceback, re, pickle, base64, md5

from persistent.mapping import PersistentMapping


LOG = logging.getLogger("jcu.shibboleth.pas")

class ShibbolethHelper(BasePlugin):
    '''Multi-plugin Shibboleth

    '''

    meta_type = 'Shibboleth Helper'

    security = ClassSecurityInfo()

    manage_options = ( BasePlugin.manage_options +
                       ( { 'label': 'Map Roles',
                           'action': 'roleview',
                           'help':('Shibboleth','manage_mapping.stx')}
                         ,
                       ) +
                       ( { 'label': 'Map Groups',
                           'action': 'groupview',
                           'help':('Shibboleth','manage_mapping.stx')}
                         ,
                       ) +
                       ( { 'label': 'Import/Export',
                           'action': 'import_exportview',
                           'help':('Shibboleth','manage_mapping.stx')}
                         ,
                       )
                     )

    _properties = BasePlugin._properties + \
                  ({'label': 'Shibboleth Provider Attribute',
                    'id': Constants.idp_identifier_attribute,
                    'type': 'string',
                    'mode': 'w', 'value':'HTTP_SHIB_IDENTITY_PROVIDER'},
                   {'label':'User Common Name Attribute',
                    'id': Constants.user_cn_attribute,
                    'type': 'string',
                    'mode':'w'},
                   {'label':'User UID Attribute',
                    'id': Constants.user_uid_attribute,
                    'type': 'string',
                    'mode':'w'},
                   {'label':'Maxium Brackets To Display',
                    'id': Constants.max_brackets,
                    'type': 'int',
                    'mode':'w'},
                   {'label':'Shibboleth SP configuration dir',
                    'id': Constants.shib_config_dir,
                    'type': 'string',
                    'mode':'w'})

    security.declareProtected( ManageUsers, 'roleview')
    roleview = mypt('www/manage_mapping', Constants.RoleM, globals())
    security.declareProtected( ManageUsers, 'groupview')
    groupview = mypt('www/manage_mapping', Constants.GroupM, globals())
    security.declareProtected( ManageUsers, 'import_export')
    import_exportview = mypt('www/import_export', Constants.ExportImportM, globals())


    #conf = pyShibTarget.IConfig()
    #app = pyShibTarget.IApplication(conf)
    #lisn = pyShibTarget.IListener(conf)
    _valid_item_func_map = {Constants.RoleM: lambda x: x.valid_roles(), Constants.GroupM: lambda x: x.valid_groups()}
    _op_switch = None

    def __init__(self, id, title=None, total_shib=False):
        self._id = self.id = id
        self.title = title
        self.total_shib = total_shib
        self.log(INFO,'Initilizing Shibboleth Authentication.')
        self.__login_location = "login"
        self.role_mapping =  PersistentMapping()
        self.group_mapping =  PersistentMapping()
        self._mapping_map = {Constants.RoleM: self.role_mapping, Constants.GroupM:self.group_mapping}
        self.__setup_compiled_func_map()

        #Properties for the Property Manager.
        self.__dict__[Constants.max_brackets] = Constants.default_max_brackets
        self.__dict__[Constants.user_cn_attribute] = Constants.default_user_cn_attribute_value
        self.__dict__[Constants.user_uid_attribute] = Constants.default_user_uid_attribute_value
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

        data = session[credentials['login']]
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
        sesid = self.__getShibbolethSessionId(request)
        self.log(INFO, "Extracting credentials for handle: %s"%sesid)
        if not sesid:
            self.log(INFO, "Not Shib, Ending.")
            return None
        #if not self.__validShibSession(sesid, self.__getIPAddress(request)):
#       if not self.__validShibSession(request):
#           self.log(INFO, "Not a valid Handle")
#           return None
#       data = None
        #if self.total_shib:
        #    data = self.__extract_shib_data(request)
        return {"login":sesid, "password":sesid}
        #convert to credentials


    #
    #    IRolesPlugin implementation
    #
    security.declarePrivate('getRolesForPrincipal')
    def getRolesForPrincipal( self, principal, request=None ):
        self.log(INFO, "Principle: %s"%principal)
        if not hasattr(self,'_v_compiled_mapping_func_map'):
           self.__compileMappings()
        return self.__caculateMapping(self.REQUEST, self._v_compiled_mapping_func_map[Constants.RoleM])


    #
    #    IGroupsPlugin implementation
    #
    security.declarePrivate('getRolesForPrincipal')
    def getGroupsForPrincipal( self, principal, request=None ):
        if not hasattr(self,'_v_compiled_mapping_func_map'):
           self.__compileMappings()
        return self.__caculateMapping(self.REQUEST, self._v_compiled_mapping_func_map[Constants.GroupM])


    #
    #   IUserEnumerationPlugin implementation
    #
    security.declarePrivate('enumerateUsers')
    def enumerateUsers(self, id=None, login=None, exact_match=False, sort_by=None, max_results=None, **kw):
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
            self.log(INFO,str({'id':session[session_id]['login'],'login':session[session_id][self.getProperty(Constants.user_uid_attribute)],'pluginid':self.getId()}))
            return ({'id':session[session_id]['login'],'login':session[session_id][self.getProperty(Constants.user_uid_attribute)],'pluginid':self.getId()},)
        self.log(INFO, "Not Found.")
        return None


    security.declarePublic('login')
    def login(self):
        """The Login Method
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
            if not session[session_id].has_key(self.getProperty(Constants.user_uid_attribute)):
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
        """Extracts Credentials
        """
        toRet={}
        keys = request.keys()
        for key in keys:
            if key.startswith("HTTP_"):
                toRet[key] = request[key];
        #toRet["login"] = request['HTTP_SHIB_PERSON_UID']
        uid_attr = self.getProperty(Constants.user_uid_attribute)
        if uid_attr.strip().__len__() > 0:
             if not (uid_attr in request.keys()):
                  toRet["login"] = self.__getShibbolethSessionId(request)
                  self.log(INFO, "User UID not supplied using handle: %s, from provider: %s."%(toRet["login"], request[self.getProperty(Constants.idp_identifier_attribute)]))
             else:
                  self.log(INFO, 'Login: %s, %s'%(uid_attr,request[uid_attr]))
                  toRet["login"] = request[uid_attr]
        else:
            self.log(ERROR, "%s property is not set to anything."%(Constants.user_uid_attribute,))
        self.log(INFO, "Extracted Values: %s"%str(toRet))
        return toRet


    security.declarePrivate('__getShibbolethSessionId')
    def __getShibbolethSessionId(self, request):
        """Gets the Shibboleth Session ID from the Request
        """

        key = None
        for _key in request.cookies.keys():
                if _key.startswith("_shibsession_"):
                        key = _key
        if not key: return None
        return request.cookies[key]

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
        sesid = self.__getShibbolethSessionId(request)
        if request.SESSION.has_key(Constants.session_id):
            #self.log(INFO, request.SESSION[Constants.session_id])
            #self.log(INFO, request.SESSION[Constants.session_id] == sesid)
            return  request.SESSION[Constants.session_id] == sesid
        return False



    security.declarePrivate('__getIPAddress')
    def __getIPAddress(self, request):
        """Get the IP Address
        """
        toRet = request['HTTP_X_FORWARDED_FOR']
        if not toRet:
            toRet = request.getClientAddr()
        return toRet


    security.declarePrivate('log')
    def log(self, level, message):
        """
        Log a message for this object.
        """
        LOG.log(level, ": "+ str(message))


    security.declarePrivate('__caculateMapping')
    def __caculateMapping(self, request, funcs):
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
        self.log(INFO, "Targets: %s"%str(toRet))
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
        """This method is called by the mapping/import export pages to carry out there operations."""
        if self._op_switch is None: self.__setup_op_switch()
        if self._mapping_map.has_key(mapping):
                map = self._mapping_map[mapping]
        else:
                map = None
        if REQUEST:
            if self._op_switch.has_key(op_type):
                if not self._op_switch[op_type](REQUEST, map):
                    return REQUEST.RESPONSE.redirect(REQUEST['HTTP_REFERER'])


    security.declareProtected( ManageUsers, 'compileItem')
    def compileItem(self, map, item, mapping):
        """Compiles a mapping element, and stores it for use."""
        if not hasattr(self,'_v_compiled_mapping_func_map'):
            self.__setup_compiled_func_map()
        results =  self.__compileItem(item, map[item])
        error, code, function = results
        if error is None:
            self._v_compiled_mapping_func_map[mapping][item] = function
        return results


    security.declarePrivate('__compileMapping')
    def __compileMappings(self):
        """Compiles all mappings and there items."""
        self.log(DEBUG, "Compiling Mappings.")
        if not hasattr(self,'_v_compiled_mapping_func_map'):
           self.__setup_compiled_func_map()
        for mapping in self._mapping_map:
            print "MAPPING:", mapping
            for item in self._mapping_map[mapping]:
                print "ITEM:", item
                self.compileItem(self._mapping_map[mapping], item, mapping)


    security.declarePrivate('__compileItem')
    def __compileItem(self, name, map):
        """Does the actual compiling of a mapping item (called by compileItem)."""
        self.log(DEBUG, "Compiling: "+str(map))
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

        return (None, code, assign_target)

    security.declareProtected( ManageUsers, 'getMap')
    def getMap(self, name):
        return dict(self._mapping_map[name])

    security.declareProtected( ManageUsers, 'getValidItems')
    def getValidItems(self, name):
        items =  self._valid_item_func_map[name](self)
        keys = self.getMap(name).keys()
        return [x for x in items if x not in keys]

    security.declareProtected(ManageUsers, 'valid_groups')
    def valid_groups(self):
        return [group['title'] for group in self.searchGroups()]

    security.declareProtected(ManageUsers, 'valid_mappings')
    def valid_mappings(self):
        return self._mapping_map.keys()

#    security.declareProtected(ManageUsers, 'do_encode')
#    def do_encode(self, toEncode):
#       return string.join([("&#%s;"%ord(x))  for x in list(toEncode)],'')

    security.declareProtected(ManageUsers, 'configfileExists')
    def configfileExists(self):
        return path.exists(path.join(self.getProperty(Constants.shib_config_dir), "AAP.xml"))

    security.declareProtected(ManageUsers, 'getPossibleAttributes')
    def getPossibleAttributes(self, file=None):
        from xml.dom.ext.reader import Sax2
        from xml import xpath
        # Should read the shibboleth.xml to figureout where the AAP is
        #doc = Sax2.Reader().fromStream(open(self.getProperty(Constants.shib_config_dir)))
        #AAPConf = xpath.Evaluate('/SPConfig/Applications/AAPProvider/@uri', doc.documentElement)[0]
        #file = AAPConf._get_value()
        if not file:
            file = path.join(self.getProperty(Constants.shib_config_dir), "AAP.xml")
        doc = Sax2.Reader().fromStream(open(file))
        nodes = [n for n in xpath.Evaluate('AttributeRule/@Header', doc.documentElement)]
        return list(set(['HTTP_' + n._get_value().upper().replace('-','_') for n in nodes]))



classImplements(ShibbolethHelper, interface.IShibbolethHelper)

InitializeClass( ShibbolethHelper )
