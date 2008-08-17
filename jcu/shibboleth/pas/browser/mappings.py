from os import path

from Acquisition import aq_inner
from zope.interface import implements
from Products.Five import BrowserView
from jcu.shibboleth.pas import Constants

class roleMappingsView(BrowserView):
    """
        >>> from zope.publisher.browser import TestRequest
        >>> from zope.component import getMultiAdapter
        >>> request = TestRequest()
        >>> self.rmv = getMultiAdapter((self.folder.acl_users.shib, request,), name=u'manage_roles')
    """
    sa_const = Constants

    # XXX Should probably be replaced
    OBPos  = 0  #Opening Bracket Position
    SVNPos = 1  #S? Variable Name Position
    OTPos  = 2  #Operator Type Position
    SVVPos = 3  #S? Variable Value Position
    CBPos  = 4  #Closing Bracket Position
    BOTPos = 5  #Boolean Operator Type Position
    EXPRESSIONS = {0:'==', 1:'!=', 2:'>', 3:'=>', 4:'<', 5:'<=', 6:'matches', 7:'!matches', 8:'search', 9:'!search', 10:'exists', 11:'!exists'}
    BOOL_EXPRESSIONS = {0: 'AND', 1: 'OR', 2:'NAND', 3:'NOR', 4:'XOR'}

    def __init__(self, context, request):
        super(roleMappingsView, self).__init__(context, request)

    def name(self):
        """
        Return the name of the view being called, it's used in the templates because they are so symilar
            >>> self.rmv.name()
            'Role'
        """
        return "Role"

    def getValidItems(self):
        """
        Return the valid possible items for this view (either groups or roles)
            >>> self.rmv.getValidItems()
            ['Owner', 'Manager', 'test_role_1_']
        """
        context = aq_inner(self.context)
        return context.valid_roles()

    def getMap(self):
        return self.context.getMap(self.name())

    def configfileExists(self):
        """
        Checks for the existance of the AAP Configuration file
            >>> self.rmv.configfileExists()
            True
        """
        return self.context.configfileExists()

    def getPossibleAttributes(self):
        return self.context.getPossibleAttributes()

    def compileItem(self, map, item, name):
        context = aq_inner(self.context)
        return context.compileItem(map, item, name)

    def getMaxBrackets(self):
        """
        Return the maximum brackets.
            >>> self.rmv.getMaxBrackets()
            [0, 1, 2, 3, 4, 5, 6]
        """
        return range(self.context.getProperty(self.sa_const.max_brackets)+1)


class groupMappingsView(roleMappingsView):
    """
        >>> from zope.publisher.browser import TestRequest
        >>> from zope.component import getMultiAdapter
        >>> request = TestRequest()
        >>> self.gmv = getMultiAdapter((self.shib, request,), name=u'manage_groups')
    """
    def __init__(self, context, request):
        super(groupMappingsView, self).__init__(context, request)

    def name(self):
        """
        Return the name of the view being called, it's used in the templates because they are so symilar
            >>> self.gmv.name()
            'Group'
        """
        return "Group"

    def getValidItems(self):
        """
        Return the valid possible items for this view (either groups or roles)
            >>> self.gmv.getValidItems()
            []
        """
        context = aq_inner(self.context)
        return context.valid_groups()

    def getMap(self):
        return self.context.getMap(self.name())

    def getPossibleAttributes(self):
        return context.getPossibleAttributes()

