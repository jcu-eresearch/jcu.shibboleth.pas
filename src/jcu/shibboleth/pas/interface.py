from Products.PluggableAuthService import interfaces
from Products.PluggableAuthService.interfaces.plugins import \
        ILoginPasswordExtractionPlugin
from Products.PluggableAuthService.interfaces.plugins import \
        IChallengePlugin
from Products.PluggableAuthService.interfaces.plugins import \
        IAuthenticationPlugin
from Products.PluggableAuthService.interfaces.plugins import \
        IRolesPlugin
from Products.PluggableAuthService.interfaces.plugins import \
        IGroupsPlugin
from Products.PluggableAuthService.interfaces.plugins import \
        IUserEnumerationPlugin
from Products.PluggableAuthService.interfaces.plugins import \
        IPropertiesPlugin

from zope import schema
from zope.interface import Interface

from jcu.shibboleth.pas import ShibbolethHelperMessageFactory as _

class IShibbolethHelper(IAuthenticationPlugin,
        IRolesPlugin,
        IGroupsPlugin,
#       IUserFactoryPlugin,
        IUserEnumerationPlugin,
        IChallengePlugin,
        IPropertiesPlugin,
        ILoginPasswordExtractionPlugin ):
    """interface for PasShibboleth
    """

    userid_attribute = schema.TextLine(title=_(u"User ID Attribute"),
                              description=_(u""),
                              required=True)

    prefix = schema.TextLine(title=_(u"Optional Prefix"),
                              description=_(u""),
                              required=False)

    idp_attribute = schema.TextLine(title=_(u"Shibboleth Provider Attribute"),
                           description=_(u""),
                           required=True)

    max_brackets = schema.Int(title=_(u"Maxium Brackets To Display"),
                           description=_(u""),
                           required=True)

    shibboleth_config_dir = schema.TextLine(title=_(u"Shibboleth SP configuration dir"),
                           description=_(u""),
                           required=True)

    sso_url = schema.TextLine(title=_(u"The location of the SSO that will authenticate the user."),
                           description=_(u"The '%s' symbol should be placed in the string where the return url should be added."),
                           required=True)


class IShibbolethAttributes(Interface):
    attr_map = schema.Dict(title=_(u"Shibboleth SP configuration dir"),
                           description=_(u""),
                           required=True)

