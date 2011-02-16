from Products.PluggableAuthService import interfaces
from Products.PluggableAuthService.interfaces.plugins import \
        IExtractionPlugin, \
        IChallengePlugin, \
        IAuthenticationPlugin, \
        IRolesPlugin, \
        IGroupsPlugin, \
        IUserEnumerationPlugin, \
        IPropertiesPlugin, \
        ICredentialsResetPlugin


from Products.PlonePAS.interfaces.plugins import IUserIntrospection

from zope import schema
from zope.interface import Interface

from jcu.shibboleth.pas import ShibbolethHelperMessageFactory as _

class IShibbolethHelper(IAuthenticationPlugin,
        IRolesPlugin,
        IGroupsPlugin,
        IUserEnumerationPlugin,
        IChallengePlugin,
        IPropertiesPlugin,
        IExtractionPlugin,
        IUserIntrospection,
        ICredentialsResetPlugin):
    """interface for PasShibboleth
    """

    userid_attribute = schema.TextLine(title=_(u"User ID Attribute"),
                              description=_(u""),
                              required=True)

    # TODO currently disabled because when you save the form with no input it
    # sets the attribute to None. This causes the plugin to fail.
    #prefix = schema.TextLine(title=_(u"Optional Prefix"),
    #                          description=_(u""),
    #                          default=u"",
    #                          required=False)

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

