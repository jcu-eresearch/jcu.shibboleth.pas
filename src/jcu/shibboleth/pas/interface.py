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


class IShibbolethHelper (IAuthenticationPlugin,
        IRolesPlugin,
        IGroupsPlugin,
#       IUserFactoryPlugin,
        IUserEnumerationPlugin,
        IChallengePlugin,
        IPropertiesPlugin,
        ILoginPasswordExtractionPlugin ):
    """interface for PasShibboleth
    """
