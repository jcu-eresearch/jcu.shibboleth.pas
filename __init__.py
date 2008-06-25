"""Shibboleth Authentication
"""


from AccessControl.Permissions import manage_users as ManageUsers
from Products.PluggableAuthService.PluggableAuthService import registerMultiPlugin
import ShibAuthenticator
from ShibAuthenticator import ShibAuthenticator as SHA

def initialize(context):

    try:
        try:
            registerMultiPlugin(SHA.meta_type)
        except RuntimeError:
            #Already Registered (Happens on Refresh).
            pass

        context.registerClass( SHA
                             , permission=ManageUsers
                             , constructors=(
                             ShibAuthenticator.manage_addShibAuthenticatorForm,
                             ShibAuthenticator.addShibAuthenticator, )
                             , icon='www/shib.png'
                             )
        #registerDirectory('help', globals())
        context.registerHelp(directory='help', clear=1)
    except ImportError:
        # If we don't have pyShibTarget installed (and installed
        # correctly) then there is no point in exposing this plugin.
        pass
