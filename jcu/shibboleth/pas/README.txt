Tests for jcu.shibboleth.pas

test setup
----------

    >>> from Testing.ZopeTestCase import user_password
    >>> from Products.Five.testbrowser import Browser
    >>> browser = Browser()

Plugin setup
------------

    >>> acl_users_url = "%s/acl_users" % self.folder.absolute_url()
    >>> browser.addHeader('Authorization', 'Basic %s:%s' % ('portal_owner', user_password))
    >>> browser.open("%s/manage_main" % acl_users_url)
    >>> browser.url
    'http://nohost/acl_users/manage_main'
    >>> form = browser.getForm(index=0)
    >>> select = form.getControl(name=':action')

jcu.shibboleth.pas should be in the list of installable plugins:

    >>> 'Shibboleth Helper' in select.displayOptions
    True

and we can select it:

    >>> select.getControl('Shibboleth Helper').click()
    >>> select.displayValue
    ['Shibboleth Helper']
    >>> select.value
    ['manage_addProduct/jcu.shibboleth.pas/manage_add_shibboleth_helper_form']

we add 'Shibboleth Helper' to acl_users:

    >>> from jcu.shibboleth.pas.plugin import ShibbolethHelper
    >>> myhelper = ShibbolethHelper('myplugin', 'Shibboleth Helper')
    >>> self.folder.acl_users['myplugin'] = myhelper

and so on. Continue your tests here

    >>> 'ALL OK'
    'ALL OK'

