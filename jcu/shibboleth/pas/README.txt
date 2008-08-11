Tests for jcu.shibboleth.pas

test setup
----------

    >>> from Testing.ZopeTestCase import user_password
    >>> from Products.Five.testbrowser import Browser
    >>> browser = Browser()

Plugin setup
------------

    >>> acl_users_url = "%s/acl_users" % self.portal.absolute_url()
    >>> browser.addHeader('Authorization', 'Basic %s:%s' % ('portal_owner', user_password))
    >>> browser.open("%s/manage_main" % acl_users_url)
    >>> browser.url
    'http://nohost/plone/acl_users/manage_main'
    >>> form = browser.getForm(index=0)
    >>> select = form.getControl(name=':action')

jcu.shibboleth.pas should be in the list of installable plugins:

    >>> 'Pas Helper' in select.displayOptions
    True

and we can select it:

    >>> select.getControl('Pas Helper').click()
    >>> select.displayValue
    ['Pas Helper']
    >>> select.value
    ['manage_addProduct/jcu.shibboleth.pas/manage_add_pas_helper_form']

we add 'Pas Helper' to acl_users:

    >>> from jcu.shibboleth.pas.plugin import PasHelper
    >>> myhelper = PasHelper('myplugin', 'Pas Helper')
    >>> self.portal.acl_users['myplugin'] = myhelper

and so on. Continue your tests here

    >>> 'ALL OK'
    'ALL OK'

