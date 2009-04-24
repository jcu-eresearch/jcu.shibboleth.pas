from zope.interface import implements
from Products.Five import BrowserView
import jcu.shibboleth.pas.Constants

class importExportView(BrowserView):
    def __init__(self, context, request):
        super(importExportView, self).__init__(context, request)

    sa_const = jcu.shibboleth.pas.Constants
