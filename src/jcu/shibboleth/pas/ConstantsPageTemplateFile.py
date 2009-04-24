from Products.PageTemplates.PageTemplateFile import PageTemplateFile
import Constants as Constants

class mypt(PageTemplateFile):

    def __init__(self, filename, name, _prefix=None, **kw):
        PageTemplateFile.__init__(self, filename, _prefix)
        self.s = self
        self.name = name

    def pt_getContext(self):
       from Products.PageTemplates.PageTemplateFile import PageTemplateFile
       import jcu.shibboleth.pas.Constants as Constants
       c = PageTemplateFile.pt_getContext(self)
       dict = Constants.__dict__.copy()
       del dict['__builtins__']
       c['sa_const'] = dict
       return c

