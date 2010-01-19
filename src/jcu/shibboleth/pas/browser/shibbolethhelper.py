#############################################################################
#
# Copyright (c) 2010 Victorian Partnership for Advanced Computing Ltd and
# Contributors.
# All Rights Reserved.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#############################################################################

from zope.formlib import form
from Products.Five.formlib import formbase
from Products.Five.formlib.formbase import PageEditForm
from Products.Five.browser.pagetemplatefile import ViewPageTemplateFile

from jcu.shibboleth.pas.interface import IShibbolethHelper
from jcu.shibboleth.pas import ShibbolethHelperMessageFactory as _

shib_form_fields = form.Fields(IShibbolethHelper)

class ShibbolethHelperEditForm(PageEditForm):
    """Edit form for projects
    """

    form_fields = shib_form_fields

    label = _(u"Edit Shibboleth Helper")
    form_name = _(u"Shibboleth settings")

    base_template = PageEditForm.template
    template = ViewPageTemplateFile('shibbolethhelper.pt')



