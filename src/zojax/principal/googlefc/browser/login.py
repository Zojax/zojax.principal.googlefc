##############################################################################
#
# Copyright (c) 2009 Zope Foundation and Contributors.
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################
"""

$Id$
"""
from zope.component import getUtility, queryUtility
from zope.traversing.browser import absoluteURL
from zope.app.component.hooks import getSite

from zojax.principal.googlefc.interfaces import IGoogleFCAuthenticationProduct,
                                                IGoogleFCUsersPlugin

class LoginAction(object):

    id = u'googlefc.login'
    order = 20

    def update(self):
        self.siteId = getUtility(IGoogleFCAuthenticationProduct).siteId
        self.successUrl = '%s/login-success.html'%absoluteURL(getSite(), self.request)

    def isProcessed(self):
        return False
    
    def render(self):
        if queryUtility(IGoogleFCUsersPlugin) is not None:
            return super(LoginAction, self).render()
        return u''
