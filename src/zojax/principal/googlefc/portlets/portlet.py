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
import random, sys

from zope import component
from zope.app.component.hooks import getSite
from zope.traversing.browser import absoluteURL

from zojax.portlets.htmlsource.portlet import HTMLSourcePortlet
from zojax.resourcepackage import library

from zojax.principal.googlefc.interfaces import IGoogleFCAuthenticationProduct


script = r"""
<script src="http://www.google.com/jsapi"></script>

<script type="text/javascript">
  google.load('friendconnect', '0.8');
</script>

<script>
google.friendconnect.container.initOpenSocialApi({
  site: '%(siteId)s',
  onload: function() {
    if (!window.timesloaded) {
      window.timesloaded = 1;
    } else {
      window.timesloaded++;
    }
    if (window.timesloaded > 1) {
      window.top.location.href = "%(successURL)s";
    }
  }
});
</script>
"""

class GoogleFC(HTMLSourcePortlet):

    def update(self):
        super(GoogleFC, self).update()
        product = component.getUtility(IGoogleFCAuthenticationProduct)

        source = script % dict(siteId=product.siteId,
                               successURL='%s/login-success.html'%absoluteURL(getSite(), self.request))
        if source not in library.includes.sources:
            library.includeInplaceSource(source)
