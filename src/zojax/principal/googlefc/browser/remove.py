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
from zope import interface, event
from zope.security.proxy import removeSecurityProxy
from zope.security.management import queryInteraction
from zojax.statusmessage.interfaces import IStatusMessage
from zojax.principal.googlefc.interfaces import _, IGoogleFCPrincipal


def isNotSelf(group):
    principal_id = None

    interaction = queryInteraction()
    if interaction is not None:
        for participation in interaction.participations:
            principal_id = participation.principal.id
            break

    return principal_id != group.__principal__.id


class IPrincipalRemoverPreference(interface.Interface):
    """ principal remover """


class RemovePrincipalView(object):

    def update(self):
        request = self.request
        principal = self.context.__principal__

        if 'form.remove' in request:
            internal = removeSecurityProxy(IGoogleFCPrincipal(principal))
            del internal.__parent__[internal.__name__]

            IStatusMessage(request).add(_('User has been removed.'))
            return self.redirect('../../../../')
