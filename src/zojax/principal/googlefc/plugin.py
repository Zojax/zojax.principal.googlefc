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
import logging
from persistent import Persistent

from zope import interface, component, event
from zope.location import Location
from zope.component import getUtility
from zope.proxy import removeAllProxies
from zope.exceptions.interfaces import UserError
from zope.cachedescriptors.property import Lazy
from zope.session.interfaces import ISession
from zope.traversing.browser import absoluteURL
from zope.app.component.hooks import getSite
from zope.app.container.btree import BTreeContainer
from zope.app.container.interfaces import DuplicateIDError
from zope.app.container.interfaces import INameChooser, IObjectRemovedEvent
from zope.app.security.interfaces import IAuthentication, PrincipalLookupError
from zope.app.authentication.interfaces import IFoundPrincipalFactory

import opensocial

from zojax.cache.interfaces import ICacheConfiglet
from zojax.authentication.factory import AuthenticatorPluginFactory
from zojax.authentication.interfaces import PrincipalRemovingEvent
from zojax.authentication.interfaces import PrincipalInitializationFailed
from zojax.statusmessage.interfaces import IStatusMessage
from zojax.principal.registration.interfaces import IPortalRegistration

from zojax.principal.googlefc.interfaces import _, IGoogleFCPrincipal
from zojax.principal.googlefc.interfaces import \
    IGoogleFCCredentials, IGoogleFCUsersPlugin, IGoogleFCPrincipalInfo, \
    IGoogleFCAuthenticationProduct

SESSION_KEY = 'zojax.principal.googlefc'
CHALLENGE_INITIATED_MARKER = '_googlefc_challenge_initiated'

logger = logging.getLogger('zojax.principal.googlefc')
_marker = object()


class GoogleFCPrincipal(Persistent, Location):
    interface.implements(IGoogleFCPrincipal)

    @Lazy
    def id(self):
        self.id = '%s%s%s'%(getUtility(IAuthentication).prefix,
                            self.__parent__.prefix, self.__name__)
        return self.id


class GoogleFCPrincipalInfo(object):
    interface.implements(IGoogleFCPrincipalInfo)

    description = u''

    def __init__(self, id, internal):
        self.id = id
        self.identifier = internal.identifier
        self.title = internal.title
        self.internalId = internal.__name__

    def __repr__(self):
        return 'GoogleFCPrincipalInfo(%r)' % self.id


def getReturnToURL(request):
    return absoluteURL(getSite(), request) + '/@@completeGoogleFCSignIn'


def normalizeIdentifier(identifier):
    identifier = identifier.lower()

    if not identifier.startswith('http://') and \
            not identifier.startswith('https://'):
        identifier = 'http://' + identifier

    if not identifier.endswith('/'):
        identifier = identifier + '/'

    return unicode(identifier)


class AuthenticatorPlugin(BTreeContainer):
    interface.implements(IGoogleFCUsersPlugin, INameChooser)

    def __init__(self, prefix=u'zojax.googlefc.'):
        self.prefix = unicode(prefix)
        self.__name_chooser_counter = 1
        self.__id_by_identifier = self._newContainerData()

        super(AuthenticatorPlugin, self).__init__()

    def _getGoogleFCUserInfo(self, fcauth):
        product = component.getUtility(IGoogleFCAuthenticationProduct)
        cache = component.getUtility(ICacheConfiglet, context=self)
        ob = ('zojax.principal.googlefc', '_getGoogleFCUserInfo')
        key = {'fcauth': fcauth}
        result = cache.query(ob, key, _marker)
        if result is _marker:
            params = {
              "server_rpc_base" : product.rpcURL,
              "security_token" : fcauth,
              "security_token_param" : "fcauth",
            }
            config = opensocial.ContainerConfig(**params)
            self.__container = opensocial.ContainerContext(config)

            batch = opensocial.RequestBatch()
            args = [ "@me", ['@all']]
            request = opensocial.request.FetchPersonRequest(*args)
            batch.add_request("viewer", request)

            try:
              batch.send(self.__container)
              result = batch.get("viewer")
            except:
              logger.exception("Problem getting the viewer")
              result = False
            cache.set(result, ob, key)
        return result

    def authenticateCredentials(self, credentials):
        """Authenticates credentials.

        If the credentials can be authenticated, return an object that provides
        IPrincipalInfo. If the plugin cannot authenticate the credentials,
        returns None.
        """
        if not IGoogleFCCredentials.providedBy(credentials):
            return None

        fcauth = credentials.fcauth

        if fcauth is None:
            return None

        info  = self._getGoogleFCUserInfo(fcauth)

        principalId = self.getPrincipalByGoogleFCIdentifier(info['id'])
        if principalId is None:
            # Principal does not exist.
            principal = self._createPrincipal(info)
            name = INameChooser(self).chooseName('', principal)
            self[name] = principal
            principalId = self.getPrincipalByGoogleFCIdentifier(info['id'])

        return self.principalInfo(self.prefix + principalId)

    def _createPrincipal(self, userInfo):
        principal = GoogleFCPrincipal()
        principal.title = userInfo['displayName']
        principal.identifier = userInfo['id']
        return principal

    def principalInfo(self, id):
        """Returns an IPrincipalInfo object for the specified principal id.

        If the plugin cannot find information for the id, returns None.
        """
        if id.startswith(self.prefix):
            internal = self.get(id[len(self.prefix):])
            if internal is not None:
                return GoogleFCPrincipalInfo(id, internal)

    def getPrincipalByGoogleFCIdentifier(self, identifier):
        """ return principal info by OpenID Identifier """
        if identifier in self.__id_by_identifier:
            return self.__id_by_identifier.get(identifier)

    def checkName(self, name, object):
        if not name:
            raise UserError(
                "An empty name was provided. Names cannot be empty.")

        if isinstance(name, str):
            name = unicode(name)
        elif not isinstance(name, unicode):
            raise TypeError("Invalid name type", type(name))

        if not name.isdigit():
            raise UserError("Name must consist of digits.")

        if name in self:
            raise UserError("The given name is already being used.")

        return True

    def chooseName(self, name, object):
        while True:
            name = unicode(self.__name_chooser_counter)
            try:
                self.checkName(name, object)
                return name
            except UserError:
                self.__name_chooser_counter += 1

    def __setitem__(self, id, principal):
        # A user with the identifier already exists
        identifier = principal.identifier
        if identifier in self.__id_by_identifier:
            raise DuplicateIDError(
                'Principal Identifier already taken!, ' + identifier)

        super(AuthenticatorPlugin, self).__setitem__(id, principal)

        self.__id_by_identifier[principal.identifier] = id

    def __delitem__(self, id):
        # notify about principal removing
        internal = self[id]

        auth = getUtility(IAuthentication)
        info = GoogleFCPrincipalInfo(self.prefix+id, internal)
        info.credentialsPlugin = None
        info.authenticatorPlugin = self
        principal = IFoundPrincipalFactory(info)(auth)
        principal.id = auth.prefix + self.prefix + id
        event.notify(PrincipalRemovingEvent(principal))

        # actual remove
        super(AuthenticatorPlugin, self).__delitem__(id)

        del self.__id_by_identifier[internal.identifier]


@component.adapter(IGoogleFCUsersPlugin, IObjectRemovedEvent)
def pluginRemovedHandler(plugin, event):
    plugin = removeAllProxies(plugin)

    for id in plugin:
        del plugin[id]


authenticatorFactory = AuthenticatorPluginFactory(
    "principal.googlefc", AuthenticatorPlugin, ((IGoogleFCUsersPlugin, ''),),
    _(u'Google Friend Connect plugin'),
    _(u'This plugin allow use googlefc login '
      u'like google, yahoo, lifejournal and many others'))
