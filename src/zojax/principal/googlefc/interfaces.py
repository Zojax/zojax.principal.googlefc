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
""" zojax.principal.googlefc interfaces

$Id$
"""
from zope import interface, schema
from zope.i18nmessageid.message import MessageFactory
from zope.app.authentication.interfaces import IPrincipalInfo
from zope.app.authentication.interfaces import IAuthenticatorPlugin

_ = MessageFactory("zojax.principal.googlefc")


class IGoogleFCAuthenticationProduct(interface.Interface):
    """ product """

    siteId = schema.TextLine(title=_(u"Site id"),
                             required=True,)

    consumerKey = schema.TextLine(title=_(u"Consumer key"),
                                  required=True,)

    consumerSecret = schema.TextLine(title=_(u"Consumer secret"),
                                     required=True,)

    parentURL = schema.TextLine(title=_(u"Parent Url"),
                                default=u'/',
                                required=True,)

    baseDomain = schema.TextLine(title=_(u"Base domain"),
                                default=u'www.google.com',
                                required=True,)

    rpcURL = schema.TextLine(title=_(u"RPC url"),
                                default=u'http://friendconnect.gmodules.com/ps/api/rpc',
                                required=True,)

    cookieNames = interface.Attribute(u"Cookie name")


class IGoogleFCPrincipal(interface.Interface):
    """ googlefc principal """

    title = schema.TextLine(
        title = _('Title'),
        required = True)

    identifier = interface.Attribute('OpenID Identifier')


class IGoogleFCPrincipalInfo(IPrincipalInfo):
    """ principal info """

    internalId = interface.Attribute('OpenID Identifier')


class IGoogleFCPrincipalMarker(interface.Interface):
    """ openId principal marker """


class IGoogleFCAuthenticator(interface.Interface):

    def getPrincipalByGoogleFCIdentifier(identifier):
        """ Get principal id by her OpenID identifier. Return None if
        principal with given identifier does not exist. """


class IGoogleFCCredentials(interface.Interface):
    """ open id credentials info """

    fcauth = interface.Attribute(u"fcauth")


class IGoogleFCUsersPlugin(IGoogleFCAuthenticator, IAuthenticatorPlugin):
    """A container that contains googlefc principals."""

    title = schema.TextLine(
        title = _('Title'),
        required = False)

    prefix = schema.TextLine(
        title=_("Prefix"),
        description=_("Prefix to be added to all principal ids to assure "
                      "that all ids are unique within the authentication service"),
        missing_value=u"",
        default=u'',
        readonly=True)

    def getPrincipalByLogin(login):
        """ return principal info by login """
