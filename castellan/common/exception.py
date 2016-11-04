# Copyright (c) 2015 The Johns Hopkins University/Applied Physics Laboratory
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Castellan exception subclasses
"""

import six.moves.urllib.parse as urlparse

from castellan.i18n import _

_FATAL_EXCEPTION_FORMAT_ERRORS = False


class RedirectException(Exception):
    def __init__(self, url):
        self.url = urlparse.urlparse(url)


class CastellanException(Exception):
    """Base Castellan Exception

    To correctly use this class, inherit from it and define
    a 'message' property. That message will get printf'd
    with the keyword arguments provided to the constructor.
    """
    message = _("An unknown exception occurred")

    def __init__(self, message_arg=None, *args, **kwargs):
        if not message_arg:
            message_arg = self.message
        try:
            self.message = message_arg % kwargs
        except Exception:
            if _FATAL_EXCEPTION_FORMAT_ERRORS:
                raise
            else:
                # at least get the core message out if something happened
                pass
        super(CastellanException, self).__init__(self.message)


class Forbidden(CastellanException):
    message = _("You are not authorized to complete this action.")


class KeyManagerError(CastellanException):
    message = _("Key manager error: %(reason)s")


class ManagedObjectNotFoundError(CastellanException):
    message = _("Key not found, uuid: %(uuid)s")


class AuthTypeInvalidError(CastellanException):
    message = _("Invalid auth_type was specified, auth_type: %(type)s")


class InsufficientCredentialDataError(CastellanException):
    message = _("Insufficient credential data was provided, either "
                "\"token\" must be set in the passed conf, or a context "
                "with an \"auth_token\" property must be passed.")
