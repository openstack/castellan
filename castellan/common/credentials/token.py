# Copyright (c) 2015 IBM
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
Base Token Credential

This module defines the Token credential.
"""

from castellan.common.credentials import credential


class Token(credential.Credential):
    """This class represents a token credential."""

    def __init__(self, token):
        """Create a new Token credential.

        :param string token: Token for authentication.
        """

        self._token = token

    @property
    def token(self):
        """This method returns a token."""
        return self._token

    def __eq__(self, other):
        if isinstance(other, Token):
            return (self._token == other._token)
        else:
            return False

    def __ne__(self, other):
        result = self.__eq__(other)
        return not result
