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
Base Password Credential

This module defines the Password credential.
"""

from castellan.common.credentials import credential


class Password(credential.Credential):
    """This class represents a password credential."""

    def __init__(self, username, password):
        """Create a new Password credential.

        :param string password: Password for authentication.
        :param string username: Username for authentication.
        """

        self._username = username
        self._password = password

    @property
    def username(self):
        """This method returns a username."""
        return self._username

    @property
    def password(self):
        """This method returns a password."""
        return self._password

    def __eq__(self, other):
        if isinstance(other, Password):
            return (self._username == other._username and
                    self._password == other._password)
        else:
            return False

    def __ne__(self, other):
        result = self.__eq__(other)
        return not result
