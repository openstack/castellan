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
Base Passphrase Class

This module defines the Passphrase class.
"""

from castellan.common.objects import managed_object


class Passphrase(managed_object.ManagedObject):
    """This class represents a passphrase."""

    def __init__(self, passphrase, name=None, created=None):
        """Create a new Passphrase object.

        The expected type for the passphrase is a bytestring.
        """
        self._passphrase = passphrase
        super(Passphrase, self).__init__(name=name, created=created)

    @property
    def format(self):
        """This method returns 'RAW'."""
        return "RAW"

    def get_encoded(self):
        """Returns the data in a bytestring."""
        return self._passphrase

    def __eq__(self, other):
        if isinstance(other, Passphrase):
            return (self._passphrase == other._passphrase)
        else:
            return False

    def __ne__(self, other):
        result = self.__eq__(other)
        return not result
