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
X509 Class

This module defines the X509 class, used to represent X.509 certificates.
"""

from castellan.common.objects import certificate


class X509(certificate.Certificate):
    """This class represents X.509 certificates."""

    def __init__(self, data, name=None, created=None, id=None):
        """Create a new X509 object.

        The data should be in a bytestring.
        """
        self._data = data
        super(X509, self).__init__(name=name, created=created, id=id)

    @property
    def format(self):
        """This method returns 'X.509'."""
        return "X.509"

    def get_encoded(self):
        """Returns the data in its encoded format."""
        return self._data

    def __eq__(self, other):
        if isinstance(other, X509):
            return (self._data == other._data)
        else:
            return False

    def __ne__(self, other):
        result = self.__eq__(other)
        return not result
