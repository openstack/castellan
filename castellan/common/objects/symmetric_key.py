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
Base SymmetricKey Class

This module defines the SymmetricKey class.
"""

from castellan.common.objects import key


class SymmetricKey(key.Key):
    """This class represents symmetric keys."""

    def __init__(self, algorithm, bit_length, key,
                 name=None, created=None, id=None, consumers=[]):
        """Create a new SymmetricKey object.

        The arguments specify the algorithm and bit length for the symmetric
        encryption and the bytes for the key in a bytestring.
        """
        self._alg = algorithm
        self._bit_length = bit_length
        self._key = key
        super().__init__(name=name, created=created, id=id,
                         consumers=consumers)

    @classmethod
    def managed_type(cls):
        return "symmetric"

    @property
    def algorithm(self):
        return self._alg

    @property
    def format(self):
        return "RAW"

    def get_encoded(self):
        return self._key

    @property
    def bit_length(self):
        return self._bit_length

    def __eq__(self, other):
        if isinstance(other, SymmetricKey):
            return (self._alg == other._alg and
                    self._bit_length == other._bit_length and
                    self._key == other._key)
        else:
            return False

    def __ne__(self, other):
        result = self.__eq__(other)
        return not result
