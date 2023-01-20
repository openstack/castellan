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
Base Key Class

This module defines the Key class. The Key class is the base class to
represent all encryption keys. The basis for this class was copied
from Java.
"""

import abc
import binascii

from castellan.common.objects import exception
from castellan.common.objects import managed_object


class Key(managed_object.ManagedObject):
    """Base class to represent all keys."""

    @property
    @abc.abstractmethod
    def algorithm(self):
        """Returns the key's algorithm.

        Returns the key's algorithm. For example, "DSA" indicates that this key
        is a DSA key and "AES" indicates that this key is an AES key.
        """
        pass

    @property
    @abc.abstractmethod
    def bit_length(self):
        """Returns the key's bit length.

        Returns the key's bit length. For example, for AES symmetric keys,
        this refers to the length of the key, and for RSA keys, this refers to
        the length of the modulus.
        """
        pass

    def to_dict(self):
        dict_fields = super().to_dict()

        dict_fields["algorithm"] = self.algorithm
        dict_fields["bit_length"] = self.bit_length
        dict_fields["consumers"] = self.consumers

        return dict_fields

    @classmethod
    def from_dict(cls, dict_fields, id=None, metadata_only=False):
        try:
            value = None

            # NOTE(moguimar): the managed object's value is exported as
            # a hex string. For now, this is a compatibility thing with
            # the already existent vault_key_manager backend.
            if not metadata_only and dict_fields["value"] is not None:
                value = binascii.unhexlify(dict_fields["value"])

            return cls(
                algorithm=dict_fields["algorithm"],
                bit_length=dict_fields["bit_length"],
                key=value,
                name=dict_fields["name"],
                created=dict_fields["created"],
                id=id,
                consumers=dict_fields["consumers"]
            )
        except KeyError as e:
            raise exception.InvalidManagedObjectDictError(field=str(e))
