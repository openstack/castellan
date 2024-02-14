# Copyright (c) The Johns Hopkins University/Applied Physics Laboratory
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
Base ManagedObject Class

This module defines the ManagedObject class. The ManagedObject class
is the base class to represent all objects managed by the key manager.
"""

import abc
import binascii

from castellan.common import exception


class ManagedObject(object, metaclass=abc.ABCMeta):
    """Base class to represent all managed objects."""

    def __init__(self, name=None, created=None, id=None, consumers=[]):
        """Managed Object

        :param name: the name of the managed object.
        :param created: the time a managed object was created.
        :param id: the ID of the object, generated after storing the object.
        :param consumers: the list of object's consumers.
        """
        self._name = name

        # If None or POSIX times
        if not created or isinstance(created, int):
            self._created = created
        else:
            raise ValueError('created must be of long type, actual type %s' %
                             type(created))

        self._id = id
        self._consumers = consumers

    @property
    def id(self):
        """Returns the ID of the managed object.

        Returns the ID of the managed object or None if this object does not
        have one. If the ID is None, the object has not been persisted yet.
        """
        return self._id

    @property
    def name(self):
        """Returns the name.

        Returns the object's name or None if this object does not have one.
        """
        return self._name

    @property
    def created(self):
        """Returns the POSIX time(long) of the object that was created.

        Returns the POSIX time(long) of the object that was created or None if
        the object does not have one, meaning it has not been persisted.
        """
        return self._created

    @property
    def consumers(self):
        """Returns the list of consumers for this object.

        Returns the object's consumers or [] if the object does not have any.
        """
        return self._consumers

    @property
    @abc.abstractmethod
    def format(self):
        """Returns the encoding format.

        Returns the object's encoding format or None if this object is not
        encoded.
        """
        pass

    @property
    def value(self):
        """Returns the managed object value."""
        return self.get_encoded()

    @abc.abstractmethod
    def get_encoded(self):
        """Returns the encoded object.

        Returns a bytestring object in a format represented in the encoding
        specified.
        """
        pass

    def is_metadata_only(self):
        """Returns if the associated object is only metadata or not."""
        return self.get_encoded() is None

    @classmethod
    @abc.abstractmethod
    def managed_type(cls):
        """Returns the managed object type identifier.

        Returns the object's type identifier for serialization purpose.
        """
        pass

    @classmethod
    def from_dict(cls, dict_fields, id=None, metadata_only=False,
                  consumers=[]):
        """Returns an instance of this class based on a dict object.

        :param dict_fields: The dictionary containing all necessary params
                            to create one instance.
        :param id: The optional param 'id' to be passed to the constructor.
        :param metadata_only: A switch to create an instance with metadata
                              only, without the secret itself.
        :param consumers: A list with object's consumers.
        """
        try:
            value = None

            # NOTE(moguimar): the managed object's value is exported as
            # a hex string. For now, this is a compatibility thing with
            # the already existent vault_key_manager backend.
            if not metadata_only and dict_fields["value"] is not None:
                value = binascii.unhexlify(dict_fields["value"])

            return cls(
                value,
                name=dict_fields["name"],
                created=dict_fields["created"],
                id=id,
                consumers=consumers
            )
        except KeyError as e:
            raise exception.InvalidManagedObjectDictError(field=str(e))

    def to_dict(self, metadata_only=False):
        """Returns a dict that can be used with the from_dict() method.

        :param metadata_only: A switch to create an dictionary with metadata
                              only, without the secret itself.

        :rtype: dict
        """
        value = None

        # NOTE(moguimar): the managed object's value is exported as
        # a hex string. For now, this is a compatibility thing with
        # the already existent vault_key_manager backend.
        if not metadata_only and self.value is not None:
            value = binascii.hexlify(self.value).decode("utf-8")

        return {
            "type": self.managed_type(),
            "name": self.name,
            "created": self.created,
            "value": value,
            "consumers": self.consumers
        }
