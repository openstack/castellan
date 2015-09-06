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

import six


@six.add_metaclass(abc.ABCMeta)
class ManagedObject(object):
    """Base class to represent all managed objects."""

    def __init__(self, name=None):
        """Managed Object has a name, defaulted to None."""
        self._name = name

    @property
    def name(self):
        """Returns the name.

        Returns the object's name or None if this object does not have one.
        """
        return self._name

    @abc.abstractproperty
    def format(self):
        """Returns the encoding format.

        Returns the object's encoding format or None if this object is not
        encoded.
        """
        pass

    @abc.abstractmethod
    def get_encoded(self):
        """Returns the encoded object.

        Returns a bytestring object in a format represented in the encoding
        specified.
        """
        pass
