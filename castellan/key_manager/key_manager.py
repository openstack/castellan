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
Key manager API
"""

from __future__ import annotations

from typing import TypeAlias

import abc
import builtins

from oslo_config import cfg
from oslo_context import context as ctx

from castellan.common.credentials import credential
from castellan.common.objects import managed_object
from castellan.common.objects import opaque_data as op_data
from castellan.common.objects import passphrase
from castellan.common.objects import private_key as pri_key
from castellan.common.objects import public_key as pub_key
from castellan.common.objects import symmetric_key as sym_key
from castellan.common.objects import x_509

Context: TypeAlias = credential.Credential | ctx.RequestContext


class KeyManager(metaclass=abc.ABCMeta):
    """Base Key Manager Interface

    A Key Manager is responsible for managing encryption keys for volumes. A
    Key Manager is responsible for creating, reading, and deleting keys.
    """

    _secret_type_dict: dict[type[managed_object.ManagedObject], str] = {
        op_data.OpaqueData: "opaque",
        passphrase.Passphrase: "passphrase",
        pri_key.PrivateKey: "private",
        pub_key.PublicKey: "public",
        sym_key.SymmetricKey: "symmetric",
        x_509.X509: "certificate",
    }

    @abc.abstractmethod
    def __init__(self, configuration: cfg.ConfigOpts | None) -> None:
        """Instantiate a KeyManager object.

        Creates a KeyManager object with implementation specific details
        obtained from the supplied configuration.
        """
        pass

    @abc.abstractmethod
    def create_key(
        self,
        context: Context | None,
        algorithm: str,
        length: int,
        expiration: str | None = None,
        name: str | None = None,
    ) -> str:
        """Creates a symmetric key.

        This method creates a symmetric key and returns the key's UUID. If the
        specified context does not permit the creation of keys, then a
        NotAuthorized exception should be raised.
        """
        pass

    @abc.abstractmethod
    def create_key_pair(
        self,
        context: Context | None,
        algorithm: str,
        length: int,
        expiration: str | None = None,
        name: str | None = None,
    ) -> tuple[str, str]:
        """Creates an asymmetric key pair.

        This method creates an asymmetric key pair and returns the pair of key
        UUIDs. If the specified context does not permit the creation of keys,
        then a NotAuthorized exception should be raised. The order of the UUIDs
        will be (private, public).
        """
        pass

    @abc.abstractmethod
    def store(
        self,
        context: Context | None,
        managed_object: managed_object.ManagedObject,
        expiration: str | None = None,
    ) -> str:
        """Stores a managed object with the key manager.

        This method stores the specified managed object and returns its UUID
        that identifies it within the key manager. If the specified context
        does not permit the creation of keys, then a NotAuthorized exception
        should be raised.
        """
        pass

    @abc.abstractmethod
    def get(
        self,
        context: Context | None,
        managed_object_id: str,
        metadata_only: bool = False,
    ) -> managed_object.ManagedObject:
        """Retrieves the specified managed object.

        Implementations should verify that the caller has permissions to
        retrieve the managed object by checking the context object passed in
        as context. If the user lacks permission then a NotAuthorized
        exception is raised.

        If the caller requests only metadata, then the object that is
        returned will contain only the secret metadata and no secret bytes.

        If the specified object does not exist, then a KeyError should be
        raised. Implementations should preclude users from discerning the
        UUIDs of objects that belong to other users by repeatedly calling
        this method. That is, objects that belong to other users should be
        considered "non-existent" and completely invisible.
        """
        pass

    @abc.abstractmethod
    def delete(
        self,
        context: Context | None,
        managed_object_id: str,
        force: bool = False,
    ) -> None:
        """Deletes the specified managed object.

        Implementations should verify that the caller has permission to delete
        the managed object by checking the context object (context). A
        NotAuthorized exception should be raised if the caller lacks
        permission.

        If the specified object does not exist, then a KeyError should be
        raised. Implementations should preclude users from discerning the
        UUIDs of objects that belong to other users by repeatedly calling this
        method. That is, objects that belong to other users should be
        considered "non-existent" and completely invisible.

        Implementations that block the deletion of secrets with consumers
        without making the "force" parameter equals True should raise
        an exception.
        """
        pass

    @abc.abstractmethod
    def add_consumer(
        self,
        context: Context | None,
        managed_object_id: str,
        consumer_data: dict[str, str],
    ) -> None:
        """Add a consumer to a managed object.

        Implementations should verify that the caller has permission to
        add a consumer to the managed object by checking the context object
        (context). A NotAuthorized exception should be raised if the caller
        lacks permission.

        If the specified object does not exist, then a KeyError should be
        raised. Implementations should preclude users from discerning the
        UUIDs of objects that belong to other users by repeatedly calling this
        method. That is, objects that belong to other users should be
        considered "non-existent" and completely invisible.
        """
        pass

    @abc.abstractmethod
    def remove_consumer(
        self,
        context: Context | None,
        managed_object_id: str,
        consumer_data: dict[str, str],
    ) -> None:
        """Remove a consumer from a managed object.

        Implementations should verify that the caller has permission to
        remove a consumer to the managed object by checking the context object
        (context). A NotAuthorized exception should be raised if the caller
        lacks permission.

        If the specified object does not exist, then a KeyError should be
        raised. Implementations should preclude users from discerning the
        UUIDs of objects that belong to other users by repeatedly calling this
        method. That is, objects that belong to other users should be
        considered "non-existent" and completely invisible.
        """
        pass

    def list(
        self,
        context: Context | None,
        object_type: type[managed_object.ManagedObject] | None = None,
        metadata_only: bool = False,
    ) -> list[managed_object.ManagedObject]:
        """Lists the managed objects given the criteria.

        Implementations should verify that the caller has permission to list
        the managed objects and should only list the objects the caller has
        access to by checking the context object (context). A NotAuthorized
        exception should be raised if the caller lacks permission.

        A list of managed objects or managed object metadata should be
        returned, depending on the metadata_only flag. If no objects are
        found, an empty list should be returned instead.
        """
        return []

    def list_options_for_discovery(
        self,
    ) -> builtins.list[tuple[str | None, builtins.list[cfg.Opt]]]:
        """Lists the KeyManager's configure options.

        KeyManagers should advertise all supported options through this
        method for the purpose of sample generation by oslo-config-generator.
        Each item in the advertised list should be tuple composed by the group
        name and a list of options belonging to that group. None should be used
        as the group name for the DEFAULT group.

        :returns: the list of supported options of a KeyManager.
        """
        return []
