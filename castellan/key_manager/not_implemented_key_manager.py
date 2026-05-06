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
Key manager implementation that raises NotImplementedError
"""

from typing import Any

from oslo_config import cfg

from castellan.common.objects import managed_object
from castellan.key_manager import key_manager
from castellan.key_manager.key_manager import Context


class NotImplementedKeyManager(key_manager.KeyManager):
    """Key Manager that raises NotImplementedError for all operations."""

    def __init__(self, configuration: cfg.ConfigOpts | None = None) -> None:
        pass

    def create_key(
        self,
        context: Context | None,
        algorithm: str = 'AES',
        length: int = 256,
        expiration: str | None = None,
        name: str | None = None,
    ) -> str:
        raise NotImplementedError()

    def create_key_pair(
        self,
        context: Context | None,
        algorithm: str = 'AES',
        length: int = 256,
        expiration: str | None = None,
        name: str | None = None,
    ) -> tuple[str, str]:
        raise NotImplementedError()

    def store(
        self,
        context: Context | None,
        managed_object: managed_object.ManagedObject,
        expiration: str | None = None,
    ) -> str:
        raise NotImplementedError()

    # TODO(stephenfin): This is not defined on the base class nor on other
    # in-tree key managers. Can we remove it?
    def copy(
        self,
        context: Context | None,
        managed_object_id: str,
        **kwargs: Any,
    ) -> Any:
        raise NotImplementedError()

    def get(
        self,
        context: Context | None,
        managed_object_id: str,
        metadata_only: bool = False,
    ) -> managed_object.ManagedObject:
        raise NotImplementedError()

    def list(
        self,
        context: Context | None,
        object_type: type[managed_object.ManagedObject] | None = None,
        metadata_only: bool = False,
    ) -> list[managed_object.ManagedObject]:
        raise NotImplementedError()

    def delete(
        self,
        context: Context | None,
        managed_object_id: str,
        force: bool = False,
    ) -> None:
        raise NotImplementedError()

    def add_consumer(
        self,
        context: Context | None,
        managed_object_id: str,
        consumer_data: dict[str, str],
    ) -> None:
        raise NotImplementedError()

    def remove_consumer(
        self,
        context: Context | None,
        managed_object_id: str,
        consumer_data: dict[str, str],
    ) -> None:
        raise NotImplementedError()
