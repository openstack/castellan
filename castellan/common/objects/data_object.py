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

"""Base class for managed objects with payload-first constructors."""

import abc
import binascii
from typing import Any, Self

from castellan.common import exception
from castellan.common.objects import managed_object


class DataObject(managed_object.ManagedObject):
    """A managed object constructed from encoded data and metadata."""

    @abc.abstractmethod
    def __init__(
        self,
        data: bytes | None,
        name: str | None = None,
        created: int | None = None,
        id: str | None = None,
        consumers: list[dict[str, str]] | None = None,
    ) -> None:
        """Initialize metadata; subclasses store the encoded data."""
        super().__init__(
            name=name, created=created, id=id, consumers=consumers
        )

    @classmethod
    def from_dict(
        cls,
        dict_fields: dict[str, Any],
        id: str | None = None,
        metadata_only: bool = False,
        consumers: list[dict[str, str]] | None = None,
    ) -> Self:
        """Returns an instance of this class based on a dict object.

        :param dict_fields: The dictionary containing all necessary params
            to create one instance.
        :param id: The optional param 'id' to be passed to the constructor.
        :param metadata_only: A switch to create an instance with metadata
            only, without the secret itself.
        :param consumers: A list with object's consumers.
        """
        if consumers is None:
            consumers = []

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
                consumers=consumers,
            )
        except KeyError as e:
            raise exception.InvalidManagedObjectDictError(field=str(e))
