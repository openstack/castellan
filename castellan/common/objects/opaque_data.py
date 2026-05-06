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
Base OpaqueData Class

This module defines the OpaqueData class.
"""

from castellan.common.objects import managed_object


class OpaqueData(managed_object.ManagedObject):
    """This class represents opaque data."""

    def __init__(
        self,
        data: bytes | None,
        name: str | None = None,
        created: int | None = None,
        id: str | None = None,
        consumers: list[dict[str, str]] | None = None,
    ) -> None:
        """Create a new OpaqueData object.

        Expected type for data is a bytestring.
        """
        self._data = data
        super().__init__(
            name=name, created=created, id=id, consumers=consumers
        )

    @classmethod
    def managed_type(cls) -> str:
        return "opaque"

    @property
    def format(self) -> str:
        return "Opaque"

    def get_encoded(self) -> bytes | None:
        return self._data

    def __eq__(self, other: object) -> bool:
        if isinstance(other, OpaqueData):
            return self._data == other._data
        else:
            return False

    def __ne__(self, other: object) -> bool:
        result = self.__eq__(other)
        return not result
