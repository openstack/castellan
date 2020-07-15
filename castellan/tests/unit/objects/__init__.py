# Copyright 2020 Red Hat, Inc.
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
Test cases for Managed Objects.
"""
from castellan.common import exception
from castellan.common import objects
from castellan.tests import base


class ManagedObjectFromDictTestCase(base.TestCase):
    def test_invalid_dict(self):
        self.assertRaises(
            exception.InvalidManagedObjectDictError,
            objects.from_dict,
            {},
        )

    def test_unknown_type(self):
        self.assertRaises(
            exception.UnknownManagedObjectTypeError,
            objects.from_dict,
            {"type": "non-existing-managed-object-type"},
        )
