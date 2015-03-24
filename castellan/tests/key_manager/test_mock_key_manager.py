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
Test cases for the mock key manager.
"""

import array
import binascii

from castellan.common import exception
from castellan import context
from castellan.key_manager import symmetric_key as sym_key
from castellan.tests.key_manager import mock_key_manager as mock_key_mgr
from castellan.tests.key_manager import test_key_manager as test_key_mgr


class MockKeyManagerTestCase(test_key_mgr.KeyManagerTestCase):

    def _create_key_manager(self):
        return mock_key_mgr.MockKeyManager()

    def setUp(self):
        super(MockKeyManagerTestCase, self).setUp()

        self.context = context.RequestContext('fake', 'fake')

    def test_create_key(self):
        key_id_1 = self.key_mgr.create_key(self.context)
        key_id_2 = self.key_mgr.create_key(self.context)
        # ensure that the UUIDs are unique
        self.assertNotEqual(key_id_1, key_id_2)

    def test_create_key_with_length(self):
        for length in [64, 128, 256]:
            key_id = self.key_mgr.create_key(self.context, key_length=length)
            key = self.key_mgr.get_key(self.context, key_id)
            self.assertEqual(length / 8, len(key.get_encoded()))

    def test_create_null_context(self):
        self.assertRaises(exception.Forbidden,
                          self.key_mgr.create_key, None)

    def test_store_and_get_key(self):
        secret_key = array.array('B', binascii.unhexlify('0' * 64)).tolist()
        _key = sym_key.SymmetricKey('AES', secret_key)
        key_id = self.key_mgr.store_key(self.context, _key)

        actual_key = self.key_mgr.get_key(self.context, key_id)
        self.assertEqual(_key, actual_key)

    def test_store_null_context(self):
        self.assertRaises(exception.Forbidden,
                          self.key_mgr.store_key, None, None)

    def test_copy_key(self):
        key_id = self.key_mgr.create_key(self.context)
        key = self.key_mgr.get_key(self.context, key_id)

        copied_key_id = self.key_mgr.copy_key(self.context, key_id)
        copied_key = self.key_mgr.get_key(self.context, copied_key_id)

        self.assertNotEqual(key_id, copied_key_id)
        self.assertEqual(key, copied_key)

    def test_copy_null_context(self):
        self.assertRaises(exception.Forbidden,
                          self.key_mgr.copy_key, None, None)

    def test_get_null_context(self):
        self.assertRaises(exception.Forbidden,
                          self.key_mgr.get_key, None, None)

    def test_get_unknown_key(self):
        self.assertRaises(KeyError, self.key_mgr.get_key, self.context, None)

    def test_delete_key(self):
        key_id = self.key_mgr.create_key(self.context)
        self.key_mgr.delete_key(self.context, key_id)

        self.assertRaises(KeyError, self.key_mgr.get_key, self.context,
                          key_id)

    def test_delete_null_context(self):
        self.assertRaises(exception.Forbidden,
                          self.key_mgr.delete_key, None, None)

    def test_delete_unknown_key(self):
        self.assertRaises(KeyError, self.key_mgr.delete_key, self.context,
                          None)
