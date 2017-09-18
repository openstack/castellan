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

from cryptography.hazmat import backends
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from oslo_context import context

from castellan.common import exception
from castellan.common.objects import symmetric_key as sym_key
from castellan.tests.unit.key_manager import mock_key_manager as mock_key_mgr
from castellan.tests.unit.key_manager import test_key_manager as test_key_mgr


def get_cryptography_private_key(private_key):
    crypto_private_key = serialization.load_der_private_key(
        bytes(private_key.get_encoded()),
        password=None,
        backend=backends.default_backend())
    return crypto_private_key


def get_cryptography_public_key(public_key):
    crypto_public_key = serialization.load_der_public_key(
        bytes(public_key.get_encoded()),
        backend=backends.default_backend())
    return crypto_public_key


class MockKeyManagerTestCase(test_key_mgr.KeyManagerTestCase):

    def _create_key_manager(self):
        return mock_key_mgr.MockKeyManager()

    def setUp(self):
        super(MockKeyManagerTestCase, self).setUp()

        self.context = context.RequestContext('fake', 'fake')

    def cleanUp(self):
        super(MockKeyManagerTestCase, self).cleanUp()

        self.key_mgr.keys = {}

    def test_create_key(self):
        key_id_1 = self.key_mgr.create_key(self.context)
        key_id_2 = self.key_mgr.create_key(self.context)
        # ensure that the UUIDs are unique
        self.assertNotEqual(key_id_1, key_id_2)

    def test_create_key_with_length(self):
        for length in [64, 128, 256]:
            key_id = self.key_mgr.create_key(self.context, length=length)
            key = self.key_mgr.get(self.context, key_id)
            self.assertEqual(length / 8, len(key.get_encoded()))
            self.assertIsNotNone(key.id)

    def test_create_key_with_name(self):
        name = 'my key'
        key_id = self.key_mgr.create_key(self.context, name=name)
        key = self.key_mgr.get(self.context, key_id)
        self.assertEqual(name, key.name)
        self.assertIsNotNone(key.id)

    def test_create_key_with_algorithm(self):
        algorithm = 'DES'
        key_id = self.key_mgr.create_key(self.context, algorithm=algorithm)
        key = self.key_mgr.get(self.context, key_id)
        self.assertEqual(algorithm, key.algorithm)
        self.assertIsNotNone(key.id)

    def test_create_key_null_context(self):
        self.assertRaises(exception.Forbidden,
                          self.key_mgr.create_key, None)

    def test_create_key_pair(self):
        for length in [2048, 3072, 4096]:
            name = str(length) + ' key'
            private_key_uuid, public_key_uuid = self.key_mgr.create_key_pair(
                self.context, 'RSA', length, name=name)

            private_key = self.key_mgr.get(self.context, private_key_uuid)
            self.assertIsNotNone(private_key.id)
            public_key = self.key_mgr.get(self.context, public_key_uuid)
            self.assertIsNotNone(public_key.id)

            crypto_private_key = get_cryptography_private_key(private_key)
            crypto_public_key = get_cryptography_public_key(public_key)

            self.assertEqual(name, private_key.name)
            self.assertEqual(name, public_key.name)

            self.assertEqual(length, crypto_private_key.key_size)
            self.assertEqual(length, crypto_public_key.key_size)

    def test_create_key_pair_encryption(self):
        private_key_uuid, public_key_uuid = self.key_mgr.create_key_pair(
            self.context, 'RSA', 2048)

        private_key = self.key_mgr.get(self.context, private_key_uuid)
        public_key = self.key_mgr.get(self.context, public_key_uuid)

        crypto_private_key = get_cryptography_private_key(private_key)
        crypto_public_key = get_cryptography_public_key(public_key)

        message = b'secret plaintext'
        ciphertext = crypto_public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None))
        plaintext = crypto_private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None))

        self.assertEqual(message, plaintext)

    def test_create_key_pair_null_context(self):
        self.assertRaises(exception.Forbidden,
                          self.key_mgr.create_key_pair, None, 'RSA', 2048)

    def test_create_key_pair_invalid_algorithm(self):
        self.assertRaises(ValueError,
                          self.key_mgr.create_key_pair,
                          self.context, 'DSA', 2048)

    def test_create_key_pair_invalid_length(self):
        self.assertRaises(ValueError,
                          self.key_mgr.create_key_pair,
                          self.context, 'RSA', 10)

    def test_store_and_get_key(self):
        secret_key = bytes(b'0' * 64)
        _key = sym_key.SymmetricKey('AES', 64 * 8, secret_key)
        key_id = self.key_mgr.store(self.context, _key)

        actual_key = self.key_mgr.get(self.context, key_id)
        self.assertEqual(_key, actual_key)

        self.assertIsNotNone(actual_key.id)

    def test_store_key_and_get_metadata(self):
        secret_key = bytes(b'0' * 64)
        _key = sym_key.SymmetricKey('AES', 64 * 8, secret_key)
        key_id = self.key_mgr.store(self.context, _key)

        actual_key = self.key_mgr.get(self.context,
                                      key_id,
                                      metadata_only=True)
        self.assertIsNone(actual_key.get_encoded())
        self.assertTrue(actual_key.is_metadata_only())

        self.assertIsNotNone(actual_key.id)

    def test_store_key_and_get_metadata_and_get_key(self):
        secret_key = bytes(b'0' * 64)
        _key = sym_key.SymmetricKey('AES', 64 * 8, secret_key)
        key_id = self.key_mgr.store(self.context, _key)

        actual_key = self.key_mgr.get(self.context,
                                      key_id,
                                      metadata_only=True)
        self.assertIsNone(actual_key.get_encoded())
        self.assertTrue(actual_key.is_metadata_only())

        actual_key = self.key_mgr.get(self.context,
                                      key_id,
                                      metadata_only=False)
        self.assertIsNotNone(actual_key.get_encoded())
        self.assertFalse(actual_key.is_metadata_only())

        self.assertIsNotNone(actual_key.id)

    def test_store_null_context(self):
        self.assertRaises(exception.Forbidden,
                          self.key_mgr.store, None, None)

    def test_get_null_context(self):
        self.assertRaises(exception.Forbidden,
                          self.key_mgr.get, None, None)

    def test_get_unknown_key(self):
        self.assertRaises(KeyError, self.key_mgr.get, self.context, None)

    def test_delete_key(self):
        key_id = self.key_mgr.create_key(self.context)
        self.key_mgr.delete(self.context, key_id)

        self.assertRaises(KeyError, self.key_mgr.get, self.context,
                          key_id)

    def test_delete_null_context(self):
        self.assertRaises(exception.Forbidden,
                          self.key_mgr.delete, None, None)

    def test_delete_unknown_key(self):
        self.assertRaises(KeyError, self.key_mgr.delete, self.context,
                          None)

    def test_list_null_context(self):
        self.assertRaises(exception.Forbidden, self.key_mgr.list, None)

    def test_list_keys(self):
        key1 = sym_key.SymmetricKey('AES', 64 * 8, bytes(b'0' * 64))
        self.key_mgr.store(self.context, key1)
        key2 = sym_key.SymmetricKey('AES', 32 * 8, bytes(b'0' * 32))
        self.key_mgr.store(self.context, key2)

        keys = self.key_mgr.list(self.context)
        self.assertEqual(2, len(keys))
        self.assertTrue(key1 in keys)
        self.assertTrue(key2 in keys)

        for key in keys:
            self.assertIsNotNone(key.id)

    def test_list_keys_metadata_only(self):
        key1 = sym_key.SymmetricKey('AES', 64 * 8, bytes(b'0' * 64))
        self.key_mgr.store(self.context, key1)
        key2 = sym_key.SymmetricKey('AES', 32 * 8, bytes(b'0' * 32))
        self.key_mgr.store(self.context, key2)

        keys = self.key_mgr.list(self.context, metadata_only=True)
        self.assertEqual(2, len(keys))
        bit_length_list = [key1.bit_length, key2.bit_length]
        for key in keys:
            self.assertTrue(key.is_metadata_only())
            self.assertTrue(key.bit_length in bit_length_list)

        for key in keys:
            self.assertIsNotNone(key.id)
