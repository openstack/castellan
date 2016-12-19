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
Test cases for a key manager.

These test cases should pass against any key manager.
"""

from castellan.common import exception
from castellan.common.objects import opaque_data
from castellan.common.objects import passphrase
from castellan.common.objects import private_key
from castellan.common.objects import public_key
from castellan.common.objects import symmetric_key
from castellan.common.objects import x_509
from castellan.tests import utils


def _get_test_symmetric_key():
    key_bytes = bytes(utils.get_symmetric_key())
    bit_length = 128
    key = symmetric_key.SymmetricKey('AES', bit_length, key_bytes)
    return key


def _get_test_public_key():
    key_bytes = bytes(utils.get_public_key_der())
    bit_length = 2048
    key = public_key.PublicKey('RSA', bit_length, key_bytes)
    return key


def _get_test_private_key():
    key_bytes = bytes(utils.get_private_key_der())
    bit_length = 2048
    key = private_key.PrivateKey('RSA', bit_length, key_bytes)
    return key


def _get_test_certificate():
    data = bytes(utils.get_certificate_der())
    cert = x_509.X509(data)
    return cert


def _get_test_opaque_data():
    data = bytes(b'opaque data')
    opaque_object = opaque_data.OpaqueData(data)
    return opaque_object


def _get_test_passphrase():
    data = bytes(b'passphrase')
    passphrase_object = passphrase.Passphrase(data)
    return passphrase_object


@utils.parameterized_test_case
class KeyManagerTestCase(object):

    def _create_key_manager(self):
        raise NotImplementedError()

    def setUp(self):
        super(KeyManagerTestCase, self).setUp()
        self.key_mgr = self._create_key_manager()

    def _get_valid_object_uuid(self, managed_object):
        object_uuid = self.key_mgr.store(self.ctxt, managed_object)
        self.assertIsNotNone(object_uuid)
        return object_uuid

    def test_create_key(self):
        key_uuid = self.key_mgr.create_key(self.ctxt,
                                           algorithm='AES',
                                           length=256)
        self.addCleanup(self.key_mgr.delete, self.ctxt, key_uuid)
        self.assertIsNotNone(key_uuid)

    def test_create_key_pair(self):
        private_key_uuid, public_key_uuid = self.key_mgr.create_key_pair(
            self.ctxt,
            algorithm='RSA',
            length=2048)

        self.addCleanup(self.key_mgr.delete, self.ctxt, private_key_uuid)
        self.addCleanup(self.key_mgr.delete, self.ctxt, public_key_uuid)

        self.assertIsNotNone(private_key_uuid)
        self.assertIsNotNone(public_key_uuid)
        self.assertNotEqual(private_key_uuid, public_key_uuid)

    @utils.parameterized_dataset({
        'symmetric_key': [_get_test_symmetric_key()],
        'public_key': [_get_test_public_key()],
        'private_key': [_get_test_private_key()],
        'certificate': [_get_test_certificate()],
        'passphrase': [_get_test_passphrase()],
        'opaque_data': [_get_test_opaque_data()],
    })
    def test_delete(self, managed_object):
        object_uuid = self._get_valid_object_uuid(managed_object)
        self.key_mgr.delete(self.ctxt, object_uuid)
        try:
            self.key_mgr.get(self.ctxt, object_uuid)
        except exception.ManagedObjectNotFoundError:
            pass
        else:
            self.fail('No exception when deleting non-existent key')

    @utils.parameterized_dataset({
        'symmetric_key': [_get_test_symmetric_key()],
        'public_key': [_get_test_public_key()],
        'private_key': [_get_test_private_key()],
        'certificate': [_get_test_certificate()],
        'passphrase': [_get_test_passphrase()],
        'opaque_data': [_get_test_opaque_data()],
    })
    def test_get(self, managed_object):
        uuid = self._get_valid_object_uuid(managed_object)
        self.addCleanup(self.key_mgr.delete, self.ctxt, uuid)

        retrieved_object = self.key_mgr.get(self.ctxt, uuid)
        self.assertEqual(managed_object.get_encoded(),
                         retrieved_object.get_encoded())
        self.assertFalse(managed_object.is_metadata_only())

    @utils.parameterized_dataset({
        'symmetric_key': [_get_test_symmetric_key()],
        'public_key': [_get_test_public_key()],
        'private_key': [_get_test_private_key()],
        'certificate': [_get_test_certificate()],
        'passphrase': [_get_test_passphrase()],
        'opaque_data': [_get_test_opaque_data()],
    })
    def test_get_metadata(self, managed_object):
        uuid = self._get_valid_object_uuid(managed_object)
        self.addCleanup(self.key_mgr.delete, self.ctxt, uuid)

        retrieved_object = self.key_mgr.get(self.ctxt,
                                            uuid,
                                            metadata_only=True)
        self.assertFalse(managed_object.is_metadata_only())
        self.assertTrue(retrieved_object.is_metadata_only())

    @utils.parameterized_dataset({
        'symmetric_key': [_get_test_symmetric_key()],
        'public_key': [_get_test_public_key()],
        'private_key': [_get_test_private_key()],
        'certificate': [_get_test_certificate()],
        'passphrase': [_get_test_passphrase()],
        'opaque_data': [_get_test_opaque_data()],
    })
    def test_store(self, managed_object):
        uuid = self.key_mgr.store(self.ctxt, managed_object)
        self.addCleanup(self.key_mgr.delete, self.ctxt, uuid)

        retrieved_object = self.key_mgr.get(self.ctxt, uuid)
        self.assertEqual(managed_object.get_encoded(),
                         retrieved_object.get_encoded())
