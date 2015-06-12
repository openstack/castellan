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
Functional test cases for the Barbican key manager.

Note: This requires local running instances of Barbican and Keystone.
"""

import uuid

from barbicanclient import exceptions as barbican_exceptions
from keystoneclient.v3 import client
from oslo_context import context

from castellan.common import exception
from castellan.common.objects import symmetric_key
from castellan.key_manager import barbican_key_manager
from castellan.tests.functional import config
from castellan.tests.functional.key_manager import test_key_manager


CONF = config.get_config()


class BarbicanKeyManagerTestCase(test_key_manager.KeyManagerTestCase):

    def _create_key_manager(self):
        return barbican_key_manager.BarbicanKeyManager()

    def setUp(self):
        super(BarbicanKeyManagerTestCase, self).setUp()
        username = CONF.identity.username
        password = CONF.identity.password
        project_name = CONF.identity.project_name
        auth_url = CONF.identity.uri
        keystone_client = client.Client(username=username,
                                        password=password,
                                        project_name=project_name,
                                        auth_url=auth_url)
        self.ctxt = context.RequestContext(
            auth_token=keystone_client.auth_token)

    def tearDown(self):
        super(BarbicanKeyManagerTestCase, self).tearDown()

    def test_create_key(self):
        key_uuid = self.key_mgr.create_key(self.ctxt,
                                           algorithm='AES',
                                           length=256)
        self.addCleanup(self.key_mgr.delete_key, self.ctxt, key_uuid)
        self.assertIsNotNone(key_uuid)

    def test_create_null_context(self):
        self.assertRaises(exception.Forbidden,
                          self.key_mgr.create_key, None, 'AES', 256)

    def test_delete_symmetric_key(self):
        key_uuid = self.key_mgr.create_key(self.ctxt,
                                           algorithm='AES',
                                           length=256)
        self.key_mgr.delete_key(self.ctxt, key_uuid)
        try:
            self.key_mgr.get_key(self.ctxt, key_uuid)
        except barbican_exceptions.HTTPClientError as e:
            self.assertEqual(404, e.status_code)
        else:
            self.fail('No exception when deleting non-existent key')

    def test_delete_null_context(self):
        key_uuid = self.key_mgr.create_key(self.ctxt,
                                           algorithm='AES',
                                           length=256)
        self.addCleanup(self.key_mgr.delete_key, self.ctxt, key_uuid)
        self.assertRaises(exception.Forbidden,
                          self.key_mgr.delete_key, None, key_uuid)

    def test_delete_null_key(self):
        self.assertRaises(exception.KeyManagerError,
                          self.key_mgr.delete_key, self.ctxt, None)

    def test_delete_unknown_key(self):
        bad_key_uuid = str(uuid.uuid4())
        self.assertRaises(barbican_exceptions.HTTPClientError,
                          self.key_mgr.delete_key, self.ctxt, bad_key_uuid)

    def test_get_key(self):
        secret_key = b'\x01\x02\xA0\xB3'
        key = symmetric_key.SymmetricKey('AES', secret_key)

        uuid = self.key_mgr.store_key(self.ctxt, key)
        self.addCleanup(self.key_mgr.delete_key, self.ctxt, uuid)

        retrieved_key = self.key_mgr.get_key(self.ctxt, uuid)
        self.assertEqual(key.get_encoded(), retrieved_key.get_encoded())

    def test_get_null_context(self):
        key_uuid = self.key_mgr.create_key(self.ctxt,
                                           algorithm='AES',
                                           length=256)
        self.assertRaises(exception.Forbidden,
                          self.key_mgr.get_key, None, key_uuid)

    def test_get_null_key(self):
        key_uuid = self.key_mgr.create_key(self.ctxt,
                                           algorithm='AES',
                                           length=256)
        self.addCleanup(self.key_mgr.delete_key, self.ctxt, key_uuid)
        self.assertRaises(exception.KeyManagerError,
                          self.key_mgr.get_key, self.ctxt, None)

    def test_get_unknown_key(self):
        key_uuid = self.key_mgr.create_key(self.ctxt,
                                           algorithm='AES',
                                           length=256)
        self.addCleanup(self.key_mgr.delete_key, self.ctxt, key_uuid)
        bad_key_uuid = str(uuid.uuid4())
        self.assertRaises(barbican_exceptions.HTTPClientError,
                          self.key_mgr.get_key, self.ctxt, bad_key_uuid)

    def test_store(self):
        secret_key = b'\x01\x02\xA0\xB3'
        key = symmetric_key.SymmetricKey('AES', secret_key)

        uuid = self.key_mgr.store_key(self.ctxt, key)
        self.addCleanup(self.key_mgr.delete_key, self.ctxt, uuid)

        retrieved_key = self.key_mgr.get_key(self.ctxt, uuid)
        self.assertEqual(key.get_encoded(), retrieved_key.get_encoded())

    def test_store_null_context(self):
        secret_key = b'\x01\x02\xA0\xB3'
        key = symmetric_key.SymmetricKey('AES', secret_key)

        self.assertRaises(exception.Forbidden,
                          self.key_mgr.store_key, None, key)
