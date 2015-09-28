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

from keystoneclient.v3 import client
from oslo_config import cfg
from oslo_context import context
from oslotest import base

from castellan.common import exception
from castellan.key_manager import barbican_key_manager
from castellan.tests.functional import config
from castellan.tests.functional.key_manager import test_key_manager


CONF = config.get_config()


class BarbicanKeyManagerTestCase(test_key_manager.KeyManagerTestCase,
                                 base.BaseTestCase):

    def _create_key_manager(self):
        return barbican_key_manager.BarbicanKeyManager(cfg.CONF)

    def setUp(self):
        super(BarbicanKeyManagerTestCase, self).setUp()
        username = CONF.identity.username
        password = CONF.identity.password
        project_name = CONF.identity.project_name
        auth_url = CONF.identity.uri
        keystone_client = client.Client(username=username,
                                        password=password,
                                        project_name=project_name,
                                        auth_url=auth_url,
                                        project_domain_id='default')
        project_list = keystone_client.projects.list(name=project_name)

        self.ctxt = context.RequestContext(
            auth_token=keystone_client.auth_token,
            tenant=project_list[0].id)

    def tearDown(self):
        super(BarbicanKeyManagerTestCase, self).tearDown()

    def test_create_null_context(self):
        self.assertRaises(exception.Forbidden,
                          self.key_mgr.create_key, None, 'AES', 256)

    def test_create_key_pair_null_context(self):
        self.assertRaises(exception.Forbidden,
                          self.key_mgr.create_key_pair, None, 'RSA', 2048)

    def test_delete_null_context(self):
        key_uuid = self._get_valid_object_uuid(
            test_key_manager._get_test_symmetric_key())
        self.addCleanup(self.key_mgr.delete, self.ctxt, key_uuid)
        self.assertRaises(exception.Forbidden,
                          self.key_mgr.delete, None, key_uuid)

    def test_delete_null_object(self):
        self.assertRaises(exception.KeyManagerError,
                          self.key_mgr.delete, self.ctxt, None)

    def test_delete_unknown_object(self):
        unknown_uuid = str(uuid.uuid4())
        self.assertRaises(exception.ManagedObjectNotFoundError,
                          self.key_mgr.delete, self.ctxt, unknown_uuid)

    def test_get_null_context(self):
        key_uuid = self._get_valid_object_uuid(
            test_key_manager._get_test_symmetric_key())
        self.assertRaises(exception.Forbidden,
                          self.key_mgr.get, None, key_uuid)

    def test_get_null_object(self):
        self.assertRaises(exception.KeyManagerError,
                          self.key_mgr.get, self.ctxt, None)

    def test_get_unknown_key(self):
        bad_key_uuid = str(uuid.uuid4())
        self.assertRaises(exception.ManagedObjectNotFoundError,
                          self.key_mgr.get, self.ctxt, bad_key_uuid)

    def test_store_null_context(self):
        key = test_key_manager._get_test_symmetric_key()

        self.assertRaises(exception.Forbidden,
                          self.key_mgr.store, None, key)
