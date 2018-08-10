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
Functional test cases for the Vault key manager.

Note: This requires local running instance of Vault.
"""
import abc
import os

from oslo_config import cfg
from oslo_context import context
from oslo_utils import uuidutils
from oslotest import base
from testtools import testcase

from castellan.common import exception
from castellan.key_manager import vault_key_manager
from castellan.tests.functional import config
from castellan.tests.functional.key_manager import test_key_manager

CONF = config.get_config()


class VaultKeyManagerTestCase(test_key_manager.KeyManagerTestCase):
    def _create_key_manager(self):
        key_mgr = vault_key_manager.VaultKeyManager(cfg.CONF)

        if ('VAULT_TEST_URL' not in os.environ or
                'VAULT_TEST_ROOT_TOKEN' not in os.environ):
            raise testcase.TestSkipped('Missing Vault setup information')

        key_mgr._root_token_id = os.environ['VAULT_TEST_ROOT_TOKEN']
        key_mgr._vault_url = os.environ['VAULT_TEST_URL']
        return key_mgr

    @abc.abstractmethod
    def get_context(self):
        """Retrieves Context for Authentication"""
        return

    def setUp(self):
        super(VaultKeyManagerTestCase, self).setUp()
        self.ctxt = self.get_context()

    def tearDown(self):
        super(VaultKeyManagerTestCase, self).tearDown()

    def test_create_null_context(self):
        self.assertRaises(exception.Forbidden,
                          self.key_mgr.create_key, None, 'AES', 256)

    def test_create_key_pair_null_context(self):
        self.assertRaises(exception.Forbidden,
                          self.key_mgr.create_key_pair, None, 'RSA', 2048)

    def test_create_key_pair_bad_algorithm(self):
        self.assertRaises(
            NotImplementedError,
            self.key_mgr.create_key_pair,
            self.ctxt, 'DSA', 2048
        )

    def test_delete_null_context(self):
        key_uuid = self._get_valid_object_uuid(
            test_key_manager._get_test_symmetric_key())
        self.addCleanup(self.key_mgr.delete, self.ctxt, key_uuid)
        self.assertRaises(exception.Forbidden,
                          self.key_mgr.delete, None, key_uuid)

    def test_delete_null_object(self):
        self.assertRaises(exception.KeyManagerError,
                          self.key_mgr.delete, self.ctxt, None)

    def test_get_null_context(self):
        key_uuid = self._get_valid_object_uuid(
            test_key_manager._get_test_symmetric_key())
        self.addCleanup(self.key_mgr.delete, self.ctxt, key_uuid)
        self.assertRaises(exception.Forbidden,
                          self.key_mgr.get, None, key_uuid)

    def test_get_null_object(self):
        self.assertRaises(exception.KeyManagerError,
                          self.key_mgr.get, self.ctxt, None)

    def test_get_unknown_key(self):
        bad_key_uuid = uuidutils.generate_uuid()
        self.assertRaises(exception.ManagedObjectNotFoundError,
                          self.key_mgr.get, self.ctxt, bad_key_uuid)

    def test_store_null_context(self):
        key = test_key_manager._get_test_symmetric_key()

        self.assertRaises(exception.Forbidden,
                          self.key_mgr.store, None, key)


class VaultKeyManagerOSLOContextTestCase(VaultKeyManagerTestCase,
                                         base.BaseTestCase):
    def get_context(self):
        return context.get_admin_context()
