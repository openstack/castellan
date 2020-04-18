# Copyright 2017 Red Hat, Inc.
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
Test cases for the migration key manager.
"""

import binascii
from unittest import mock

from oslo_config import cfg

from castellan.common import exception
from castellan.common.objects import symmetric_key as key
from castellan import key_manager
from castellan.key_manager import not_implemented_key_manager
from castellan.tests.unit.key_manager import test_key_manager

CONF = cfg.CONF


class ConfKeyManager(not_implemented_key_manager.NotImplementedKeyManager):
    pass


class MigrationKeyManagerTestCase(test_key_manager.KeyManagerTestCase):

    def _create_key_manager(self):
        self.fixed_key = '1' * 64
        try:
            self.conf.register_opt(cfg.StrOpt('fixed_key'),
                                   group='key_manager')
        except cfg.DuplicateOptError:
            pass
        self.conf.set_override('fixed_key',
                               self.fixed_key,
                               group='key_manager')
        return key_manager.API(self.conf)

    def setUp(self):
        super(MigrationKeyManagerTestCase, self).setUp()

        # Create fake context (actual contents doesn't matter).
        self.ctxt = mock.Mock()

        fixed_key_bytes = bytes(binascii.unhexlify(self.fixed_key))
        fixed_key_length = len(fixed_key_bytes) * 8
        self.fixed_key_secret = key.SymmetricKey('AES',
                                                 fixed_key_length,
                                                 fixed_key_bytes)
        self.fixed_key_id = '00000000-0000-0000-0000-000000000000'
        self.other_key_id = "d152fa13-2b41-42ca-a934-6c21566c0f40"

    def test_get_fixed_key(self):
        self.assertEqual('MigrationKeyManager', type(self.key_mgr).__name__)
        secret = self.key_mgr.get(self.ctxt, self.fixed_key_id)
        self.assertEqual(self.fixed_key_secret, secret)

    def test_get_fixed_key_fail_bad_context(self):
        self.assertRaises(exception.Forbidden,
                          self.key_mgr.get,
                          context=None,
                          managed_object_id=self.fixed_key_id)

    def test_delete_fixed_key(self):
        self.key_mgr.delete(self.ctxt, self.fixed_key_id)
        # Delete looks like it succeeded, but nothing actually happened.
        secret = self.key_mgr.get(self.ctxt, self.fixed_key_id)
        self.assertEqual(self.fixed_key_secret, secret)

    def test_delete_fixed_key_fail_bad_context(self):
        self.assertRaises(exception.Forbidden,
                          self.key_mgr.delete,
                          context=None,
                          managed_object_id=self.fixed_key_id)

    def test_get_other_key(self):
        # Request to get other_key_id should be passed on to the backend,
        # who will throw an error because we don't have a valid context.
        self.assertRaises(exception.KeyManagerError,
                          self.key_mgr.get,
                          context=self.ctxt,
                          managed_object_id=self.other_key_id)

    def test_delete_other_key(self):
        # Request to delete other_key_id should be passed on to the backend,
        # who will throw an error because we don't have a valid context.
        self.assertRaises(exception.KeyManagerError,
                          self.key_mgr.delete,
                          context=self.ctxt,
                          managed_object_id=self.other_key_id)

    def test_no_fixed_key(self):
        conf = self.conf
        conf.set_override('fixed_key', None, group='key_manager')
        key_mgr = key_manager.API(conf)
        self.assertNotEqual('MigrationKeyManager', type(key_mgr).__name__)
        self.assertRaises(exception.KeyManagerError,
                          key_mgr.get,
                          context=self.ctxt,
                          managed_object_id=self.fixed_key_id)

    def test_using_conf_key_manager(self):
        conf = self.conf
        ckm_backend = 'castellan.tests.unit.key_manager.' \
                      'test_migration_key_manager.ConfKeyManager'
        conf.set_override('backend', ckm_backend, group='key_manager')
        key_mgr = key_manager.API(conf)
        self.assertNotEqual('MigrationKeyManager', type(key_mgr).__name__)
        self.assertRaises(NotImplementedError,
                          key_mgr.get,
                          context=self.ctxt,
                          managed_object_id=self.fixed_key_id)
