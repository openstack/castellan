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
import abc
import uuid

from keystoneauth1 import identity
from keystoneauth1 import session
from oslo_config import cfg
from oslo_context import context
from oslotest import base

from castellan.common.credentials import keystone_password
from castellan.common.credentials import keystone_token
from castellan.common import exception
from castellan.key_manager import barbican_key_manager
from castellan.tests.functional import config
from castellan.tests.functional.key_manager import test_key_manager


CONF = config.get_config()


class BarbicanKeyManagerTestCase(test_key_manager.KeyManagerTestCase):

    def _create_key_manager(self):
        return barbican_key_manager.BarbicanKeyManager(cfg.CONF)

    @abc.abstractmethod
    def get_context(self):
        """Retrieves Context for Authentication"""
        return

    def setUp(self):
        super(BarbicanKeyManagerTestCase, self).setUp()
        self.ctxt = self.get_context()

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
        self.addCleanup(self.key_mgr.delete, self.ctxt, key_uuid)
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


class BarbicanKeyManagerOSLOContextTestCase(BarbicanKeyManagerTestCase,
                                            base.BaseTestCase):

    def get_context(self):
        username = CONF.identity.username
        password = CONF.identity.password
        project_name = CONF.identity.project_name
        auth_url = CONF.identity.auth_url
        user_domain_name = CONF.identity.user_domain_name
        project_domain_name = CONF.identity.project_domain_name

        auth = identity.V3Password(auth_url=auth_url,
                                   username=username,
                                   password=password,
                                   project_name=project_name,
                                   user_domain_name=user_domain_name,
                                   project_domain_name=project_domain_name)
        sess = session.Session(auth=auth)

        return context.RequestContext(auth_token=auth.get_token(sess),
                                      tenant=auth.get_project_id(sess))


class BarbicanKeyManagerKSPasswordTestCase(BarbicanKeyManagerTestCase,
                                           base.BaseTestCase):

    def get_context(self):
        username = CONF.identity.username
        password = CONF.identity.password
        project_name = CONF.identity.project_name
        user_domain_name = CONF.identity.user_domain_name
        project_domain_name = CONF.identity.project_domain_name

        ctxt = keystone_password.KeystonePassword(
            username=username, password=password,
            project_name=project_name,
            user_domain_name=user_domain_name,
            project_domain_name=project_domain_name)

        return ctxt


class BarbicanKeyManagerKSTokenTestCase(BarbicanKeyManagerTestCase,
                                        base.BaseTestCase):

    def get_context(self):
        username = CONF.identity.username
        password = CONF.identity.password
        project_name = CONF.identity.project_name
        auth_url = CONF.identity.auth_url
        user_domain_name = CONF.identity.user_domain_name
        project_domain_name = CONF.identity.project_domain_name

        auth = identity.V3Password(auth_url=auth_url,
                                   username=username,
                                   password=password,
                                   project_name=project_name,
                                   user_domain_name=user_domain_name,
                                   project_domain_name=project_domain_name)
        sess = session.Session()

        return keystone_token.KeystoneToken(
            token=auth.get_token(sess),
            project_id=auth.get_project_id(sess))
