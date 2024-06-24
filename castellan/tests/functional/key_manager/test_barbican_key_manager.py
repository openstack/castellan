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
import unittest

from keystoneauth1 import identity
from keystoneauth1 import session
from oslo_config import cfg
from oslo_context import context
from oslo_utils import uuidutils
from oslotest import base

from castellan.common.credentials import keystone_password
from castellan.common.credentials import keystone_token
from castellan.common import exception
from castellan.key_manager import barbican_key_manager
from castellan.tests.functional import config
from castellan.tests.functional.key_manager import test_key_manager
from castellan.tests import utils


CONF = config.get_config()


@utils.parameterized_test_case
class BarbicanKeyManagerTestCase(test_key_manager.KeyManagerTestCase):

    def _create_key_manager(self):
        return barbican_key_manager.BarbicanKeyManager(cfg.CONF)

    @abc.abstractmethod
    def get_context(self):
        """Retrieves Context for Authentication"""
        return

    def setUp(self):
        super(BarbicanKeyManagerTestCase, self).setUp()
        try:
            self.ctxt = self.get_context()
            self.key_mgr._get_barbican_client(self.ctxt)
        except Exception as e:
            # When we run functional-vault target, This test class needs
            # to be skipped as barbican is not running
            raise unittest.SkipTest(str(e))

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
        unknown_uuid = uuidutils.generate_uuid()
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
        bad_key_uuid = uuidutils.generate_uuid()
        self.assertRaises(exception.ManagedObjectNotFoundError,
                          self.key_mgr.get, self.ctxt, bad_key_uuid)

    def test_store_null_context(self):
        key = test_key_manager._get_test_symmetric_key()

        self.assertRaises(exception.Forbidden,
                          self.key_mgr.store, None, key)

    def test_secret_create_check_empty_consumers_list(self):
        """Check that the consumers entity is a list and is empty."""

        key = test_key_manager._get_test_passphrase()
        self.assertIsNotNone(key)

        stored_id = self.key_mgr.store(self.ctxt, key)
        self.addCleanup(self.key_mgr.delete, self.ctxt, stored_id, True)
        self.assertIsNotNone(stored_id)

        resp = self.key_mgr.get(self.ctxt, stored_id)
        consumers = resp.consumers
        self.assertIsInstance(consumers, list)
        self.assertEqual(len(consumers), 0)

    def test_secret_create_check_consumers_list_consistency(self):
        """Consumers List Consistency

        Check that the consumers list contains a single element,
        and that it corresponds to the consumer created.
        """

        key = test_key_manager._get_test_passphrase()
        self.assertIsNotNone(key)

        stored_id = self.key_mgr.store(self.ctxt, key)
        self.addCleanup(self.key_mgr.delete, self.ctxt, stored_id, True)
        self.assertIsNotNone(stored_id)

        resource_id = uuidutils.generate_uuid()
        consumer_data = {
            'service': 'dummy_service',
            'resource_type': 'dummy_resource_type',
            'resource_id': resource_id
        }
        self.key_mgr.add_consumer(self.ctxt, stored_id, consumer_data)
        stored_secret = self.key_mgr.get(self.ctxt, stored_id)
        self.assertIsNotNone(stored_secret)
        self.assertIsInstance(stored_secret.consumers, list)
        self.assertEqual(len(stored_secret.consumers), 1)
        self.assertEqual(stored_secret.consumers[0]['service'],
                         consumer_data['service'])
        self.assertEqual(stored_secret.consumers[0]['resource_type'],
                         consumer_data['resource_type'])
        self.assertEqual(stored_secret.consumers[0]['resource_id'],
                         consumer_data['resource_id'])

    def test_secret_create_remove_nonexistent_consumer(self):
        """Removing a nonexistent consumer should raise an exception."""
        key = test_key_manager._get_test_passphrase()
        self.assertIsNotNone(key)

        stored_id = self.key_mgr.store(self.ctxt, key)
        self.addCleanup(self.key_mgr.delete, self.ctxt, stored_id, True)
        self.assertIsNotNone(stored_id)

        resource_id = uuidutils.generate_uuid()
        consumer_data = {
            'service': 'dummy_service',
            'resource_type': 'dummy_resource_type',
            'resource_id': resource_id
        }
        self.assertRaises(exception.ManagedObjectNotFoundError,
                          self.key_mgr.remove_consumer, self.ctxt,
                          stored_id, consumer_data)

    @utils.parameterized_dataset({
        'remove_one': [[{'service': 'service_test1',
                         'resource_type': 'type_test1',
                         'resource_id': 'id_test1'},
                        {'service': 'service_test2',
                         'resource_type': 'type_test2',
                         'resource_id': 'id_test2'}],
                       [{'service': 'service_test1',
                         'resource_type': 'type_test1',
                         'resource_id': 'id_test1'}]],
        'remove_all': [[{'service': 'service_test1',
                         'resource_type': 'type_test1',
                         'resource_id': 'id_test1'},
                        {'service': 'service_test2',
                         'resource_type': 'type_test2',
                         'resource_id': 'id_test2'}],
                       [{'service': 'service_test1',
                         'resource_type': 'type_test1',
                         'resource_id': 'id_test1'},
                        {'service': 'service_test2',
                         'resource_type': 'type_test2',
                         'resource_id': 'id_test2'}]]
    })
    def test_secret_create_and_adding_removing_consumers(
            self,
            add_consumers,
            remove_consumers):
        """The following activities are carried:

        Create a secret, then register each consumer
        in the register_consumers list, then remove each consumer
        in the remove_consumers list.
        """
        key = test_key_manager._get_test_passphrase()
        self.assertIsNotNone(key)

        stored_id = self.key_mgr.store(self.ctxt, key)
        self.addCleanup(self.key_mgr.delete, self.ctxt, stored_id, True)
        self.assertIsNotNone(stored_id)

        for consumer in add_consumers:
            self.key_mgr.add_consumer(self.ctxt, stored_id, consumer)
        stored_secret = self.key_mgr.get(self.ctxt, stored_id)
        self.assertCountEqual(add_consumers, stored_secret.consumers)

        for consumer in remove_consumers:
            self.key_mgr.remove_consumer(self.ctxt, stored_id, consumer)
        stored_secret = self.key_mgr.get(self.ctxt, stored_id)

        removed_ids = set([v['resource_id'] for v in remove_consumers])
        remaining_consumers = [v for v in add_consumers
                               if v['resource_id'] not in removed_ids]
        self.assertCountEqual(remaining_consumers, stored_secret.consumers)

    @utils.parameterized_dataset({
        'no_args': [[{}]],
        'one_arg_1': [[{'service': 'service1'}]],
        'one_arg_2': [[{'resource_type': 'type1'}]],
        'one_arg_3': [[{'resource_id': 'id1'}]],
        'two_args_1': [[{'service': 'service1',
                         'resource_type': 'type1'}]],
        'two_args_2': [[{'service': 'service1',
                         'resource_id': 'id1'}]],
        'two_args_3': [[{'resource_type': 'type1',
                         'resource_id': 'id'}]]
    })
    def test_consumer_add_missing_positional_arguments(self, consumers):
        """Missing Positional Arguments - Addition

        Tries to add a secret consumer without providing all of the required
        positional arguments (service, resource_type, resource_id).
        """
        key = test_key_manager._get_test_passphrase()
        self.assertIsNotNone(key)

        stored_id = self.key_mgr.store(self.ctxt, key)
        self.addCleanup(self.key_mgr.delete, self.ctxt, stored_id, True)
        self.assertIsNotNone(stored_id)

        for consumer in consumers:
            e = self.assertRaises(
                TypeError,
                self.key_mgr.add_consumer,
                self.ctxt, stored_id, consumer)
        self.assertIn('register_consumer() missing', str(e))

    @utils.parameterized_dataset({
        'no_args': [[{}]],
        'one_arg_1': [[{'service': 'service1'}]],
        'one_arg_2': [[{'resource_type': 'type1'}]],
        'one_arg_3': [[{'resource_id': 'id1'}]],
        'two_args_1': [[{'service': 'service1',
                         'resource_type': 'type1'}]],
        'two_args_2': [[{'service': 'service1',
                         'resource_id': 'id1'}]],
        'two_args_3': [[{'resource_type': 'type1',
                         'resource_id': 'id'}]]
    })
    def test_consumer_remove_missing_positional_arguments(self, consumers):
        """Missing Positional Arguments - Removal

        Tries to remove a secret consumer without providing all of the required
        positional arguments (service, resource_type, resource_id).
        """
        key = test_key_manager._get_test_passphrase()
        self.assertIsNotNone(key)

        stored_id = self.key_mgr.store(self.ctxt, key)
        self.addCleanup(self.key_mgr.delete, self.ctxt, stored_id, True)
        self.assertIsNotNone(stored_id)

        consumer_data = {
            'service': 'service1',
            'resource_type': 'type1',
            'resource_id': 'id1'
        }
        self.key_mgr.add_consumer(self.ctxt, stored_id, consumer_data)
        for consumer in consumers:
            e = self.assertRaises(
                TypeError,
                self.key_mgr.remove_consumer,
                self.ctxt, stored_id, consumer)
        self.assertIn('remove_consumer() missing', str(e))

    def test_consumer_add_two_remove_one_check_consumers_list(self):
        """Consumers addition and removal - check of list consistency

        Adds two consumers, removes one and verifies if the consumers
        list's length is consistent (equals to 1).
        """
        key = test_key_manager._get_test_passphrase()
        self.assertIsNotNone(key)

        stored_id = self.key_mgr.store(self.ctxt, key)
        self.addCleanup(self.key_mgr.delete, self.ctxt, stored_id, True)
        self.assertIsNotNone(stored_id)

        consumers = [
            {'service': 'service1',
             'resource_type': 'type1',
             'resource_id': 'id1'},
            {'service': 'service2',
             'resource_type': 'type2',
             'resource_id': 'id2'}
        ]
        for consumer in consumers:
            self.key_mgr.add_consumer(self.ctxt, stored_id, consumer)
        stored_secret = self.key_mgr.get(self.ctxt, stored_id)
        self.assertCountEqual(consumers, stored_secret.consumers)

        self.key_mgr.remove_consumer(self.ctxt, stored_id, consumers[0])
        stored_secret = self.key_mgr.get(self.ctxt, stored_id)
        self.assertCountEqual(consumers[1:], stored_secret.consumers)

    def test_consumer_add_secret_delete_force_parameter_nonexisting(self):
        """Consumer addition, secret deletion with no 'force' parameter

        Creates a secret, adds a consumer to it and tries to delete the secret
        without specifying the 'force' parameter.
        """
        key = test_key_manager._get_test_passphrase()
        self.assertIsNotNone(key)

        stored_id = self.key_mgr.store(self.ctxt, key)
        self.addCleanup(self.key_mgr.delete, self.ctxt, stored_id, True)
        self.assertIsNotNone(stored_id)

        consumer = {'service': 'service1',
                    'resource_type': 'type1',
                    'resource_id': 'id1'}
        self.key_mgr.add_consumer(self.ctxt, stored_id, consumer)

        e = self.assertRaises(ValueError, self.key_mgr.delete,
                              self.ctxt, stored_id)
        self.assertIn("Secret has consumers! Remove them first or use the "
                      "force parameter to delete it.", str(e))

    def test_consumer_add_secret_delete_force_parameter_false(self):
        """Consumer addition, secret deletion, 'force' parameter equals False

        Creates a secret, adds a consumer to it and tries to delete the secret
        specifying the 'force' parameter as False.
        """
        key = test_key_manager._get_test_passphrase()
        self.assertIsNotNone(key)

        stored_id = self.key_mgr.store(self.ctxt, key)
        self.addCleanup(self.key_mgr.delete, self.ctxt, stored_id, True)
        self.assertIsNotNone(stored_id)

        consumer = {'service': 'service1',
                    'resource_type': 'type1',
                    'resource_id': 'id1'}
        self.key_mgr.add_consumer(self.ctxt, stored_id, consumer)

        e = self.assertRaises(ValueError, self.key_mgr.delete,
                              self.ctxt, stored_id, False)
        self.assertIn("Secret has consumers! Remove them first or use the "
                      "force parameter to delete it.", str(e))

    def test_consumer_add_secret_delete_force_parameter_true(self):
        """Consumer addition, secret deletion, 'force' parameter equals True

        Creates a secret, adds a consumer to it and deletes the secret,
        specifying the 'force' parameter as True.
        """
        key = test_key_manager._get_test_passphrase()
        self.assertIsNotNone(key)

        stored_id = self.key_mgr.store(self.ctxt, key)
        self.assertIsNotNone(stored_id)

        consumer = {'service': 'service1',
                    'resource_type': 'type1',
                    'resource_id': 'id1'}
        self.key_mgr.add_consumer(self.ctxt, stored_id, consumer)

        self.key_mgr.delete(self.ctxt, stored_id, True)


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
        auth_url = CONF.identity.auth_url
        username = CONF.identity.username
        password = CONF.identity.password
        project_name = CONF.identity.project_name
        user_domain_name = CONF.identity.user_domain_name
        project_domain_name = CONF.identity.project_domain_name

        ctxt = keystone_password.KeystonePassword(
            auth_url=auth_url, username=username, password=password,
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
            auth_url=auth_url,
            project_id=auth.get_project_id(sess))
