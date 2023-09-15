# Copyright (c) The Johns Hopkins University/Applied Physics Laboratory
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
Test cases for the barbican key manager.
"""
import calendar
from unittest import mock

from barbicanclient import exceptions as barbican_exceptions
from keystoneauth1 import identity
from keystoneauth1 import service_token
from oslo_context import context
from oslo_utils import timeutils

from castellan.common import exception
from castellan.common.objects import symmetric_key as sym_key
from castellan.key_manager import barbican_key_manager
from castellan.tests.unit.key_manager import test_key_manager


class BarbicanKeyManagerTestCase(test_key_manager.KeyManagerTestCase):

    def _create_key_manager(self):
        return barbican_key_manager.BarbicanKeyManager(self.conf)

    def setUp(self):
        super(BarbicanKeyManagerTestCase, self).setUp()

        # Create fake auth_token
        self.ctxt = mock.Mock(spec=context.RequestContext)
        self.ctxt.auth_token = "fake_token"
        self.ctxt.project_name = "foo"
        self.ctxt.project_domain_name = "foo"

        # Create mock barbican client
        self._build_mock_barbican()

        # Create a key_id, secret_ref, pre_hex, and hex to use
        self.key_id = "d152fa13-2b41-42ca-a934-6c21566c0f40"
        self.secret_ref = ("http://host:9311/v1/secrets/" + self.key_id)
        self.pre_hex = "AIDxQp2++uAbKaTVDMXFYIu8PIugJGqkK0JLqkU0rhY="
        self.hex = ("0080f1429dbefae01b29a4d50cc5c5608bbc3c8ba0246aa42b424baa4"
                    "534ae16")
        self.key_mgr._base_url = "http://host:9311/v1/"

        self.key_mgr.conf.barbican.number_of_retries = 3
        self.key_mgr.conf.barbican.retry_delay = 1

        self.addCleanup(self._restore)

    def _restore(self):
        try:
            getattr(self, 'original_key')
            sym_key.SymmetricKey = self.original_key
        except AttributeError:
            return None

    def _build_mock_barbican(self):
        self.mock_barbican = mock.MagicMock(name='mock_barbican')

        # Set commonly used methods
        self.get = self.mock_barbican.secrets.get
        self.delete = self.mock_barbican.secrets.delete
        self.store = self.mock_barbican.secrets.store
        self.create = self.mock_barbican.secrets.create
        self.list = self.mock_barbican.secrets.list

        self.key_mgr._barbican_client = self.mock_barbican
        self.key_mgr._current_context = self.ctxt

    def test_barbican_endpoint(self):
        endpoint_data = mock.Mock()
        endpoint_data.url = 'http://localhost:9311'

        auth = mock.Mock(spec=['service_catalog'])
        auth.service_catalog.endpoint_data_for.return_value = endpoint_data

        endpoint = self.key_mgr._get_barbican_endpoint(auth, mock.Mock())
        self.assertEqual(endpoint, 'http://localhost:9311')
        auth.service_catalog.endpoint_data_for.assert_called_once_with(
            service_type='key-manager', interface='public',
            region_name=None)

    def test_barbican_endpoint_with_endpoint_type(self):
        self.key_mgr.conf.barbican.barbican_endpoint_type = 'internal'

        endpoint_data = mock.Mock()
        endpoint_data.url = 'http://localhost:9311'

        auth = mock.Mock(spec=['service_catalog'])
        auth.service_catalog.endpoint_data_for.return_value = endpoint_data

        endpoint = self.key_mgr._get_barbican_endpoint(auth, mock.Mock())
        self.assertEqual(endpoint, 'http://localhost:9311')
        auth.service_catalog.endpoint_data_for.assert_called_once_with(
            service_type='key-manager', interface='internal',
            region_name=None)

    def test_barbican_endpoint_with_region_name(self):
        self.key_mgr.conf.barbican.barbican_region_name = 'regionOne'

        endpoint_data = mock.Mock()
        endpoint_data.url = 'http://localhost:9311'

        auth = mock.Mock(spec=['service_catalog'])
        auth.service_catalog.endpoint_data_for.return_value = endpoint_data

        endpoint = self.key_mgr._get_barbican_endpoint(auth, mock.Mock())
        self.assertEqual(endpoint, 'http://localhost:9311')
        auth.service_catalog.endpoint_data_for.assert_called_once_with(
            service_type='key-manager', interface='public',
            region_name='regionOne')

    def test_barbican_endpoint_from_config(self):
        self.key_mgr.conf.barbican.barbican_endpoint = 'http://localhost:9311'

        endpoint = self.key_mgr._get_barbican_endpoint(
            mock.Mock(), mock.Mock())
        self.assertEqual(endpoint, 'http://localhost:9311')

    def test_barbican_endpoint_by_get_endpoint(self):
        auth = mock.Mock(spec=['get_endppint'])
        sess = mock.Mock()
        auth.get_endpoint = mock.Mock(return_value='http://localhost:9311')

        endpoint = self.key_mgr._get_barbican_endpoint(auth, sess)
        self.assertEqual(endpoint, 'http://localhost:9311')
        auth.get_endpoint.assert_called_once_with(
            sess, service_type='key-manager', interface='public',
            region_name=None)

    def test_barbican_endpoint_by_get_endpoint_with_endpoint_type(self):
        self.key_mgr.conf.barbican.barbican_endpoint_type = 'internal'

        auth = mock.Mock(spec=['get_endppint'])
        sess = mock.Mock()
        auth.get_endpoint = mock.Mock(return_value='http://localhost:9311')

        endpoint = self.key_mgr._get_barbican_endpoint(auth, sess)
        self.assertEqual(endpoint, 'http://localhost:9311')
        auth.get_endpoint.assert_called_once_with(
            sess, service_type='key-manager', interface='internal',
            region_name=None)

    def test_barbican_endpoint_by_get_endpoint_with_region_name(self):
        self.key_mgr.conf.barbican.barbican_region_name = 'regionOne'

        auth = mock.Mock(spec=['get_endppint'])
        sess = mock.Mock()
        auth.get_endpoint = mock.Mock(return_value='http://localhost:9311')

        endpoint = self.key_mgr._get_barbican_endpoint(auth, sess)
        self.assertEqual(endpoint, 'http://localhost:9311')
        auth.get_endpoint.assert_called_once_with(
            sess, service_type='key-manager', interface='public',
            region_name='regionOne')

    def test__get_keystone_auth(self):
        auth = self.key_mgr._get_keystone_auth(self.ctxt)
        self.assertIsInstance(auth, identity.Token)

    def test__get_keystone_auth_service_user(self):
        self.key_mgr.conf.barbican.send_service_user_token = True
        auth = self.key_mgr._get_keystone_auth(self.ctxt)
        self.assertIsInstance(auth, service_token.ServiceTokenAuthWrapper)

    def test_base_url_old_version(self):
        version = "v1"
        self.key_mgr.conf.barbican.barbican_api_version = version
        endpoint = "http://localhost:9311"
        base_url = self.key_mgr._create_base_url(mock.Mock(),
                                                 mock.Mock(),
                                                 endpoint)
        self.assertEqual(endpoint + "/" + version, base_url)

    def test_base_url_new_version(self):
        version = "v1"
        self.key_mgr.conf.barbican.barbican_api_version = version
        endpoint = "http://localhost/key_manager"
        base_url = self.key_mgr._create_base_url(mock.Mock(),
                                                 mock.Mock(),
                                                 endpoint)
        self.assertEqual(endpoint + "/" + version, base_url)

    def test_base_url_service_catalog(self):
        endpoint_data = mock.Mock()
        endpoint_data.api_version = 'v321'

        auth = mock.Mock(spec=['service_catalog'])
        auth.service_catalog.endpoint_data_for.return_value = endpoint_data

        endpoint = "http://localhost/key_manager"

        base_url = self.key_mgr._create_base_url(auth,
                                                 mock.Mock(),
                                                 endpoint)
        self.assertEqual(endpoint + "/" + endpoint_data.api_version, base_url)
        auth.service_catalog.endpoint_data_for.assert_called_once_with(
            service_type='key-manager', interface='public',
            region_name=None)

    def test_base_url_service_catalog_with_endpoint_type(self):
        self.key_mgr.conf.barbican.barbican_endpoint_type = 'internal'

        endpoint_data = mock.Mock()
        endpoint_data.api_version = 'v321'

        auth = mock.Mock(spec=['service_catalog'])
        auth.service_catalog.endpoint_data_for.return_value = endpoint_data

        endpoint = "http://localhost/key_manager"

        base_url = self.key_mgr._create_base_url(auth,
                                                 mock.Mock(),
                                                 endpoint)
        self.assertEqual(endpoint + "/" + endpoint_data.api_version, base_url)
        auth.service_catalog.endpoint_data_for.assert_called_once_with(
            service_type='key-manager', interface='internal',
            region_name=None)

    def test_base_url_service_catalog_with_region_name(self):
        self.key_mgr.conf.barbican.barbican_region_name = 'regionOne'

        endpoint_data = mock.Mock()
        endpoint_data.api_version = 'v321'

        auth = mock.Mock(spec=['service_catalog'])
        auth.service_catalog.endpoint_data_for.return_value = endpoint_data

        endpoint = "http://localhost/key_manager"

        base_url = self.key_mgr._create_base_url(auth,
                                                 mock.Mock(),
                                                 endpoint)
        self.assertEqual(endpoint + "/" + endpoint_data.api_version, base_url)
        auth.service_catalog.endpoint_data_for.assert_called_once_with(
            service_type='key-manager', interface='public',
            region_name='regionOne')

    def test_base_url_raise_exception(self):
        auth = mock.Mock(spec=['get_discovery'])
        sess = mock.Mock()
        discovery = mock.Mock()
        discovery.raw_version_data = mock.Mock(return_value=[])
        auth.get_discovery = mock.Mock(return_value=discovery)

        endpoint = "http://localhost/key_manager"

        self.assertRaises(exception.KeyManagerError,
                          self.key_mgr._create_base_url,
                          auth, sess, endpoint)
        auth.get_discovery.assert_called_once_with(sess, url=endpoint)
        self.assertEqual(1, discovery.raw_version_data.call_count)

    def test_base_url_get_discovery(self):
        version = 'v100500'
        auth = mock.Mock(spec=['get_discovery'])
        sess = mock.Mock()
        discovery = mock.Mock()
        auth.get_discovery = mock.Mock(return_value=discovery)
        discovery.raw_version_data = mock.Mock(return_value=[{'id': version}])

        endpoint = "http://localhost/key_manager"

        base_url = self.key_mgr._create_base_url(auth,
                                                 sess,
                                                 endpoint)
        self.assertEqual(endpoint + "/" + version, base_url)
        auth.get_discovery.assert_called_once_with(sess, url=endpoint)
        self.assertEqual(1, discovery.raw_version_data.call_count)

    def test_create_key(self):
        # Create order_ref_url and assign return value
        order_ref_url = ("http://localhost:9311/v1/orders/"
                         "4fe939b7-72bc-49aa-bd1e-e979589858af")
        key_order = mock.Mock()
        self.mock_barbican.orders.create_key.return_value = key_order
        key_order.submit.return_value = order_ref_url

        # Create order and assign return value
        order = mock.Mock()
        order.secret_ref = self.secret_ref
        order.status = 'ACTIVE'
        self.mock_barbican.orders.get.return_value = order

        # Create the key, get the UUID
        returned_uuid = self.key_mgr.create_key(self.ctxt,
                                                algorithm='AES',
                                                length=256)

        self.mock_barbican.orders.get.assert_called_once_with(order_ref_url)
        self.assertEqual(self.key_id, returned_uuid)

    def test_create_key_null_context(self):
        self.key_mgr._barbican_client = None
        self.assertRaises(exception.Forbidden,
                          self.key_mgr.create_key, None, 'AES', 256)

    def test_create_key_with_error(self):
        key_order = mock.Mock()
        self.mock_barbican.orders.create_key.return_value = key_order
        key_order.submit = mock.Mock(
            side_effect=barbican_exceptions.HTTPClientError('test error'))
        self.assertRaises(exception.KeyManagerError,
                          self.key_mgr.create_key, self.ctxt, 'AES', 256)

    def test_create_key_pair(self):
        # Create order_ref_url and assign return value
        order_ref_url = ("http://localhost:9311/v1/orders/"
                         "f45bf211-a917-4ead-9aec-1c91e52609df")
        asym_order = mock.Mock()
        self.mock_barbican.orders.create_asymmetric.return_value = asym_order
        asym_order.submit.return_value = order_ref_url

        # Create order and assign return value
        order = mock.Mock()
        container_id = "16caa8f4-dd34-4fb3-bf67-6c20533a30e4"
        container_ref = ("http://localhost:9311/v1/containers/" + container_id)
        order.container_ref = container_ref
        order.status = 'ACTIVE'
        self.mock_barbican.orders.get.return_value = order

        # Create container and assign return value
        container = mock.Mock()
        public_key_id = "43ed09c3-e551-4c24-b612-e619abe9b534"
        pub_key_ref = ("http://localhost:9311/v1/secrets/" + public_key_id)
        private_key_id = "32a0bc60-4e10-4269-9f17-f49767e99586"
        priv_key_ref = ("http://localhost:9311/v1/secrets/" + private_key_id)
        container.secret_refs = {'public_key': pub_key_ref,
                                 'private_key': priv_key_ref}
        self.mock_barbican.containers.get.return_value = container

        # Create the keys, get the UUIDs
        returned_private_uuid, returned_public_uuid = (
            self.key_mgr.create_key_pair(self.ctxt,
                                         algorithm='RSA',
                                         length=2048))

        self.mock_barbican.orders.get.assert_called_once_with(order_ref_url)
        self.mock_barbican.containers.get.assert_called_once_with(
            container_ref)

        self.mock_barbican.orders.get.assert_called_once_with(order_ref_url)
        self.assertEqual(private_key_id, returned_private_uuid)
        self.assertEqual(public_key_id, returned_public_uuid)

    def test_create_key_pair_null_context(self):
        self.key_mgr._barbican_client = None
        self.assertRaises(exception.Forbidden,
                          self.key_mgr.create_key_pair, None, 'RSA', 2048)

    def test_create_key_pair_with_error(self):
        asym_order = mock.Mock()
        self.mock_barbican.orders.create_asymmetric.return_value = asym_order
        asym_order.submit = mock.Mock(
            side_effect=barbican_exceptions.HTTPClientError('test error'))
        self.assertRaises(exception.KeyManagerError,
                          self.key_mgr.create_key_pair, self.ctxt, 'RSA', 2048)

    def test_delete_null_context(self):
        self.key_mgr._barbican_client = None
        self.assertRaises(exception.Forbidden,
                          self.key_mgr.delete, None, self.key_id)

    def test_delete_key(self):
        self.key_mgr.delete(self.ctxt, self.key_id)
        self.delete.assert_called_once_with(self.secret_ref)

    def test_delete_unknown_key(self):
        self.assertRaises(exception.KeyManagerError,
                          self.key_mgr.delete, self.ctxt, None)

    def test_delete_with_error(self):
        self.mock_barbican.secrets.delete = mock.Mock(
            side_effect=barbican_exceptions.HTTPClientError('test error'))
        self.assertRaises(exception.KeyManagerError,
                          self.key_mgr.delete, self.ctxt, self.key_id)

    def test_get_key(self):
        original_secret_metadata = mock.Mock()
        original_secret_metadata.algorithm = mock.sentinel.alg
        original_secret_metadata.bit_length = mock.sentinel.bit
        original_secret_metadata.secret_type = 'symmetric'

        key_id = "43ed09c3-e551-4c24-b612-e619abe9b534"
        key_ref = ("http://localhost:9311/v1/secrets/" + key_id)
        original_secret_metadata.secret_ref = key_ref

        created = timeutils.parse_isotime('2015-10-20 18:51:17+00:00')
        original_secret_metadata.created = created
        created_formatted = timeutils.parse_isotime(str(created))
        created_posix = calendar.timegm(created_formatted.timetuple())

        key_name = 'my key'
        original_secret_metadata.name = key_name

        original_secret_data = b'test key'
        original_secret_metadata.payload = original_secret_data

        self.mock_barbican.secrets.get.return_value = original_secret_metadata
        key = self.key_mgr.get(self.ctxt, self.key_id)

        self.get.assert_called_once_with(self.secret_ref)
        self.assertEqual(key_id, key.id)
        self.assertEqual(key_name, key.name)
        self.assertEqual(original_secret_data, key.get_encoded())
        self.assertEqual(created_posix, key.created)

    def test_get_null_context(self):
        self.key_mgr._barbican_client = None
        self.assertRaises(exception.Forbidden,
                          self.key_mgr.get, None, self.key_id)

    def test_get_unknown_key(self):
        self.assertRaises(exception.KeyManagerError,
                          self.key_mgr.get, self.ctxt, None)

    def test_get_with_error(self):
        self.mock_barbican.secrets.get = mock.Mock(
            side_effect=barbican_exceptions.HTTPClientError('test error'))
        self.assertRaises(exception.KeyManagerError,
                          self.key_mgr.get, self.ctxt, self.key_id)

    def test_store_key(self):
        # Create Key to store
        secret_key = bytes(b'\x01\x02\xA0\xB3')
        key_length = len(secret_key) * 8
        _key = sym_key.SymmetricKey('AES',
                                    key_length,
                                    secret_key)

        # Define the return values
        secret = mock.Mock()
        self.create.return_value = secret
        secret.store.return_value = self.secret_ref

        # Store the Key
        returned_uuid = self.key_mgr.store(self.ctxt, _key)

        self.create.assert_called_once_with(algorithm='AES',
                                            bit_length=key_length,
                                            name=None,
                                            payload=secret_key,
                                            secret_type='symmetric')
        self.assertEqual(self.key_id, returned_uuid)

    def test_store_key_with_name(self):
        # Create Key to store
        secret_key = bytes(b'\x01\x02\xA0\xB3')
        key_length = len(secret_key) * 8
        secret_name = 'My Secret'
        _key = sym_key.SymmetricKey('AES',
                                    key_length,
                                    secret_key,
                                    secret_name)

        # Define the return values
        secret = mock.Mock()
        self.create.return_value = secret
        secret.store.return_value = self.secret_ref

        # Store the Key
        returned_uuid = self.key_mgr.store(self.ctxt, _key)

        self.create.assert_called_once_with(algorithm='AES',
                                            bit_length=key_length,
                                            payload=secret_key,
                                            name=secret_name,
                                            secret_type='symmetric')
        self.assertEqual(self.key_id, returned_uuid)

    def test_store_null_context(self):
        self.key_mgr._barbican_client = None
        self.assertRaises(exception.Forbidden,
                          self.key_mgr.store, None, None)

    def test_store_with_error(self):
        self.mock_barbican.secrets.create = mock.Mock(
            side_effect=barbican_exceptions.HTTPClientError('test error'))
        secret_key = bytes(b'\x01\x02\xA0\xB3')
        key_length = len(secret_key) * 8
        _key = sym_key.SymmetricKey('AES',
                                    key_length,
                                    secret_key)
        self.assertRaises(exception.KeyManagerError,
                          self.key_mgr.store, self.ctxt, _key)

    def test_get_active_order(self):
        order_ref_url = ("http://localhost:9311/v1/orders/"
                         "4fe939b7-72bc-49aa-bd1e-e979589858af")

        pending_order = mock.Mock()
        pending_order.status = 'PENDING'
        pending_order.order_ref = order_ref_url

        active_order = mock.Mock()
        active_order.secret_ref = self.secret_ref
        active_order.status = 'ACTIVE'
        active_order.order_ref = order_ref_url

        self.mock_barbican.orders.get.side_effect = [pending_order,
                                                     active_order]

        self.key_mgr._get_active_order(self.mock_barbican, order_ref_url)

        self.assertEqual(2, self.mock_barbican.orders.get.call_count)

        calls = [mock.call(order_ref_url), mock.call(order_ref_url)]
        self.mock_barbican.orders.get.assert_has_calls(calls)

    def test_get_active_order_timeout(self):
        order_ref_url = ("http://localhost:9311/v1/orders/"
                         "4fe939b7-72bc-49aa-bd1e-e979589858af")

        number_of_retries = self.key_mgr.conf.barbican.number_of_retries

        pending_order = mock.Mock()
        pending_order.status = 'PENDING'
        pending_order.order_ref = order_ref_url

        self.mock_barbican.orders.get.return_value = pending_order

        self.assertRaises(exception.KeyManagerError,
                          self.key_mgr._get_active_order,
                          self.mock_barbican,
                          order_ref_url)

        self.assertEqual(number_of_retries + 1,
                         self.mock_barbican.orders.get.call_count)

    def test_get_active_order_error(self):
        order_ref_url = ("http://localhost:9311/v1/orders/"
                         "4fe939b7-72bc-49aa-bd1e-e979589858af")

        error_order = mock.Mock()
        error_order.status = 'ERROR'
        error_order.order_ref = order_ref_url
        error_order.error_status_code = u"500"
        error_order.error_reason = u"Test Error"

        self.mock_barbican.orders.get.return_value = error_order

        self.assertRaises(exception.KeyManagerError,
                          self.key_mgr._get_active_order,
                          self.mock_barbican,
                          order_ref_url)

        self.assertEqual(1, self.mock_barbican.orders.get.call_count)

    def test_list_null_context(self):
        self.key_mgr._barbican_client = None
        self.assertRaises(exception.Forbidden,
                          self.key_mgr.list, None)

    def test_list(self):
        original_secret_metadata = mock.Mock()
        original_secret_metadata.algorithm = mock.sentinel.alg
        original_secret_metadata.bit_length = mock.sentinel.bit
        original_secret_metadata.secret_type = 'symmetric'

        key_id = "43ed09c3-e551-4c24-b612-e619abe9b534"
        key_ref = ("http://localhost:9311/v1/secrets/" + key_id)
        original_secret_metadata.secret_ref = key_ref

        created = timeutils.parse_isotime('2015-10-20 18:51:17+00:00')
        original_secret_metadata.created = created
        created_formatted = timeutils.parse_isotime(str(created))
        created_posix = calendar.timegm(created_formatted.timetuple())

        key_name = 'my key'
        original_secret_metadata.name = key_name

        original_secret_data = b'test key'
        original_secret_metadata.payload = original_secret_data

        self.mock_barbican.secrets.list.return_value = (
            [original_secret_metadata])

        # check metadata_only = False
        key_list = self.key_mgr.list(self.ctxt)
        self.assertEqual(1, len(key_list))
        key = key_list[0]

        self.list.assert_called_once()
        self.assertEqual(key_id, key.id)
        self.assertEqual(key_name, key.name)
        self.assertEqual(original_secret_data, key.get_encoded())
        self.assertEqual(created_posix, key.created)

        self.list.reset_mock()

        # check metadata_only = True
        key_list = self.key_mgr.list(self.ctxt, metadata_only=True)
        self.assertEqual(1, len(key_list))
        key = key_list[0]

        self.list.assert_called_once()
        self.assertEqual(key_name, key.name)
        self.assertIsNone(key.get_encoded())
        self.assertEqual(created_posix, key.created)

    def test_list_with_error(self):
        self.mock_barbican.secrets.list = mock.Mock(
            side_effect=barbican_exceptions.HTTPClientError('test error'))
        self.assertRaises(exception.KeyManagerError,
                          self.key_mgr.list, self.ctxt)

    def test_list_with_invalid_object_type(self):
        self.assertRaises(exception.KeyManagerError,
                          self.key_mgr.list, self.ctxt, "invalid_type")

    def test_list_options_for_discovery(self):
        opts = self.key_mgr.list_options_for_discovery()
        expected_sections = ['barbican', 'barbican_service_user']
        self.assertEqual(expected_sections, [section[0] for section in opts])
        barbican_opts = [opt.name for opt in opts[0][1]]
        # From Castellan opts.
        self.assertIn('barbican_endpoint', barbican_opts)
        barbican_service_user_opts = [opt.name for opt in opts[1][1]]
        # From session opts.
        self.assertIn('cafile', barbican_service_user_opts)
        # From auth common opts.
        self.assertIn('auth_section', barbican_service_user_opts)
