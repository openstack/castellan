# Copyright (c) 2015 Red Hat, Inc.
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

from oslo_config import cfg

from castellan import key_manager
from castellan.key_manager import barbican_key_manager as bkm
from castellan import options
from castellan.tests import base
from castellan.tests.unit.key_manager import mock_key_manager


class TestOptions(base.TestCase):

    def test_set_defaults(self):
        conf = cfg.ConfigOpts()

        self.assertTrue(isinstance(key_manager.API(conf),
                                   bkm.BarbicanKeyManager))

        cls = mock_key_manager.MockKeyManager
        backend = '%s.%s' % (cls.__module__, cls.__name__)
        options.set_defaults(conf, backend=backend)
        self.assertEqual(backend, conf.key_manager.backend)
        self.assertIsInstance(key_manager.API(conf),
                              mock_key_manager.MockKeyManager)

        barbican_endpoint = 'http://test-server.org:9311/'
        options.set_defaults(conf, barbican_endpoint=barbican_endpoint)
        self.assertEqual(barbican_endpoint,
                         conf.barbican.barbican_endpoint)

        barbican_api_version = 'vSomething'
        options.set_defaults(conf, barbican_api_version=barbican_api_version)
        self.assertEqual(barbican_api_version,
                         conf.barbican.barbican_api_version)

        auth_endpoint = 'http://test-server.org/identity'
        options.set_defaults(conf, auth_endpoint=auth_endpoint)
        self.assertEqual(auth_endpoint,
                         conf.barbican.auth_endpoint)

        retry_delay = 3
        options.set_defaults(conf, retry_delay=retry_delay)
        self.assertEqual(retry_delay,
                         conf.barbican.retry_delay)

        number_of_retries = 10
        options.set_defaults(conf, number_of_retries=number_of_retries)
        self.assertEqual(number_of_retries,
                         conf.barbican.number_of_retries)

        verify_ssl = False
        options.set_defaults(conf, verify_ssl=False)
        self.assertEqual(verify_ssl,
                         conf.barbican.verify_ssl)

        verify_ssl_path = '/mnt'
        options.set_defaults(conf, verify_ssl_path='/mnt')
        self.assertEqual(verify_ssl_path,
                         conf.barbican.verify_ssl_path)

        barbican_endpoint_type = 'internal'
        options.set_defaults(conf, barbican_endpoint_type='internal')
        result_type = conf.barbican.barbican_endpoint_type
        self.assertEqual(barbican_endpoint_type, result_type)
