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

from castellan.key_manager import barbican_key_manager as bkm
from castellan import options
from castellan.tests import base


class TestOptions(base.TestCase):

    def test_set_defaults(self):
        conf = cfg.ConfigOpts()

        api_class = 'test.api.class'
        options.set_defaults(conf, api_class=api_class)
        self.assertEqual(api_class, conf.key_manager.api_class)

        barbican_endpoint = 'http://test-server.org:9311/'
        options.set_defaults(conf, barbican_endpoint=barbican_endpoint)
        self.assertEqual(barbican_endpoint,
                         conf.get(bkm.BARBICAN_OPT_GROUP).barbican_endpoint)

        barbican_api_version = 'vSomething'
        options.set_defaults(conf, barbican_api_version=barbican_api_version)
        self.assertEqual(barbican_api_version,
                         conf.get(bkm.BARBICAN_OPT_GROUP).barbican_api_version)

        auth_endpoint = 'http://test-server.org/identity'
        options.set_defaults(conf, auth_endpoint=auth_endpoint)
        self.assertEqual(auth_endpoint,
                         conf.get(bkm.BARBICAN_OPT_GROUP).auth_endpoint)

        retry_delay = 3
        options.set_defaults(conf, retry_delay=retry_delay)
        self.assertEqual(retry_delay,
                         conf.get(bkm.BARBICAN_OPT_GROUP).retry_delay)

        number_of_retries = 10
        options.set_defaults(conf, number_of_retries=number_of_retries)
        self.assertEqual(number_of_retries,
                         conf.get(bkm.BARBICAN_OPT_GROUP).number_of_retries)

        verify_ssl = True
        options.set_defaults(conf, verify_ssl=True)
        self.assertEqual(verify_ssl,
                         conf.get(bkm.BARBICAN_OPT_GROUP).verify_ssl)
