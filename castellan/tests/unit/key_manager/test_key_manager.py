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
Test cases for the key manager.
"""

from oslo_config import cfg
from oslo_config import fixture

from castellan import key_manager
from castellan.key_manager import barbican_key_manager
from castellan.tests import base

CONF = cfg.CONF


class KeyManagerTestCase(base.TestCase):

    def _create_key_manager(self):
        raise NotImplementedError()

    def setUp(self):
        super(KeyManagerTestCase, self).setUp()

        self.conf = self.useFixture(fixture.Config()).conf

        self.key_mgr = self._create_key_manager()


class DefaultKeyManagerImplTestCase(KeyManagerTestCase):

    def _create_key_manager(self):
        return key_manager.API(self.conf)

    def test_default_key_manager(self):
        self.assertEqual("barbican", self.conf.key_manager.backend)
        self.assertIsNotNone(self.key_mgr)
        self.assertIsInstance(self.key_mgr,
                              barbican_key_manager.BarbicanKeyManager)
