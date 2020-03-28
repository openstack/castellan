# Copyright (c) 2015 IBM
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
Test cases for the keystone token credential
"""

from castellan.common.credentials import keystone_token
from castellan.tests import base


class KeystoneTokenTestCase(base.TestCase):

    def _create_ks_token_credential(self):
        return keystone_token.KeystoneToken(
            self.token,
            trust_id=self.trust_id,
            domain_id=self.domain_id,
            domain_name=self.domain_name,
            project_id=self.project_id,
            project_name=self.project_name,
            project_domain_id=self.project_domain_id,
            project_domain_name=self.project_domain_name,
            reauthenticate=self.reauthenticate)

    def setUp(self):
        self.token = "8a4aa147d58141c39a7a22905b90ba4e",
        self.trust_id = "14b38a8296f144148138466ce9280940",
        self.domain_id = "default",
        self.domain_name = "default",
        self.project_id = "1099302ec608486f9879ba2466c60720",
        self.project_name = "demo",
        self.project_domain_id = "default",
        self.project_domain_name = "default",
        self.reauthenticate = True

        self.ks_token_credential = self._create_ks_token_credential()

        super(KeystoneTokenTestCase, self).setUp()

    def test_get_token(self):
        self.assertEqual(self.token,
                         self.ks_token_credential.token)

    def test_get_trust_id(self):
        self.assertEqual(self.trust_id,
                         self.ks_token_credential.trust_id)

    def test_get_domain_id(self):
        self.assertEqual(self.domain_id,
                         self.ks_token_credential.domain_id)

    def test_get_domain_name(self):
        self.assertEqual(self.domain_name,
                         self.ks_token_credential.domain_name)

    def test_get_project_id(self):
        self.assertEqual(self.project_id,
                         self.ks_token_credential.project_id)

    def test_get_project_name(self):
        self.assertEqual(self.project_name,
                         self.ks_token_credential.project_name)

    def test_get_project_domain_id(self):
        self.assertEqual(self.project_domain_id,
                         self.ks_token_credential.project_domain_id)

    def test_get_project_domain_name(self):
        self.assertEqual(self.project_domain_name,
                         self.ks_token_credential.project_domain_name)

    def test_get_reauthenticate(self):
        self.assertEqual(self.reauthenticate,
                         self.ks_token_credential.reauthenticate)

    def test___eq__(self):
        self.assertTrue(self.ks_token_credential ==
                        self.ks_token_credential)
        self.assertTrue(self.ks_token_credential is
                        self.ks_token_credential)

        self.assertFalse(self.ks_token_credential is None)
        self.assertFalse(None == self.ks_token_credential)  # noqa: E711

        other_ks_token_credential = keystone_token.KeystoneToken(
            self.token,
            trust_id=self.trust_id,
            domain_id=self.domain_id,
            domain_name=self.domain_name,
            project_id=self.project_id,
            project_name=self.project_name,
            project_domain_id=self.project_domain_id,
            project_domain_name=self.project_domain_name,
            reauthenticate=self.reauthenticate)
        self.assertTrue(self.ks_token_credential ==
                        other_ks_token_credential)
        self.assertFalse(self.ks_token_credential is
                         other_ks_token_credential)

    def test___ne___none(self):
        self.assertTrue(self.ks_token_credential is not None)
        self.assertTrue(None != self.ks_token_credential)  # noqa: E711

    def test___ne___token(self):
        other_token = "5c59e3217d3d4dd297589b297aee2a6f"

        other_ks_token_credential = keystone_token.KeystoneToken(
            other_token,
            trust_id=self.trust_id,
            domain_id=self.domain_id,
            domain_name=self.domain_name,
            project_id=self.project_id,
            project_name=self.project_name,
            project_domain_id=self.project_domain_id,
            project_domain_name=self.project_domain_name,
            reauthenticate=self.reauthenticate)

        self.assertTrue(self.ks_token_credential !=
                        other_ks_token_credential)

    def test___ne___trust_id(self):
        other_trust_id = "00000000000000"

        other_ks_token_credential = keystone_token.KeystoneToken(
            self.token,
            trust_id=other_trust_id,
            domain_id=self.domain_id,
            domain_name=self.domain_name,
            project_id=self.project_id,
            project_name=self.project_name,
            project_domain_id=self.project_domain_id,
            project_domain_name=self.project_domain_name,
            reauthenticate=self.reauthenticate)

        self.assertTrue(self.ks_token_credential !=
                        other_ks_token_credential)

    def test___ne___domain_id(self):
        other_domain_id = "domain0"

        other_ks_token_credential = keystone_token.KeystoneToken(
            self.token,
            trust_id=self.trust_id,
            domain_id=other_domain_id,
            domain_name=self.domain_name,
            project_id=self.project_id,
            project_name=self.project_name,
            project_domain_id=self.project_domain_id,
            project_domain_name=self.project_domain_name,
            reauthenticate=self.reauthenticate)

        self.assertTrue(self.ks_token_credential !=
                        other_ks_token_credential)

    def test___ne___domain_name(self):
        other_domain_name = "domain0"

        other_ks_token_credential = keystone_token.KeystoneToken(
            self.token,
            trust_id=self.trust_id,
            domain_id=self.domain_id,
            domain_name=other_domain_name,
            project_id=self.project_id,
            project_name=self.project_name,
            project_domain_id=self.project_domain_id,
            project_domain_name=self.project_domain_name,
            reauthenticate=self.reauthenticate)

        self.assertTrue(self.ks_token_credential !=
                        other_ks_token_credential)

    def test___ne___project_id(self):
        other_project_id = "00000000000000"

        other_ks_token_credential = keystone_token.KeystoneToken(
            self.token,
            trust_id=self.trust_id,
            domain_id=self.domain_id,
            domain_name=self.domain_name,
            project_id=other_project_id,
            project_name=self.project_name,
            project_domain_id=self.project_domain_id,
            project_domain_name=self.project_domain_name,
            reauthenticate=self.reauthenticate)

        self.assertTrue(self.ks_token_credential !=
                        other_ks_token_credential)

    def test___ne___project_name(self):
        other_project_name = "proj0"

        other_ks_token_credential = keystone_token.KeystoneToken(
            self.token,
            trust_id=self.trust_id,
            domain_id=self.domain_id,
            domain_name=self.domain_name,
            project_id=self.project_id,
            project_name=other_project_name,
            project_domain_id=self.project_domain_id,
            project_domain_name=self.project_domain_name,
            reauthenticate=self.reauthenticate)

        self.assertTrue(self.ks_token_credential !=
                        other_ks_token_credential)

    def test___ne___project_domain_id(self):
        other_project_domain_id = "domain0"

        other_ks_token_credential = keystone_token.KeystoneToken(
            self.token,
            trust_id=self.trust_id,
            domain_id=self.domain_id,
            domain_name=self.domain_name,
            project_id=self.project_id,
            project_name=self.project_name,
            project_domain_id=other_project_domain_id,
            project_domain_name=self.project_domain_name,
            reauthenticate=self.reauthenticate)

        self.assertTrue(self.ks_token_credential !=
                        other_ks_token_credential)

    def test___ne___project_domain_name(self):
        other_project_domain_name = "domain0"

        other_ks_token_credential = keystone_token.KeystoneToken(
            self.token,
            trust_id=self.trust_id,
            domain_id=self.domain_id,
            domain_name=self.domain_name,
            project_id=self.project_id,
            project_name=self.project_name,
            project_domain_id=self.project_domain_id,
            project_domain_name=other_project_domain_name,
            reauthenticate=self.reauthenticate)

        self.assertTrue(self.ks_token_credential !=
                        other_ks_token_credential)

    def test___ne___reauthenticate(self):
        other_reauthenticate = False

        other_ks_token_credential = keystone_token.KeystoneToken(
            self.token,
            trust_id=self.trust_id,
            domain_id=self.domain_id,
            domain_name=self.domain_name,
            project_id=self.project_id,
            project_name=self.project_name,
            project_domain_id=self.project_domain_id,
            project_domain_name=self.project_domain_name,
            reauthenticate=other_reauthenticate)

        self.assertTrue(self.ks_token_credential !=
                        other_ks_token_credential)
