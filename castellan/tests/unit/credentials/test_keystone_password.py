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
Test cases for the keystone password credential
"""

from castellan.common.credentials import keystone_password
from castellan.tests import base


class KeystonePasswordTestCase(base.TestCase):

    def _create_ks_password_credential(self):
        return keystone_password.KeystonePassword(
            self.password,
            username=self.username,
            user_id=self.user_id,
            user_domain_id=self.user_domain_id,
            user_domain_name=self.user_domain_name,
            trust_id=self.trust_id,
            domain_id=self.domain_id,
            domain_name=self.domain_name,
            project_id=self.project_id,
            project_name=self.project_name,
            project_domain_id=self.project_domain_id,
            project_domain_name=self.project_domain_name,
            reauthenticate=self.reauthenticate)

    def setUp(self):
        self.password = "Pa$$w0rd1",
        self.username = "admin",
        self.user_id = "1adb2391c009443aa5224b316d4a06ae",
        self.user_domain_id = "default",
        self.user_domain_name = "default",
        self.trust_id = "14b38a8296f144148138466ce9280940",
        self.domain_id = "default",
        self.domain_name = "default",
        self.project_id = "1099302ec608486f9879ba2466c60720",
        self.project_name = "demo",
        self.project_domain_id = "default",
        self.project_domain_name = "default",
        self.reauthenticate = True

        self.ks_password_credential = self._create_ks_password_credential()

        super(KeystonePasswordTestCase, self).setUp()

    def test_get_password(self):
        self.assertEqual(self.password,
                         self.ks_password_credential.password)

    def test_get_username(self):
        self.assertEqual(self.username,
                         self.ks_password_credential.username)

    def test_get_user_id(self):
        self.assertEqual(self.user_id,
                         self.ks_password_credential.user_id)

    def test_get_user_domain_id(self):
        self.assertEqual(self.user_domain_id,
                         self.ks_password_credential.user_domain_id)

    def test_get_user_domain_name(self):
        self.assertEqual(self.user_domain_name,
                         self.ks_password_credential.user_domain_name)

    def test_get_trust_id(self):
        self.assertEqual(self.trust_id,
                         self.ks_password_credential.trust_id)

    def test_get_domain_id(self):
        self.assertEqual(self.domain_id,
                         self.ks_password_credential.domain_id)

    def test_get_domain_name(self):
        self.assertEqual(self.domain_name,
                         self.ks_password_credential.domain_name)

    def test_get_project_id(self):
        self.assertEqual(self.project_id,
                         self.ks_password_credential.project_id)

    def test_get_project_name(self):
        self.assertEqual(self.project_name,
                         self.ks_password_credential.project_name)

    def test_get_project_domain_id(self):
        self.assertEqual(self.project_domain_id,
                         self.ks_password_credential.project_domain_id)

    def test_get_project_domain_name(self):
        self.assertEqual(self.project_domain_name,
                         self.ks_password_credential.project_domain_name)

    def test_get_reauthenticate(self):
        self.assertEqual(self.reauthenticate,
                         self.ks_password_credential.reauthenticate)

    def test___eq__(self):
        self.assertTrue(self.ks_password_credential ==
                        self.ks_password_credential)
        self.assertTrue(self.ks_password_credential is
                        self.ks_password_credential)

        self.assertFalse(self.ks_password_credential is None)
        self.assertFalse(None == self.ks_password_credential)  # noqa: E711

        other_ks_password_credential = keystone_password.KeystonePassword(
            self.password,
            username=self.username,
            user_id=self.user_id,
            user_domain_id=self.user_domain_id,
            user_domain_name=self.user_domain_name,
            trust_id=self.trust_id,
            domain_id=self.domain_id,
            domain_name=self.domain_name,
            project_id=self.project_id,
            project_name=self.project_name,
            project_domain_id=self.project_domain_id,
            project_domain_name=self.project_domain_name,
            reauthenticate=self.reauthenticate)
        self.assertTrue(self.ks_password_credential ==
                        other_ks_password_credential)
        self.assertFalse(self.ks_password_credential is
                         other_ks_password_credential)

    def test___ne___none(self):
        self.assertTrue(self.ks_password_credential is not None)
        self.assertTrue(None != self.ks_password_credential)  # noqa: E711

    def test___ne___password(self):
        other_password = "wheresmyCat??"

        other_ks_password_credential = keystone_password.KeystonePassword(
            other_password,
            username=self.username,
            user_id=self.user_id,
            user_domain_id=self.user_domain_id,
            user_domain_name=self.user_domain_name,
            trust_id=self.trust_id,
            domain_id=self.domain_id,
            domain_name=self.domain_name,
            project_id=self.project_id,
            project_name=self.project_name,
            project_domain_id=self.project_domain_id,
            project_domain_name=self.project_domain_name,
            reauthenticate=self.reauthenticate)

        self.assertTrue(self.ks_password_credential !=
                        other_ks_password_credential)

    def test___ne___username(self):
        other_username = "service"

        other_ks_password_credential = keystone_password.KeystonePassword(
            self.password,
            username=other_username,
            user_id=self.user_id,
            user_domain_id=self.user_domain_id,
            user_domain_name=self.user_domain_name,
            trust_id=self.trust_id,
            domain_id=self.domain_id,
            domain_name=self.domain_name,
            project_id=self.project_id,
            project_name=self.project_name,
            project_domain_id=self.project_domain_id,
            project_domain_name=self.project_domain_name,
            reauthenticate=self.reauthenticate)

        self.assertTrue(self.ks_password_credential !=
                        other_ks_password_credential)

    def test___ne___user_id(self):
        other_user_id = "service"

        other_ks_password_credential = keystone_password.KeystonePassword(
            self.password,
            username=self.username,
            user_id=other_user_id,
            user_domain_id=self.user_domain_id,
            user_domain_name=self.user_domain_name,
            trust_id=self.trust_id,
            domain_id=self.domain_id,
            domain_name=self.domain_name,
            project_id=self.project_id,
            project_name=self.project_name,
            project_domain_id=self.project_domain_id,
            project_domain_name=self.project_domain_name,
            reauthenticate=self.reauthenticate)

        self.assertTrue(self.ks_password_credential !=
                        other_ks_password_credential)

    def test___ne___user_domain_id(self):
        other_user_domain_id = "domain0"

        other_ks_password_credential = keystone_password.KeystonePassword(
            self.password,
            username=self.username,
            user_id=self.user_id,
            user_domain_id=other_user_domain_id,
            user_domain_name=self.user_domain_name,
            trust_id=self.trust_id,
            domain_id=self.domain_id,
            domain_name=self.domain_name,
            project_id=self.project_id,
            project_name=self.project_name,
            project_domain_id=self.project_domain_id,
            project_domain_name=self.project_domain_name,
            reauthenticate=self.reauthenticate)

        self.assertTrue(self.ks_password_credential !=
                        other_ks_password_credential)

    def test___ne___user_domain_name(self):
        other_user_domain_name = "domain0"

        other_ks_password_credential = keystone_password.KeystonePassword(
            self.password,
            username=self.username,
            user_id=self.user_id,
            user_domain_id=self.domain_id,
            user_domain_name=other_user_domain_name,
            trust_id=self.trust_id,
            domain_id=self.domain_id,
            domain_name=self.domain_name,
            project_id=self.project_id,
            project_name=self.project_name,
            project_domain_id=self.project_domain_id,
            project_domain_name=self.project_domain_name,
            reauthenticate=self.reauthenticate)

        self.assertTrue(self.ks_password_credential !=
                        other_ks_password_credential)

    def test___ne___trust_id(self):
        other_trust_id = "00000000000000"

        other_ks_password_credential = keystone_password.KeystonePassword(
            self.password,
            username=self.username,
            user_id=self.user_id,
            user_domain_id=self.user_domain_id,
            user_domain_name=self.user_domain_name,
            trust_id=other_trust_id,
            domain_id=self.domain_id,
            domain_name=self.domain_name,
            project_id=self.project_id,
            project_name=self.project_name,
            project_domain_id=self.project_domain_id,
            project_domain_name=self.project_domain_name,
            reauthenticate=self.reauthenticate)

        self.assertTrue(self.ks_password_credential !=
                        other_ks_password_credential)

    def test___ne___domain_id(self):
        other_domain_id = "domain0"

        other_ks_password_credential = keystone_password.KeystonePassword(
            self.password,
            username=self.username,
            user_id=self.user_id,
            user_domain_id=self.user_domain_id,
            user_domain_name=self.user_domain_name,
            trust_id=self.trust_id,
            domain_id=other_domain_id,
            domain_name=self.domain_name,
            project_id=self.project_id,
            project_name=self.project_name,
            project_domain_id=self.project_domain_id,
            project_domain_name=self.project_domain_name,
            reauthenticate=self.reauthenticate)

        self.assertTrue(self.ks_password_credential !=
                        other_ks_password_credential)

    def test___ne___domain_name(self):
        other_domain_name = "domain0"

        other_ks_password_credential = keystone_password.KeystonePassword(
            self.password,
            username=self.username,
            user_id=self.user_id,
            user_domain_id=self.user_domain_id,
            user_domain_name=self.user_domain_name,
            trust_id=self.trust_id,
            domain_id=self.domain_id,
            domain_name=other_domain_name,
            project_id=self.project_id,
            project_name=self.project_name,
            project_domain_id=self.project_domain_id,
            project_domain_name=self.project_domain_name,
            reauthenticate=self.reauthenticate)

        self.assertTrue(self.ks_password_credential !=
                        other_ks_password_credential)

    def test___ne___project_id(self):
        other_project_id = "00000000000000"

        other_ks_password_credential = keystone_password.KeystonePassword(
            self.password,
            username=self.username,
            user_id=self.user_id,
            user_domain_id=self.user_domain_id,
            user_domain_name=self.user_domain_name,
            trust_id=self.trust_id,
            domain_id=self.domain_id,
            domain_name=self.domain_name,
            project_id=other_project_id,
            project_name=self.project_name,
            project_domain_id=self.project_domain_id,
            project_domain_name=self.project_domain_name,
            reauthenticate=self.reauthenticate)

        self.assertTrue(self.ks_password_credential !=
                        other_ks_password_credential)

    def test___ne___project_name(self):
        other_project_name = "proj0"

        other_ks_password_credential = keystone_password.KeystonePassword(
            self.password,
            username=self.username,
            user_id=self.user_id,
            user_domain_id=self.user_domain_id,
            user_domain_name=self.user_domain_name,
            trust_id=self.trust_id,
            domain_id=self.domain_id,
            domain_name=self.domain_name,
            project_id=self.project_id,
            project_name=other_project_name,
            project_domain_id=self.project_domain_id,
            project_domain_name=self.project_domain_name,
            reauthenticate=self.reauthenticate)

        self.assertTrue(self.ks_password_credential !=
                        other_ks_password_credential)

    def test___ne___project_domain_id(self):
        other_project_domain_id = "domain0"

        other_ks_password_credential = keystone_password.KeystonePassword(
            self.password,
            username=self.username,
            user_id=self.user_id,
            user_domain_id=self.user_domain_id,
            user_domain_name=self.user_domain_name,
            trust_id=self.trust_id,
            domain_id=self.domain_id,
            domain_name=self.domain_name,
            project_id=self.project_id,
            project_name=self.project_name,
            project_domain_id=other_project_domain_id,
            project_domain_name=self.project_domain_name,
            reauthenticate=self.reauthenticate)

        self.assertTrue(self.ks_password_credential !=
                        other_ks_password_credential)

    def test___ne___project_domain_name(self):
        other_project_domain_name = "domain0"

        other_ks_password_credential = keystone_password.KeystonePassword(
            self.password,
            username=self.username,
            user_id=self.user_id,
            user_domain_id=self.user_domain_id,
            user_domain_name=self.user_domain_name,
            trust_id=self.trust_id,
            domain_id=self.domain_id,
            domain_name=self.domain_name,
            project_id=self.project_id,
            project_name=self.project_name,
            project_domain_id=self.project_domain_id,
            project_domain_name=other_project_domain_name,
            reauthenticate=self.reauthenticate)

        self.assertTrue(self.ks_password_credential !=
                        other_ks_password_credential)

    def test___ne___reauthenticate(self):
        other_reauthenticate = False

        other_ks_password_credential = keystone_password.KeystonePassword(
            self.password,
            username=self.username,
            user_id=self.user_id,
            user_domain_id=self.user_domain_id,
            user_domain_name=self.user_domain_name,
            trust_id=self.trust_id,
            domain_id=self.domain_id,
            domain_name=self.domain_name,
            project_id=self.project_id,
            project_name=self.project_name,
            project_domain_id=self.project_domain_id,
            project_domain_name=self.project_domain_name,
            reauthenticate=other_reauthenticate)

        self.assertTrue(self.ks_password_credential !=
                        other_ks_password_credential)
