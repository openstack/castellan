# Copyright (c) 2021 Mirantis Inc
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
Test cases for Vault key manager.
"""
import requests_mock

from castellan.key_manager import vault_key_manager
from castellan.tests.unit.key_manager import test_key_manager


class VaultKeyManagerTestCase(test_key_manager.KeyManagerTestCase):

    def _create_key_manager(self):
        return vault_key_manager.VaultKeyManager(self.conf)

    def test_auth_headers_root_token(self):
        self.key_mgr._root_token_id = "spam"
        expected_headers = {"X-Vault-Token": "spam"}
        self.assertEqual(expected_headers,
                         self.key_mgr._build_auth_headers())

    def test_auth_headers_root_token_with_namespace(self):
        self.key_mgr._root_token_id = "spam"
        self.key_mgr._namespace = "ham"
        expected_headers = {"X-Vault-Token": "spam",
                            "X-Vault-Namespace": "ham"}
        self.assertEqual(expected_headers,
                         self.key_mgr._build_auth_headers())

    @requests_mock.Mocker()
    def test_auth_headers_app_role(self, m):
        self.key_mgr._approle_role_id = "spam"
        self.key_mgr._approle_secret_id = "secret"
        m.post(
            "http://127.0.0.1:8200/v1/auth/approle/login",
            json={"auth": {"client_token": "token", "lease_duration": 3600}}
        )
        expected_headers = {"X-Vault-Token": "token"}
        self.assertEqual(expected_headers, self.key_mgr._build_auth_headers())

    @requests_mock.Mocker()
    def test_auth_headers_app_role_with_namespace(self, m):
        self.key_mgr._approle_role_id = "spam"
        self.key_mgr._approle_secret_id = "secret"
        self.key_mgr._namespace = "ham"
        m.post(
            "http://127.0.0.1:8200/v1/auth/approle/login",
            json={"auth": {"client_token": "token", "lease_duration": 3600}}
        )
        expected_headers = {"X-Vault-Token": "token",
                            "X-Vault-Namespace": "ham"}
        self.assertEqual(expected_headers, self.key_mgr._build_auth_headers())
