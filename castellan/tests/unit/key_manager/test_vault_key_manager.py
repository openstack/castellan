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

import os
import tempfile

import requests_mock

from castellan.common import exception
from castellan.key_manager import vault_key_manager
from castellan.tests.unit.key_manager import test_key_manager


class VaultKeyManagerTestCase(test_key_manager.KeyManagerTestCase):
    def _create_key_manager(self):
        return vault_key_manager.VaultKeyManager(self.conf)

    def _create_sa_token_file(self, content="fake-sa-jwt-token"):
        """Create a temporary SA token file and register cleanup."""
        token_file = tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.token',
            delete=False,
        )
        token_file.write(content)
        token_file.close()
        self.addCleanup(os.unlink, token_file.name)
        return token_file.name

    def _setup_token_auth(
        self,
        auth_method="kubernetes",
        role="my-role",
        token_content="fake-sa-jwt-token",
        auth_path=None,
    ):
        """Configure the key manager for token-based auth."""
        self.key_mgr._auth_method = auth_method
        self.key_mgr._token_role = role
        self.key_mgr._token_file = self._create_sa_token_file(token_content)
        self.key_mgr._auth_path = auth_path or auth_method

    def test_auth_headers_root_token(self):
        self.key_mgr._root_token_id = "spam"
        expected_headers = {"X-Vault-Token": "spam"}
        self.assertEqual(expected_headers, self.key_mgr._build_auth_headers())

    def test_auth_headers_root_token_with_namespace(self):
        self.key_mgr._root_token_id = "spam"
        self.key_mgr._namespace = "ham"
        expected_headers = {
            "X-Vault-Token": "spam",
            "X-Vault-Namespace": "ham",
        }
        self.assertEqual(expected_headers, self.key_mgr._build_auth_headers())

    @requests_mock.Mocker()
    def test_auth_headers_app_role(self, m):
        self.key_mgr._approle_role_id = "spam"
        self.key_mgr._approle_secret_id = "secret"
        m.post(
            "http://127.0.0.1:8200/v1/auth/approle/login",
            json={"auth": {"client_token": "token", "lease_duration": 3600}},
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
            json={"auth": {"client_token": "token", "lease_duration": 3600}},
        )
        expected_headers = {
            "X-Vault-Token": "token",
            "X-Vault-Namespace": "ham",
        }
        self.assertEqual(expected_headers, self.key_mgr._build_auth_headers())

    @requests_mock.Mocker()
    def test_auth_headers_app_role_token_caching(self, m):
        """Verify that the AppRole token is cached and reused."""
        self.key_mgr._approle_role_id = "spam"
        self.key_mgr._approle_secret_id = "secret"
        m.post(
            "http://127.0.0.1:8200/v1/auth/approle/login",
            json={"auth": {"client_token": "token", "lease_duration": 3600}},
        )
        headers1 = self.key_mgr._build_auth_headers()
        headers2 = self.key_mgr._build_auth_headers()
        self.assertEqual(headers1, headers2)
        self.assertEqual({"X-Vault-Token": "token"}, headers2)
        self.assertEqual(1, m.call_count)

    @requests_mock.Mocker()
    def test_auth_headers_token_file(self, m):
        self._setup_token_auth()
        m.post(
            "http://127.0.0.1:8200/v1/auth/kubernetes/login",
            json={
                "auth": {
                    "client_token": "k8s-token",
                    "lease_duration": 1800,
                },
            },
        )
        expected_headers = {"X-Vault-Token": "k8s-token"}
        self.assertEqual(expected_headers, self.key_mgr._build_auth_headers())
        # Verify the request body
        self.assertEqual(
            m.last_request.json(),
            {"role": "my-role", "jwt": "fake-sa-jwt-token"},
        )

    @requests_mock.Mocker()
    def test_auth_headers_token_file_custom_path(self, m):
        self._setup_token_auth(auth_method="jwt")
        m.post(
            "http://127.0.0.1:8200/v1/auth/jwt/login",
            json={
                "auth": {
                    "client_token": "jwt-token",
                    "lease_duration": 900,
                },
            },
        )
        expected_headers = {"X-Vault-Token": "jwt-token"}
        self.assertEqual(expected_headers, self.key_mgr._build_auth_headers())

    @requests_mock.Mocker()
    def test_auth_headers_token_file_with_namespace(self, m):
        self._setup_token_auth()
        self.key_mgr._namespace = "my-namespace"
        m.post(
            "http://127.0.0.1:8200/v1/auth/kubernetes/login",
            json={
                "auth": {
                    "client_token": "k8s-ns-token",
                    "lease_duration": 1800,
                },
            },
        )
        expected_headers = {
            "X-Vault-Token": "k8s-ns-token",
            "X-Vault-Namespace": "my-namespace",
        }
        self.assertEqual(expected_headers, self.key_mgr._build_auth_headers())

    def test_auth_headers_token_file_missing(self):
        self.key_mgr._auth_method = 'kubernetes'
        self.key_mgr._token_role = "my-role"
        self.key_mgr._auth_path = "kubernetes"
        self.key_mgr._token_file = "/nonexistent/path/token"
        self.assertRaises(
            exception.KeyManagerError, self.key_mgr._build_auth_headers
        )

    @requests_mock.Mocker()
    def test_auth_headers_token_file_forbidden(self, m):
        self._setup_token_auth(role="bad-role")
        m.post(
            "http://127.0.0.1:8200/v1/auth/kubernetes/login",
            status_code=403,
        )
        self.assertRaises(
            exception.Forbidden, self.key_mgr._build_auth_headers
        )

    @requests_mock.Mocker()
    def test_auth_headers_token_file_bad_request(self, m):
        self._setup_token_auth()
        m.post(
            "http://127.0.0.1:8200/v1/auth/kubernetes/login",
            status_code=400,
            json={"errors": ["missing role", "invalid jwt"]},
        )
        self.assertRaises(
            exception.KeyManagerError, self.key_mgr._build_auth_headers
        )

    @requests_mock.Mocker()
    def test_auth_headers_token_file_caching(self, m):
        """Verify that the token from file-based auth is cached and reused."""
        self._setup_token_auth()
        m.post(
            "http://127.0.0.1:8200/v1/auth/kubernetes/login",
            json={
                "auth": {
                    "client_token": "cached-token",
                    "lease_duration": 3600,
                },
            },
        )
        # First call -- authenticates
        headers1 = self.key_mgr._build_auth_headers()
        # Second call -- should use cached token
        headers2 = self.key_mgr._build_auth_headers()
        self.assertEqual(headers1, headers2)
        self.assertEqual({"X-Vault-Token": "cached-token"}, headers2)
        # Only one HTTP request should have been made
        self.assertEqual(1, m.call_count)

    def test_auth_priority_root_over_token_file(self):
        """Root token takes priority over token file auth."""
        self.key_mgr._root_token_id = "root-token"
        self.key_mgr._auth_method = 'kubernetes'
        self.key_mgr._token_role = "my-role"
        expected_headers = {"X-Vault-Token": "root-token"}
        self.assertEqual(expected_headers, self.key_mgr._build_auth_headers())

    @requests_mock.Mocker()
    def test_auth_priority_root_over_approle(self, m):
        """Root token takes priority over AppRole auth."""
        self.key_mgr._root_token_id = "root-token"
        self.key_mgr._approle_role_id = "app-role"
        expected_headers = {"X-Vault-Token": "root-token"}
        self.assertEqual(expected_headers, self.key_mgr._build_auth_headers())

    def test_auth_token_missing_role(self):
        """auth_method=kubernetes without token_role raises error."""
        self.key_mgr._auth_method = 'kubernetes'
        self.key_mgr._auth_path = 'kubernetes'
        self.assertRaises(
            exception.KeyManagerError, self.key_mgr._build_auth_headers
        )

    @requests_mock.Mocker()
    def test_auth_headers_token_file_custom_auth_path(self, m):
        """auth_path overrides auth_method in the login URL."""
        self._setup_token_auth(
            auth_method="kubernetes",
            auth_path="kubernetes-my-custom-cluster",
        )
        m.post(
            "http://127.0.0.1:8200/v1/auth/kubernetes-my-custom-cluster/login",
            json={
                "auth": {
                    "client_token": "custom-token",
                    "lease_duration": 1800,
                },
            },
        )
        expected_headers = {"X-Vault-Token": "custom-token"}
        self.assertEqual(expected_headers, self.key_mgr._build_auth_headers())

    def test_auth_token_missing_token_file(self):
        """auth_method=kubernetes without token_file raises error."""
        self.key_mgr._auth_method = 'kubernetes'
        self.key_mgr._auth_path = 'kubernetes'
        self.key_mgr._token_role = "my-role"
        self.key_mgr._token_file = None
        self.assertRaises(
            exception.KeyManagerError, self.key_mgr._build_auth_headers
        )

    def test_auth_approle_no_role_id_returns_empty(self):
        """auth_method=approle without approle_role_id returns empty."""
        self.key_mgr._auth_method = 'approle'
        self.assertEqual({}, self.key_mgr._build_auth_headers())
