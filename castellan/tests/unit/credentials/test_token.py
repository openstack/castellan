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
Test cases for the token credential
"""

from castellan.common.credentials import token
from castellan.tests import base


class TokenTestCase(base.TestCase):

    def _create_token_credential(self):
        return token.Token(self.token)

    def setUp(self):
        self.token = "8a4aa147d58141c39a7a22905b90ba4e"
        self.token_credential = self._create_token_credential()
        super(TokenTestCase, self).setUp()

    def test_get_token(self):
        self.assertEqual(self.token, self.token_credential.token)

    def test___eq__(self):
        self.assertTrue(self.token_credential == self.token_credential)
        self.assertTrue(self.token_credential is self.token_credential)

        self.assertFalse(self.token_credential is None)
        self.assertFalse(None == self.token_credential)  # noqa: E711

        other_token_credential = token.Token(self.token)
        self.assertTrue(self.token_credential == other_token_credential)
        self.assertFalse(self.token_credential is other_token_credential)

    def test___ne___none(self):
        self.assertTrue(self.token_credential is not None)
        self.assertTrue(None != self.token_credential)  # noqa: E711

    def test___ne___token(self):
        other_token = "fe32af1fe47e4744a48254e60ae80012"
        other_token_credential = token.Token(other_token)
        self.assertTrue(self.token_credential != other_token_credential)
