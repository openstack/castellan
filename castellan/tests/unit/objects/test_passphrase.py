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
Test cases for the passphrase class.
"""
from castellan.common.objects import passphrase
from castellan.tests import base


class PassphraseTestCase(base.TestCase):

    def _create_passphrase(self):
        return passphrase.Passphrase(self.passphrase_data,
                                     self.name,
                                     self.created)

    def setUp(self):
        self.passphrase_data = bytes(b"secret passphrase")
        self.name = 'my phrase'
        self.created = 1448088699
        self.passphrase = self._create_passphrase()

        super(PassphraseTestCase, self).setUp()

    def test_is_not_only_metadata(self):
        self.assertFalse(self.passphrase.is_metadata_only())

    def test_is_only_metadata(self):
        p = passphrase.Passphrase(None, self.name, self.created)
        self.assertTrue(p.is_metadata_only())

    def test_get_format(self):
        self.assertEqual('RAW', self.passphrase.format)

    def test_get_encoded(self):
        self.assertEqual(self.passphrase_data, self.passphrase.get_encoded())

    def test_get_name(self):
        self.assertEqual(self.name, self.passphrase.name)

    def test_get_created(self):
        self.assertEqual(self.created, self.passphrase.created)

    def test_get_created_none(self):
        created = None
        phrase = passphrase.Passphrase(self.passphrase_data,
                                       self.name,
                                       created)

        self.assertEqual(created, phrase.created)

    def test___eq__(self):
        self.assertTrue(self.passphrase == self.passphrase)
        self.assertTrue(self.passphrase is self.passphrase)

        self.assertFalse(self.passphrase is None)
        self.assertFalse(None == self.passphrase)  # noqa: E711

        other_passphrase = passphrase.Passphrase(self.passphrase_data)
        self.assertTrue(self.passphrase == other_passphrase)
        self.assertFalse(self.passphrase is other_passphrase)

    def test___ne___none(self):
        self.assertTrue(self.passphrase is not None)
        self.assertTrue(None != self.passphrase)  # noqa: E711

    def test___ne___data(self):
        other_phrase = passphrase.Passphrase(b"other passphrase", self.name)
        self.assertTrue(self.passphrase != other_phrase)
