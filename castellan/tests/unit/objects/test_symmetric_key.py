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
Test cases for the symmetric key class.
"""
from castellan.common.objects import symmetric_key as sym_key
from castellan.tests import base


class SymmetricKeyTestCase(base.KeyTestCase):

    def _create_key(self):
        return sym_key.SymmetricKey(self.algorithm,
                                    self.bit_length,
                                    self.encoded,
                                    self.name,
                                    self.created)

    def setUp(self):
        self.algorithm = 'AES'
        self.encoded = bytes(b'0' * 64)
        self.bit_length = len(self.encoded) * 8
        self.name = 'my key'
        self.created = 1448088699

        super(SymmetricKeyTestCase, self).setUp()

    def test_is_not_only_metadata(self):
        self.assertFalse(self.key.is_metadata_only())

    def test_is_only_metadata(self):
        k = sym_key.SymmetricKey(self.algorithm,
                                 self.bit_length,
                                 None,
                                 self.name,
                                 self.created)
        self.assertTrue(k.is_metadata_only())

    def test_get_format(self):
        self.assertEqual('RAW', self.key.format)

    def test_get_name(self):
        self.assertEqual(self.name, self.key.name)

    def test_get_encoded(self):
        self.assertEqual(self.encoded, self.key.get_encoded())

    def test_get_algorithm(self):
        self.assertEqual(self.algorithm, self.key.algorithm)

    def test_get_bit_length(self):
        self.assertEqual(self.bit_length, self.key.bit_length)

    def test_get_created(self):
        self.assertEqual(self.created, self.key.created)

    def test_get_created_none(self):
        created = None
        key = sym_key.SymmetricKey(self.algorithm,
                                   self.bit_length,
                                   self.encoded,
                                   self.name,
                                   created)

        self.assertEqual(created, key.created)

    def test___eq__(self):
        self.assertTrue(self.key == self.key)
        self.assertTrue(self.key is self.key)

        self.assertFalse(self.key is None)
        self.assertFalse(None == self.key)  # noqa: E711

        other_key = sym_key.SymmetricKey(self.algorithm,
                                         self.bit_length,
                                         self.encoded)
        self.assertTrue(self.key == other_key)
        self.assertFalse(self.key is other_key)

    def test___ne___none(self):
        self.assertTrue(self.key is not None)
        self.assertTrue(None != self.key)  # noqa: E711

    def test___ne___algorithm(self):
        other_key = sym_key.SymmetricKey('DES',
                                         self.bit_length,
                                         self.encoded,
                                         self.name)
        self.assertTrue(self.key != other_key)

    def test___ne___bit_length(self):
        other_key = sym_key.SymmetricKey(self.algorithm,
                                         self.bit_length * 2,
                                         self.encoded,
                                         self.name)
        self.assertTrue(self.key != other_key)

    def test___ne___encoded(self):
        different_encoded = self.encoded * 2
        other_key = sym_key.SymmetricKey(self.algorithm,
                                         self.bit_length,
                                         different_encoded,
                                         self.name)
        self.assertTrue(self.key != other_key)
