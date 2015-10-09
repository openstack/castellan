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
Test cases for the private key class.
"""

from castellan.common.objects import private_key
from castellan.tests import base
from castellan.tests import utils


class PrivateKeyTestCase(base.KeyTestCase):

    def _create_key(self):
        return private_key.PrivateKey(self.algorithm,
                                      self.length,
                                      self.encoded,
                                      self.name)

    def setUp(self):
        self.algorithm = 'RSA'
        self.length = 2048
        self.encoded = bytes(utils.get_private_key_der())
        self.name = 'my key'

        super(PrivateKeyTestCase, self).setUp()

    def test_get_algorithm(self):
        self.assertEqual(self.algorithm, self.key.algorithm)

    def test_get_length(self):
        self.assertEqual(self.length, self.key.bit_length)

    def test_get_name(self):
        self.assertEqual(self.name, self.key.name)

    def test_get_format(self):
        self.assertEqual('PKCS8', self.key.format)

    def test_get_encoded(self):
        self.assertEqual(self.encoded, self.key.get_encoded())

    def test___eq__(self):
        self.assertTrue(self.key == self.key)
        self.assertTrue(self.key is self.key)

        self.assertFalse(self.key is None)
        self.assertFalse(None == self.key)

        other_key = private_key.PrivateKey(self.algorithm,
                                           self.length,
                                           self.encoded,
                                           self.name)
        self.assertTrue(self.key == other_key)
        self.assertFalse(self.key is other_key)

    def test___ne___none(self):
        self.assertTrue(self.key is not None)
        self.assertTrue(None != self.key)

    def test___ne___algorithm(self):
        other_key = private_key.PrivateKey('DSA',
                                           self.length,
                                           self.encoded,
                                           self.name)
        self.assertTrue(self.key != other_key)

    def test___ne___length(self):
        other_key = private_key.PrivateKey(self.algorithm,
                                           4096,
                                           self.encoded,
                                           self.name)
        self.assertTrue(self.key != other_key)

    def test___ne___encoded(self):
        different_encoded = bytes(utils.get_private_key_der()) + b'\x00'
        other_key = private_key.PrivateKey(self.algorithm,
                                           self.length,
                                           different_encoded,
                                           self.name)
        self.assertTrue(self.key != other_key)

    def test___ne___name(self):
        other_key = private_key.PrivateKey(self.algorithm,
                                           self.length,
                                           self.encoded,
                                           'other key')
        self.assertTrue(self.key != other_key)
