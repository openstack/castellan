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
Test cases for the X.509 certificate class.
"""

from castellan.common.objects import x_509
from castellan.tests import base
from castellan.tests import utils


class X509TestCase(base.CertificateTestCase):

    def _create_cert(self):
        return x_509.X509(self.data, self.name)

    def setUp(self):
        self.data = utils.get_certificate_der()
        self.name = 'my cert'

        super(X509TestCase, self).setUp()

    def test_get_format(self):
        self.assertEqual('X.509', self.cert.format)

    def test_get_name(self):
        self.assertEqual(self.name, self.cert.name)

    def test_get_encoded(self):
        self.assertEqual(self.data, self.cert.get_encoded())

    def test___eq__(self):
        self.assertTrue(self.cert == self.cert)

        self.assertFalse(self.cert is None)
        self.assertFalse(None == self.cert)

    def test___ne__(self):
        self.assertFalse(self.cert != self.cert)
        self.assertFalse(self.name != self.name)

        self.assertTrue(self.cert is not None)
        self.assertTrue(None != self.cert)

    def test___ne__name(self):
        other_x509 = x_509.X509(self.data, "other x509")
        self.assertTrue(self.cert != other_x509)
