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
from castellan.common import objects
from castellan.common.objects import x_509
from castellan.tests import base
from castellan.tests import utils


class X509TestCase(base.CertificateTestCase):

    def _create_cert(self):
        return x_509.X509(self.data,
                          self.name,
                          self.created,
                          consumers=self.consumers)

    def setUp(self):
        self.data = utils.get_certificate_der()
        self.name = 'my cert'
        self.created = 1448088699
        self.consumers = [{'service': 'service_test',
                           'resource_type': 'type_test',
                           'resource_id': 'id_test'}]

        super(X509TestCase, self).setUp()

    def test_is_not_only_metadata(self):
        self.assertFalse(self.cert.is_metadata_only())

    def test_is_only_metadata(self):
        c = x_509.X509(None, self.name, self.created)
        self.assertTrue(c.is_metadata_only())

    def test_get_format(self):
        self.assertEqual('X.509', self.cert.format)

    def test_get_name(self):
        self.assertEqual(self.name, self.cert.name)

    def test_get_encoded(self):
        self.assertEqual(self.data, self.cert.get_encoded())

    def test_get_created(self):
        self.assertEqual(self.created, self.cert.created)

    def test_get_consumers(self):
        self.assertEqual(self.consumers, self.cert.consumers)

    def test_get_created_none(self):
        created = None
        cert = x_509.X509(self.data,
                          self.name,
                          created,
                          consumers=self.consumers)

        self.assertEqual(created, cert.created)

    def test___eq__(self):
        self.assertTrue(self.cert == self.cert)
        self.assertTrue(self.cert is self.cert)

        self.assertFalse(self.cert is None)
        self.assertFalse(None == self.cert)  # noqa: E711

        other_x_509 = x_509.X509(self.data)
        self.assertTrue(self.cert == other_x_509)
        self.assertFalse(self.cert is other_x_509)

    def test___ne___none(self):
        self.assertTrue(self.cert is not None)
        self.assertTrue(None != self.cert)  # noqa: E711

    def test___ne___data(self):
        other_x509 = x_509.X509(b'\x00\x00\x00', self.name)
        self.assertTrue(self.cert != other_x509)

    def test___ne___consumers(self):
        different_consumers = [{'service': 'other_service',
                                'resource_type': 'other_type',
                                'resource_id': 'other_id'}]
        other_cert = x_509.X509(self.data,
                                self.name,
                                self.created,
                                consumers=different_consumers)
        self.assertTrue(self.cert is not other_cert)

    def test_to_and_from_dict(self):
        other = objects.from_dict(self.cert.to_dict())
        self.assertEqual(self.cert, other)
