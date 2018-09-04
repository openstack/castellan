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
Functional test cases for the Castellan Oslo Config Driver.

Note: This requires local running instance of Vault.
"""
import tempfile

from oslo_config import cfg
from oslo_config import fixture

from oslotest import base

from castellan import _config_driver
from castellan.common.objects import opaque_data
from castellan.tests.unit.key_manager import fake


class CastellanSourceTestCase(base.BaseTestCase):

    def setUp(self):
        super(CastellanSourceTestCase, self).setUp()
        self.driver = _config_driver.CastellanConfigurationSourceDriver()
        self.conf = cfg.ConfigOpts()
        self.conf_fixture = self.useFixture(fixture.Config(self.conf))

    def test_incomplete_driver(self):
        # The group exists, but does not specify the
        # required options for this driver.
        self.conf_fixture.load_raw_values(
            group='incomplete_driver',
            driver='castellan',
        )
        source = self.conf._open_source_from_opt_group('incomplete_driver')

        self.assertIsNone(source)
        self.assertEqual(self.conf.incomplete_driver.driver, 'castellan')

    def test_complete_driver(self):
        self.conf_fixture.load_raw_values(
            group='castellan_source',
            driver='castellan',
            config_file='config.conf',
            mapping_file='mapping.conf',
        )

        with base.mock.patch.object(
                _config_driver,
                'CastellanConfigurationSource') as source_class:
            self.driver.open_source_from_opt_group(
                self.conf, 'castellan_source')

            source_class.assert_called_once_with(
                'castellan_source',
                self.conf.castellan_source.config_file,
                self.conf.castellan_source.mapping_file)

    def test_fetch_secret(self):
        # fake KeyManager populated with secret
        km = fake.fake_api()
        secret_id = km.store("fake_context",
                             opaque_data.OpaqueData(b"super_secret!"))

        # driver config
        config = "[key_manager]\nbackend=vault"
        mapping = "[DEFAULT]\nmy_secret=" + secret_id

        # creating temp files
        with tempfile.NamedTemporaryFile() as config_file:
            config_file.write(config.encode("utf-8"))
            config_file.flush()

            with tempfile.NamedTemporaryFile() as mapping_file:
                mapping_file.write(mapping.encode("utf-8"))
                mapping_file.flush()

                self.conf_fixture.load_raw_values(
                    group='castellan_source',
                    driver='castellan',
                    config_file=config_file.name,
                    mapping_file=mapping_file.name,
                )

                source = self.driver.open_source_from_opt_group(
                    self.conf,
                    'castellan_source')

                # replacing key_manager with fake one
                source._mngr = km

                # testing if the source is able to retrieve
                # the secret value stored in the key_manager
                # using the secret_id from the mapping file
                self.assertEqual("super_secret!",
                                 source.get("DEFAULT",
                                            "my_secret",
                                            cfg.StrOpt(""))[0])
