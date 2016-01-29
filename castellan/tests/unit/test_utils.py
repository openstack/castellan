# Copyright (c) 2016 IBM
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Test Common utilities for Castellan.
"""

from castellan.common import exception
from castellan.common import utils
from castellan.tests import base

from oslo_config import cfg
from oslo_config import fixture as config_fixture
from oslo_context import context

CONF = cfg.CONF


class TestUtils(base.TestCase):

    def setUp(self):
        super(TestUtils, self).setUp()
        self.config_fixture = self.useFixture(config_fixture.Config(CONF))
        CONF.register_opts(utils.credential_opts, group=utils.OPT_GROUP)

    def test_token_credential(self):
        token_value = 'ec9799cd921e4e0a8ab6111c08ebf065'

        self.config_fixture.config(
            auth_type='token',
            token=token_value,
            group='key_manager'
        )

        token_context = utils.credential_factory(conf=CONF)
        token_context_class = token_context.__class__.__name__

        self.assertEqual('Token', token_context_class)
        self.assertEqual(token_value, token_context.token)

    def test_token_credential_with_context(self):
        token_value = 'ec9799cd921e4e0a8ab6111c08ebf065'
        ctxt = context.RequestContext(auth_token=token_value)

        self.config_fixture.config(
            auth_type='token',
            group='key_manager'
        )

        token_context = utils.credential_factory(conf=CONF, context=ctxt)
        token_context_class = token_context.__class__.__name__

        self.assertEqual('Token', token_context_class)
        self.assertEqual(token_value, token_context.token)

    def test_token_credential_config_override_context(self):
        ctxt_token_value = '00000000000000000000000000000000'
        ctxt = context.RequestContext(auth_token=ctxt_token_value)

        conf_token_value = 'ec9799cd921e4e0a8ab6111c08ebf065'

        self.config_fixture.config(
            auth_type='token',
            token=conf_token_value,
            group='key_manager'
        )

        token_context = utils.credential_factory(conf=CONF, context=ctxt)
        token_context_class = token_context.__class__.__name__

        self.assertEqual('Token', token_context_class)
        self.assertEqual(conf_token_value, token_context.token)

    def test_token_credential_exception(self):
        self.config_fixture.config(
            auth_type='token',
            group='key_manager'
        )

        self.assertRaises(exception.InsufficientCredentialDataError,
                          utils.credential_factory,
                          CONF)

    def test_password_credential(self):
        password_value = 'p4ssw0rd'

        self.config_fixture.config(
            auth_type='password',
            password=password_value,
            group='key_manager'
        )

        password_context = utils.credential_factory(conf=CONF)
        password_context_class = password_context.__class__.__name__

        self.assertEqual('Password', password_context_class)
        self.assertEqual(password_value, password_context.password)

    def test_keystone_token_credential(self):
        token_value = 'ec9799cd921e4e0a8ab6111c08ebf065'

        self.config_fixture.config(
            auth_type='keystone_token',
            token=token_value,
            group='key_manager'
        )

        ks_token_context = utils.credential_factory(conf=CONF)
        ks_token_context_class = ks_token_context.__class__.__name__

        self.assertEqual('KeystoneToken', ks_token_context_class)
        self.assertEqual(token_value, ks_token_context.token)

    def test_keystone_token_credential_with_context(self):
        token_value = 'ec9799cd921e4e0a8ab6111c08ebf065'
        ctxt = context.RequestContext(auth_token=token_value)

        self.config_fixture.config(
            auth_type='keystone_token',
            group='key_manager'
        )

        ks_token_context = utils.credential_factory(conf=CONF, context=ctxt)
        ks_token_context_class = ks_token_context.__class__.__name__

        self.assertEqual('KeystoneToken', ks_token_context_class)
        self.assertEqual(token_value, ks_token_context.token)

    def test_keystone_token_credential_config_override_context(self):
        ctxt_token_value = 'ec9799cd921e4e0a8ab6111c08ebf065'
        ctxt = context.RequestContext(auth_token=ctxt_token_value)

        conf_token_value = 'ec9799cd921e4e0a8ab6111c08ebf065'

        self.config_fixture.config(
            auth_type='keystone_token',
            token=conf_token_value,
            group='key_manager'
        )

        ks_token_context = utils.credential_factory(conf=CONF, context=ctxt)
        ks_token_context_class = ks_token_context.__class__.__name__

        self.assertEqual('KeystoneToken', ks_token_context_class)
        self.assertEqual(conf_token_value, ks_token_context.token)

    def test_keystone_token_credential_exception(self):
        self.config_fixture.config(
            auth_type='keystone_token',
            group='key_manager'
        )

        self.assertRaises(exception.InsufficientCredentialDataError,
                          utils.credential_factory,
                          CONF)

    def test_keystone_password_credential(self):
        password_value = 'p4ssw0rd'

        self.config_fixture.config(
            auth_type='keystone_password',
            password=password_value,
            group='key_manager'
        )

        ks_password_context = utils.credential_factory(conf=CONF)
        ks_password_context_class = ks_password_context.__class__.__name__

        self.assertEqual('KeystonePassword', ks_password_context_class)
        self.assertEqual(password_value, ks_password_context.password)

    def test_oslo_context_to_keystone_token(self):
        auth_token_value = '16bd612f28ec479b8ffe8e124fc37b43'
        tenant_value = '00c6ef5ad2984af2acd7d42c299935c0'

        ctxt = context.RequestContext(
            auth_token=auth_token_value,
            tenant=tenant_value)

        ks_token_context = utils.credential_factory(context=ctxt)
        ks_token_context_class = ks_token_context.__class__.__name__

        self.assertEqual('KeystoneToken', ks_token_context_class)
        self.assertEqual(auth_token_value, ks_token_context.token)
        self.assertEqual(tenant_value, ks_token_context.project_id)

    def test_invalid_auth_type(self):
        self.config_fixture.config(
            auth_type='hotdog',
            group='key_manager'
        )

        self.assertRaises(exception.AuthTypeInvalidError,
                          utils.credential_factory,
                          conf=CONF)
