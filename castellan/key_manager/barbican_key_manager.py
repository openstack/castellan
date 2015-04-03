# Copyright (c) The Johns Hopkins University/Applied Physics Laboratory
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
Key manager implementation for Barbican
"""
from barbicanclient import client as barbican_client
from barbicanclient import exceptions as barbican_exceptions
from keystoneclient.auth import token_endpoint
from keystoneclient import session
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils

from castellan.common import exception
from castellan.key_manager import key_manager
from castellan.key_manager import symmetric_key as key_manager_key
from castellan.openstack.common import _i18n as u

from six.moves import urllib

barbican_opts = [
    cfg.StrOpt('barbican_endpoint',
               default='http://localhost:9311/',
               help='Use this endpoint to connect to Barbican'),
    cfg.StrOpt('api_version',
               default='v1',
               help='Version of the Barbican API'),
]

CONF = cfg.CONF
BARBICAN_OPT_GROUP = 'barbican'

CONF.register_opts(barbican_opts, group=BARBICAN_OPT_GROUP)

session.Session.register_conf_options(CONF, BARBICAN_OPT_GROUP)

LOG = logging.getLogger(__name__)


class BarbicanKeyManager(key_manager.KeyManager):
    """Key Manager Interface that wraps the Barbican client API."""

    def __init__(self):
        self._barbican_client = None
        self._base_url = None

    def _get_barbican_client(self, context):
        """Creates a client to connect to the Barbican service.

        :param context: the user context for authentication
        :return: a Barbican Client object
        :raises Forbidden: if the context is None
        """

        # Confirm context is provided, if not raise forbidden
        if not context:
            msg = u._("User is not authorized to use key manager.")
            LOG.error(msg)
            raise exception.Forbidden(msg)

        if self._barbican_client and self._current_context == context:
                return self._barbican_client

        try:
            self._current_context = context
            sess = self._get_keystone_session(context)

            self._barbican_client = barbican_client.Client(
                session=sess,
                endpoint=self._barbican_endpoint)

        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error(u._LE("Error creating Barbican client: %s"), e)

        self._base_url = self._create_base_url()

        return self._barbican_client

    def _get_keystone_session(self, context):
        sess = session.Session.load_from_conf_options(
            CONF, BARBICAN_OPT_GROUP)

        self._barbican_endpoint = CONF.barbican.barbican_endpoint

        auth = token_endpoint.Token(self._barbican_endpoint,
                                    context.auth_token)
        sess.auth = auth
        return sess

    def _create_base_url(self):
        base_url = urllib.parse.urljoin(self._barbican_endpoint,
                                        CONF.barbican.api_version)
        return base_url

    def create_key(self, context, algorithm, length, expiration=None):
        """Creates a key.

        :param context: contains information of the user and the environment
                     for the request (castellan/context.py)
        :param algorithm: the algorithm associated with the secret
        :param length: the bit length of the secret
        :param expiration: the date the key will expire
        :return: the UUID of the new key
        :raises HTTPAuthError: if key creation fails with 401
        :raises HTTPClientError: if key creation failes with 4xx
        :raises HTTPServerError: if key creation fails with 5xx
        """
        barbican_client = self._get_barbican_client(context)

        try:
            key_order = barbican_client.orders.create_key(
                algorithm=algorithm,
                bit_length=length,
                expiration=expiration)
            order_ref = key_order.submit()
            order = barbican_client.orders.get(order_ref)
            return self._retrieve_secret_uuid(order.secret_ref)
        except (barbican_exceptions.HTTPAuthError,
                barbican_exceptions.HTTPClientError,
                barbican_exceptions.HTTPServerError) as e:
            with excutils.save_and_reraise_exception():
                LOG.error(u._LE("Error creating key: %s"), e)

    def store_key(self, context, key, expiration=None):
        """Stores (i.e., registers) a key with the key manager.

        :param context: contains information of the user and the environment
                     for the request (castellan/context.py)
        :param key: the unencrypted secret data. Known as "payload" to the
                    barbicanclient api
        :param expiration: the expiration time of the secret in ISO 8601
                           format
        :returns: the UUID of the stored key
        :raises HTTPAuthError: if key creation fails with 401
        :raises HTTPClientError: if key creation failes with 4xx
        :raises HTTPServerError: if key creation fails with 5xx
        """
        barbican_client = self._get_barbican_client(context)

        try:
            if key.get_algorithm():
                algorithm = key.get_algorithm()
            encoded_key = key.get_encoded()
            # TODO(kfarr) add support for objects other than symmetric keys
            secret = barbican_client.secrets.create(payload=encoded_key,
                                                    algorithm=algorithm,
                                                    expiration=expiration)
            secret_ref = secret.store()
            return self._retrieve_secret_uuid(secret_ref)
        except (barbican_exceptions.HTTPAuthError,
                barbican_exceptions.HTTPClientError,
                barbican_exceptions.HTTPServerError) as e:
            with excutils.save_and_reraise_exception():
                LOG.error(u._LE("Error storing key: %s"), e)

    def copy_key(self, context, key_id):
        """Copies (i.e., clones) a key stored by barbican.

        :param context: contains information of the user and the environment
                     for the request (castellan/context.py)
        :param key_id: the UUID of the key to copy
        :return: the UUID of the key copy
        :raises HTTPAuthError: if key creation fails with 401
        :raises HTTPClientError: if key creation failes with 4xx
        :raises HTTPServerError: if key creation fails with 5xx
        """

        try:
            secret = self._get_secret(context, key_id)
            secret_data = self._get_secret_data(secret)
            # TODO(kfarr) modify to support other types of keys
            key = key_manager_key.SymmetricKey(secret.algorithm, secret_data)
            copy_uuid = self.store_key(context, key, secret.expiration)
            return copy_uuid
        except (barbican_exceptions.HTTPAuthError,
                barbican_exceptions.HTTPClientError,
                barbican_exceptions.HTTPServerError) as e:
            with excutils.save_and_reraise_exception():
                LOG.error(u._LE("Error copying key: %s"), e)

    def _create_secret_ref(self, key_id):
        """Creates the URL required for accessing a secret.

        :param key_id: the UUID of the key to copy
        :return: the URL of the requested secret
        """
        if not key_id:
            msg = "Key ID is None"
            raise exception.KeyManagerError(msg)
        base_url = self._base_url
        if base_url[-1] != '/':
            base_url += '/'
        return urllib.parse.urljoin(base_url, "secrets/" + key_id)

    def _retrieve_secret_uuid(self, secret_ref):
        """Retrieves the UUID of the secret from the secret_ref.

        :param secret_ref: the href of the secret
        :return: the UUID of the secret
        """

        # The secret_ref is assumed to be of a form similar to
        # http://host:9311/v1/secrets/d152fa13-2b41-42ca-a934-6c21566c0f40
        # with the UUID at the end. This command retrieves everything
        # after the last '/', which is the UUID.
        return secret_ref.rpartition('/')[2]

    def _get_secret_data(self, secret):
        """Retrieves the secret data given a secret and content_type.

        :param secret: the secret from barbican with the payload of data
        :returns: the secret data
        """
        # TODO(kfarr) support other types of keys
        return secret.payload

    def _get_secret(self, context, key_id):
        """Returns the metadata of the secret.

        :param context: contains information of the user and the environment
                     for the request (castellan/context.py)
        :param key_id: UUID of the secret
        :return: the secret's metadata
        :raises HTTPAuthError: if key creation fails with 401
        :raises HTTPClientError: if key creation failes with 4xx
        :raises HTTPServerError: if key creation fails with 5xx
        """

        barbican_client = self._get_barbican_client(context)

        try:
            secret_ref = self._create_secret_ref(key_id)
            return barbican_client.secrets.get(secret_ref)
        except (barbican_exceptions.HTTPAuthError,
                barbican_exceptions.HTTPClientError,
                barbican_exceptions.HTTPServerError) as e:
            with excutils.save_and_reraise_exception():
                LOG.error(u._LE("Error getting secret metadata: %s"), e)

    def get_key(self, context, key_id):
        """Retrieves the specified key.

        :param context: contains information of the user and the environment
                     for the request (castellan/context.py)
        :param key_id: the UUID of the key to retrieve
        :return: SymmetricKey representation of the key
        :raises HTTPAuthError: if key creation fails with 401
        :raises HTTPClientError: if key creation failes with 4xx
        :raises HTTPServerError: if key creation fails with 5xx
        """
        try:
            secret = self._get_secret(context, key_id)
            secret_data = self._get_secret_data(secret)
            # TODO(kfarr) add support for other objects
            key = key_manager_key.SymmetricKey(secret.algorithm, secret_data)
            return key
        except (barbican_exceptions.HTTPAuthError,
                barbican_exceptions.HTTPClientError,
                barbican_exceptions.HTTPServerError) as e:
            with excutils.save_and_reraise_exception():
                LOG.error(u._LE("Error getting key: %s"), e)

    def delete_key(self, context, key_id):
        """Deletes the specified key.

        :param context: contains information of the user and the environment
                     for the request (castellan/context.py)
        :param key_id: the UUID of the key to delete
        :raises HTTPAuthError: if key creation fails with 401
        :raises HTTPClientError: if key creation failes with 4xx
        :raises HTTPServerError: if key creation fails with 5xx
        """
        barbican_client = self._get_barbican_client(context)

        try:
            secret_ref = self._create_secret_ref(key_id)
            barbican_client.secrets.delete(secret_ref)
        except (barbican_exceptions.HTTPAuthError,
                barbican_exceptions.HTTPClientError,
                barbican_exceptions.HTTPServerError) as e:
            with excutils.save_and_reraise_exception():
                LOG.error(u._LE("Error deleting key: %s"), e)
