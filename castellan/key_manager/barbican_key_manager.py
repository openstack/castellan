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
import calendar
import time
import urllib

from cryptography.hazmat import backends
from cryptography.hazmat.primitives import serialization
from cryptography import x509 as cryptography_x509
from keystoneauth1 import identity
from keystoneauth1 import loading
from keystoneauth1 import service_token
from keystoneauth1 import session
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils

from castellan.common import exception
from castellan.common.objects import key as key_base_class
from castellan.common.objects import opaque_data as op_data
from castellan.i18n import _
from castellan.key_manager import key_manager


from barbicanclient import client as barbican_client_import
from barbicanclient import exceptions as barbican_exceptions
from oslo_utils import timeutils


_barbican_opts = [
    cfg.StrOpt('barbican_endpoint',
               help='Use this endpoint to connect to Barbican, for example: '
                    '"http://localhost:9311/"'),
    cfg.StrOpt('barbican_api_version',
               help='Version of the Barbican API, for example: "v1"'),
    cfg.StrOpt('auth_endpoint',
               default='http://localhost/identity/v3',
               deprecated_name='auth_url',
               deprecated_group='key_manager',
               help='Use this endpoint to connect to Keystone'),
    cfg.IntOpt('retry_delay',
               default=1,
               help='Number of seconds to wait before retrying poll for key '
                    'creation completion'),
    cfg.IntOpt('number_of_retries',
               default=60,
               help='Number of times to retry poll for key creation '
                    'completion'),
    cfg.BoolOpt('verify_ssl',
                default=True,
                help='Specifies if insecure TLS (https) requests. If False, '
                     'the server\'s certificate will not be validated, if '
                     'True, we can set the verify_ssl_path config meanwhile.'),
    cfg.StrOpt('verify_ssl_path',
               default=None,
               help='A path to a bundle or CA certs to check against, or '
                    'None for requests to attempt to locate and use '
                    'certificates which verify_ssh is True. If verify_ssl '
                    'is False, this is ignored.'),
    cfg.StrOpt('barbican_endpoint_type',
               default='public',
               choices=['public', 'internal', 'admin'],
               help='Specifies the type of endpoint.  Allowed values are: '
                    'public, private, and admin'),
    cfg.StrOpt('barbican_region_name',
               default=None,
               help='Specifies the region of the chosen endpoint.'),
    cfg.BoolOpt('send_service_user_token',
                default=False,
                help="""
When True, if sending a user token to a REST API, also send a service token.

Nova often reuses the user token provided to the nova-api to talk to other REST
APIs, such as Cinder, Glance and Neutron. It is possible that while the user
token was valid when the request was made to Nova, the token may expire before
it reaches the other service. To avoid any failures, and to make it clear it is
Nova calling the service on the user's behalf, we include a service token along
with the user token. Should the user's token have expired, a valid service
token ensures the REST API request will still be accepted by the keystone
middleware.
"""),
]


_BARBICAN_OPT_GROUP = 'barbican'
_BARBICAN_SERVICE_USER_OPT_GROUP = 'barbican_service_user'

LOG = logging.getLogger(__name__)


class BarbicanKeyManager(key_manager.KeyManager):
    """Key Manager Interface that wraps the Barbican client API."""

    def __init__(self, configuration):
        self._barbican_client = None
        self._base_url = None
        self.conf = configuration
        self.conf.register_opts(_barbican_opts, group=_BARBICAN_OPT_GROUP)
        loading.register_session_conf_options(self.conf, _BARBICAN_OPT_GROUP)

        loading.register_session_conf_options(self.conf,
                                              _BARBICAN_SERVICE_USER_OPT_GROUP)
        loading.register_auth_conf_options(self.conf,
                                           _BARBICAN_SERVICE_USER_OPT_GROUP)

    def _get_barbican_client(self, context):
        """Creates a client to connect to the Barbican service.

        :param context: the user context for authentication
        :return: a Barbican Client object
        :raises Forbidden: if the context is None
        :raises KeyManagerError: if context is missing tenant or tenant is
                                 None or error occurs while creating client
        """

        # Confirm context is provided, if not raise forbidden
        if not context:
            msg = _("User is not authorized to use key manager.")
            LOG.error(msg)
            raise exception.Forbidden(msg)

        if self._barbican_client and self._current_context == context:
            return self._barbican_client

        try:
            auth = self._get_keystone_auth(context)
            verify_ssl = self.conf.barbican.verify_ssl
            verify_ssl_path = self.conf.barbican.verify_ssl_path
            verify = verify_ssl and verify_ssl_path or verify_ssl
            sess = session.Session(auth=auth, verify=verify)

            self._barbican_endpoint = self._get_barbican_endpoint(auth, sess)
            self._barbican_client = barbican_client_import.Client(
                session=sess,
                endpoint=self._barbican_endpoint)
            self._current_context = context

        # TODO(pbourke): more fine grained exception handling - we are eating
        # tracebacks here
        except Exception as e:
            LOG.error("Error creating Barbican client: %s", e)
            raise exception.KeyManagerError(reason=e)

        self._base_url = self._create_base_url(auth,
                                               sess,
                                               self._barbican_endpoint)

        return self._barbican_client

    def _get_keystone_auth(self, context):
        if context.__class__.__name__ == 'KeystonePassword':
            auth = identity.Password(
                auth_url=context.auth_url,
                username=context.username,
                password=context.password,
                user_id=context.user_id,
                user_domain_id=context.user_domain_id,
                user_domain_name=context.user_domain_name,
                trust_id=context.trust_id,
                domain_id=context.domain_id,
                domain_name=context.domain_name,
                project_id=context.project_id,
                project_name=context.project_name,
                project_domain_id=context.project_domain_id,
                project_domain_name=context.project_domain_name,
                reauthenticate=context.reauthenticate)
        elif context.__class__.__name__ == 'KeystoneToken':
            auth = identity.Token(
                auth_url=context.auth_url,
                token=context.token,
                trust_id=context.trust_id,
                domain_id=context.domain_id,
                domain_name=context.domain_name,
                project_id=context.project_id,
                project_name=context.project_name,
                project_domain_id=context.project_domain_id,
                project_domain_name=context.project_domain_name,
                reauthenticate=context.reauthenticate)
        # this will be kept for oslo.context compatibility until
        # projects begin to use utils.credential_factory
        elif context.__class__.__name__ == 'RequestContext':
            if getattr(context, 'get_auth_plugin', None):
                auth = context.get_auth_plugin()
            else:
                auth = identity.Token(
                    auth_url=self.conf.barbican.auth_endpoint,
                    token=context.auth_token,
                    project_id=context.project_id,
                    project_name=context.project_name,
                    project_domain_id=context.project_domain_id,
                    project_domain_name=context.project_domain_name)
        else:
            msg = _("context must be of type KeystonePassword, "
                    "KeystoneToken, or RequestContext.")
            LOG.error(msg)
            raise exception.Forbidden(reason=msg)

        if self.conf.barbican.send_service_user_token:
            service_auth = loading.load_auth_from_conf_options(
                self.conf,
                group=_BARBICAN_SERVICE_USER_OPT_GROUP)
            auth = service_token.ServiceTokenAuthWrapper(
                user_auth=auth,
                service_auth=service_auth)

        return auth

    def _get_barbican_endpoint(self, auth, sess):
        if self.conf.barbican.barbican_endpoint:
            return self.conf.barbican.barbican_endpoint
        elif getattr(auth, 'service_catalog', None):
            endpoint_data = auth.service_catalog.endpoint_data_for(
                service_type='key-manager',
                interface=self.conf.barbican.barbican_endpoint_type,
                region_name=self.conf.barbican.barbican_region_name)
            return endpoint_data.url
        else:
            return auth.get_endpoint(
                sess,
                service_type='key-manager',
                interface=self.conf.barbican.barbican_endpoint_type,
                region_name=self.conf.barbican.barbican_region_name)

    def _create_base_url(self, auth, sess, endpoint):
        api_version = None
        if self.conf.barbican.barbican_api_version:
            api_version = self.conf.barbican.barbican_api_version
        elif getattr(auth, 'service_catalog', None):
            endpoint_data = auth.service_catalog.endpoint_data_for(
                service_type='key-manager',
                interface=self.conf.barbican.barbican_endpoint_type,
                region_name=self.conf.barbican.barbican_region_name)
            api_version = endpoint_data.api_version
        elif getattr(auth, 'get_discovery', None):
            discovery = auth.get_discovery(sess, url=endpoint)
            raw_data = discovery.raw_version_data()
            if len(raw_data) == 0:
                msg = _(
                    "Could not find discovery information for %s") % endpoint
                LOG.error(msg)
                raise exception.KeyManagerError(reason=msg)
            latest_version = raw_data[-1]
            api_version = latest_version.get('id')

        if endpoint[-1] != '/':
            endpoint += '/'

        base_url = urllib.parse.urljoin(
            endpoint, api_version)

        return base_url

    def create_key(self, context, algorithm, length,
                   expiration=None, name=None):
        """Creates a symmetric key.

        :param context: contains information of the user and the environment
                        for the request (castellan/context.py)
        :param algorithm: the algorithm associated with the secret
        :param length: the bit length of the secret
        :param name: the name of the key
        :param expiration: the date the key will expire
        :return: the UUID of the new key
        :raises KeyManagerError: if key creation fails
        """
        barbican_client = self._get_barbican_client(context)

        try:
            key_order = barbican_client.orders.create_key(
                name=name,
                algorithm=algorithm,
                bit_length=length,
                expiration=expiration)
            order_ref = key_order.submit()
            order = self._get_active_order(barbican_client, order_ref)
            return self._retrieve_secret_uuid(order.secret_ref)
        except (barbican_exceptions.HTTPAuthError,
                barbican_exceptions.HTTPClientError,
                barbican_exceptions.HTTPServerError) as e:
            LOG.error("Error creating key: %s", e)
            raise exception.KeyManagerError(reason=e)

    def create_key_pair(self, context, algorithm, length,
                        expiration=None, name=None):
        """Creates an asymmetric key pair.

        :param context: contains information of the user and the environment
                        for the request (castellan/context.py)
        :param algorithm: the algorithm associated with the secret
        :param length: the bit length of the secret
        :param name: the name of the key
        :param expiration: the date the key will expire
        :return: the UUIDs of the new key, in the order (private, public)
        :raises NotImplementedError: until implemented
        :raises KeyManagerError: if key pair creation fails
        """
        barbican_client = self._get_barbican_client(context)

        try:
            key_pair_order = barbican_client.orders.create_asymmetric(
                algorithm=algorithm,
                bit_length=length,
                name=name,
                expiration=expiration)

            order_ref = key_pair_order.submit()
            order = self._get_active_order(barbican_client, order_ref)
            container = barbican_client.containers.get(order.container_ref)

            private_key_uuid = self._retrieve_secret_uuid(
                container.secret_refs['private_key'])
            public_key_uuid = self._retrieve_secret_uuid(
                container.secret_refs['public_key'])
            return private_key_uuid, public_key_uuid
        except (barbican_exceptions.HTTPAuthError,
                barbican_exceptions.HTTPClientError,
                barbican_exceptions.HTTPServerError) as e:
            LOG.error("Error creating key pair: %s", e)
            raise exception.KeyManagerError(reason=e)

    def _get_barbican_object(self, barbican_client, managed_object):
        """Converts the Castellan managed_object to a Barbican secret."""
        name = getattr(managed_object, 'name', None)

        try:
            algorithm = managed_object.algorithm
            bit_length = managed_object.bit_length
        except AttributeError:
            algorithm = None
            bit_length = None

        secret_type = self._secret_type_dict.get(type(managed_object),
                                                 'opaque')
        payload = self._get_normalized_payload(managed_object.get_encoded(),
                                               secret_type)
        secret = barbican_client.secrets.create(payload=payload,
                                                algorithm=algorithm,
                                                bit_length=bit_length,
                                                name=name,
                                                secret_type=secret_type)
        return secret

    def _get_normalized_payload(self, encoded_bytes, secret_type):
        """Normalizes the bytes of the object.

        Barbican expects certificates, public keys, and private keys in PEM
        format, but Castellan expects these objects to be DER encoded bytes
        instead.
        """
        if secret_type == 'public':
            key = serialization.load_der_public_key(
                encoded_bytes,
                backend=backends.default_backend())
            return key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)
        elif secret_type == 'private':
            key = serialization.load_der_private_key(
                encoded_bytes,
                backend=backends.default_backend(),
                password=None)
            return key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption())
        elif secret_type == 'certificate':
            cert = cryptography_x509.load_der_x509_certificate(
                encoded_bytes,
                backend=backends.default_backend())
            return cert.public_bytes(encoding=serialization.Encoding.PEM)
        else:
            return encoded_bytes

    def store(self, context, managed_object, expiration=None):
        """Stores (i.e., registers) an object with the key manager.

        :param context: contains information of the user and the environment
            for the request (castellan/context.py)
        :param managed_object: a secret object with unencrypted payload.
            Known as "secret" to the barbicanclient api
        :param expiration: the expiration time of the secret in ISO 8601
            format
        :returns: the UUID of the stored object
        :raises KeyManagerError: if object store fails
        """
        barbican_client = self._get_barbican_client(context)

        try:
            secret = self._get_barbican_object(barbican_client,
                                               managed_object)
            secret.expiration = expiration
            secret_ref = secret.store()
            return self._retrieve_secret_uuid(secret_ref)
        except (barbican_exceptions.HTTPAuthError,
                barbican_exceptions.HTTPClientError,
                barbican_exceptions.HTTPServerError) as e:
            LOG.error("Error storing object: %s", e)
            raise exception.KeyManagerError(reason=e)

    def _create_secret_ref(self, object_id):
        """Creates the URL required for accessing a secret.

        :param object_id: the UUID of the key to copy
        :return: the URL of the requested secret
        """
        if not object_id:
            msg = _("Key ID is None")
            raise exception.KeyManagerError(reason=msg)
        base_url = self._base_url
        if base_url[-1] != '/':
            base_url += '/'
        return urllib.parse.urljoin(base_url, "secrets/" + object_id)

    def _get_active_order(self, barbican_client, order_ref):
        """Returns the order when it is active.

        Barbican key creation is done asynchronously, so this loop continues
        checking until the order is active or a timeout occurs.
        """
        active_status = 'ACTIVE'
        error_status = 'ERROR'
        number_of_retries = self.conf.barbican.number_of_retries
        retry_delay = self.conf.barbican.retry_delay
        order = barbican_client.orders.get(order_ref)
        time.sleep(.25)
        for n in range(number_of_retries):
            if order.status == error_status:
                kwargs = {"status": error_status,
                          "code": order.error_status_code,
                          "reason": order.error_reason}
                msg = _("Order is in %(status)s status - status code: "
                        "%(code)s, status reason: %(reason)s") % kwargs
                LOG.error(msg)
                raise exception.KeyManagerError(reason=msg)
            if order.status != active_status:
                kwargs = {'attempt': n,
                          'total': number_of_retries,
                          'status': order.status,
                          'active': active_status,
                          'delay': retry_delay}
                msg = _("Retry attempt #%(attempt)i out of %(total)i: "
                        "Order status is '%(status)s'. Waiting for "
                        "'%(active)s', will retry in %(delay)s "
                        "seconds")
                LOG.info(msg, kwargs)
                time.sleep(retry_delay)
                order = barbican_client.orders.get(order_ref)
            else:
                return order
        msg = _("Exceeded retries: Failed to find '%(active)s' status "
                "within %(num_retries)i retries") % {
            'active': active_status,
            'num_retries': number_of_retries}
        LOG.error(msg)
        raise exception.KeyManagerError(reason=msg)

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
        """Retrieves the secret data.

        Converts the Barbican secret to bytes suitable for a Castellan object.
        If the secret is a public key, private key, or certificate, the secret
        is expected to be in PEM format and will be converted to DER.

        :param secret: the secret from barbican with the payload of data
        :returns: the secret data
        """
        if secret.secret_type == 'public':
            key = serialization.load_pem_public_key(
                secret.payload,
                backend=backends.default_backend())
            return key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)
        elif secret.secret_type == 'private':
            key = serialization.load_pem_private_key(
                secret.payload,
                backend=backends.default_backend(),
                password=None)
            return key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption())
        elif secret.secret_type == 'certificate':
            cert = cryptography_x509.load_pem_x509_certificate(
                secret.payload,
                backend=backends.default_backend())
            return cert.public_bytes(encoding=serialization.Encoding.DER)
        else:
            return secret.payload

    def _get_castellan_object(self, secret, metadata_only=False):
        """Creates a Castellan managed object given the Barbican secret.

        The python barbicanclient lazy-loads the secret data, i.e. the secret
        data is not requested until secret.payload is called. If the user
        specifies metadata_only=True, secret.payload is never called,
        preventing unnecessary loading of secret data.

        :param secret: the barbican secret object
        :metadata_only: boolean indicating if the secret bytes should be
                        included in the managed object
        :returns: the castellan object
        """
        secret_type = op_data.OpaqueData
        for castellan_type, barbican_type in self._secret_type_dict.items():
            if barbican_type == secret.secret_type:
                secret_type = castellan_type

        if metadata_only:
            secret_data = None
        else:
            secret_data = self._get_secret_data(secret)

        if secret.secret_ref:
            object_id = self._retrieve_secret_uuid(secret.secret_ref)
        else:
            object_id = None

        # convert created ISO8601 in Barbican to POSIX
        if secret.created:
            time_stamp = timeutils.parse_isotime(
                str(secret.created)).timetuple()
            created = calendar.timegm(time_stamp)

        if issubclass(secret_type, key_base_class.Key):
            return secret_type(secret.algorithm,
                               secret.bit_length,
                               secret_data,
                               secret.name,
                               created,
                               object_id)
        else:
            return secret_type(secret_data,
                               secret.name,
                               created,
                               object_id)

    def _get_secret(self, context, object_id):
        """Returns the metadata of the secret.

        :param context: contains information of the user and the environment
                        for the request (castellan/context.py)
        :param object_id: UUID of the secret
        :return: the secret's metadata
        :raises HTTPAuthError: if object retrieval fails with 401
        :raises HTTPClientError: if object retrieval fails with 4xx
        :raises HTTPServerError: if object retrieval fails with 5xx
        """

        barbican_client = self._get_barbican_client(context)

        try:
            secret_ref = self._create_secret_ref(object_id)
            return barbican_client.secrets.get(secret_ref)
        except (barbican_exceptions.HTTPAuthError,
                barbican_exceptions.HTTPClientError,
                barbican_exceptions.HTTPServerError) as e:
            with excutils.save_and_reraise_exception():
                LOG.error("Error getting secret metadata: %s", e)

    def _is_secret_not_found_error(self, error):
        if (isinstance(error, barbican_exceptions.HTTPClientError) and
                error.status_code == 404):
            return True
        else:
            return False

    def get(self, context, managed_object_id, metadata_only=False):
        """Retrieves the specified managed object.

        :param context: contains information of the user and the environment
                        for the request (castellan/context.py)
        :param managed_object_id: the UUID of the object to retrieve
        :param metadata_only: whether secret data should be included
        :return: ManagedObject representation of the managed object
        :raises KeyManagerError: if object retrieval fails
        :raises ManagedObjectNotFoundError: if object not found
        """
        try:
            secret = self._get_secret(context, managed_object_id)
            return self._get_castellan_object(secret, metadata_only)
        except (barbican_exceptions.HTTPAuthError,
                barbican_exceptions.HTTPClientError,
                barbican_exceptions.HTTPServerError) as e:
            LOG.error("Error retrieving object: %s", e)
            if self._is_secret_not_found_error(e):
                raise exception.ManagedObjectNotFoundError(
                    uuid=managed_object_id)
            else:
                raise exception.KeyManagerError(reason=e)

    def delete(self, context, managed_object_id):
        """Deletes the specified managed object.

        :param context: contains information of the user and the environment
                     for the request (castellan/context.py)
        :param managed_object_id: the UUID of the object to delete
        :raises KeyManagerError: if object deletion fails
        :raises ManagedObjectNotFoundError: if the object could not be found
        """
        barbican_client = self._get_barbican_client(context)

        try:
            secret_ref = self._create_secret_ref(managed_object_id)
            barbican_client.secrets.delete(secret_ref)
        except (barbican_exceptions.HTTPAuthError,
                barbican_exceptions.HTTPClientError,
                barbican_exceptions.HTTPServerError) as e:
            LOG.error("Error deleting object: %s", e)
            if self._is_secret_not_found_error(e):
                raise exception.ManagedObjectNotFoundError(
                    uuid=managed_object_id)
            else:
                raise exception.KeyManagerError(reason=e)

    def list(self, context, object_type=None, metadata_only=False):
        """Retrieves a list of managed objects that match the criteria.

        If no search criteria is given, all objects are returned.

        :param context: contains information of the user and the environment
                     for the request (castellan/context.py)
        :param object_type: the type of object to retrieve
        :param metadata_only: whether secret data should be included
        :raises KeyManagerError: if listing secrets fails
        """
        objects = []
        barbican_client = self._get_barbican_client(context)

        if object_type and object_type not in self._secret_type_dict:
            msg = _("Invalid secret type: %s") % object_type
            LOG.error(msg)
            raise exception.KeyManagerError(reason=msg)

        secret_type = self._secret_type_dict.get(object_type)

        try:
            secrets = barbican_client.secrets.list(secret_type=secret_type)
        except (barbican_exceptions.HTTPAuthError,
                barbican_exceptions.HTTPClientError,
                barbican_exceptions.HTTPServerError) as e:
            LOG.error("Error listing objects: %s", e)
            raise exception.KeyManagerError(reason=e)

        for secret in secrets:
            try:
                obj = self._get_castellan_object(secret, metadata_only)
                objects.append(obj)
            except (barbican_exceptions.HTTPAuthError,
                    barbican_exceptions.HTTPClientError,
                    barbican_exceptions.HTTPServerError) as e:
                LOG.warning("Error occurred while retrieving object "
                            "metadata, not adding it to the list: %s", e)

        return objects

    def list_options_for_discovery(self):
        barbican_service_user_opts = loading.get_session_conf_options()
        barbican_service_user_opts += loading.get_auth_common_conf_options()

        return [
            (_BARBICAN_OPT_GROUP, _barbican_opts),
            (_BARBICAN_SERVICE_USER_OPT_GROUP, barbican_service_user_opts),
        ]
