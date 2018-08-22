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
Key manager implementation for Vault
"""

import binascii
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import PublicFormat

import os
import time
import uuid

from keystoneauth1 import loading
from oslo_config import cfg
from oslo_log import log as logging
import requests
import six

from castellan.common import exception
from castellan.common.objects import opaque_data as op_data
from castellan.common.objects import passphrase
from castellan.common.objects import private_key as pri_key
from castellan.common.objects import public_key as pub_key
from castellan.common.objects import symmetric_key as sym_key
from castellan.common.objects import x_509
from castellan.i18n import _
from castellan.key_manager import key_manager

DEFAULT_VAULT_URL = "http://127.0.0.1:8200"

vault_opts = [
    cfg.StrOpt('root_token_id',
               help='root token for vault'),
    cfg.StrOpt('vault_url',
               default=DEFAULT_VAULT_URL,
               help='Use this endpoint to connect to Vault, for example: '
                    '"%s"' % DEFAULT_VAULT_URL),
    cfg.StrOpt('ssl_ca_crt_file',
               help='Absolute path to ca cert file'),
    cfg.BoolOpt('use_ssl',
                default=False,
                help=_('SSL Enabled/Disabled')),
]

VAULT_OPT_GROUP = 'vault'

_EXCEPTIONS_BY_CODE = [
    requests.codes['internal_server_error'],
    requests.codes['service_unavailable'],
    requests.codes['request_timeout'],
    requests.codes['gateway_timeout'],
    requests.codes['precondition_failed'],
]

LOG = logging.getLogger(__name__)


class VaultKeyManager(key_manager.KeyManager):
    """Key Manager Interface that wraps the Vault REST API."""

    _secret_type_dict = {
        op_data.OpaqueData: 'opaque',
        passphrase.Passphrase: 'passphrase',
        pri_key.PrivateKey: 'private',
        pub_key.PublicKey: 'public',
        sym_key.SymmetricKey: 'symmetric',
        x_509.X509: 'certificate'}

    def __init__(self, configuration):
        self._conf = configuration
        self._conf.register_opts(vault_opts, group=VAULT_OPT_GROUP)
        loading.register_session_conf_options(self._conf, VAULT_OPT_GROUP)
        self._session = requests.Session()
        self._root_token_id = self._conf.vault.root_token_id
        self._vault_url = self._conf.vault.vault_url
        if self._vault_url.startswith("https://"):
            self._verify_server = self._conf.vault.ssl_ca_crt_file or True
        else:
            self._verify_server = False
        self._vault_kv_version = None

    def _get_url(self):
        if not self._vault_url.endswith('/'):
            self._vault_url += '/'
        return self._vault_url

    def _get_api_version(self):
        if self._vault_kv_version:
            return self._vault_kv_version

        headers = {'X-Vault-Token': self._root_token_id}
        try:
            resource_url = self._get_url() + 'v1/sys/internal/ui/mounts/secret'
            resp = self._session.get(resource_url,
                                     verify=self._verify_server,
                                     headers=headers)
        except requests.exceptions.Timeout as ex:
            raise exception.KeyManagerError(six.text_type(ex))
        except requests.exceptions.ConnectionError as ex:
            raise exception.KeyManagerError(six.text_type(ex))
        except Exception as ex:
            raise exception.KeyManagerError(six.text_type(ex))

        if resp.status_code in _EXCEPTIONS_BY_CODE:
            raise exception.KeyManagerError(resp.reason)
        if resp.status_code == requests.codes['forbidden']:
            raise exception.Forbidden()
        if resp.status_code == requests.codes['not_found']:
            self._vault_kv_version = '1'
        else:
            self._vault_kv_version = resp.json()['data']['options']['version']

        return self._vault_kv_version

    def create_key_pair(self, context, algorithm, length,
                        expiration=None, name=None):
        """Creates an asymmetric key pair."""

        # Confirm context is provided, if not raise forbidden
        if not context:
            msg = _("User is not authorized to use key manager.")
            raise exception.Forbidden(msg)

        if algorithm.lower() != 'rsa':
            raise NotImplementedError(
                "VaultKeyManager only implements rsa keys"
            )

        priv_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=length,
            backend=default_backend()
        )

        private_key = pri_key.PrivateKey(
            'RSA',
            length,
            priv_key.private_bytes(
                Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
            )
        )

        private_key_id = uuid.uuid4().hex
        private_id = self._store_key_value(
            private_key_id,
            private_key
        )

        # pub_key = priv_key.public_key()
        public_key = pub_key.PublicKey(
            'RSA',
            length,
            priv_key.public_key().public_bytes(
                Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
            )
        )

        public_key_id = uuid.uuid4().hex
        public_id = self._store_key_value(
            public_key_id,
            public_key
        )

        return private_id, public_id

    def _store_key_value(self, key_id, value):

        type_value = self._secret_type_dict.get(type(value))
        if type_value is None:
            raise exception.KeyManagerError(
                "Unknown type for value : %r" % value)

        headers = {'X-Vault-Token': self._root_token_id}
        try:
            resource_url = '{}v1/secret/{}{}'.format(
                self._get_url(),
                '' if self._get_api_version() == '1' else 'data/',
                key_id)

            record = {
                'type': type_value,
                'value': binascii.hexlify(value.get_encoded()).decode('utf-8'),
                'algorithm': (value.algorithm if hasattr(value, 'algorithm')
                              else None),
                'bit_length': (value.bit_length if hasattr(value, 'bit_length')
                               else None),
                'name': value.name,
                'created': value.created
            }
            if self._get_api_version() != '1':
                record = {'data': record}

            resp = self._session.post(resource_url,
                                      verify=self._verify_server,
                                      json=record,
                                      headers=headers)
        except requests.exceptions.Timeout as ex:
            raise exception.KeyManagerError(six.text_type(ex))
        except requests.exceptions.ConnectionError as ex:
            raise exception.KeyManagerError(six.text_type(ex))
        except Exception as ex:
            raise exception.KeyManagerError(six.text_type(ex))

        if resp.status_code in _EXCEPTIONS_BY_CODE:
            raise exception.KeyManagerError(resp.reason)
        if resp.status_code == requests.codes['forbidden']:
            raise exception.Forbidden()

        return key_id

    def create_key(self, context, algorithm, length, name=None, **kwargs):
        """Creates a symmetric key."""

        # Confirm context is provided, if not raise forbidden
        if not context:
            msg = _("User is not authorized to use key manager.")
            raise exception.Forbidden(msg)

        key_id = uuid.uuid4().hex
        key_value = os.urandom(length or 32)
        key = sym_key.SymmetricKey(algorithm,
                                   length or 32,
                                   key_value,
                                   key_id,
                                   name or int(time.time()))
        return self._store_key_value(key_id, key)

    def store(self, context, key_value, **kwargs):
        """Stores (i.e., registers) a key with the key manager."""

        # Confirm context is provided, if not raise forbidden
        if not context:
            msg = _("User is not authorized to use key manager.")
            raise exception.Forbidden(msg)

        key_id = uuid.uuid4().hex
        return self._store_key_value(key_id, key_value)

    def get(self, context, key_id, metadata_only=False):
        """Retrieves the key identified by the specified id."""

        # Confirm context is provided, if not raise forbidden
        if not context:
            msg = _("User is not authorized to use key manager.")
            raise exception.Forbidden(msg)

        if not key_id:
            raise exception.KeyManagerError('key identifier not provided')

        headers = {'X-Vault-Token': self._root_token_id}
        try:
            resource_url = '{}v1/secret/{}{}'.format(
                self._get_url(),
                '' if self._get_api_version() == '1' else 'data/',
                key_id)

            resp = self._session.get(resource_url,
                                     verify=self._verify_server,
                                     headers=headers)
        except requests.exceptions.Timeout as ex:
            raise exception.KeyManagerError(six.text_type(ex))
        except requests.exceptions.ConnectionError as ex:
            raise exception.KeyManagerError(six.text_type(ex))
        except Exception as ex:
            raise exception.KeyManagerError(six.text_type(ex))

        if resp.status_code in _EXCEPTIONS_BY_CODE:
            raise exception.KeyManagerError(resp.reason)
        if resp.status_code == requests.codes['forbidden']:
            raise exception.Forbidden()
        if resp.status_code == requests.codes['not_found']:
            raise exception.ManagedObjectNotFoundError(uuid=key_id)

        record = resp.json()['data']
        if self._get_api_version() != '1':
            record = record['data']

        key = None if metadata_only else binascii.unhexlify(record['value'])

        clazz = None
        for type_clazz, type_name in self._secret_type_dict.items():
            if type_name == record['type']:
                clazz = type_clazz

        if clazz is None:
            raise exception.KeyManagerError(
                "Unknown type : %r" % record['type'])

        if hasattr(clazz, 'algorithm') and hasattr(clazz, 'bit_length'):
            return clazz(record['algorithm'],
                         record['bit_length'],
                         key,
                         record['name'],
                         record['created'],
                         key_id)
        else:
            return clazz(key,
                         record['name'],
                         record['created'],
                         key_id)

    def delete(self, context, key_id):
        """Represents deleting the key."""

        # Confirm context is provided, if not raise forbidden
        if not context:
            msg = _("User is not authorized to use key manager.")
            raise exception.Forbidden(msg)

        if not key_id:
            raise exception.KeyManagerError('key identifier not provided')

        headers = {'X-Vault-Token': self._root_token_id}
        try:
            resource_url = '{}v1/secret/{}{}'.format(
                self._get_url(),
                '' if self._get_api_version() == '1' else 'data/',
                key_id)

            resp = self._session.delete(resource_url,
                                        verify=self._verify_server,
                                        headers=headers)
        except requests.exceptions.Timeout as ex:
            raise exception.KeyManagerError(six.text_type(ex))
        except requests.exceptions.ConnectionError as ex:
            raise exception.KeyManagerError(six.text_type(ex))
        except Exception as ex:
            raise exception.KeyManagerError(six.text_type(ex))

        if resp.status_code in _EXCEPTIONS_BY_CODE:
            raise exception.KeyManagerError(resp.reason)
        if resp.status_code == requests.codes['forbidden']:
            raise exception.Forbidden()
        if resp.status_code == requests.codes['not_found']:
            raise exception.ManagedObjectNotFoundError(uuid=key_id)

    def list(self, context, object_type=None, metadata_only=False):
        """Lists the managed objects given the criteria."""

        # Confirm context is provided, if not raise forbidden
        if not context:
            msg = _("User is not authorized to use key manager.")
            raise exception.Forbidden(msg)

        if object_type and object_type not in self._secret_type_dict:
            msg = _("Invalid secret type: %s") % object_type
            raise exception.KeyManagerError(reason=msg)

        headers = {'X-Vault-Token': self._root_token_id}
        try:
            resource_url = '{}v1/secret/{}?list=true'.format(
                self._get_url(),
                '' if self._get_api_version() == '1' else 'metadata/')

            resp = self._session.get(resource_url,
                                     verify=self._verify_server,
                                     headers=headers)
            keys = resp.json()['data']['keys']
        except requests.exceptions.Timeout as ex:
            raise exception.KeyManagerError(six.text_type(ex))
        except requests.exceptions.ConnectionError as ex:
            raise exception.KeyManagerError(six.text_type(ex))
        except Exception as ex:
            raise exception.KeyManagerError(six.text_type(ex))

        if resp.status_code in _EXCEPTIONS_BY_CODE:
            raise exception.KeyManagerError(resp.reason)
        if resp.status_code == requests.codes['forbidden']:
            raise exception.Forbidden()
        if resp.status_code == requests.codes['not_found']:
            keys = []

        objects = []
        for obj_id in keys:
            try:
                obj = self.get(context, obj_id, metadata_only=metadata_only)
                if object_type is None or isinstance(obj, object_type):
                    objects.append(obj)
            except exception.ManagedObjectNotFoundError as e:
                LOG.warning(_("Error occurred while retrieving object "
                              "metadata, not adding it to the list: %s"), e)
                pass
        return objects
