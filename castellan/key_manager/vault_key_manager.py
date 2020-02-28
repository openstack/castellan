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
from oslo_utils import timeutils
import requests

from castellan.common import exception
from castellan.common.objects import private_key as pri_key
from castellan.common.objects import public_key as pub_key
from castellan.common.objects import symmetric_key as sym_key
from castellan.i18n import _
from castellan.key_manager import key_manager

_DEFAULT_VAULT_URL = "http://127.0.0.1:8200"
_DEFAULT_MOUNTPOINT = "secret"

_vault_opts = [
    cfg.StrOpt('root_token_id',
               help='root token for vault'),
    cfg.StrOpt('approle_role_id',
               help='AppRole role_id for authentication with vault'),
    cfg.StrOpt('approle_secret_id',
               help='AppRole secret_id for authentication with vault'),
    cfg.StrOpt('kv_mountpoint',
               default=_DEFAULT_MOUNTPOINT,
               help='Mountpoint of KV store in Vault to use, for example: '
                    '{}'.format(_DEFAULT_MOUNTPOINT)),
    cfg.StrOpt('vault_url',
               default=_DEFAULT_VAULT_URL,
               help='Use this endpoint to connect to Vault, for example: '
                    '"%s"' % _DEFAULT_VAULT_URL),
    cfg.StrOpt('ssl_ca_crt_file',
               help='Absolute path to ca cert file'),
    cfg.BoolOpt('use_ssl',
                default=False,
                help=_('SSL Enabled/Disabled')),
]

_VAULT_OPT_GROUP = 'vault'

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

    def __init__(self, configuration):
        self._conf = configuration
        self._conf.register_opts(_vault_opts, group=_VAULT_OPT_GROUP)
        loading.register_session_conf_options(self._conf, _VAULT_OPT_GROUP)
        self._session = requests.Session()
        self._root_token_id = self._conf.vault.root_token_id
        self._approle_role_id = self._conf.vault.approle_role_id
        self._approle_secret_id = self._conf.vault.approle_secret_id
        self._cached_approle_token_id = None
        self._approle_token_ttl = None
        self._approle_token_issue = None
        self._kv_mountpoint = self._conf.vault.kv_mountpoint
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

        resource_url = '{}v1/sys/internal/ui/mounts/{}'.format(
            self._get_url(),
            self._kv_mountpoint
        )
        resp = self._do_http_request(self._session.get, resource_url)

        if resp.status_code == requests.codes['not_found']:
            self._vault_kv_version = '1'
        else:
            self._vault_kv_version = resp.json()['data']['options']['version']

        return self._vault_kv_version

    def _get_resource_url(self, key_id=None):
        return '{}v1/{}/{}{}'.format(
            self._get_url(),
            self._kv_mountpoint,

            '' if self._get_api_version() == '1' else
            'data/' if key_id else
            'metadata/',  # no key_id is for listing and 'data/' doesn't works

            key_id if key_id else '?list=true')

    @property
    def _approle_token_id(self):
        if (all((self._approle_token_issue, self._approle_token_ttl)) and
                timeutils.is_older_than(self._approle_token_issue,
                                        self._approle_token_ttl)):
            self._cached_approle_token_id = None
        return self._cached_approle_token_id

    def _build_auth_headers(self):
        if self._root_token_id:
            return {'X-Vault-Token': self._root_token_id}

        if self._approle_token_id:
            return {'X-Vault-Token': self._approle_token_id}

        if self._approle_role_id:
            params = {
                'role_id': self._approle_role_id
            }
            if self._approle_secret_id:
                params['secret_id'] = self._approle_secret_id
            approle_login_url = '{}v1/auth/approle/login'.format(
                self._get_url()
            )
            token_issue_utc = timeutils.utcnow()
            try:
                resp = self._session.post(url=approle_login_url,
                                          json=params,
                                          verify=self._verify_server)
            except requests.exceptions.Timeout as ex:
                raise exception.KeyManagerError(str(ex))
            except requests.exceptions.ConnectionError as ex:
                raise exception.KeyManagerError(str(ex))
            except Exception as ex:
                raise exception.KeyManagerError(str(ex))

            if resp.status_code in _EXCEPTIONS_BY_CODE:
                raise exception.KeyManagerError(resp.reason)
            if resp.status_code == requests.codes['forbidden']:
                raise exception.Forbidden()

            resp = resp.json()
            self._cached_approle_token_id = resp['auth']['client_token']
            self._approle_token_issue = token_issue_utc
            self._approle_token_ttl = resp['auth']['lease_duration']
            return {'X-Vault-Token': self._approle_token_id}

        return {}

    def _do_http_request(self, method, resource, json=None):
        verify = self._verify_server
        headers = self._build_auth_headers()

        try:
            resp = method(resource, headers=headers, json=json, verify=verify)
        except requests.exceptions.Timeout as ex:
            raise exception.KeyManagerError(str(ex))
        except requests.exceptions.ConnectionError as ex:
            raise exception.KeyManagerError(str(ex))
        except Exception as ex:
            raise exception.KeyManagerError(str(ex))

        if resp.status_code in _EXCEPTIONS_BY_CODE:
            raise exception.KeyManagerError(resp.reason)
        if resp.status_code == requests.codes['forbidden']:
            raise exception.Forbidden()

        return resp

    def create_key_pair(self, context, algorithm, length,
                        expiration=None, name=None):
        """Creates an asymmetric key pair."""

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

        self._do_http_request(self._session.post,
                              self._get_resource_url(key_id),
                              json=record)

        return key_id

    def create_key(self, context, algorithm, length, name=None, **kwargs):
        """Creates a symmetric key."""

        if length % 8:
            msg = _("Length must be multiple of 8.")
            raise ValueError(msg)

        key_id = uuid.uuid4().hex
        key_value = os.urandom((length or 256) // 8)
        key = sym_key.SymmetricKey(algorithm,
                                   length or 256,
                                   key_value,
                                   key_id,
                                   name or int(time.time()))

        return self._store_key_value(key_id, key)

    def store(self, context, key_value, **kwargs):
        """Stores (i.e., registers) a key with the key manager."""

        key_id = uuid.uuid4().hex
        return self._store_key_value(key_id, key_value)

    def get(self, context, key_id, metadata_only=False):
        """Retrieves the key identified by the specified id."""

        if not key_id:
            raise exception.KeyManagerError('key identifier not provided')

        resp = self._do_http_request(self._session.get,
                                     self._get_resource_url(key_id))

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

        if not key_id:
            raise exception.KeyManagerError('key identifier not provided')

        resp = self._do_http_request(self._session.delete,
                                     self._get_resource_url(key_id))

        if resp.status_code == requests.codes['not_found']:
            raise exception.ManagedObjectNotFoundError(uuid=key_id)

    def list(self, context, object_type=None, metadata_only=False):
        """Lists the managed objects given the criteria."""

        if object_type and object_type not in self._secret_type_dict:
            msg = _("Invalid secret type: %s") % object_type
            raise exception.KeyManagerError(reason=msg)

        resp = self._do_http_request(self._session.get,
                                     self._get_resource_url())

        if resp.status_code == requests.codes['not_found']:
            keys = []
        else:
            keys = resp.json()['data']['keys']

        objects = []
        for obj_id in keys:
            try:
                obj = self.get(context, obj_id, metadata_only=metadata_only)
                if object_type is None or isinstance(obj, object_type):
                    objects.append(obj)
            except exception.ManagedObjectNotFoundError as e:
                LOG.warning("Error occurred while retrieving object "
                            "metadata, not adding it to the list: %s", e)
                pass
        return objects

    def list_options_for_discovery(self):
        return [(_VAULT_OPT_GROUP, _vault_opts)]
