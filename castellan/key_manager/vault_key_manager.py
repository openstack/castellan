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

from __future__ import annotations

import binascii
import builtins
from collections.abc import Callable
import datetime
import os
import time
from typing import Any
from typing import NoReturn
import uuid

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import PublicFormat
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import timeutils
import requests

from castellan.common import exception
from castellan.common.objects import managed_object
from castellan.common.objects import private_key as pri_key
from castellan.common.objects import public_key as pub_key
from castellan.common.objects import symmetric_key as sym_key
from castellan.i18n import _
from castellan.key_manager import key_manager
from castellan.key_manager.key_manager import Context

_DEFAULT_VAULT_URL = "http://127.0.0.1:8200"
_DEFAULT_MOUNTPOINT = "secret"
_DEFAULT_VERSION = 2

_vault_opts = [
    cfg.StrOpt('root_token_id', secret=True, help='root token for vault'),
    cfg.StrOpt(
        'approle_role_id',
        secret=True,
        help='AppRole role_id for authentication with vault',
    ),
    cfg.StrOpt(
        'approle_secret_id',
        secret=True,
        help='AppRole secret_id for authentication with vault',
    ),
    cfg.StrOpt(
        'kv_mountpoint',
        default=_DEFAULT_MOUNTPOINT,
        help='Mountpoint of KV store in Vault to use',
    ),
    cfg.StrOpt(
        'kv_path', help='Path relative to root of KV store in Vault to use.'
    ),
    cfg.IntOpt(
        'kv_version',
        default=_DEFAULT_VERSION,
        choices=(1, 2),
        help='Version of KV store in Vault to use.',
    ),
    cfg.URIOpt(
        'vault_url',
        default=_DEFAULT_VAULT_URL,
        schemes=('http', 'https'),
        help='Use this endpoint to connect to Vault',
    ),
    cfg.StrOpt('ssl_ca_crt_file', help='Absolute path to ca cert file'),
    cfg.BoolOpt(
        'use_ssl',
        default=False,
        deprecated_for_removal=True,
        deprecated_reason='This option has no effect.',
        help=_('SSL Enabled/Disabled'),
    ),
    cfg.StrOpt(
        "namespace",
        help=_(
            "Vault Namespace to use for all requests to Vault. "
            "Vault Namespaces feature is available only in "
            "Vault Enterprise"
        ),
    ),
    cfg.FloatOpt(
        'timeout',
        default=60,
        help=_('Timeout (in seconds) in each request to Vault'),
    ),
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

    _conf: cfg.ConfigOpts
    _session: requests.Session
    _root_token_id: str | None
    _approle_role_id: str | None
    _approle_secret_id: str | None
    _cached_approle_token_id: str | None
    _approle_token_ttl: int | None
    _approle_token_issue: datetime.datetime | None
    _kv_mountpoint: str
    _kv_path: str | None
    _kv_version: int
    _vault_url: str
    _namespace: str | None
    _timeout: float
    _verify_server: str | bool

    def __init__(self, configuration: cfg.ConfigOpts) -> None:
        self._conf = configuration
        self._conf.register_opts(_vault_opts, group=_VAULT_OPT_GROUP)
        self._session = requests.Session()
        self._root_token_id = self._conf.vault.root_token_id
        self._approle_role_id = self._conf.vault.approle_role_id
        self._approle_secret_id = self._conf.vault.approle_secret_id
        self._cached_approle_token_id = None
        self._approle_token_ttl = None
        self._approle_token_issue = None
        self._kv_mountpoint = self._conf.vault.kv_mountpoint
        self._kv_path = self._conf.vault.kv_path
        self._kv_version = self._conf.vault.kv_version
        self._vault_url = self._conf.vault.vault_url
        self._namespace = self._conf.vault.namespace
        self._timeout = self._conf.vault.timeout
        if self._vault_url.startswith("https://"):
            self._verify_server = self._conf.vault.ssl_ca_crt_file or True
        else:
            self._verify_server = False

    def _get_url(self) -> str:
        if not self._vault_url.endswith('/'):
            self._vault_url += '/'
        return self._vault_url

    def _get_resource_url(self, key_id: str | None = None) -> str:
        return '{}v1/{}/{}{}{}'.format(
            self._get_url(),
            self._kv_mountpoint,
            # no key_id is for listing and 'data/' doesn't works
            ''
            if self._kv_version == 1
            else 'data/'
            if key_id
            else 'metadata/',
            (self._kv_path + '/') if self._kv_path else '',
            key_id if key_id else '?list=true',
        )

    @property
    def _approle_token_id(self) -> str | None:
        if (
            self._approle_token_issue is not None
            and self._approle_token_ttl is not None
            and timeutils.is_older_than(
                self._approle_token_issue, self._approle_token_ttl
            )
        ):
            self._cached_approle_token_id = None
        return self._cached_approle_token_id

    def _set_namespace(self, headers: dict[str, str]) -> dict[str, str]:
        if self._namespace:
            headers["X-Vault-Namespace"] = self._namespace
        return headers

    def _build_auth_headers(self) -> dict[str, str]:
        if self._root_token_id:
            return self._set_namespace({'X-Vault-Token': self._root_token_id})

        if self._approle_token_id:
            return self._set_namespace(
                {'X-Vault-Token': self._approle_token_id}
            )

        if self._approle_role_id:
            params: dict[str, str] = {'role_id': self._approle_role_id}
            if self._approle_secret_id:
                params['secret_id'] = self._approle_secret_id
            approle_login_url = f'{self._get_url()}v1/auth/approle/login'
            token_issue_utc = timeutils.utcnow()
            headers = self._set_namespace({})
            try:
                resp = self._session.post(
                    url=approle_login_url,
                    json=params,
                    headers=headers,
                    verify=self._verify_server,
                    timeout=self._timeout,
                )
            except Exception as ex:
                raise exception.KeyManagerError(str(ex))

            if resp.status_code in _EXCEPTIONS_BY_CODE:
                raise exception.KeyManagerError(resp.reason)
            if resp.status_code == requests.codes['forbidden']:
                raise exception.Forbidden()

            resp_data = resp.json()

            if resp.status_code == requests.codes['bad_request']:
                raise exception.KeyManagerError(', '.join(resp_data['errors']))

            self._cached_approle_token_id = resp_data['auth']['client_token']
            self._approle_token_issue = token_issue_utc
            self._approle_token_ttl = resp_data['auth']['lease_duration']
            return self._set_namespace(
                {'X-Vault-Token': self._cached_approle_token_id}
            )

        return {}

    def _do_http_request(
        self,
        method: Callable[..., requests.Response],
        resource: str,
        json: dict[str, Any] | None = None,
    ) -> requests.Response:
        headers = self._build_auth_headers()

        try:
            resp = method(
                resource,
                headers=headers,
                json=json,
                verify=self._verify_server,
                timeout=self._timeout,
            )
        except Exception as ex:
            raise exception.KeyManagerError(str(ex))

        if resp.status_code in _EXCEPTIONS_BY_CODE:
            raise exception.KeyManagerError(resp.reason)
        if resp.status_code == requests.codes['forbidden']:
            raise exception.Forbidden()

        return resp

    def create_key_pair(
        self,
        context: Context | None,
        algorithm: str,
        length: int,
        expiration: str | None = None,
        name: str | None = None,
    ) -> tuple[str, str]:
        """Creates an asymmetric key pair."""

        if algorithm.lower() != 'rsa':
            raise NotImplementedError(
                "VaultKeyManager only implements rsa keys"
            )

        priv_key = rsa.generate_private_key(
            public_exponent=65537, key_size=length, backend=default_backend()
        )

        private_key = pri_key.PrivateKey(
            'RSA',
            length,
            priv_key.private_bytes(
                Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
            ),
        )

        private_key_id = uuid.uuid4().hex
        private_id = self._store_key_value(private_key_id, private_key)

        # pub_key = priv_key.public_key()
        public_key = pub_key.PublicKey(
            'RSA',
            length,
            priv_key.public_key().public_bytes(
                Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
            ),
        )

        public_key_id = uuid.uuid4().hex
        public_id = self._store_key_value(public_key_id, public_key)

        return private_id, public_id

    def _store_key_value(
        self, key_id: str, value: managed_object.ManagedObject
    ) -> str:

        type_value = self._secret_type_dict.get(type(value))
        if type_value is None:
            raise exception.KeyManagerError(
                f"Unknown type for value : {value!r}"
            )

        encoded = value.get_encoded()
        if encoded is None:
            raise exception.KeyManagerError("Cannot store object without data")

        record: dict[str, Any] = {
            'type': type_value,
            'value': binascii.hexlify(encoded).decode('utf-8'),
            'algorithm': (
                value.algorithm if hasattr(value, 'algorithm') else None
            ),
            'bit_length': (
                value.bit_length if hasattr(value, 'bit_length') else None
            ),
            'name': value.name,
            'created': value.created,
        }
        if self._kv_version > 1:
            record = {'data': record}

        self._do_http_request(
            self._session.post, self._get_resource_url(key_id), json=record
        )

        return key_id

    def create_key(
        self,
        context: Context | None,
        algorithm: str,
        length: int,
        expiration: str | None = None,
        name: str | None = None,
    ) -> str:
        """Creates a symmetric key."""

        if length % 8:
            msg = _("Length must be multiple of 8.")
            raise ValueError(msg)

        key_id = uuid.uuid4().hex
        key_value = os.urandom((length or 256) // 8)
        key = sym_key.SymmetricKey(
            algorithm,
            length or 256,
            key_value,
            key_id,
            # FIXME(stephenfin): This should be an int yet we pass name (a str)
            # if set?
            name or int(time.time()),  # type: ignore[arg-type]
        )

        return self._store_key_value(key_id, key)

    def store(
        self,
        context: Context | None,
        key_value: managed_object.ManagedObject,
        expiration: str | None = None,
    ) -> str:
        """Stores (i.e., registers) a key with the key manager."""

        key_id = uuid.uuid4().hex
        return self._store_key_value(key_id, key_value)

    def get(
        self, context: Context | None, key_id: str, metadata_only: bool = False
    ) -> managed_object.ManagedObject:
        """Retrieves the key identified by the specified id."""

        if not key_id:
            raise exception.KeyManagerError('key identifier not provided')

        resp = self._do_http_request(
            self._session.get, self._get_resource_url(key_id)
        )

        if resp.status_code == requests.codes['not_found']:
            raise exception.ManagedObjectNotFoundError(uuid=key_id)

        record = resp.json()['data']
        if self._kv_version > 1:
            record = record['data']

        key = None if metadata_only else binascii.unhexlify(record['value'])

        clazz: type[managed_object.ManagedObject] | None = None
        for type_clazz, type_name in self._secret_type_dict.items():
            if type_name == record['type']:
                clazz = type_clazz

        if clazz is None:
            raise exception.KeyManagerError(
                "Unknown type : {!r}".format(record['type'])
            )

        # TODO(stephenfin): Use isinstance checks instead of hasattr checks
        if hasattr(clazz, 'algorithm') and hasattr(clazz, 'bit_length'):
            return clazz(  # type: ignore[call-arg]
                record['algorithm'],
                record['bit_length'],
                key,  # type: ignore[arg-type]
                record['name'],
                record['created'],
                key_id,
            )
        else:
            return clazz(
                key,  # type: ignore[arg-type]
                record['name'],
                record['created'],
                key_id,  # type: ignore[arg-type]
            )

    def delete(
        self, context: Context | None, key_id: str, force: bool = False
    ) -> None:
        """Represents deleting the key.

        The 'force' parameter is not used whatsoever and only kept to allow
        consistency with the Barbican implementation.
        """

        if not key_id:
            raise exception.KeyManagerError('key identifier not provided')

        resp = self._do_http_request(
            self._session.delete, self._get_resource_url(key_id)
        )

        if resp.status_code == requests.codes['not_found']:
            raise exception.ManagedObjectNotFoundError(uuid=key_id)

    def add_consumer(
        self,
        context: Context | None,
        managed_object_id: str,
        consumer_data: dict[str, str],
    ) -> NoReturn:
        raise NotImplementedError(
            "VaultKeyManager does not implement adding consumers"
        )

    def remove_consumer(
        self,
        context: Context | None,
        managed_object_id: str,
        consumer_data: dict[str, str],
    ) -> NoReturn:
        raise NotImplementedError(
            "VaultKeyManager does not implement deleting consumers"
        )

    def list(
        self,
        context: Context | None,
        object_type: type[managed_object.ManagedObject] | None = None,
        metadata_only: bool = False,
    ) -> list[managed_object.ManagedObject]:
        """Lists the managed objects given the criteria."""

        if object_type and object_type not in self._secret_type_dict:
            msg = _("Invalid secret type: %s") % object_type
            raise exception.KeyManagerError(reason=msg)

        resp = self._do_http_request(
            self._session.get, self._get_resource_url()
        )

        keys: list[str]
        if resp.status_code == requests.codes['not_found']:
            keys = []
        else:
            keys = resp.json()['data']['keys']

        objects: list[managed_object.ManagedObject] = []
        for obj_id in keys:
            try:
                obj = self.get(context, obj_id, metadata_only=metadata_only)
                if object_type is None or isinstance(obj, object_type):
                    objects.append(obj)
            except exception.ManagedObjectNotFoundError as e:
                LOG.warning(
                    "Error occurred while retrieving object "
                    "metadata, not adding it to the list: %s",
                    e,
                )
                pass
        return objects

    def list_options_for_discovery(
        self,
    ) -> builtins.list[tuple[str | None, builtins.list[cfg.Opt]]]:
        return [(_VAULT_OPT_GROUP, _vault_opts)]
