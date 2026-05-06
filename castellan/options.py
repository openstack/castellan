# Copyright (c) 2015 Red Hat, Inc.
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

import warnings

from oslo_config import cfg
from oslo_log import log
from stevedore import ExtensionManager

from castellan.common import utils
from castellan import key_manager
from castellan.key_manager import barbican_key_manager as bkm
from castellan.key_manager import key_manager as base_key_manager
from castellan.key_manager import vault_key_manager as vkm

_DEFAULT_LOG_LEVELS = ['castellan=WARN']


def set_defaults(
    conf: cfg.ConfigOpts,
    backend: str | None = None,
    barbican_endpoint: str | None = None,
    barbican_api_version: str | None = None,
    auth_endpoint: str | None = None,
    retry_delay: int | None = None,
    number_of_retries: int | None = None,
    verify_ssl: bool | None = None,
    verify_ssl_path: str | None = None,
    api_class: str | None = None,
    vault_root_token_id: str | None = None,
    vault_approle_role_id: str | None = None,
    vault_approle_secret_id: str | None = None,
    vault_kv_mountpoint: str | None = None,
    vault_kv_path: str | None = None,
    vault_url: str | None = None,
    vault_ssl_ca_crt_file: str | None = None,
    vault_use_ssl: bool | None = None,
    vault_namespace: str | None = None,
    barbican_endpoint_type: str | None = None,
    vault_kv_version: int | None = None,
) -> None:
    """Set defaults for configuration values.

    Overrides the default options values.
    :param conf: Config instance in which to set default options.
    :param api_class: The full class name of the key manager API class.
    :param barbican_endpoint: Use this endpoint to connect to Barbican.
    :param barbican_api_version: Version of the Barbican API.
    :param auth_endpoint: Use this endpoint to connect to Keystone.
    :param retry_delay: Use this attribute to set retry delay.
    :param number_of_retries: Use this attribute to set number of retries.
    :param verify_ssl: Use this to specify if ssl should be verified.
    :param verify_ssl_path: Use this to specify the CA path.
    :param vault_root_token_id: Use this for the root token id for vault.
    :param vault_approle_role_id: Use this for the approle role_id for vault.
    :param vault_approle_secret_id: Use this for the approle secret_id
                                    for vault.
    :param vault_kv_mountpoint: Mountpoint of KV store in vault to use.
    :param vault_kv_path: Path relative to root of KV store in Vault to use.
    :param vault_url: Use this for the url for vault.
    :param vault_use_ssl: Use this to force vault driver to use ssl.
    :param vault_ssl_ca_crt_file: Use this for the CA file for vault.
    :param vault_namespace: Namespace to use for all requests to Vault.
    :param barbican_endpoint_type: Use this to specify the type of URL.
    :                              Valid values are: public, internal or admin.
    :param vault_kv_version: Use this for the kv version for vault.
    """
    conf.register_opts(key_manager.key_manager_opts, group='key_manager')

    ext_mgr: ExtensionManager[base_key_manager.KeyManager]
    ext_mgr = ExtensionManager(
        "castellan.drivers", invoke_on_load=True, invoke_args=(cfg.CONF,)
    )

    for km in ext_mgr.names():
        obj = ext_mgr[km].obj
        if obj is not None:
            for group, opts in obj.list_options_for_discovery():
                conf.register_opts(opts, group=group)

    # Use the new backend option if set or fall back to the older api_class
    default_backend = backend or api_class
    if default_backend is not None:
        conf.set_default('backend', default_backend, group='key_manager')

    if barbican_endpoint is not None:
        conf.set_default(
            'barbican_endpoint',
            barbican_endpoint,
            group=bkm._BARBICAN_OPT_GROUP,
        )
    if barbican_api_version is not None:
        conf.set_default(
            'barbican_api_version',
            barbican_api_version,
            group=bkm._BARBICAN_OPT_GROUP,
        )
    if auth_endpoint is not None:
        conf.set_default(
            'auth_endpoint', auth_endpoint, group=bkm._BARBICAN_OPT_GROUP
        )
    if retry_delay is not None:
        conf.set_default(
            'retry_delay', retry_delay, group=bkm._BARBICAN_OPT_GROUP
        )
    if number_of_retries is not None:
        conf.set_default(
            'number_of_retries',
            number_of_retries,
            group=bkm._BARBICAN_OPT_GROUP,
        )
    if verify_ssl is not None:
        conf.set_default(
            'verify_ssl', verify_ssl, group=bkm._BARBICAN_OPT_GROUP
        )
    if verify_ssl_path is not None:
        conf.set_default(
            'verify_ssl_path', verify_ssl_path, group=bkm._BARBICAN_OPT_GROUP
        )
    if barbican_endpoint_type is not None:
        conf.set_default(
            'barbican_endpoint_type',
            barbican_endpoint_type,
            group=bkm._BARBICAN_OPT_GROUP,
        )

    if vault_root_token_id is not None:
        conf.set_default(
            'root_token_id', vault_root_token_id, group=vkm._VAULT_OPT_GROUP
        )
    if vault_approle_role_id is not None:
        conf.set_default(
            'approle_role_id',
            vault_approle_role_id,
            group=vkm._VAULT_OPT_GROUP,
        )
    if vault_approle_secret_id is not None:
        conf.set_default(
            'approle_secret_id',
            vault_approle_secret_id,
            group=vkm._VAULT_OPT_GROUP,
        )
    if vault_kv_mountpoint is not None:
        conf.set_default(
            'kv_mountpoint', vault_kv_mountpoint, group=vkm._VAULT_OPT_GROUP
        )
    if vault_kv_path is not None:
        conf.set_default('kv_path', vault_kv_path, group=vkm._VAULT_OPT_GROUP)
    if vault_url is not None:
        conf.set_default('vault_url', vault_url, group=vkm._VAULT_OPT_GROUP)
    if vault_ssl_ca_crt_file is not None:
        conf.set_default(
            'ssl_ca_crt_file',
            vault_ssl_ca_crt_file,
            group=vkm._VAULT_OPT_GROUP,
        )
    if vault_use_ssl is not None:
        warnings.warn(
            'use_ssl option is deprecated', category=DeprecationWarning
        )
    if vault_namespace is not None:
        conf.set_default(
            'namespace', vault_namespace, group=vkm._VAULT_OPT_GROUP
        )
    if vault_kv_version is not None:
        conf.set_default(
            'kv_version', vault_kv_version, group=vkm._VAULT_OPT_GROUP
        )


def enable_logging(
    conf: cfg.ConfigOpts | None = None, app_name: str = 'castellan'
) -> None:
    conf = conf or cfg.CONF

    log.register_options(conf)
    log.set_defaults(default_log_levels=_DEFAULT_LOG_LEVELS)

    log.setup(conf, app_name)


def list_opts() -> list[tuple[str | None, list[cfg.Opt]]]:
    """Returns a list of oslo.config options available in the library.

    The returned list includes all oslo.config options which may be registered
    at runtime by the library.

    Each element of the list is a tuple. The first element is the name of the
    group under which the list of elements in the second element will be
    registered. A group name of None corresponds to the [DEFAULT] group in
    config files.

    The purpose of this is to allow tools like the Oslo sample config file
    generator to discover the options exposed to users by this library.

    :returns: a list of (group_name, opts) tuples
    """
    key_manager_opts: list[cfg.Opt] = []
    key_manager_opts.extend(key_manager.key_manager_opts)
    key_manager_opts.extend(utils.credential_opts)
    opts: list[tuple[str | None, list[cfg.Opt]]] = [
        ('key_manager', key_manager_opts)
    ]

    ext_mgr: ExtensionManager[base_key_manager.KeyManager]
    ext_mgr = ExtensionManager(
        "castellan.drivers", invoke_on_load=True, invoke_args=(cfg.CONF,)
    )

    for driver_name in ext_mgr.names():
        obj = ext_mgr[driver_name].obj
        if obj is not None:
            opts.extend(obj.list_options_for_discovery())

    return opts
