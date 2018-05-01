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
from oslo_config import cfg
from oslo_log import log

from castellan import key_manager as km
try:
    from castellan.key_manager import barbican_key_manager as bkm
except ImportError:
    bkm = None

try:
    from castellan.key_manager import vault_key_manager as vkm
except ImportError:
    vkm = None

from castellan.common import utils

_DEFAULT_LOG_LEVELS = ['castellan=WARN']

_DEFAULT_LOGGING_CONTEXT_FORMAT = ('%(asctime)s.%(msecs)03d %(process)d '
                                   '%(levelname)s %(name)s [%(request_id)s '
                                   '%(user_identity)s] %(instance)s'
                                   '%(message)s')


def set_defaults(conf, backend=None, barbican_endpoint=None,
                 barbican_api_version=None, auth_endpoint=None,
                 retry_delay=None, number_of_retries=None, verify_ssl=None,
                 api_class=None, vault_root_token_id=None, vault_url=None,
                 vault_ssl_ca_crt_file=None, vault_use_ssl=None,
                 barbican_endpoint_type=None):
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
    :param vault_root_token_id: Use this for the root token id for vault.
    :param vault_url: Use this for the url for vault.
    :param vault_use_ssl: Use this to force vault driver to use ssl.
    :param vault_ssl_ca_crt_file: Use this for the CA file for vault.
    :param barbican_endpoint_type: Use this to specify the type of URL.
    :                              Valid values are: public, internal or admin.
    """
    conf.register_opts(km.key_manager_opts, group='key_manager')
    if bkm:
        conf.register_opts(bkm.barbican_opts, group=bkm.BARBICAN_OPT_GROUP)
    if vkm:
        conf.register_opts(vkm.vault_opts, group=vkm.VAULT_OPT_GROUP)

    # Use the new backend option if set or fall back to the older api_class
    default_backend = backend or api_class
    if default_backend is not None:
        conf.set_default('backend', default_backend, group='key_manager')

    if bkm is not None:
        if barbican_endpoint is not None:
            conf.set_default('barbican_endpoint', barbican_endpoint,
                             group=bkm.BARBICAN_OPT_GROUP)
        if barbican_api_version is not None:
            conf.set_default('barbican_api_version', barbican_api_version,
                             group=bkm.BARBICAN_OPT_GROUP)
        if auth_endpoint is not None:
            conf.set_default('auth_endpoint', auth_endpoint,
                             group=bkm.BARBICAN_OPT_GROUP)
        if retry_delay is not None:
            conf.set_default('retry_delay', retry_delay,
                             group=bkm.BARBICAN_OPT_GROUP)
        if number_of_retries is not None:
            conf.set_default('number_of_retries', number_of_retries,
                             group=bkm.BARBICAN_OPT_GROUP)
        if verify_ssl is not None:
            conf.set_default('verify_ssl', verify_ssl,
                             group=bkm.BARBICAN_OPT_GROUP)
        if barbican_endpoint_type is not None:
            conf.set_default('barbican_endpoint_type', barbican_endpoint_type,
                             group=bkm.BARBICAN_OPT_GROUP)

    if vkm is not None:
        if vault_root_token_id is not None:
            conf.set_default('root_token_id', vault_root_token_id,
                             group=vkm.VAULT_OPT_GROUP)
        if vault_url is not None:
            conf.set_default('vault_url', vault_url,
                             group=vkm.VAULT_OPT_GROUP)
        if vault_ssl_ca_crt_file is not None:
            conf.set_default('ssl_ca_crt_file', vault_ssl_ca_crt_file,
                             group=vkm.VAULT_OPT_GROUP)
        if vault_use_ssl is not None:
            conf.set_default('use_ssl', vault_use_ssl,
                             group=vkm.VAULT_OPT_GROUP)


def enable_logging(conf=None, app_name='castellan'):
    conf = conf or cfg.CONF

    log.register_options(conf)
    log.set_defaults(_DEFAULT_LOGGING_CONTEXT_FORMAT,
                     _DEFAULT_LOG_LEVELS)

    log.setup(conf, app_name)


def list_opts():
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
    key_manager_opts = []
    key_manager_opts.extend(km.key_manager_opts)
    key_manager_opts.extend(utils.credential_opts)
    opts = [('key_manager', key_manager_opts)]

    if bkm is not None:
        opts.append((bkm.BARBICAN_OPT_GROUP, bkm.barbican_opts))
    if vkm is not None:
        opts.append((vkm.VAULT_OPT_GROUP, vkm.vault_opts))
    return opts
