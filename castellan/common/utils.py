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
Common utilities for Castellan.
"""

from castellan.common.credentials import keystone_password
from castellan.common.credentials import keystone_token
from castellan.common.credentials import password
from castellan.common.credentials import token
from castellan.common import exception

from oslo_config import cfg
from oslo_log import log as logging


LOG = logging.getLogger(__name__)

credential_opts = [
    # auth_type opt
    cfg.StrOpt('auth_type', default=None),

    # token opt
    cfg.StrOpt('token', default=None),

    # password opts
    cfg.StrOpt('username', default=None),
    cfg.StrOpt('password', default=None),

    # keystone credential opts
    cfg.StrOpt('user_id', default=None),
    cfg.StrOpt('user_domain_id', default=None),
    cfg.StrOpt('user_domain_name', default=None),
    cfg.StrOpt('trust_id', default=None),
    cfg.StrOpt('domain_id', default=None),
    cfg.StrOpt('domain_name', default=None),
    cfg.StrOpt('project_id', default=None),
    cfg.StrOpt('project_name', default=None),
    cfg.StrOpt('project_domain_id', default=None),
    cfg.StrOpt('project_domain_name', default=None),
    cfg.BoolOpt('reauthenticate', default=True)
]

OPT_GROUP = 'key_manager'


def credential_factory(conf=None, context=None):
    """This function provides a factory for credentials.

    It is used to create an appropriare credential object
    from a passed configuration. This should be called before
    making any calls to a key manager.

    :param conf: Configuration file which this factory method uses
    to generate a credential object. Note: In the future it will
    become a required field.
    :param context: Context used for authentication. It can be used
    in conjunction with the configuration file. If no conf is passed,
    then the context object will be converted to a KeystoneToken and
    returned. If a conf is passed then only the 'token' is grabbed from
    the context for the authentication types that require a token.
    :returns: A credential object used for authenticating with the
    Castellan key manager. Type of credential returned depends on
    config and/or context passed.
    """
    if conf:
        conf.register_opts(credential_opts, group=OPT_GROUP)

        if conf.key_manager.auth_type == 'token':
            if conf.key_manager.token:
                auth_token = conf.key_manager.token
            elif context:
                auth_token = context.auth_token
            else:
                raise exception.InsufficientCredentialDataError()

            return token.Token(auth_token)

        elif conf.key_manager.auth_type == 'password':
            return password.Password(
                conf.key_manager.username,
                conf.key_manager.password)

        elif conf.key_manager.auth_type == 'keystone_password':
            return keystone_password.KeystonePassword(
                conf.key_manager.password,
                username=conf.key_manager.username,
                user_id=conf.key_manager.user_id,
                user_domain_id=conf.key_manager.user_domain_id,
                user_domain_name=conf.key_manager.user_domain_name,
                trust_id=conf.key_manager.trust_id,
                domain_id=conf.key_manager.domain_id,
                domain_name=conf.key_manager.domain_name,
                project_id=conf.key_manager.project_id,
                project_name=conf.key_manager.project_name,
                project_domain_id=conf.key_manager.domain_id,
                project_domain_name=conf.key_manager.domain_name,
                reauthenticate=conf.key_manager.reauthenticate)

        elif conf.key_manager.auth_type == 'keystone_token':
            if conf.key_manager.token:
                auth_token = conf.key_manager.token
            elif context:
                auth_token = context.auth_token
            else:
                raise exception.InsufficientCredentialDataError()

            return keystone_token.KeystoneToken(
                auth_token,
                trust_id=conf.key_manager.trust_id,
                domain_id=conf.key_manager.domain_id,
                domain_name=conf.key_manager.domain_name,
                project_id=conf.key_manager.project_id,
                project_name=conf.key_manager.project_name,
                project_domain_id=conf.key_manager.domain_id,
                project_domain_name=conf.key_manager.domain_name,
                reauthenticate=conf.key_manager.reauthenticate)

        else:
            LOG.error("Invalid auth_type specified.")
            raise exception.AuthTypeInvalidError(
                type=conf.key_manager.auth_type)

    # for compatibility between _TokenData and RequestContext
    if hasattr(context, 'tenant') and context.tenant:
        project_id = context.tenant
    elif hasattr(context, 'project_id') and context.project_id:
        project_id = context.project_id

    return keystone_token.KeystoneToken(
        context.auth_token,
        project_id=project_id)
