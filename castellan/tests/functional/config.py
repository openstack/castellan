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

import os

from oslo_config import cfg

TEST_CONF = None

identity_group = cfg.OptGroup(name='identity')
identity_options = [
    cfg.StrOpt('auth_url',
               default='http://localhost/identity/v3',
               help='Keystone endpoint'),
    cfg.StrOpt('username',
               default='admin',
               help='Keystone username'),
    cfg.StrOpt('password',
               default='secretadmin',
               help='Password used with Keystone username'),
    cfg.StrOpt('project_name',
               default='admin',
               help='Name of project, used by the given username'),
    cfg.StrOpt('user_domain_name',
               default='Default',
               help='Name of domain, used by the given username'),
    cfg.StrOpt('project_domain_name',
               default='Default',
               help='Name of domain, used by the given project')]


def setup_config(config_file=''):
    global TEST_CONF
    TEST_CONF = cfg.ConfigOpts()

    TEST_CONF.register_group(identity_group)
    TEST_CONF.register_opts(identity_options, group=identity_group)

    config_to_load = []
    local_config = './etc/castellan/castellan-functional.conf'
    main_config = '/etc/castellan/castellan-functional.conf'
    if os.path.isfile(config_file):
        config_to_load.append(config_file)
    elif os.path.isfile(local_config):
        config_to_load.append(local_config)
    elif os.path.isfile(main_config):
        config_to_load.append(main_config)

    TEST_CONF(
        (),  # Required to load an anonymous configuration
        default_config_files=config_to_load
    )


def get_config():
    if not TEST_CONF:
        setup_config()
    return TEST_CONF


def list_opts():
    yield identity_group.name, identity_options
