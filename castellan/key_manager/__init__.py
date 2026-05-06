# Copyright (c) 2015 The Johns Hopkins University/Applied Physics Laboratory
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

from typing import cast

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import importutils
from stevedore import driver
from stevedore import exception

from castellan.key_manager import key_manager
from castellan.key_manager import migration

LOG = logging.getLogger(__name__)

key_manager_opts = [
    cfg.StrOpt(
        'backend',
        default='barbican',
        deprecated_name='api_class',
        deprecated_group='key_manager',
        help='Specify the key manager implementation. Options are '
        '"barbican" and "vault". Default is  "barbican". Will '
        'support the  values earlier set using '
        '[key_manager]/api_class for some time.',
    ),
]


def API(
    configuration: cfg.ConfigOpts | None = None,
) -> key_manager.KeyManager:
    conf = configuration or cfg.CONF
    conf.register_opts(key_manager_opts, group='key_manager')

    mgr: driver.DriverManager[key_manager.KeyManager]
    try:
        mgr = driver.DriverManager(
            "castellan.drivers",
            conf.key_manager.backend,
            invoke_on_load=True,
            invoke_args=(conf,),
        )
        # we know the return type will be an instance since invoke_on_load is
        # true: stevedore just needs better hints
        key_mgr = cast(key_manager.KeyManager, mgr.driver)
    except exception.NoMatches:
        LOG.warning(
            "Deprecation Warning : %s is not a stevedore based driver, "
            "trying to load it as a class",
            conf.key_manager.backend,
        )
        cls = importutils.import_class(conf.key_manager.backend)
        key_mgr = cls(configuration=conf)

    return migration.handle_migration(conf, key_mgr)
