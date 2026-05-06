# Copyright 2017 Red Hat, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import binascii

from oslo_config import cfg
from oslo_log import log as logging

from castellan.common import exception
from castellan.common.objects import managed_object
from castellan.common.objects import symmetric_key
from castellan.key_manager import key_manager
from castellan.key_manager.key_manager import Context

LOG = logging.getLogger(__name__)


def handle_migration(
    conf: cfg.ConfigOpts, key_mgr: key_manager.KeyManager
) -> key_manager.KeyManager:
    try:
        conf.register_opt(cfg.StrOpt('fixed_key'), group='key_manager')
    except cfg.DuplicateOptError:
        pass

    if (
        conf.key_manager.fixed_key is not None
        and not conf.key_manager.backend.endswith('ConfKeyManager')
    ):
        LOG.warning(
            "Using MigrationKeyManager to provide support for legacy "
            "fixed_key encryption"
        )

        # mypy can't handle dynamic types
        class MigrationKeyManager(type(key_mgr)):  # type: ignore[misc]
            def __init__(self, configuration: cfg.ConfigOpts) -> None:
                self.fixed_key = configuration.key_manager.fixed_key
                self.fixed_key_id = '00000000-0000-0000-0000-000000000000'
                super().__init__(configuration)

            def get(
                self, context: Context | None, managed_object_id: str
            ) -> managed_object.ManagedObject:
                if managed_object_id == self.fixed_key_id:
                    LOG.debug(
                        "Processing request for secret associated "
                        "with fixed_key key ID"
                    )

                    if context is None:
                        raise exception.Forbidden()

                    key_bytes = bytes(binascii.unhexlify(self.fixed_key))
                    secret: managed_object.ManagedObject = (
                        symmetric_key.SymmetricKey(
                            'AES', len(key_bytes) * 8, key_bytes
                        )
                    )
                else:
                    secret = super().get(context, managed_object_id)
                return secret

            def delete(
                self, context: Context | None, managed_object_id: str
            ) -> None:
                if managed_object_id == self.fixed_key_id:
                    LOG.debug(
                        "Not deleting key associated with fixed_key key ID"
                    )

                    if context is None:
                        raise exception.Forbidden()
                else:
                    super().delete(context, managed_object_id)

        key_mgr = MigrationKeyManager(configuration=conf)

    return key_mgr
