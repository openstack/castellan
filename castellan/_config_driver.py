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

r"""
Castellan Oslo Config Driver
----------------------------

This driver is an oslo.config backend driver implemented with Castellan. It
extends oslo.config's capabilities by enabling it to retrieve configuration
values from a secret manager behind Castellan.

The setup of a Castellan configuration source is as follow::

    [DEFAULT]
    config_source = castellan_config_group

    [castellan_config_group]
    driver = castellan
    config_file = castellan.conf
    mapping_file = mapping.conf

In the following sessions, you can find more information about this driver's
classes and its options.

The Driver Class
================

.. autoclass:: CastellanConfigurationSourceDriver

The Configuration Source Class
==============================

.. autoclass:: CastellanConfigurationSource

"""
from castellan.common.exception import KeyManagerError
from castellan.common.exception import ManagedObjectNotFoundError
from castellan import key_manager

from oslo_config import cfg
from oslo_config import sources
from oslo_log import log

LOG = log.getLogger(__name__)


class CastellanConfigurationSourceDriver(sources.ConfigurationSourceDriver):
    """A backend driver for configuration values served through castellan.

    Required options:
      - config_file: The castellan configuration file.

      - mapping_file: A configuration/castellan_id mapping file. This file
                      creates connections between configuration options and
                      castellan ids. The group and option name remains the
                      same, while the value gets stored a secret manager behind
                      castellan and is replaced by its castellan id. The ids
                      will be used to fetch the values through castellan.
    """

    _castellan_driver_opts = [
        cfg.StrOpt(
            'config_file',
            required=True,
            sample_default='etc/castellan/castellan.conf',
            help=('The path to a castellan configuration file.'),
        ),
        cfg.StrOpt(
            'mapping_file',
            required=True,
            sample_default='etc/castellan/secrets_mapping.conf',
            help=('The path to a configuration/castellan_id mapping file.'),
        ),
    ]

    def list_options_for_discovery(self):
        return self._castellan_driver_opts

    def open_source_from_opt_group(self, conf, group_name):
        conf.register_opts(self._castellan_driver_opts, group_name)

        return CastellanConfigurationSource(
            group_name,
            conf[group_name].config_file,
            conf[group_name].mapping_file)


class CastellanConfigurationSource(sources.ConfigurationSource):
    """A configuration source for configuration values served through castellan.

    :param config_file: The path to a castellan configuration file.

    :param mapping_file: The path to a configuration/castellan_id mapping file.
    """

    def __init__(self, group_name, config_file, mapping_file):
        conf = cfg.ConfigOpts()
        conf(args=[], default_config_files=[config_file])

        self._name = group_name
        self._mngr = key_manager.API(conf)
        self._mapping = {}

        cfg.ConfigParser(mapping_file, self._mapping).parse()

    def get(self, group_name, option_name, opt):
        try:
            group_name = group_name or "DEFAULT"

            castellan_id = self._mapping[group_name][option_name][0]

            return (self._mngr.get("ctx", castellan_id).get_encoded().decode(),
                    cfg.LocationInfo(cfg.Locations.user, castellan_id))

        except KeyError:
            # no mapping 'option = castellan_id'
            LOG.info("option '[%s] %s' not present in '[%s] mapping_file'",
                     group_name, option_name, self._name)

        except KeyManagerError:
            # bad mapping 'option =' without a castellan_id
            LOG.warning("missing castellan_id for option "
                        "'[%s] %s' in '[%s] mapping_file'",
                        group_name, option_name, self._name)

        except ManagedObjectNotFoundError:
            # good mapping, but unknown castellan_id by secret manager
            LOG.warning("invalid castellan_id for option "
                        "'[%s] %s' in '[%s] mapping_file'",
                        group_name, option_name, self._name)

        return (sources._NoValue, None)
