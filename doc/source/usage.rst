========
Usage
========

To use castellan in a project::

    import castellan


Configuring castellan
~~~~~~~~~~~~~~~~~~~~~

Castellan contains several options which control the key management
service usage and the configuration of that service. It also contains
functions to help configure the defaults and produce listings for use
with the ``oslo-config-generator`` application.

In general, castellan configuration is handled by passing an
``oslo_config.cfg.ConfigOpts`` object into the
``castellan.key_manager.API`` call when creating your key manager. By
default, when no ``ConfigOpts`` object is provided, the key manager will
use the global ``oslo_config.cfg.CONF`` object.

**Example. Using the global CONF object for configuration.**

.. code:: python

    from castellan import key_manager

    manager = key_manager.API()

**Example. Using a predetermined configuration object.**

.. code:: python

    from oslo_config import cfg
    from castellan import key_manager

    conf = cfg.ConfigOpts()
    manager = key_manager.API(configuration=conf)

Controlling default options
---------------------------

To change the default behavior of castellan, and the key management service
it uses, the ``castellan.options`` module provides the ``set_defaults``
function. This function can be used at run-time to change the behavior of
the library or the key management service provider.

**Example. Changing the barbican endpoint.**

.. code:: python

    from oslo_config import cfg
    from castellan import options
    from castellan import key_manager

    conf = cfg.ConfigOpts()
    options.set_defaults(conf, barbican_endpoint='http://192.168.0.1:9311/')
    manager = key_manager.API(conf)

**Example. Changing the key manager provider while using the global
configuration.**

.. code:: python

    from oslo_config import cfg
    from castellan import options
    from castellan import key_manager

    options.set_defaults(cfg.CONF, api_class='some.other.KeyManager')
    manager = key_manager.API()

Generating sample configuration files
-------------------------------------

Castellan includes a tox configuration for creating a sample configuration
file. This file will contain only the values that will be used by
castellan. To produce this file, run the following command from the
root of the castellan project directory:

.. code:: console

    $ tox -e genconfig

Adding castellan to configuration files
---------------------------------------

One common task for OpenStack projects is to create project configuration
files. Castellan provides a ``list_opts`` function in the
``castellan.options`` module to aid in generating these files when using
the ``oslo-config-generator``. This function can be specified in the
:file:`setup.cfg` file of your project to inform oslo of the
configuration options. *Note, this will use the default values supplied
by the castellan package.*

**Example. Adding castellan to the oslo.config entry point.**

.. code:: ini

    [entry_points]
    oslo.config.opts =
        castellan.config = castellan.options:list_opts

For more information on the oslo configuration generator, please see
http://docs.openstack.org/developer/oslo.config/generator.html
