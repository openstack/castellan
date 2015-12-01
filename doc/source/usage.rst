=====
Usage
=====

This document describes some of the common usage patterns for Castellan. When
incorporating this package into your applications, care should be taken to
consider the key manager behavior you wish to encapsulate and the OpenStack
deployments on which your application will run.

Basic usage
~~~~~~~~~~~

Castellan works on the principle of providing an abstracted key manager based
on your configuration. In this manner, several different management services
can be supported through a single interface.

In addition to the key manager, Castellan also provides primitives for
various types of secrets (for example, asymmetric keys, simple passphrases,
and certificates). These primitives are used in conjunction with the key
manager to create, store, retrieve, and destroy managed secrets.

Another fundamental concept to using Castellan is the context object, most
frequently inherited from ``oslo.context.RequestContext``. This object
represents information that is contained in the current request, and is
usually populated in the WSGI pipeline. The information contained in this
object will be used by Castellan to interact with the specific key manager
that is being abstracted.

**Example. Creating RequestContext from Keystone Client**

.. code:: python

    from keystoneclient.v3 import client
    from oslo_context import context

    username = 'admin'
    password = 'openstack'
    project_name = 'admin'
    auth_url = 'http://localhost:5000/v3'
    keystone_client = client.Client(username=username,
                                    password=password,
                                    project_name=project_name,
                                    auth_url=auth_url,
                                    project_domain_id='default')

    project_list = keystone_client.projects.list(name=project_name)

    ctxt = context.RequestContext(auth_token=keystone_client.auth_token,
                                  tenant=project_list[0].id)

ctxt can then be passed into any key_manager api call which requires
a RequestContext object.

**Example. Creating and storing a key.**

.. code:: python

    import myapp
    from castellan.common.objects import passphrase
    from castellan import key_manager

    key = passphrase.Passphrase('super_secret_password')
    manager = key_manager.API()
    stored_key_id = manager.store(myapp.context(), key)

To begin with, we'd like to create a key to manage. We create a simple
passphrase key, then instantiate the key manager, and finally store it to
the manager service. We record the key identifier for later usage.

**Example. Retrieving a key and checking the contents.**

.. code:: python

    import myapp
    from castellan import key_manager

    manager = key_manager.API()
    key = manager.get(myapp.context(), stored_key_id)
    if key.get_encoded() == 'super_secret_password':
        myapp.do_secret_stuff()

This example demonstrates retrieving a stored key from the key manager service
and checking its contents. First we instantiate the key manager, then
retrieve the key using a previously stored identifier, and finally we check
the validity of key before performing our restricted actions.

**Example. Deleting a key.**

.. code:: python

    import myapp
    from castellan import key_manager

    manager = key_manager.API()
    manager.delete(myapp.context(), stored_key_id)

Having finished our work with the key, we can now delete it from the key
manager service. We once again instantiate a key manager, then we simply
delete the key by using its identifier. Under normal conditions, this call
will not return anything but may raise exceptions if there are communication,
identification, or authorization issues.

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

Logging from within Castellan
-----------------------------

Castellan uses ``oslo_log`` for logging. Log information will be generated
if your application has configured the ``oslo_log`` module. If your
application does not use ``oslo_log`` then you can enable default logging
using ``enable_logging`` in the ``castellan.options`` module.

**Example. Enabling default logging.**

.. code:: python

    from castellan import options
    from castellan import key_manager

    options.enable_logging()
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
