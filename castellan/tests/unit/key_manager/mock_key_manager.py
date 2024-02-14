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

"""
A mock implementation of a key manager that stores keys in a dictionary.

This key manager implementation is primarily intended for testing. In
particular, it does not store keys persistently. Lack of a centralized key
store also makes this implementation unsuitable for use among different
services.

Note: Instantiating this class multiple times will create separate key stores.
Keys created in one instance will not be accessible from other instances of
this class.
"""

import binascii
import copy
import random

from cryptography.hazmat import backends
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from oslo_utils import uuidutils

from castellan.common import exception
from castellan.common.objects import private_key as pri_key
from castellan.common.objects import public_key as pub_key
from castellan.common.objects import symmetric_key as sym_key
from castellan.key_manager import key_manager


class MockKeyManager(key_manager.KeyManager):
    """Mocking manager for integration tests.

    This mock key manager implementation supports all the methods specified
    by the key manager interface. This implementation stores keys within a
    dictionary, and as a result, it is not acceptable for use across different
    services. Side effects (e.g., raising exceptions) for each method are
    handled as specified by the key manager interface.

    This key manager is not suitable for use in production deployments.
    """

    def __init__(self, configuration=None):
        self.conf = configuration
        self.keys = {}

    def _generate_hex_key(self, key_length):
        # hex digit => 4 bits
        length = int(key_length / 4)
        hex_encoded = self._generate_password(length=length,
                                              symbolgroups='0123456789ABCDEF')
        return hex_encoded

    def _generate_key(self, **kwargs):
        name = kwargs.get('name', None)
        algorithm = kwargs.get('algorithm', 'AES')
        key_length = kwargs.get('length', 256)
        _hex = self._generate_hex_key(key_length)
        return sym_key.SymmetricKey(
            algorithm,
            key_length,
            bytes(binascii.unhexlify(_hex)),
            name)

    def create_key(self, context, **kwargs):
        """Creates a symmetric key.

        This implementation returns a UUID for the created key. The algorithm
        for the key will always be AES. A Forbidden exception is raised if the
        specified context is None.
        """
        if context is None:
            raise exception.Forbidden()

        key = self._generate_key(**kwargs)
        return self.store(context, key)

    def _generate_public_and_private_key(self, length, name):
        crypto_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=length,
            backend=backends.default_backend())

        private_der = crypto_private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption())

        crypto_public_key = crypto_private_key.public_key()

        public_der = crypto_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

        private_key = pri_key.PrivateKey(
            algorithm='RSA',
            bit_length=length,
            key=bytearray(private_der),
            name=name)

        public_key = pub_key.PublicKey(
            algorithm='RSA',
            bit_length=length,
            key=bytearray(public_der),
            name=name)

        return private_key, public_key

    def create_key_pair(self, context, algorithm, length,
                        expiration=None, name=None):
        """Creates an asymmetric key pair.

        This implementation returns UUIDs for the created keys in the order:
            (private, public)
        Forbidden is raised if the context is None.
        """
        if context is None:
            raise exception.Forbidden()

        if algorithm.lower() != 'rsa':
            msg = 'Invalid algorithm: {}, only RSA supported'.format(algorithm)
            raise ValueError(msg)

        valid_lengths = [2048, 3072, 4096]

        if length not in valid_lengths:
            msg = 'Invalid bit length: {}, only {} supported'.format(
                length, valid_lengths)
            raise ValueError(msg)

        private_key, public_key = self._generate_public_and_private_key(length,
                                                                        name)

        private_key_uuid = self.store(context, private_key)
        public_key_uuid = self.store(context, public_key)

        return private_key_uuid, public_key_uuid

    def _generate_key_id(self):
        key_id = uuidutils.generate_uuid()
        while key_id in self.keys:
            key_id = uuidutils.generate_uuid()

        return key_id

    def store(self, context, managed_object, **kwargs):
        """Stores (i.e., registers) a key with the key manager."""
        if context is None:
            raise exception.Forbidden()

        key_id = self._generate_key_id()
        managed_object._id = key_id
        self.keys[key_id] = managed_object

        return key_id

    def get(self, context, managed_object_id, metadata_only=False, **kwargs):
        """Retrieves the key identified by the specified id.

        This implementation returns the key that is associated with the
        specified UUID. A Forbidden exception is raised if the specified
        context is None; a KeyError is raised if the UUID is invalid.
        """
        if context is None:
            raise exception.Forbidden()

        try:
            obj = copy.deepcopy(self.keys[managed_object_id])
        except KeyError:
            raise exception.ManagedObjectNotFoundError()

        if metadata_only:
            if hasattr(obj, "_key"):
                obj._key = None
            if hasattr(obj, "_data"):
                obj._data = None
            if hasattr(obj, "_passphrase"):
                obj._passphrase = None
        return obj

    def delete(self, context, managed_object_id, **kwargs):
        """Deletes the object identified by the specified id.

        A Forbidden exception is raised if the context is None and a
        KeyError is raised if the UUID is invalid.
        """
        if context is None:
            raise exception.Forbidden()

        try:
            del self.keys[managed_object_id]
        except KeyError:
            raise exception.ManagedObjectNotFoundError()

    def add_consumer(self, context, managed_object_id, consumer_data):
        if context is None:
            raise exception.Forbidden()
        if managed_object_id not in self.keys:
            raise exception.ManagedObjectNotFoundError()
        self.keys[managed_object_id].consumers.append(consumer_data)

    def remove_consumer(self, context, managed_object_id, consumer_data):
        if context is None:
            raise exception.Forbidden()
        if managed_object_id not in self.keys:
            raise exception.ManagedObjectNotFoundError()
        self.keys[managed_object_id].consumers = [
            c for c in self.keys[managed_object_id].consumers
            if c != consumer_data]

    def _generate_password(self, length, symbolgroups):
        """Generate a random password from the supplied symbol groups.

        At least one symbol from each group will be included. Unpredictable
        results if length is less than the number of symbol groups.

        Believed to be reasonably secure (with a reasonable password length!)
        """
        # NOTE(jerdfelt): Some password policies require at least one character
        # from each group of symbols, so start off with one random character
        # from each symbol group
        password = [random.choice(s) for s in symbolgroups]
        # If length < len(symbolgroups), the leading characters will only
        # be from the first length groups. Try our best to not be predictable
        # by shuffling and then truncating.
        random.shuffle(password)
        password = password[:length]
        length -= len(password)

        # then fill with random characters from all symbol groups
        symbols = ''.join(symbolgroups)
        password.extend([random.choice(symbols) for _i in range(length)])

        # Finally, shuffle to ensure first x characters aren't from a
        # predictable group
        random.shuffle(password)

        return ''.join(password)

    def list(self, context, object_type=None, metadata_only=False):
        """Retrieves a list of managed objects that match the criteria.

        A Forbidden exception is raised if the context is None.
        If no search criteria is given, all objects are returned.
        """
        if context is None:
            raise exception.Forbidden()

        objects = []
        for obj_id in self.keys:
            obj = self.get(context, obj_id, metadata_only=metadata_only)
            if object_type is None or isinstance(obj, object_type):
                objects.append(obj)
        return objects
