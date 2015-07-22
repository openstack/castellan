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

import array
import binascii
import random
import uuid

from castellan.common import exception
from castellan.key_manager import key_manager
from castellan.key_manager import symmetric_key as sym_key


class MockKeyManager(key_manager.KeyManager):

    """Mocking manager for integration tests.

    This mock key manager implementation supports all the methods specified
    by the key manager interface. This implementation stores keys within a
    dictionary, and as a result, it is not acceptable for use across different
    services. Side effects (e.g., raising exceptions) for each method are
    handled as specified by the key manager interface.

    This key manager is not suitable for use in production deployments.
    """

    def __init__(self):
        self.keys = {}

    def _generate_hex_key(self, **kwargs):
        key_length = kwargs.get('key_length', 256)
        # hex digit => 4 bits
        length = int(key_length / 4)
        hex_encoded = self._generate_password(length=length,
                                              symbolgroups='0123456789ABCDEF')
        return hex_encoded

    def _generate_key(self, **kwargs):
        _hex = self._generate_hex_key(**kwargs)
        return sym_key.SymmetricKey(
            'AES',
            array.array('B', binascii.unhexlify(_hex)).tolist())

    def create_key(self, context, **kwargs):
        """Creates a key.

        This implementation returns a UUID for the created key. A
        Forbidden exception is raised if the specified context is None.
        """
        if context is None:
            raise exception.Forbidden()

        key = self._generate_key(**kwargs)
        return self.store_key(context, key)

    def _generate_key_id(self):
        key_id = str(uuid.uuid4())
        while key_id in self.keys:
            key_id = str(uuid.uuid4())

        return key_id

    def store_key(self, context, key, **kwargs):
        """Stores (i.e., registers) a key with the key manager."""
        if context is None:
            raise exception.Forbidden()

        key_id = self._generate_key_id()
        self.keys[key_id] = key

        return key_id

    def copy_key(self, context, key_id, **kwargs):
        if context is None:
            raise exception.Forbidden()

        copied_key_id = self._generate_key_id()
        self.keys[copied_key_id] = self.keys[key_id]

        return copied_key_id

    def get_key(self, context, key_id, **kwargs):
        """Retrieves the key identified by the specified id.

        This implementation returns the key that is associated with the
        specified UUID. A Forbidden exception is raised if the specified
        context is None; a KeyError is raised if the UUID is invalid.
        """
        if context is None:
            raise exception.Forbidden()

        return self.keys[key_id]

    def delete_key(self, context, key_id, **kwargs):
        """Deletes the key identified by the specified id.

        A Forbidden exception is raised if the context is None and a
        KeyError is raised if the UUID is invalid.
        """
        if context is None:
            raise exception.Forbidden()

        del self.keys[key_id]

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

        # finally shuffle to ensure first x characters aren't from a
        # predictable group
        random.shuffle(password)

        return ''.join(password)
