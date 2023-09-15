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
Key manager implementation that raises NotImplementedError
"""

from castellan.key_manager import key_manager


class NotImplementedKeyManager(key_manager.KeyManager):
    """Key Manager Interface that raises NotImplementedError for all operations

    """

    def __init__(self, configuration=None):
        super(NotImplementedKeyManager, self).__init__(configuration)

    def create_key(self, context, algorithm='AES', length=256,
                   expiration=None, name=None, **kwargs):
        raise NotImplementedError()

    def create_key_pair(self, context, algorithm, length,
                        expiration=None, name=None):
        raise NotImplementedError()

    def store(self, context, managed_object, expiration=None, **kwargs):
        raise NotImplementedError()

    def copy(self, context, managed_object_id, **kwargs):
        raise NotImplementedError()

    def get(self, context, managed_object_id, **kwargs):
        raise NotImplementedError()

    def list(self, context, object_type=None):
        raise NotImplementedError()

    def delete(self, context, managed_object_id, **kwargs):
        raise NotImplementedError()
