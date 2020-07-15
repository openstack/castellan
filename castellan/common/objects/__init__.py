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

from castellan.common import exception
from castellan.common.objects import opaque_data
from castellan.common.objects import passphrase
from castellan.common.objects import private_key
from castellan.common.objects import public_key
from castellan.common.objects import symmetric_key
from castellan.common.objects import x_509

_managed_objects_by_type = {
    cls.managed_type(): cls for cls in [
        opaque_data.OpaqueData,
        passphrase.Passphrase,
        private_key.PrivateKey,
        public_key.PublicKey,
        symmetric_key.SymmetricKey,
        x_509.X509,
    ]
}


def from_dict(obj, id=None):
    try:
        managed_object_type = obj["type"]
    except KeyError:
        raise exception.InvalidManagedObjectDictError(field="type")

    try:
        cls = _managed_objects_by_type[managed_object_type]
    except KeyError:
        raise exception.UnknownManagedObjectTypeError(type=managed_object_type)

    try:
        managed_object = cls.from_dict(obj, id)
    except KeyError as e:
        raise exception.InvalidManagedObjectDictError(field=str(e))

    return managed_object
