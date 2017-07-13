# Copyright (c) 2015 IBM
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
Keystone Password Credential

This module defines the Keystone Password credential.
"""
from castellan.common.credentials import password


class KeystonePassword(password.Password):
    """This class represents a keystone password credential."""

    def __init__(self, password, auth_url=None, username=None, user_id=None,
                 user_domain_id=None, user_domain_name=None, trust_id=None,
                 domain_id=None, domain_name=None, project_id=None,
                 project_name=None, project_domain_id=None,
                 project_domain_name=None, reauthenticate=True):
        """Create a new Keystone Password Credential.

        :param string auth_url: Use this endpoint to connect to Keystone.
        :param string password: Password for authentication.
        :param string username: Username for authentication.
        :param string user_id: User ID for authentication.
        :param string user_domain_id: User's domain ID for authentication.
        :param string user_domain_name: User's domain name for authentication.
        :param string trust_id: Trust ID for trust scoping.
        :param string domain_id: Domain ID for domain scoping.
        :param string domain_name: Domain name for domain scoping.
        :param string project_id: Project ID for project scoping.
        :param string project_name: Project name for project scoping.
        :param string project_domain_id: Project's domain ID for project.
        :param string project_domain_name: Project's domain name for project.
        :param bool reauthenticate: Allow fetching a new token if the current
        one is going to expire. (optional) default True
        """

        self._auth_url = auth_url
        self._user_id = user_id
        self._user_domain_id = user_domain_id
        self._user_domain_name = user_domain_name
        self._trust_id = trust_id
        self._domain_id = domain_id
        self._domain_name = domain_name
        self._project_id = project_id
        self._project_name = project_name
        self._project_domain_id = project_domain_id
        self._project_domain_name = project_domain_name
        self._reauthenticate = reauthenticate

        super(KeystonePassword, self).__init__(username,
                                               password)

    @property
    def auth_url(self):
        """This method returns an auth_url."""
        return self._auth_url

    @property
    def user_id(self):
        """This method returns a user_id."""
        return self._user_id

    @property
    def user_domain_id(self):
        """This method returns a user_domain_id."""
        return self._user_domain_id

    @property
    def user_domain_name(self):
        """This method returns a user_domain_name."""
        return self._user_domain_name

    @property
    def trust_id(self):
        """This method returns a trust_id."""
        return self._trust_id

    @property
    def domain_id(self):
        """This method returns a domain_id."""
        return self._domain_id

    @property
    def domain_name(self):
        """This method returns a domain_name."""
        return self._domain_name

    @property
    def project_id(self):
        """This method returns a project_id."""
        return self._project_id

    @property
    def project_name(self):
        """This method returns a project_name."""
        return self._project_name

    @property
    def project_domain_id(self):
        """This method returns a project_domain_id."""
        return self._project_domain_id

    @property
    def project_domain_name(self):
        """This method returns a project_domain_name."""
        return self._project_domain_name

    @property
    def reauthenticate(self):
        """This method returns reauthenticate."""
        return self._reauthenticate

    def __eq__(self, other):
        if isinstance(other, KeystonePassword):
            return (
                self._password == other._password and
                self._username == other._username and
                self._user_id == other._user_id and
                self._user_domain_id == other._user_domain_id and
                self._user_domain_name == other._user_domain_name and
                self._trust_id == other._trust_id and
                self._domain_id == other._domain_id and
                self._domain_name == other._domain_name and
                self._project_id == other._project_id and
                self._project_name == other._project_name and
                self._project_domain_id == other._project_domain_id and
                self._project_domain_name == other._project_domain_name and
                self._reauthenticate == other._reauthenticate)
        else:
            return False

    def __ne__(self, other):
        result = self.__eq__(other)
        return not result
