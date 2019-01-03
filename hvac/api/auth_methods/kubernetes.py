#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Kubernetes auth method module."""
import logging

from hvac import exceptions
from hvac.api.vault_api_base import VaultApiBase

DEFAULT_MOUNT_POINT = "kubernetes"


class Kubernetes(VaultApiBase):
    """Kubernetes Auth Method (API).

    Reference: https://www.vaultproject.io/api/auth/kubernetes/index.html
    """

    def configure(
        self,
        kubernetes_host,
        kubernetes_ca_cert,
        token_reviewer_jwt,
        pem_keys=None,
        mount_point=DEFAULT_MOUNT_POINT,
    ):
        """
        The Kubernetes auth method validates service account JWTs and verifies
        their existence with the Kubernetes TokenReview API. This endpoint
        configures the public key used to validate the JWT signature and the
        necessary information to access the Kubernetes API.

        Supported methods:
            POST: /auth/{mount_point}/config. Produces: 200 application/json

        :param kubernetes_host: Host must be a host string, a host:port pair,
            or a URL to the base of the Kubernetes API server.
        :type kubernetes_host: str | unicode
        :param kubernetes_ca_cert: PEM encoded CA cert for use by the TLS
            client used to talk with the Kubernetes API.
        :type kubernetes_ca_cert: str | unicode
        :param token_reviewer_jwt: A service account JWT used to access the
            TokenReview API to validate other JWTs during login. If not set the
            JWT used for login will be used to access the API.
        :type token_reviewer_jwt: str | unicode
        :param pem_keys: Optional list of PEM-formated public keys or
            certificates used to verify the signatures of Kubernetes service
            account JWTs. If a certificate is given, its public key will be
            extracted. Not every installation of Kubernetes exposes these keys.
        :type pem_keys: List[str] | Optional
        """
        params = {
            "kubernetes_host": kubernetes_host,
            "kubernetes_ca_cert": kubernetes_ca_cert,
            "token_reviewer_jwt": token_reviewer_jwt,
        }
        if kubernetes_ca_cert is not None:
            params["pem_keys"] = pem_keys
        api_path = "/v1/auth/{mount_point}/config".format(
            mount_point=mount_point
        )
        return self._adapter.post(url=api_path, json=params)

    def read_config(self, mount_point=DEFAULT_MOUNT_POINT):
        """Return the previously configured config, including credentials.

        Supported methods:
            GET: /auth/{mount_point}/config. Produces: 200 application/json

        :param mount_point: The "path" the kubernetes auth method was mounted
            on.
        :type mount_point: str | unicode
        :return: The data key from the JSON response of the request.
        :rtype: dict
        """
        api_path = "/v1/auth/{mount_point}/config".format(
            mount_point=mount_point
        )
        response = self._adapter.get(url=api_path)
        return response.json().get("data")

    def create_role(
        self,
        name,
        bound_service_account_names,
        bound_service_account_namespaces,
        ttl=None,
        max_ttl=None,
        period=None,
        policies=None,
        mount_point=DEFAULT_MOUNT_POINT,
    ):
        """Registers a role in the auth method.

        Role types have specific entities that can perform login operations
        against this endpoint. Constraints specific to the role type must be
        set on the role. These are applied to the authenticated entities
        attempting to login.

        Supported methods:
            POST: /auth/{mount_point}/role/{name}. Produces: 204 (empty body)

        :param name: Name of the role.
        :type name: str | unicode
        :param bound_service_account_names:  List of service account names able
            to access this role. If set to "*" all names are allowed, both this
            and bound_service_account_namespaces can not be "*".
        :type bound_service_account_names: list
        :param bound_service_account_namespaces: List of namespaces allowed to
            access this role. If set to "*" all namespaces are allowed, both
            this and bound_service_account_names can not be set to "*".
        :type bound_service_account_namespaces: list
        :param ttl: The TTL period of tokens issued using this role in seconds.
        :type ttl: str | unicode
        :param max_ttl: The maximum allowed lifetime of tokens issued in
            seconds using this role.
        :type max_ttl: str | unicode
        :param period: If set, indicates that the token generated using this
            role should never expire. The token should be renewed within the
            duration specified by this value. At each renewal, the token's TTL
            will be set to the value of this parameter.
        :type period: str | unicode
        :param policies: Policies to be set on tokens issued using this role.
        :type policies: list
        """
        if bound_service_account_names == "*" and bound_service_account_namespaces == "*":
            error_msg = 'service_account_names and service_account_namespaces can not both be "*"'
            raise exceptions.ParamValidationError(error_msg)
        if policies is None:
            policies = []
        if not isinstance(policies, list) or not all(
            [isinstance(p, str) for p in policies]
        ):
            error_msg = 'unsupported policies argument provided "{arg}" ({arg_type}), required type: List[str]"'
            raise exceptions.ParamValidationError(
                error_msg.format(arg=policies, arg_type=type(policies))
            )
        params = {
            "bound_service_account_names": bound_service_account_names,
            "bound_service_account_namespaces": bound_service_account_namespaces,
            "ttl": ttl,
            "max_ttl": max_ttl,
            "period": period,
            "policies": policies,
        }

        api_path = "/v1/auth/{mount_point}/role/{name}".format(
            mount_point=mount_point, name=name
        )
        return self._adapter.post(url=api_path, json=params)

    def read_role(self, name, mount_point=DEFAULT_MOUNT_POINT):
        """Read the previously registered role configuration.

        Supported methods:
            GET: /auth/{mount_point}/role/{name}. Produces: 200 application/json


        :param name: Name of the role.
        :type name: str | unicode
        :param mount_point: The "path" the kubernetes auth method was mounted
            on.
        :type mount_point: str | unicode
        :return: The "data" key from the JSON response of the request.
        :rtype: dict
        """
        api_path = "/v1/auth/{mount_point}/role/{name}".format(
            mount_point=mount_point, name=name
        )
        response = self._adapter.get(url=api_path)
        return response.json().get("data")

    def list_roles(self, mount_point=DEFAULT_MOUNT_POINT):
        """List all the roles that are registered with the plugin.

        Supported methods:
            LIST: /auth/{mount_point}/roles. Produces: 200 application/json
            GET: /auth/{mount_point}/roles?list=true. Produces: 200 application/json


        :param mount_point: The "path" the kubernetes auth method was mounted on.
        :type mount_point: str | unicode
        :return: The "data" key from the JSON response of the request.
        :rtype: dict
        """
        api_path = "/v1/auth/{mount_point}/role".format(
            mount_point=mount_point
        )
        response = self._adapter.list(url=api_path)
        return response.json().get("data")

    def delete_role(self, role, mount_point=DEFAULT_MOUNT_POINT):
        """Delete the previously registered role.

        Supported methods:
            DELETE: /auth/{mount_point}/role/{role}. Produces: 204 (empty body)


        :param role: Name of the role.
        :type role: str | unicode
        :param mount_point: The "path" the kubernetes auth method was mounted
            on.
        :type mount_point: str | unicode
        :return: The response of the request.
        :rtype: requests.Response
        """
        api_path = "/v1/auth/{mount_point}/role/{role}".format(
            mount_point=mount_point, role=role
        )
        return self._adapter.delete(url=api_path)

    def login(
        self, role, jwt, use_token=True, mount_point=DEFAULT_MOUNT_POINT
    ):
        """
        Fetch a token.

        This endpoint takes a signed JSON Web Token (JWT) and a role name for
        some entity. It verifies the JWT signature to authenticate that entity
        and then authorizes the entity for the given role.

        Supported methods:
            POST: /auth/{mount_point}/login. Produces: 200 application/json

        :param role: Name of the role against which the login is being
            attempted.
        :type role: str | unicode
        :param jwt: Signed JSON Web Token (JWT) for authenticating a service
            account.
        :rtype: dict
        :param use_token: if True, uses the token in the response received from
            the auth request to set the "token" attribute on the the
            :py:meth:`hvac.adapters.Adapter` instance under the _adapater
            Client attribute.
        :type use_token: bool
        :param mount_point: The "path" the kubernetes auth method was mounted
            on.
        :type mount_point: str | unicode
        :return: The JSON response of the request.
        :rtype: dict
        """
        params = {"role": role, "jwt": jwt}
        api_path = "/v1/auth/{mount_point}/login".format(
            mount_point=mount_point
        )
        response = self._adapter.login(
            url=api_path, use_token=use_token, json=params
        )
        return response
