import logging
from unittest import TestCase
from unittest import skipIf

from parameterized import parameterized, param
from hvac import exceptions
from tests import utils
from tests.utils.hvac_integration_test_case import HvacIntegrationTestCase

KUBERNETES_URL = "https://kubernetes.hvac.network"
KUBERNETES_CA_CERT = utils.load_config_file("server-cert.pem").replace(
    "\n", ""
)
TOKEN_REVIEWER_JWT = utils.load_config_file("example.jwt")


@skipIf(
    utils.vault_version_lt("0.8.3"),
    "Kubernetes auth method not available before Vault version 0.8.3",
)
class TestKubernetes(HvacIntegrationTestCase, TestCase):
    TEST_MOUNT_POINT = "kubernetes-test"

    def setUp(self):
        super(TestKubernetes, self).setUp()
        if (
            "%s/" % self.TEST_MOUNT_POINT
            not in self.client.list_auth_backends()
        ):
            self.client.enable_auth_backend(
                backend_type="kubernetes", mount_point=self.TEST_MOUNT_POINT
            )

    def tearDown(self):
        self.client.disable_auth_backend(mount_point=self.TEST_MOUNT_POINT)
        super(TestKubernetes, self).tearDown()

    @parameterized.expand(
        [
            param(
                "set valid configuration",
                kubernetes_host=KUBERNETES_URL,
                kubernetes_ca_cert=KUBERNETES_CA_CERT,
                token_reviewer_jwt=TOKEN_REVIEWER_JWT,
            )
        ]
    )
    def test_configure(
        self,
        label,
        kubernetes_host,
        kubernetes_ca_cert,
        token_reviewer_jwt,
        pem_keys=None,
        raises=None,
        exception_message="",
    ):

        if raises:
            with self.assertRaises(raises) as cm:
                self.client.auth.kubernetes.configure(
                    kubernetes_host=kubernetes_host,
                    kubernetes_ca_cert=kubernetes_ca_cert,
                    token_reviewer_jwt=token_reviewer_jwt,
                    pem_keys=pem_keys,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message, container=str(cm.exception)
            )
        else:
            configure_response = self.client.auth.kubernetes.configure(
                kubernetes_host=kubernetes_host,
                kubernetes_ca_cert=kubernetes_ca_cert,
                token_reviewer_jwt=token_reviewer_jwt,
                pem_keys=pem_keys,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("configure_response: %s" % configure_response)
            self.assertEqual(first=configure_response.status_code, second=204)

    @parameterized.expand(
        [
            param("success"),
            param(
                "no config written yet",
                write_config_first=False,
                raises=exceptions.InvalidPath,
            ),
        ]
    )
    def test_read_config(self, label, write_config_first=True, raises=None):

        if write_config_first:
            self.client.auth.kubernetes.configure(
                kubernetes_host=KUBERNETES_URL,
                kubernetes_ca_cert=KUBERNETES_CA_CERT,
                token_reviewer_jwt=TOKEN_REVIEWER_JWT,
                mount_point=self.TEST_MOUNT_POINT,
            )
        if raises is not None:
            with self.assertRaises(raises):
                self.client.auth.kubernetes.read_config(
                    mount_point=self.TEST_MOUNT_POINT
                )
        else:
            read_config_response = self.client.auth.kubernetes.read_config(
                mount_point=self.TEST_MOUNT_POINT
            )
            logging.debug("read_config_response: %s" % read_config_response)

            expected_config = {
                "kubernetes_host": KUBERNETES_URL,
                "kubernetes_ca_cert": KUBERNETES_CA_CERT,
            }
            for k, v in expected_config.items():
                self.assertEqual(first=v, second=read_config_response[k])

    @parameterized.expand(
        [
            param(
                "simple params",
                bound_service_account_names="vaulth-auth",
                bound_service_account_namespaces="default",
            ),
            param(
                "complex params",
                bound_service_account_names=["vaulth-auth", "deploy"],
                bound_service_account_namespaces=["default", "hvac"],
                ttl="1800000",
                policies=["dev", "prod"],
            ),
            param(
                "wrong arguments",
                bound_service_account_names="*",
                bound_service_account_namespaces="*",
                raises=exceptions.ParamValidationError,
                exception_message='service_account_names and service_account_namespaces can not both be "*"',
            ),
        ]
    )
    def test_create_role(
        self,
        label,
        bound_service_account_names=None,
        bound_service_account_namespaces=None,
        ttl=None,
        policies=None,
        raises=None,
        exception_message="",
    ):
        role_name = "hvac"

        if raises:
            with self.assertRaises(raises) as cm:
                self.client.auth.kubernetes.create_role(
                    name=role_name,
                    bound_service_account_names=bound_service_account_names,
                    bound_service_account_namespaces=bound_service_account_namespaces,
                    ttl=None,
                    policies=policies,
                    mount_point=self.TEST_MOUNT_POINT,
                )
            self.assertIn(
                member=exception_message, container=str(cm.exception)
            )
        else:
            create_role_response = self.client.auth.kubernetes.create_role(
                name=role_name,
                bound_service_account_names=bound_service_account_names,
                bound_service_account_namespaces=bound_service_account_namespaces,
                ttl=None,
                policies=policies,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("create_role_response: %s" % create_role_response)
            self.assertEqual(
                first=create_role_response.status_code, second=204
            )

    @parameterized.expand(
        [
            param("success"),
            param(
                "nonexistent role name",
                configure_role_first=False,
                raises=exceptions.InvalidPath,
            ),
        ]
    )
    def test_read_role(
        self,
        label,
        configure_role_first=True,
        raises=None,
        exception_message="",
    ):
        role_name = "hvac"
        bound_service_account_names = "vaulth-auth"
        bound_service_account_namespaces = "default"
        if configure_role_first:
            create_role_response = self.client.auth.kubernetes.create_role(
                name=role_name,
                bound_service_account_names=bound_service_account_names,
                bound_service_account_namespaces=bound_service_account_namespaces,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("create_role_response: %s" % create_role_response)

        if raises is not None:
            with self.assertRaises(raises):
                self.client.auth.kubernetes.read_role(
                    name=role_name, mount_point=self.TEST_MOUNT_POINT
                )
        else:
            read_role_response = self.client.auth.kubernetes.read_role(
                name=role_name, mount_point=self.TEST_MOUNT_POINT
            )
            logging.debug("read_role_response: %s" % read_role_response)
            self.assertEqual(
                first=read_role_response["bound_service_account_names"][0],
                second=bound_service_account_names,
            )

    @parameterized.expand(
        [
            param("success one role"),
            param("success multiple roles", num_roles_to_create=7),
            param(
                "no roles",
                num_roles_to_create=0,
                raises=exceptions.InvalidPath,
            ),
        ]
    )
    def test_list_roles(self, label, num_roles_to_create=1, raises=None):
        bound_service_account_names = "vaulth-auth"
        bound_service_account_namespaces = "default"
        roles_to_create = ["hvac%s" % n for n in range(0, num_roles_to_create)]
        logging.debug("roles_to_create: %s" % roles_to_create)
        for role_to_create in roles_to_create:
            create_role_response = self.client.auth.kubernetes.create_role(
                name=role_to_create,
                bound_service_account_names=bound_service_account_names,
                bound_service_account_namespaces=bound_service_account_namespaces,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("create_role_response: %s" % create_role_response)

        if raises is not None:
            with self.assertRaises(raises):
                self.client.auth.kubernetes.list_roles(
                    mount_point=self.TEST_MOUNT_POINT
                )
        else:
            list_roles_response = self.client.auth.kubernetes.list_roles(
                mount_point=self.TEST_MOUNT_POINT
            )
            logging.debug("list_roles_response: %s" % list_roles_response)
            self.assertEqual(
                first=list_roles_response["keys"], second=roles_to_create
            )

    @parameterized.expand(
        [
            param("success"),
            param("nonexistent role name", configure_role_first=False),
        ]
    )
    def test_delete_role(self, label, configure_role_first=True, raises=None):
        role_name = "hvac"
        bound_service_account_names = "vaulth-auth"
        bound_service_account_namespaces = "default"
        if configure_role_first:
            create_role_response = self.client.auth.kubernetes.create_role(
                name=role_name,
                bound_service_account_names=bound_service_account_names,
                bound_service_account_namespaces=bound_service_account_namespaces,
                mount_point=self.TEST_MOUNT_POINT,
            )
            logging.debug("create_role_response: %s" % create_role_response)

        if raises is not None:
            with self.assertRaises(raises):
                self.client.auth.kubernetes.delete_role(
                    role=role_name, mount_point=self.TEST_MOUNT_POINT
                )
        else:
            delete_role_response = self.client.auth.kubernetes.delete_role(
                role=role_name, mount_point=self.TEST_MOUNT_POINT
            )
            logging.debug("delete_role_response: %s" % delete_role_response)
            self.assertEqual(
                first=delete_role_response.status_code, second=204
            )
