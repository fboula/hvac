import logging
from unittest import TestCase
from unittest import skipIf

import requests_mock
from parameterized import parameterized

from hvac.adapters import Request
from hvac.api.auth_methods import Kubernetes
from tests import utils

KUBERNETES_URL = 'https://kubernetes.hvac.network'


@skipIf(utils.vault_version_lt('0.8.3'), "Kubernetes auth method not available before Vault version 0.8.3")
class TestKubernetes(TestCase):
    TEST_MOUNT_POINT = 'kubernetes-test'

    @parameterized.expand([
        ('success', dict(), None,),
    ])
    @requests_mock.Mocker()
    def test_login(self, label, test_params, raises, requests_mocker):
        role_name = "hvac"
        credentials = utils.load_config_file('example.jwt.json')
        test_policies = [
            "default",
            "dev",
            "prod",
        ]
        expected_status_code = 200
        mock_url = 'http://localhost:8200/v1/auth/{mount_point}/login'.format(
            mount_point=self.TEST_MOUNT_POINT,
        )
        mock_response = {
            "auth": {
                "client_token": "62b858f9-529c-6b26-e0b8-0457b6aacdb4",
                "accessor": "afa306d0-be3d-c8d2-b0d7-2676e1c0d9b4",
                "policies": test_policies,
                "lease_duration": 2764800,
                "renewable": True,
            },
        }
        requests_mocker.register_uri(
            method='POST',
            url=mock_url,
            status_code=expected_status_code,
            json=mock_response
        )
        kubernetes = Kubernetes(adapter=Request())
        if raises is not None:
            with self.assertRaises(raises):
                kubernetes.login(
                    role=role_name,
                    jwt=credentials,
                    mount_point=self.TEST_MOUNT_POINT,
                    **test_params
                )
        else:
            login_response = kubernetes.login(
                role=role_name,
                jwt=credentials,
                mount_point=self.TEST_MOUNT_POINT,
                **test_params
            )
            logging.debug('login_response: %s' % login_response)
            self.assertEqual(
                first=login_response['auth']['policies'],
                second=test_policies,
            )