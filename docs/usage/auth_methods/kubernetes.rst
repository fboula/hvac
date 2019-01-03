.. _kubernetes-auth-method:

Kubernetes
==========

.. note::
    Every method under the :py:attr:`Client class's kubernetes.auth attribute<hvac.api.Kubernetes.auth>` includes a `mount_point` parameter that can be used to address the kubernetes auth method under a custom mount path. E.g., If enabling the kubernetes auth method using Vault's CLI commands via `vault auth enable -path=my-kubernetes kubernetes`", the `mount_point` parameter in :py:meth:`hvac.api.auth.Kubernetes` methods would be set to "my-kubernetes".

Enabling the Auth Method
------------------------

:py:meth:`hvac.v1.Client.enable_auth_backend`

.. code:: python

    import hvac
    client = hvac.Client()

    azure_auth_path = 'company-kubernetes'
    description = 'Auth method for use by team members in our company's Kubernetes cluster.'

    if '%s/' % kubernetes_auth_path not in vault_client.list_auth_backends():
        print('Enabling the kubernetes auth backend at mount_point: {path}'.format(
            path=kubernetes_auth_path,
        ))
        client.enable_auth_backend(
            backend_type='kubernetes',
            description=description,
            mount_point=kubernetes_auth_path,
        )


Configure
---------

:py:meth:`hvac.api.auth.Kubernetes.configure`

.. code:: python

    import hvac
    client = hvac.Client()

    client.auth.kubernetes.configure(
        kubernetes_host='Kubernetes master api URL',
        kubernetes_ca_cert='Kubernetes CA certificate',
        token_reviewer_jwt='Some service account JWT',
    )

Read Config
-----------

:py:meth:`hvac.api.auth_methods.Kubernetes.read_config`

.. code:: python

    import hvac
    client = hvac.Client()

    read_config = client.auth.kubernetes.read_config()
    print('The configured kubernetes cluster is: {id}'.format(id=read_config['kubernetes_host'))


Login
-----

:py:meth:`hvac.api.auth_methods.Kubernetes.login`

.. code:: python

    import hvac
    client = hvac.Client()

    client.kubernetes.login(
        role=role_name,
        jwt='Pod JWT...',
    )
    client.is_authenticated  # ==> returns True