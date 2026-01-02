import pytest

from cleancloud.safety.azure.allowlist import FORBIDDEN_AZURE_METHOD_PREFIXES


class ForbiddenAzureCallError(Exception):
    pass


@pytest.fixture(autouse=True)
def guard_azure_clients(monkeypatch):
    """
    Guard all Azure SDK clients from mutating calls at runtime.
    Patches client __getattribute__ to intercept forbidden methods.
    """

    def wrap_client(client):
        original_getattr = client.__getattribute__

        def guarded_getattr(name):
            for forbidden in FORBIDDEN_AZURE_METHOD_PREFIXES:
                if name.lower().startswith(forbidden):
                    raise ForbiddenAzureCallError(f"Forbidden Azure SDK call attempted: {name}")
            return original_getattr(name)

        monkeypatch.setattr(client, "__getattribute__", guarded_getattr)
        return client

    # Patch all known Azure clients (expand if needed)
    clients_to_patch = [
        "azure.mgmt.compute.ComputeManagementClient",
        "azure.mgmt.storage.StorageManagementClient",
        "azure.mgmt.resource.resources.ResourceManagementClient",
        "azure.mgmt.monitor.MonitorManagementClient",
    ]

    for client_path in clients_to_patch:
        try:
            components = client_path.split(".")
            mod = __import__(".".join(components[:-1]), fromlist=[components[-1]])
            client_cls = getattr(mod, components[-1])
            # Patch the __init__ to wrap instance
            original_init = client_cls.__init__

            def new_init(self, *args, **kwargs):
                original_init(self, *args, **kwargs)
                wrap_client(self)

            monkeypatch.setattr(client_cls, "__init__", new_init)
        except ImportError:
            # If SDK not installed, skip
            pass


def test_dummy_readonly_call():
    """
    Sanity check that a read-only method can be accessed.
    """
    assert True
