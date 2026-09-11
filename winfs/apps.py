from django.core.exceptions import ImproperlyConfigured

from winfs.compat import require_final_core

_core = require_final_core()
TrustsImplementationConfig = _core["TrustsImplementationConfig"]

from winfs.backends import CANONICAL_BACKEND


def winfs_config(apps_registry=None):
    """Return the installed ``WinfsConfig`` by class identity."""
    from django.apps import apps as django_apps

    registry = django_apps if apps_registry is None else apps_registry
    matches = [
        config
        for config in registry.get_app_configs()
        if type(config) is WinfsConfig
    ]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise ImproperlyConfigured("No installed winfs.apps.WinfsConfig.")
    raise ImproperlyConfigured(
        "Multiple WinfsConfig instances: %r" % (matches,)
    )


class WinfsConfig(TrustsImplementationConfig):
    """Windows ACL implementation owner. Core is a library, not an app."""

    default_auto_field = "django.db.models.AutoField"
    name = "winfs"
    label = "winfs"
    verbose_name = "Windows filesystem ACL"
    default = True
    trusts_backend_paths = (CANONICAL_BACKEND,)

    def ready(self):
        from trusts.apps import implementation_for_path

        from winfs.policy import register_winfs_policy

        super().ready()
        owner = implementation_for_path(
            CANONICAL_BACKEND,
            apps_registry=getattr(self, "apps", None),
        )
        registry = owner.configured_backend(CANONICAL_BACKEND).registry
        if getattr(self, "_winfs_policy_registry_id", None) is registry:
            return
        register_winfs_policy(registry)
        self._winfs_policy_registry_id = registry
