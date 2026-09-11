from django.core.exceptions import ImproperlyConfigured

from winfs.compat import require_final_core

_core = require_final_core()
TrustsImplementationConfig = _core["TrustsImplementationConfig"]

CANONICAL_BACKEND = "winfs.backends.WinfsBackend"


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
        if getattr(self, "_winfs_policy_registry_id", None) is not registry:
            register_winfs_policy(registry)
            self._winfs_policy_registry_id = registry
        from django.db.models.signals import post_migrate

        post_migrate.connect(
            _ensure_domain_permissions_on_migrate,
            sender=self,
            dispatch_uid="winfs.ensure_domain_permissions",
        )


def _ensure_domain_permissions_on_migrate(**kwargs):
    from winfs.policy import ensure_domain_permissions

    ensure_domain_permissions()
