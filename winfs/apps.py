from django.core.exceptions import ImproperlyConfigured

CANONICAL_BACKEND = 'winfs.backends.WinfsAuthorizationBackend'
CORE_REQUIREMENT = 'django-trusts>=1.0.0.dev3,<2'
FLOOR_MESSAGE = (
    'django-trusts-windows-acl 0.1.0.dev0 requires '
    '%s (TrustsImplementationConfig). '
    'Upgrade django-trusts; do not rely on a missing import.'
    % CORE_REQUIREMENT
)


def _load_implementation_config():
    try:
        from trusts.apps import TrustsImplementationConfig as imported
    except ImportError:
        raise ImproperlyConfigured(FLOOR_MESSAGE)
    return imported


TrustsImplementationConfig = _load_implementation_config()


def winfs_config(apps_registry=None):
    """Return the installed ``WinfsConfig`` by class identity."""
    from django.apps import apps as django_apps

    registry = django_apps if apps_registry is None else apps_registry
    matches = [
        config for config in registry.get_app_configs()
        if type(config) is WinfsConfig
    ]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise ImproperlyConfigured(
            'No installed winfs.apps.WinfsConfig.'
        )
    raise ImproperlyConfigured(
        'Multiple WinfsConfig instances: %r' % (matches,)
    )


class WinfsConfig(TrustsImplementationConfig):
    """Windows implementation owner. Core is a library, not an installed app.

    Owns ``winfs.backends.WinfsAuthorizationBackend``. ``ready()``
    donates the explicit-DACL OrderedFold plan and never calls
    ``kernel_config()`` or ``Context``.
    """

    name = 'winfs'
    label = 'winfs'
    verbose_name = 'Windows filesystem ACL'
    default_auto_field = 'django.db.models.AutoField'
    default = True
    trusts_backend_paths = (CANONICAL_BACKEND,)

    def ready(self):
        from trusts.apps import implementation_for_path

        from winfs.policy import register_explicit_dacl

        super(WinfsConfig, self).ready()

        owner = implementation_for_path(
            CANONICAL_BACKEND, apps_registry=getattr(self, 'apps', None),
        )
        registry = owner.configured_backend(CANONICAL_BACKEND).registry
        if getattr(self, '_winfs_policy_registry_id', None) is registry:
            return
        register_explicit_dacl(registry)
        self._winfs_policy_registry_id = registry
