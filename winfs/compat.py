"""Fail closed when this consumer is paired with an incompatible core."""

from django.core.exceptions import ImproperlyConfigured

CORE_REQUIREMENT = "django-trusts>=1.0.0.dev3,<2"
CORE_PIN = "1e19b5d464c067186aada58943c3ee67c44b2aa0"
FLOOR_MESSAGE = (
    "django-trusts-windows-acl requires %s "
    "(TrustsImplementationConfig, OrderedFold, Along; core merge %s). "
    "Upgrade django-trusts; do not rely on a missing import."
    % (CORE_REQUIREMENT, CORE_PIN)
)


def require_final_core():
    """Import final public names or raise ``ImproperlyConfigured``.

    Safe during AppConfig import: does not import ``trusts.backends``
    (its mixin body calls ``get_permission_model()``).

    Transitional ``KernelConfig`` and the removed ``trusts.context``
    contract are incompatible.
    """
    try:
        from trusts.apps import TrustsImplementationConfig
        from trusts.core import Along, FlatToken, OrderedFold, Ref
    except ImportError as exc:
        raise ImproperlyConfigured(FLOOR_MESSAGE) from exc

    import trusts.apps as apps_mod

    if hasattr(apps_mod, "KernelConfig"):
        raise ImproperlyConfigured(
            "django-trusts-windows-acl refuses KernelConfig; %s."
            % CORE_REQUIREMENT
        )
    try:
        import trusts.context  # noqa: F401
    except ImportError:
        pass
    else:
        raise ImproperlyConfigured(
            "django-trusts-windows-acl refuses trusts.context; %s."
            % CORE_REQUIREMENT
        )
    return {
        "Along": Along,
        "FlatToken": FlatToken,
        "OrderedFold": OrderedFold,
        "Ref": Ref,
        "TrustsImplementationConfig": TrustsImplementationConfig,
    }


def require_final_core_backend():
    """Import the mixin after Django models are ready. Refuse TrustModelBackend."""
    names = require_final_core()
    try:
        from trusts.backends import TrustModelBackendMixin
    except ImportError as exc:
        raise ImproperlyConfigured(FLOOR_MESSAGE) from exc

    import trusts.backends as backends_mod

    if hasattr(backends_mod, "TrustModelBackend"):
        raise ImproperlyConfigured(
            "django-trusts-windows-acl refuses TrustModelBackend; "
            "use TrustModelBackendMixin. %s."
            % CORE_REQUIREMENT
        )
    names["TrustModelBackendMixin"] = TrustModelBackendMixin
    return names
