"""Fail closed when this consumer is paired with an incompatible stack."""

from django.core.exceptions import ImproperlyConfigured

CORE_REQUIREMENT = "django-trusts>=1.0.0.dev3,<2"
CORE_PIN = "6934894489d4fc0e46de88b55b9a27f5f2eb2b41"
ORDERED_FOLD_REQUIREMENT = "django-trusts-ordered-fold>=1.0.0.dev0,<2"
ORDERED_FOLD_PIN = "c8c649aa5278db2b11fc380fa1646ae73df471ac"
ORDERED_FOLD_REVIEWED_HEAD = "639d4503f950931fee8bb900942bb1e599ae9b68"
FLOOR_MESSAGE = (
    "django-trusts-windows-acl requires %s (C1 merge %s) and %s "
    "(P2 squash %s; TrustsOrderedFoldModelBackend, "
    "OrderedFoldImplementationConfig, "
    "trusts_ordered_fold.register_ordered_fold). "
    "Do not rely on Core fold-name shims."
    % (CORE_REQUIREMENT, CORE_PIN, ORDERED_FOLD_REQUIREMENT, ORDERED_FOLD_PIN)
)


def require_ordered_fold():
    """Import the OrderedFold package and Core relationship names.

    Safe during AppConfig import: does not import
    ``trusts_ordered_fold.backends`` (its concrete backend subclasses
    Django ``ModelBackend``).

    Transitional ``KernelConfig`` and the removed ``trusts.context``
    contract are incompatible. Core fold-name shims
    (``trusts.core.OrderedFold``, ``BackendHandle.register_ordered_fold``)
    are not a compatibility floor.
    """
    try:
        from trusts.apps import TrustsImplementationConfig
        from trusts.core import Along, Ref
        from trusts_ordered_fold import (
            FlatToken,
            MaskEntry,
            OrderedFold,
            OrderedFoldBackendHandle,
            OrderedFoldImplementationConfig,
            PermissionMaskDomain,
            PolarityMap,
            register_ordered_fold,
        )
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
    if not issubclass(
        OrderedFoldImplementationConfig, TrustsImplementationConfig
    ):
        raise ImproperlyConfigured(FLOOR_MESSAGE)
    if not callable(register_ordered_fold):
        raise ImproperlyConfigured(FLOOR_MESSAGE)
    return {
        "Along": Along,
        "FlatToken": FlatToken,
        "MaskEntry": MaskEntry,
        "OrderedFold": OrderedFold,
        "OrderedFoldBackendHandle": OrderedFoldBackendHandle,
        "OrderedFoldImplementationConfig": OrderedFoldImplementationConfig,
        "PermissionMaskDomain": PermissionMaskDomain,
        "PolarityMap": PolarityMap,
        "Ref": Ref,
        "TrustsImplementationConfig": TrustsImplementationConfig,
        "register_ordered_fold": register_ordered_fold,
    }


def require_ordered_fold_backend():
    """Import the concrete OrderedFold backend after Django models are ready.

    Refuse a leftover Core ``TrustModelBackend``. Do not inherit
    ``ModelBackend`` a second time on ``WinfsBackend``.
    """
    names = require_ordered_fold()
    try:
        from trusts_ordered_fold.backends import TrustsOrderedFoldModelBackend
    except ImportError as exc:
        raise ImproperlyConfigured(FLOOR_MESSAGE) from exc

    import trusts.backends as backends_mod

    if hasattr(backends_mod, "TrustModelBackend"):
        raise ImproperlyConfigured(
            "django-trusts-windows-acl refuses TrustModelBackend; "
            "subclass TrustsOrderedFoldModelBackend. %s."
            % CORE_REQUIREMENT
        )
    names["TrustsOrderedFoldModelBackend"] = TrustsOrderedFoldModelBackend
    return names


# Historical names used by older tests / import sites.
require_final_core = require_ordered_fold
require_final_core_backend = require_ordered_fold_backend
