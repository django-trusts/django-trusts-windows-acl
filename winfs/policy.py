"""OrderedFold registration on WinNode; Along as the parent-walk bound.

Donate through the extension-owned ``register_ordered_fold`` onto the
configured ``WinfsBackend`` handle. Do not call Core
``BackendHandle.register_ordered_fold`` or construct public ``Ref``
fields on the OrderedFold declaration.

Along is not passed to ``register_relationship(..., along=)``. This
path does not register a relationship plan. Windows ACE inheritance
(OI/CI/NP/IO, protected, IO-only) is not grant-on-ancestor
reachability. The consumer ancestor CTE uses ``INHERITANCE_WALK.bound``
(64) as the parent-link cap.
"""

from django.contrib.auth.models import Permission

from winfs.compat import require_ordered_fold
from winfs.constants import (
    LIST,
    MAX_PARENT_DEPTH,
    R,
    RC,
    W,
    WD,
    X,
)

_core = require_ordered_fold()
Along = _core["Along"]
FlatToken = _core["FlatToken"]
MaskEntry = _core["MaskEntry"]
OrderedFold = _core["OrderedFold"]
OrderedFoldBackendHandle = _core["OrderedFoldBackendHandle"]
PermissionMaskDomain = _core["PermissionMaskDomain"]
PolarityMap = _core["PolarityMap"]
Ref = _core["Ref"]
register_ordered_fold = _core["register_ordered_fold"]

from winfs.models import WinAce, WinNode, WinPrincipal, WinSidMember

CANONICAL_BACKEND = "winfs.backends.WinfsBackend"

MASK_ENTRIES = (
    MaskEntry("read", R),
    MaskEntry("write", W),
    MaskEntry("execute", X),
    MaskEntry("readwrite", R | W),
    MaskEntry("list", LIST),
    MaskEntry("readcontrol", RC),
    MaskEntry("writedac", WD),
)

PERMISSION_DOMAIN = PermissionMaskDomain(Permission, MASK_ENTRIES)

# Typed bound for the consumer parent walk. Not a relationship along=.
INHERITANCE_WALK = Along(Ref(WinNode).parent, bound=MAX_PARENT_DEPTH)

NODE_FOLD = OrderedFold(
    content=WinNode,
    descriptor="security_descriptor",
    source_descriptor="descriptor",
    order="ace_order",
    polarity=PolarityMap(
        "ace_type",
        allow_value="allow",
        deny_value="deny",
    ),
    mask="access_mask",
    trustee="trustee_sid",
    token=FlatToken(
        principal=WinPrincipal,
        principal_user="user",
        principal_identity="sid",
        member=WinSidMember,
        member_identity="member_sid",
        member_group="group_sid__sid",
    ),
    domain=PERMISSION_DOMAIN,
)

# Public configured-backend identity for repeated startup donation.
# OrderedFoldBackendHandle equality is (path, registry, compiler), so a
# swapped store re-donates and the same configured backend does not.
_donated_backends = set()

_CODE_TO_MASK = {
    "%s_%s" % (entry.action, WinNode._meta.model_name): entry.mask
    for entry in MASK_ENTRIES
}


def ensure_domain_permissions():
    """Create OrderedFold domain Permission rows (post-migrate / tests)."""
    from django.contrib.contenttypes.models import ContentType

    ct = ContentType.objects.get_for_model(WinNode)
    created = []
    for entry in MASK_ENTRIES:
        codename = "%s_%s" % (entry.action, WinNode._meta.model_name)
        obj, was_created = Permission.objects.get_or_create(
            content_type=ct,
            codename=codename,
            defaults={"name": "WinFS %s" % entry.action},
        )
        if was_created:
            created.append(obj)
    return created


def register_winfs_policy(backend):
    """Donate the WinNode OrderedFold plan through the extension registry.

    Idempotent on the same configured-backend identity. Does not inspect
    private registry state for donation or idempotency. Does not call
    Core ``BackendHandle.register_ordered_fold``.
    """
    if not isinstance(backend, OrderedFoldBackendHandle):
        raise TypeError(
            "register_winfs_policy requires an OrderedFold backend "
            "handle, not %r." % (type(backend).__name__,)
        )
    if backend in _donated_backends:
        return
    register_ordered_fold(backend, WinAce, NODE_FOLD)
    _donated_backends.add(backend)


def _is_winnode_identity(app_label, model_name):
    """True only for the canonical ``winfs`` / ``WinNode`` permission identity."""
    return (
        app_label == WinNode._meta.app_label
        and model_name == WinNode._meta.model_name
    )


def mask_for_permission(permission):
    """Return the 32-bit ACCESS_MASK for a WinNode domain permission, or None.

    Requires the ``winfs`` app label and the ``WinNode`` content type. A
    matching codename on another app or model does not map.
    """
    if permission is None:
        return None
    codename = getattr(permission, "codename", None)
    if not isinstance(codename, str):
        return None
    ct = getattr(permission, "content_type", None)
    if ct is None:
        return None
    if not _is_winnode_identity(
        getattr(ct, "app_label", None),
        getattr(ct, "model", None),
    ):
        return None
    return _CODE_TO_MASK.get(codename)


def mask_for_perm_code(permext):
    """Parse ``winfs.action_winnode`` / ``winfs.action_winnode:cond`` to a mask.

    The app label must be ``winfs``. ``auth.read_winnode`` does not map.
    """
    if not isinstance(permext, str) or "." not in permext:
        return None
    app, code = permext.split(".", 1)
    code = code.split(":", 1)[0]
    if app != WinNode._meta.app_label:
        return None
    expected_suffix = "_%s" % WinNode._meta.model_name
    if not code.endswith(expected_suffix):
        return None
    return _CODE_TO_MASK.get(code)
