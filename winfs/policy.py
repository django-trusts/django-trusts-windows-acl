"""Final-core registration: OrderedFold on WinNode, Along as the parent bound.

Along is not passed to ``register()``. AnyPath and OrderedFold cannot share
one content terminal, and the Along grant-reachability renderer is
SQLite-only. Windows ACE inheritance (OI/CI/NP/IO, protected, IO-only)
is not grant-on-ancestor reachability. The consumer ancestor CTE uses
``INHERITANCE_WALK.bound`` (64) as the parent-link cap.
"""

from django.contrib.auth.models import Permission

from winfs.compat import require_final_core
from winfs.constants import (
    LIST,
    MAX_PARENT_DEPTH,
    R,
    RC,
    W,
    WD,
    X,
)

_core = require_final_core()
Along = _core["Along"]
FlatToken = _core["FlatToken"]
OrderedFold = _core["OrderedFold"]
Ref = _core["Ref"]

from trusts.core import MaskEntry, PermissionMaskDomain, PolarityMap

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

_node = Ref(WinNode)
_ace = Ref(WinAce)
_principal = Ref(WinPrincipal)
_member = Ref(WinSidMember)

# Typed bound for the consumer parent walk. Not an AnyPath along=.
INHERITANCE_WALK = Along(_node.parent, bound=MAX_PARENT_DEPTH)

NODE_FOLD = OrderedFold(
    content=_node,
    descriptor=_node.security_descriptor,
    source=_ace,
    source_descriptor=_ace.descriptor,
    order=_ace.ace_order,
    polarity=PolarityMap(
        _ace.ace_type,
        allow_value="allow",
        deny_value="deny",
    ),
    mask=_ace.access_mask,
    trustee=_ace.trustee_sid,
    token=FlatToken(
        principal=_principal,
        principal_user=_principal.user,
        principal_identity=_principal.sid,
        member=_member,
        member_identity=_member.member_sid,
        member_group=_member.group_sid.sid,
    ),
    domain=PERMISSION_DOMAIN,
)

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


def register_winfs_policy(registry):
    """Donate the WinNode OrderedFold plan. Idempotent on the same registry."""
    if any(
        compiled.content_model is WinNode
        for compiled in registry.strategies
    ):
        return registry.strategies
    return registry.register_strategy(NODE_FOLD)


def mask_for_permission(permission):
    """Return the 32-bit ACCESS_MASK for a domain permission, or None."""
    if permission is None:
        return None
    codename = getattr(permission, "codename", None)
    if not isinstance(codename, str):
        return None
    return _CODE_TO_MASK.get(codename)


def mask_for_perm_code(permext):
    """Parse ``app.action_model`` / ``app.action_model:cond`` to a mask."""
    if not isinstance(permext, str) or "." not in permext:
        return None
    _app, code = permext.split(".", 1)
    code = code.split(":", 1)[0]
    return _CODE_TO_MASK.get(code)
