"""Final-core registrations for the bounded Windows consumer.

OrderedFold compiles explicit-DACL remaining-bits. Ancestor inheritance,
OI/CI/NP/IO, CREATOR_OWNER, OWNER_RIGHTS, owner pre-grant, and
cycle/depth failure stay on the preserved PostgreSQL evaluator: Along
has no PostgreSQL renderer, and OrderedFold has no inheritance slot.
"""

from django.contrib.auth.models import Permission

from trusts.core import (
    Along,
    FlatToken,
    MaskEntry,
    OrderedFold,
    PermissionMaskDomain,
    PolarityMap,
    Ref,
)

from winfs.constants import (
    ACE_ALLOW,
    ACE_DENY,
    FILE_READ_DATA,
    FILE_WRITE_DATA,
    MAX_PARENT_DEPTH,
    READ_CONTROL,
    WRITE_DAC,
)
from winfs.models import WinAce, WinNode, WinPrincipal, WinSidMember


MASKS = (
    MaskEntry('read', FILE_READ_DATA),
    MaskEntry('write', FILE_WRITE_DATA),
    MaskEntry('rc', READ_CONTROL),
    MaskEntry('wd', WRITE_DAC),
)

# Along models the 64-parent-link bound. Runtime walk SQL is SQLite-only;
# this declaration is the closed reachability shape, not the PG evaluator.
PARENT_REACH_BOUND = MAX_PARENT_DEPTH


def register_explicit_dacl(registry):
    """Register the explicit-DACL OrderedFold plan. Zero SQL."""
    ace = Ref(WinAce)
    node = Ref(WinNode)
    principal = Ref(WinPrincipal)
    member = Ref(WinSidMember)
    registry.register_strategy(OrderedFold(
        content=node,
        descriptor=node.security_descriptor,
        source=ace,
        source_descriptor=ace.descriptor,
        order=ace.ace_order,
        polarity=PolarityMap(
            ace.ace_type, allow_value=ACE_ALLOW, deny_value=ACE_DENY,
        ),
        mask=ace.access_mask,
        trustee=ace.trustee,
        token=FlatToken(
            principal=principal,
            principal_user=principal.user,
            principal_identity=principal.sid,
            member=member,
            member_identity=member.member,
            member_group=member.group.sid,
        ),
        domain=PermissionMaskDomain(Permission, MASKS),
    ))


def parent_along():
    """Closed Along shape for WinNode.parent at the approved depth bound."""
    return Along(Ref(WinNode).parent, bound=PARENT_REACH_BOUND)
