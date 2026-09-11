"""Apply a catalog vector to the shared fixture tree for evaluator replay.

Setups mirror ``winfs.tests.test_matrix`` so docs-vs-evaluator and
host-vs-evaluator use the same relational policy. They do not encode
Windows-host outcomes.
"""

from django.contrib.auth import get_user_model
from django.db import connection

from winfs.constants import ACE_ALLOW, R, SID_OWNER_RIGHTS, W, WD
from winfs.evaluate import access_check
from winfs.fixtures import add_ace_raw, allow, deny, empty_dacl, file, sid
from winfs.inherit import set_dacl_protected
from winfs.models import WinNode

from .catalog import get_vector

User = get_user_model()


def _user(data, name):
    if name == "noprincipal":
        return data.setdefault(
            "noprincipal_user",
            User.objects.create_user("noprincipal", password="demo"),
        )
    return data["users"][name]


def _target(data, name):
    if name == "unregistered":
        return data["alice"].sid
    if name == "new":
        return data["new"]
    return data[name]


def apply_vector(vector_id, data):
    """Mutate ``data`` (a ``standard_tree()`` dict) to the vector's policy.

    Returns ``(user, resource, mask)``.
    """
    vector = get_vector(vector_id)
    setup = _SETUPS[vector_id]
    setup(data)
    return _user(data, vector.requester), _target(data, vector.target), vector.mask


def evaluate_vector(vector_id, data):
    user, resource, mask = apply_vector(vector_id, data)
    return access_check(user, resource, mask)


def _nothing(data):
    return None


def _allow_alice_r(data):
    allow(data["notes"], data["alice"], R)


def _deny_then_allow(data):
    deny(data["notes"], data["alice"], R)
    allow(data["notes"], data["alice"], R)


def _allow_then_deny(data):
    allow(data["notes"], data["alice"], R)
    deny(data["notes"], data["alice"], R)


def _user_deny_group_allow(data):
    deny(data["notes"], data["alice"], R)
    allow(data["notes"], data["eng"], R)


def _missing_sd(data):
    data["notes"].security_descriptor = None
    data["notes"].save()


def _allow_r_request_rw(data):
    allow(data["notes"], data["alice"], R)


def _allow_r_and_w(data):
    allow(data["notes"], data["alice"], R)
    allow(data["notes"], data["alice"], W)


def _allow_rw_deny_w(data):
    allow(data["notes"], data["alice"], R | W)
    deny(data["notes"], data["alice"], W)


def _allow_r_deny_w(data):
    allow(data["notes"], data["alice"], R)
    deny(data["notes"], data["alice"], W)


def _deny_owner_wd(data):
    deny(data["notes"], data["alice"], WD)


def _proj_oi_ci(data):
    allow(data["proj"], data["eng"], R, oi=True, ci=True)


def _proj_ci(data):
    allow(data["proj"], data["eng"], R, ci=True)


def _proj_oi(data):
    allow(data["proj"], data["eng"], R, oi=True)


def _proj_oi_ci_np(data):
    allow(data["proj"], data["eng"], R, oi=True, ci=True, np=True)


def _protect_empty_secret(data):
    allow(data["proj"], data["eng"], R, oi=True, ci=True)
    sd = data["secret"].security_descriptor
    sd.se_dacl_protected = True
    sd.save(update_fields=["se_dacl_protected"])


def _protect_preserve_secret(data):
    allow(data["proj"], data["eng"], R, oi=True, ci=True)
    set_dacl_protected(data["secret"], preserve=True)


def _proj_oi_ci_io(data):
    allow(data["proj"], data["eng"], R, oi=True, ci=True, io=True)


def _child_not_parent(data):
    allow(data["notes"], data["alice"], R)


def _bob_list_not_readme(data):
    allow(data["proj"], data["bob"], R)
    deny(data["readme"], data["bob"], R)


def _group_then_user_deny(data):
    allow(data["notes"], data["eng"], R)
    deny(data["notes"], data["alice"], R)


def _cycle(data):
    allow(data["proj"], data["eng"], R, oi=True, ci=True)
    with connection.cursor() as cursor:
        cursor.execute("SET LOCAL session_replication_role = replica")
        WinNode.objects.filter(pk=data["proj"].pk).update(parent=data["secret"])
        cursor.execute("SET LOCAL session_replication_role = origin")


def _new_child(data):
    allow(data["proj"], data["eng"], R, oi=True, ci=True)
    data["new"] = file(data["volume"], "new.txt", data["admin"], parent=data["proj"])


def _explicit_owner_rights(data):
    add_ace_raw(
        data["notes"].security_descriptor,
        ACE_ALLOW,
        sid(SID_OWNER_RIGHTS),
        WD,
    )


def _group_owner(data):
    sd = data["notes"].security_descriptor
    sd.owner = data["eng"].sid
    sd.save(update_fields=["owner"])


def _inherited_owner_rights(data):
    add_ace_raw(
        data["proj"].security_descriptor,
        ACE_ALLOW,
        sid(SID_OWNER_RIGHTS),
        WD,
        oi=True,
        ci=True,
    )
    empty_dacl(data["notes"])


_SETUPS = {
    "V1": _nothing,
    "V2": _missing_sd,
    "V3": _allow_alice_r,
    "V4": _deny_then_allow,
    "V5": _allow_then_deny,
    "V6": _user_deny_group_allow,
    "V7": _user_deny_group_allow,
    "V8": _user_deny_group_allow,
    "V9": _allow_r_request_rw,
    "V10": _allow_r_and_w,
    "V11": _allow_rw_deny_w,
    "V12": _allow_rw_deny_w,
    "V13": _allow_r_deny_w,
    "V14": _nothing,
    "V15": _nothing,
    "V16": _deny_owner_wd,
    "V17": _proj_oi_ci,
    "V18": _proj_oi_ci,
    "V19": _proj_ci,
    "V20": _proj_oi,
    "V21": _proj_oi,
    "V22": _proj_oi,
    "V23": _proj_oi,
    "V24": _proj_oi_ci_np,
    "V25": _proj_oi_ci_np,
    "V26": _protect_empty_secret,
    "V27": _protect_empty_secret,
    "V28": _protect_preserve_secret,
    "V29": _protect_preserve_secret,
    "V30": _proj_oi_ci_io,
    "V31": _proj_oi_ci_io,
    "V32": _child_not_parent,
    "V33": _bob_list_not_readme,
    "V34": _bob_list_not_readme,
    "V35": _group_then_user_deny,
    "V36": _cycle,
    "V37": _nothing,
    "V38": _nothing,
    "V39": _new_child,
    "V40": _explicit_owner_rights,
    "V41": _group_owner,
    "V42": _group_owner,
    "V43": _inherited_owner_rights,
}
