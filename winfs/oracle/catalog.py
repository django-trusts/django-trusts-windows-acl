"""V1–V43 catalog: Microsoft-documented expectations plus host-oracle hints.

Every row is ``microsoft-docs``. Host-observed allow/deny bits never live
here. See ``fixtures/windows_host_observed.json`` for native captures.
"""

from __future__ import annotations

from dataclasses import dataclass

from winfs.constants import R, W, WD

from .schema import MS_DOCS_PROVENANCE

# String forms match winfs.evaluate error codes. Keep literals here so
# catalog.json can be dumped without importing Django / the evaluator.
ERR_CONTEXT = "context_not_registered"
ERR_CYCLE = "cycle"
ERR_MISSING_PRINCIPAL = "missing_principal"
ERR_MISSING_SD = "missing_descriptor"
ERR_OWNER_RIGHTS = "owner_rights"


@dataclass(frozen=True)
class HostOracle:
    representable: bool
    compare: str
    notes: str


@dataclass(frozen=True)
class DocsExpected:
    allowed: bool
    error: str | None = None


@dataclass(frozen=True)
class Vector:
    id: str
    title: str
    family: str
    requester: str
    target: str
    mask: int
    docs_expected: DocsExpected
    host_oracle: HostOracle
    provenance: str = MS_DOCS_PROVENANCE

    def as_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "family": self.family,
            "provenance": self.provenance,
            "requester": self.requester,
            "target": self.target,
            "mask": self.mask,
            "docs_expected": {
                "allowed": self.docs_expected.allowed,
                "error": self.docs_expected.error,
            },
            "host_oracle": {
                "representable": self.host_oracle.representable,
                "compare": self.host_oracle.compare,
                "notes": self.host_oracle.notes,
            },
        }


def _host(representable, compare, notes):
    return HostOracle(representable, compare, notes)


def _exp(allowed, error=None):
    return DocsExpected(allowed, error)


_NTFS = "Native NTFS DACL + advapi32 AccessCheck on a Windows host."
_ORDER = _NTFS + " Non-canonical order needs a raw SECURITY_DESCRIPTOR (SDDL); high-level APIs canonicalize."
_INH = _NTFS + " Create children after the parent DACL so write-time inheritance applies."
_PROT = _NTFS + " SE_DACL_PROTECTED via SetAccessRuleProtection / icacls inheritance disable."
_OWN = _NTFS + " Owner is READ_CONTROL|WRITE_DAC, not file data. Set owner SID before AccessCheck."
_OR = (
    "Windows applies OWNER_RIGHTS (S-1-3-4) instead of implicit owner bits. "
    "This evaluator wholly rejects S-1-3-4 (DENY+error) rather than implementing that substitution. "
    "Host capture is allowed; compare is expected-divergence."
)
_LOCAL = "Evaluator-local / Trusts Context / operational gate. Not a native AccessCheck vector."


def _v(vid, title, family, requester, target, mask, allowed, error, host):
    return Vector(vid, title, family, requester, target, mask, _exp(allowed, error), host)


CATALOG: tuple[Vector, ...] = (
    _v("V1", "empty DACL denies read", "empty-missing", "alice", "notes", R, False, None, _host(True, "must-match", _NTFS)),
    _v("V2", "missing descriptor denies", "empty-missing", "alice", "notes", R, False, ERR_MISSING_SD, _host(False, "not-representable", _LOCAL)),
    _v("V3", "explicit allow", "ordered-ace", "alice", "notes", R, True, None, _host(True, "must-match", _NTFS)),
    _v("V4", "canonical deny then allow", "ordered-ace", "alice", "notes", R, False, None, _host(True, "must-match", _ORDER)),
    _v("V5", "noncanonical allow then deny is not deny-wins", "ordered-ace", "alice", "notes", R, True, None, _host(True, "must-match", _ORDER)),
    _v("V6", "user deny before group allow", "users-groups", "alice", "notes", R, False, None, _host(True, "must-match", _ORDER)),
    _v("V7", "group allow for other member", "users-groups", "bob", "notes", R, True, None, _host(True, "must-match", _NTFS)),
    _v("V8", "non-member implicit deny", "users-groups", "carol", "notes", R, False, None, _host(True, "must-match", _NTFS)),
    _v("V9", "partial bits denied", "requested-bits", "alice", "notes", R | W, False, None, _host(True, "must-match", _NTFS)),
    _v("V10", "allow bits accumulate", "requested-bits", "alice", "notes", R | W, True, None, _host(True, "must-match", _NTFS)),
    _v("V11", "noncanonical allow clears denied bit", "requested-bits", "alice", "notes", W, True, None, _host(True, "must-match", _ORDER)),
    _v("V12", "same as V11 combined request", "requested-bits", "alice", "notes", R | W, True, None, _host(True, "must-match", _ORDER)),
    _v("V13", "remaining write denied", "requested-bits", "alice", "notes", R | W, False, None, _host(True, "must-match", _NTFS)),
    _v("V14", "owner WRITE_DAC", "owner", "alice", "notes", WD, True, None, _host(True, "must-match", _OWN)),
    _v("V15", "owner is not file read", "owner", "alice", "notes", R, False, None, _host(True, "must-match", _OWN)),
    _v("V16", "owner pre-grant before owner-SID deny", "owner", "alice", "notes", WD, True, None, _host(True, "must-match", _OWN)),
    _v("V17", "file inherits OI", "inheritance", "alice", "readme", R, True, None, _host(True, "must-match", _INH)),
    _v("V18", "container CI effective", "inheritance", "alice", "proj", R, True, None, _host(True, "must-match", _INH)),
    _v("V19", "CI only does not reach file", "inheritance", "alice", "readme", R, False, None, _host(True, "must-match", _INH)),
    _v("V20", "OI without IO is effective on container", "inheritance", "alice", "proj", R, True, None, _host(True, "must-match", _INH)),
    _v("V21", "OI only file inherits", "inheritance", "alice", "readme", R, True, None, _host(True, "must-match", _INH)),
    _v("V22", "OI only child container is inherit-only", "inheritance", "alice", "secret", R, False, None, _host(True, "must-match", _INH)),
    _v("V23", "OI only grandchild file inherits", "inheritance", "alice", "notes", R, True, None, _host(True, "must-match", _INH)),
    _v("V24", "NP immediate container", "inheritance", "alice", "secret", R, True, None, _host(True, "must-match", _INH)),
    _v("V25", "NP does not reach grandchild", "inheritance", "alice", "notes", R, False, None, _host(True, "must-match", _INH)),
    _v("V26", "protected empty secret", "protected", "alice", "secret", R, False, None, _host(True, "must-match", _PROT)),
    _v("V27", "protect stops walk to notes", "protected", "alice", "notes", R, False, None, _host(True, "must-match", _PROT)),
    _v("V28", "preserve converts inherited on secret", "protected", "alice", "secret", R, True, None, _host(True, "must-match", _PROT)),
    _v("V29", "preserve children inherit from secret", "protected", "alice", "notes", R, True, None, _host(True, "must-match", _PROT)),
    _v("V30", "IO skipped on proj", "inheritance", "alice", "proj", R, False, None, _host(True, "must-match", _INH)),
    _v("V31", "IO on proj still inheritable", "inheritance", "alice", "readme", R, True, None, _host(True, "must-match", _INH)),
    _v("V32", "child read is not parent list", "listing", "alice", "secret", R, False, None, _host(True, "must-match", _NTFS)),
    _v("V33", "folder list allowed", "listing", "bob", "proj", R, True, None, _host(True, "must-match", _NTFS)),
    _v("V34", "name visibility is not read", "listing", "bob", "readme", R, False, None, _host(True, "must-match", _NTFS)),
    _v("V35", "group allow before user deny", "users-groups", "alice", "notes", R, True, None, _host(True, "must-match", _ORDER)),
    _v("V36", "cycle fail-closed", "evaluator-local", "alice", "notes", R, False, ERR_CYCLE, _host(False, "not-representable", _LOCAL)),
    _v("V37", "unregistered resource denies", "evaluator-local", "alice", "unregistered", R, False, ERR_CONTEXT, _host(False, "not-representable", _LOCAL)),
    _v("V38", "missing principal", "evaluator-local", "noprincipal", "notes", R, False, ERR_MISSING_PRINCIPAL, _host(False, "not-representable", _LOCAL)),
    _v("V39", "new child inherits from proj", "inheritance", "alice", "new", R, True, None, _host(True, "must-match", _INH)),
    _v("V40", "explicit OWNER_RIGHTS rejected", "owner-rights", "alice", "notes", WD, False, ERR_OWNER_RIGHTS, _host(True, "expected-divergence", _OR)),
    _v("V41", "group owner pre-grant", "owner", "alice", "notes", WD, True, None, _host(True, "must-match", _OWN)),
    _v("V42", "non-member group owner", "owner", "carol", "notes", WD, False, None, _host(True, "must-match", _OWN)),
    _v("V43", "inherited OWNER_RIGHTS rejected", "owner-rights", "alice", "notes", WD, False, ERR_OWNER_RIGHTS, _host(True, "expected-divergence", _OR)),
)

VECTOR_IDS = tuple(v.id for v in CATALOG)
_BY_ID = {v.id: v for v in CATALOG}


def get_vector(vector_id):
    try:
        return _BY_ID[vector_id]
    except KeyError as exc:
        raise KeyError("unknown vector %s" % vector_id) from exc


def catalog_document():
    return {
        "schema_version": 1,
        "provenance": MS_DOCS_PROVENANCE,
        "source": "Microsoft AccessCheck / ACE inheritance / MS-DTYP as cited on django-trusts#17",
        "vectors": [v.as_dict() for v in CATALOG],
    }
