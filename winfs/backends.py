"""Configured Trusts mixin backend. Login stays on Django ModelBackend."""

from django.contrib.auth.backends import ModelBackend

from winfs.compat import require_final_core_backend

_core = require_final_core_backend()
TrustModelBackendMixin = _core["TrustModelBackendMixin"]

CANONICAL_BACKEND = "winfs.backends.WinfsBackend"


class WinfsBackend(TrustModelBackendMixin, ModelBackend):
    """Object authorization host for the Windows OrderedFold plan.

    ``has_perm`` on a ``WinNode`` / ``WinStream`` uses the consumer
    AccessCheck (inheritance, owner pre-grant, fail-closed gates) so the
    Django permission path matches the V1–V43 evaluator.
    """

    def has_perm(self, user_obj, permext, obj=None):
        from winfs.evaluate import access_check_perm

        matched = access_check_perm(user_obj, obj, permext)
        if matched is not None:
            return matched
        return super().has_perm(user_obj, permext, obj)
