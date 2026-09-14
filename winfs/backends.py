"""Configured OrderedFold backend. Login stays on Django ModelBackend."""

from winfs.compat import require_ordered_fold_backend

_core = require_ordered_fold_backend()
TrustsOrderedFoldModelBackend = _core["TrustsOrderedFoldModelBackend"]

CANONICAL_BACKEND = "winfs.backends.WinfsBackend"


class WinfsBackend(TrustsOrderedFoldModelBackend):
    """Object authorization host for the Windows OrderedFold plan.

    ``TrustsOrderedFoldModelBackend`` is already the concrete Django
    ``ModelBackend``. Do not inherit ``ModelBackend`` again and do not
    list the generic OrderedFold backend as a second
    ``AUTHENTICATION_BACKENDS`` path.

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
