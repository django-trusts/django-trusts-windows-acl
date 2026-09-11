"""Windows consumer backend. Login stays Django ModelBackend."""

from django.contrib.auth.backends import ModelBackend

from trusts.backends import TrustModelBackendMixin


class WinfsAuthorizationBackend(TrustModelBackendMixin, ModelBackend):
    """Owns the OrderedFold explicit-DACL plan. Not used for username login."""
