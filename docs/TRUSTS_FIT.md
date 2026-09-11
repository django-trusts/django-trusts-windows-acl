# Where Trusts fits in this repository

Final core (`django-trusts>=1.0.0.dev3,<2`) is a Python library. This
consumer owns `WinfsConfig` (`TrustsImplementationConfig`) and
`winfs.backends.WinfsAuthorizationBackend`. Do not list `'trusts'` in
`INSTALLED_APPS`.

## What Trusts compiles

- `registry.register_strategy(OrderedFold(...))` over explicit
  `WinAce` rows on a node's security descriptor: stored-order
  allow/deny, integer masks, requester SID + flat group token.
- Object decision and authorized listing through the same `Allowed`
  predicate (`has_permission`, `WinNode.objects.authorized`).
- `Along(WinNode.parent, bound=64)` is the closed reachability shape
  for the approved depth bound. It has no PostgreSQL renderer, so it is
  not the production inheritance walk.

## What stays Windows-owned

The preserved PostgreSQL CTE in `winfs/evaluate.py` still evaluates
ancestor inheritance, OI/CI/NP/IO, `CREATOR_OWNER`, `OWNER_RIGHTS`,
owner RC|WD pre-grant, and cycle/depth/ACE-scan failure. That is the
V1–V43 oracle. `access_check` / `authorized_*` keep their signatures.

The evaluator path does not use `Trust`, Trustee, `Content`,
`Junction`, `TrustGroup`, `Role`, Django `Group`, `kernel_config()`, or
a core `AppConfig`.
