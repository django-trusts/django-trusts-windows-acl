# django-trusts-windows-acl

django-trusts-windows-acl is a bounded relational implementation of Windows filesystem DACL semantics for Django. It models SIDs, local groups, security descriptors, ownership, ordered allow/deny ACEs, and inherited permissions, with object checks and authorized listings evaluated in fixed SQL queries.

The project validates the reusable Context contract from django-trusts while keeping Windows-specific policy data and evaluation independent of its convenience models. It is a reference implementation—not a complete replacement for Windows AccessCheck—and explicitly fails closed for unsupported Windows security features.
