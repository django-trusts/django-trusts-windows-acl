# Migration record (django-trusts-windows-acl)

Consumer configuration changed in the #17 validation slice. Evaluator
method signatures did **not** change.

## 1. Ordinary authentication uses Django `ModelBackend`

| | |
| --- | --- |
| Previous | `AUTHENTICATION_BACKENDS = ["trusts.backends.TrustModelBackend"]` |
| New | `AUTHENTICATION_BACKENDS = ["django.contrib.auth.backends.ModelBackend"]` |
| Replacement | Settings-only. Login, `force_login`, and `authenticate` are Django username/password. |
| Affected | `config/settings.py`. No view or evaluator call site. |
| Authorization | Unchanged. AccessCheck does not call `user.has_perm` or compile Trust grants. On current django-trusts master, `TrustModelBackend` lives in optional `django-trusts-zero` (`trusts.zero.backends`) and is not installed here. |

### Bot checklist

- [ ] Search `TrustModelBackend` / `trusts.backends` in this repo.
- [ ] Keep `ModelBackend` unless a test truly needs Zero grant compilation (none do).
- [ ] Verify `python manage.py test winfs.tests.test_settings`.

## 2. Install Trusts as `KernelConfig` (kernel master after #53)

| | |
| --- | --- |
| Previous | `INSTALLED_APPS` included bare `"trusts"` at pin `a2ab5a13752751ee761990bea778c9f868b2ad6e`. |
| New | `INSTALLED_APPS` includes `"trusts.apps.KernelConfig"` at pin `bfd55e23a9c7706271e3560c0ee1804023f1e69f`. No `django-trusts-zero`. |
| Replacement | Mechanical settings + requirements / `pyproject.toml` pin bump. |
| Affected | `config/settings.py`, `requirements.txt`, `pyproject.toml`, CI install step. |
| Authorization | Context `register_direct` / `register_related` unchanged. Kernel system checks (`trusts.E006` / `E007` / `E008`) register from `KernelConfig.ready()`. Legacy Zero IDs `trusts.E001` / `E002` are not emitted on a kernel-only install; `manage.py check` must stay clean of all `trusts.*` issues. Bare `"trusts"` is invalid (`KernelConfig.default = False`). |

### Bot checklist

- [ ] Replace `"trusts"` in `INSTALLED_APPS` with `"trusts.apps.KernelConfig"`.
- [ ] Do not add `"trusts.zero.apps.ZeroConfig"` or `django-trusts-zero`.
- [ ] Pin `django-trusts` to `bfd55e23a9c7706271e3560c0ee1804023f1e69f` (or a later reviewed master).
- [ ] Run `python manage.py check` (no `trusts.E001` / `E002` / `E006` / `E007` / `E008`).

## 3. Evaluator API — no method change

`access_check`, `authorized_pks`, `authorized_nodes`, and
`explain_access_sql` keep the same signatures and fail-closed meaning.
`WinfsBackendError` is still the non-PostgreSQL gate. No data migration.

Oracle helpers (`winfs.oracle.*`) are new comparison/catalog surfaces,
not replacements for the evaluator.
