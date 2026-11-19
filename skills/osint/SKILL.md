---
name: ctf-osint
description: Use when an authorized CTF challenge explicitly requires public domain, certificate, DNS, image, QR, archived web, configuration leak or public-source analysis tied to the challenge.
---

# Scoped OSINT

## Allowed objective

Only investigate information necessary to solve the challenge:

- challenge-owned domains;
- public DNS/certificate records;
- challenge-authored pages and archives;
- public files or images supplied as evidence;
- explicitly named public accounts or organizations.

Do not profile unrelated people, collect private contact details, bypass logins, or combine data to identify non-public individuals.

## Workflow

1. Record the exact clue and why a public source is needed.
2. Prefer official/public sources.
3. Capture timestamp, URL, relevant excerpt and artifact hash.
4. Distinguish observed public facts from inference.
5. Stop if the search drifts away from the challenge object.

## Common techniques

- DNS/WHOIS/RDAP and certificate transparency.
- Search-engine dorks limited to challenge text.
- Wayback/public archive comparison.
- EXIF/geolocation analysis from a supplied image.
- Git, Dockerfile, configuration and source-map exposure on the authorized challenge.

## Reporting

Do not include unrelated personal data. Report only the minimum evidence needed for the flag path.
