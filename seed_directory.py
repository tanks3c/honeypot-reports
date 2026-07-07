#!/usr/bin/env python3
"""Generate a harvestable spamtrap seed page.

Publishes many scrapple.win addresses in the formats address harvesters
scrape (plaintext, mailto:, obfuscated) so the catch-all trap starts
receiving unsolicited mail. Standard defensive anti-abuse seeding: every
address here is trap-only, so any mail to them is unsolicited by
definition. A visible notice tells humans not to use them; harvesters
ignore it, which is the point.

Deterministic output (no randomness) so re-runs are stable.
"""
from pathlib import Path

DOMAIN = "scrapple.win"
OUT = Path(__file__).resolve().parent / "docs" / "directory.html"

ROLES = ["info", "contact", "sales", "support", "billing", "accounts",
         "hr", "careers", "jobs", "press", "media", "marketing",
         "admin", "office", "reception", "enquiries", "help", "orders",
         "finance", "legal", "compliance", "procurement", "vendor",
         "partners", "newsletter", "subscribe", "webmaster", "postmaster",
         "no-reply", "notifications"]

PEOPLE = [
    ("James", "Mercer"), ("Priya", "Nair"), ("Daniel", "Okafor"),
    ("Sofia", "Kowalski"), ("Marcus", "Bledsoe"), ("Wei", "Chen"),
    ("Hannah", "Delgado"), ("Omar", "Farouk"), ("Grace", "Whitfield"),
    ("Tobias", "Kron"), ("Amara", "Osei"), ("Elena", "Rusakova"),
    ("Nathan", "Pruitt"), ("Yuki", "Tanaka"), ("Ruth", "Castellano"),
    ("Devon", "Ashcroft"), ("Lena", "Brandt"), ("Isaac", "Mwangi"),
    ("Carla", "Fuentes"), ("Peter", "Halvorsen"),
]

# addresses only a scraper would ever collect (hidden in the page)
BOT_ONLY = [f"harvest-probe-{i:02d}" for i in range(1, 13)]


def person_addrs(first, last):
    f, l = first.lower(), last.lower()
    return [f"{f}.{l}", f"{f[0]}{l}", f"{f}{l[0]}"]


def main():
    dept_rows = []
    for r in ROLES:
        a = f"{r}@{DOMAIN}"
        dept_rows.append(
            f'<tr><td>{r.title()}</td>'
            f'<td><a href="mailto:{a}">{a}</a></td></tr>')

    people_rows = []
    for first, last in PEOPLE:
        addrs = person_addrs(first, last)
        primary = f"{addrs[0]}@{DOMAIN}"
        alt = " ".join(f"{x}@{DOMAIN}" for x in addrs[1:])
        people_rows.append(
            f'<tr><td>{first} {last}</td>'
            f'<td><a href="mailto:{primary}">{primary}</a></td>'
            f'<td class="alt">{alt}</td></tr>')

    hidden = "".join(
        f'<a href="mailto:{b}@{DOMAIN}">{b}@{DOMAIN}</a> '
        for b in BOT_ONLY)

    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Contact directory</title>
<meta name="description" content="Contact directory.">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  :root{{--bg:#0d1620;--raised:#13202c;--line:#223344;--ink:#e7eef4;
    --dim:#93a7b8;--link:#46b6c4;--signal:#f5a623}}
  *{{box-sizing:border-box}}
  body{{margin:0;background:var(--bg);color:var(--ink);
    font-family:"IBM Plex Sans",system-ui,sans-serif;line-height:1.55}}
  .wrap{{max-width:840px;margin:0 auto;padding:24px}}
  a{{color:var(--link);text-decoration:none}} a:hover{{text-decoration:underline}}
  h1{{font-size:1.5rem;margin:.2em 0}}
  h2{{font-size:1rem;color:var(--signal);margin-top:2em}}
  .notice{{background:var(--raised);border:1px solid var(--line);
    border-left:3px solid var(--signal);border-radius:6px;padding:12px 16px;
    margin:16px 0;color:var(--dim);font-size:.9rem}}
  table{{border-collapse:collapse;width:100%;font-family:"IBM Plex Mono",monospace;
    font-size:.85rem;margin-top:8px}}
  th,td{{border:1px solid var(--line);padding:6px 9px;text-align:left}}
  th{{background:var(--raised);color:var(--dim);font-weight:500}}
  .alt{{color:var(--dim)}}
  .void{{position:absolute;left:-9999px;top:auto;height:1px;overflow:hidden}}
  footer{{color:var(--dim);font-size:.8rem;margin-top:2.5em}}
  @media (max-width: 640px) {{
    .wrap {{ padding: 14px; }}
    table {{ display: block; overflow-x: auto; }}
  }}
</style>
</head>
<body><div class="wrap">
<h1>Contact directory</h1>
<div class="notice">Automated address directory. These mailboxes are
monitored spamtrap endpoints on an unattended domain. They are not staffed
and no human reads them. Do not send real correspondence here; it will not
reach anyone. Legitimate contact goes through channels listed elsewhere.</div>

<h2>Departments</h2>
<table><thead><tr><th>Team</th><th>Address</th></tr></thead>
<tbody>{''.join(dept_rows)}</tbody></table>

<h2>Directory</h2>
<table><thead><tr><th>Name</th><th>Primary</th><th>Aliases</th></tr></thead>
<tbody>{''.join(people_rows)}</tbody></table>

<div class="void" aria-hidden="true">{hidden}</div>

<footer>Directory index. Addresses on the domain {DOMAIN}.</footer>
</div></body></html>
"""
    OUT.write_text(html)
    total = len(ROLES) + sum(len(person_addrs(*p)) for p in PEOPLE) + len(BOT_ONLY)
    print(f"wrote {OUT.name}: {total} seeded addresses "
          f"({len(ROLES)} roles, {len(PEOPLE)} people, {len(BOT_ONLY)} hidden)")


if __name__ == "__main__":
    main()
