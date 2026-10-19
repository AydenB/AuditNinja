# AuditNinja

A free, read-only security check for your IBM i. Run one SQL file, get a score and a to-do list in plain English.

AuditNinja only reads. Every statement in `AuditNinja.sql` is a SELECT, so it changes nothing on your system, installs nothing, and sends nothing anywhere.

It is built around the findings in IBM's *Cost of a Data Breach Report 2026* (IBM and Ponemon Institute): the things that made breaches cheaper or costlier, turned into questions your system can answer.

## How to run it

1. Open **IBM i Access Client Solutions** and choose **Run SQL Scripts**.
2. Open `AuditNinja.sql`.
3. Run the first statement (the scorecard). Select it and use **Run > Selected**.
4. You get one row per check, marked PASS, FAIL, REVIEW or SKIPPED, with what to do about each, and a score out of 100.
5. To see exactly which profiles or connections are behind a FAIL, run the statements further down the file. Each section is labeled DETAIL.

The detail sections list real profile names and connection addresses from your system. Keep that output to yourself.

## Reading the results

| Result | Meaning |
|---|---|
| PASS | The check looks fine |
| FAIL | Worth fixing. The WHAT_TO_DO column says how |
| REVIEW | Needs a person to decide. It is not counted in the score |
| SKIPPED | Your profile is not allowed to see the answer. It is not counted in the score |

The score is the percent of scored checks that passed.

The audit settings (`QAUDCTL` and `QAUDLVL`) can only be read with `*ALLOBJ` or `*AUDIT` authority. Without it, the audit checks are SKIPPED and check A0 tells you why. For the full picture, run it with a profile that has that authority.

## What it checks

| IBM report finding | What AuditNinja looks at |
|---|---|
| Abusing valid accounts: $5.07M average breach | Active profiles with no password, profiles nobody has used in 180 days, and a review list of passwords that never expire |
| Excessive privileges: +$177K | How many profiles hold `*ALLOBJ` and `*SECADM` |
| Mismanaged secrets and keys: +$199K | Whether the system keeps stored passwords (`QRETSVRSEC`) |
| Identity and access management: $226K saved, the #2 cost reducer | Password rules and sign-on limits |
| Breaches took 247 days to find and contain | Is the audit journal on, and does it record failures and security changes |
| Supply chain compromise: #2 way in, +$227K | Which profiles are connected from outside right now, and which look like partner or service profiles |
| 53% had unencrypted data | Plain-text services still in use (FTP, Telnet, unencrypted host servers) |

The $227K is the extra cost compared with the $4.99M average breach, not the total cost.

You can change the limits (how many `*ALLOBJ` profiles is too many, how many days counts as dormant) in the `LIMITS` block at the top of the scorecard statement.

## What it does not cover yet

- Default passwords (IBM i has a command for this, `ANZDFTPWD`, but no SQL service)
- Stored server credentials and validation lists
- Authority on your business libraries and the IFS
- TLS versions and certificate expiry

## Status

Tested on IBM i 7.5 with an ordinary profile. The audit checks have not yet been run by a profile with `*ALLOBJ` or `*AUDIT`, so please report anything odd there. Reports from other releases are welcome. Open an issue and include the SQL error message and your IBM i release.

## Source

IBM and Ponemon Institute, *Cost of a Data Breach Report 2026*. Figures are quoted for context. AuditNinja is not affiliated with or endorsed by IBM.
