-- AuditNinja: read-only IBM i security audit
-- Every statement is a SELECT. Nothing is changed on your system.
-- Open in IBM i Access Client Solutions > Run SQL Scripts.
-- Run the first statement for the scorecard, or run all for the full detail.
-- Based on findings in IBM / Ponemon Institute, Cost of a Data Breach Report 2026.

-- ============================================================
-- SCORECARD
-- ============================================================
-- AuditNinja 06: Scorecard
-- READ ONLY. One SELECT. Run this one first for the plain-English summary.
-- Every row is one check. SCORE (same on every row) is the percent of
-- scored checks that passed. REVIEW rows need a human decision and SKIPPED
-- rows could not be answered with your authority. Neither counts in the score.
--
-- Limits you can change are in the LIMITS block below.

WITH
LIMITS (MAX_ALLOBJ, MAX_SECADM, DORMANT_DAYS, PWD_MAX_DAYS) AS (
  VALUES (5, 3, 180, 360)
),
SV AS (
  SELECT SYSTEM_VALUE_NAME AS N,
         CURRENT_NUMERIC_VALUE AS NUM,
         COALESCE(CURRENT_CHARACTER_VALUE, '') AS CHR,
         -- The value as text, whichever way IBM i stores it. Several settings
         -- (QSECURITY, QMAXSIGN, QMAXSGNACN, QPWDEXPITV) are text, not numbers.
         TRIM(SYSTEM_VALUE) AS V
    FROM QSYS2.SYSTEM_VALUE_INFO
),
UI AS (
  SELECT *
    FROM QSYS2.USER_INFO
   WHERE AUTHORIZATION_NAME NOT LIKE 'Q%'
),
CHECKS (ID, AREA, BAD, KIND, FINDING, FIX) AS (

  -- People and passwords
  SELECT 'P1', 'Profiles',
         (SELECT COUNT(*) FROM UI WHERE STATUS = '*ENABLED' AND NO_PASSWORD_INDICATOR = 'YES'),
         'SCORED',
         'Active user profiles with no password',
         'Set a password, or disable the profile if nobody signs on with it. Use CHGUSRPRF.'
    FROM (VALUES 1) AS D(X)
  UNION ALL
  SELECT 'P2', 'Profiles',
         (SELECT COUNT(*) FROM UI WHERE STATUS = '*ENABLED' AND NO_PASSWORD_INDICATOR = 'NO' AND DATE_PASSWORD_EXPIRES IS NULL),
         'REVIEW',
         'Active profiles whose password never expires',
         'Forced password changes are no longer advised on their own. Confirm these profiles use long passphrases or another safeguard such as MFA. For service profiles, write down who owns the password and when it was last changed.'
    FROM (VALUES 1) AS D(X)
  UNION ALL
  SELECT 'P3', 'Profiles',
         (SELECT COUNT(*) FROM UI, LIMITS
           WHERE STATUS = '*ENABLED'
             AND (PREVIOUS_SIGNON IS NULL OR PREVIOUS_SIGNON < CURRENT TIMESTAMP - (DORMANT_DAYS) DAYS)),
         'SCORED',
         'Active profiles nobody has used in 180 days',
         'Confirm with the owner, then disable. A profile nobody watches is the easiest one to abuse.'
    FROM (VALUES 1) AS D(X)
  UNION ALL
  SELECT 'P4', 'Privileges',
         CASE WHEN (SELECT COUNT(*) FROM UI WHERE LOCATE('*ALLOBJ', COALESCE(SPECIAL_AUTHORITIES, '')) > 0)
                   > (SELECT MAX_ALLOBJ FROM LIMITS)
              THEN (SELECT COUNT(*) FROM UI WHERE LOCATE('*ALLOBJ', COALESCE(SPECIAL_AUTHORITIES, '')) > 0)
              ELSE 0 END,
         'SCORED',
         'More profiles than expected can see and change everything (*ALLOBJ)',
         'Remove *ALLOBJ from anyone who does not need it every day. Vendors and consultants should get it only while they work.'
    FROM (VALUES 1) AS D(X)
  UNION ALL
  SELECT 'P5', 'Privileges',
         CASE WHEN (SELECT COUNT(*) FROM UI WHERE LOCATE('*SECADM', COALESCE(SPECIAL_AUTHORITIES, '')) > 0)
                   > (SELECT MAX_SECADM FROM LIMITS)
              THEN (SELECT COUNT(*) FROM UI WHERE LOCATE('*SECADM', COALESCE(SPECIAL_AUTHORITIES, '')) > 0)
              ELSE 0 END,
         'SCORED',
         'More profiles than expected can create and change other profiles (*SECADM)',
         'Keep *SECADM to two or three named people.'
    FROM (VALUES 1) AS D(X)

  -- Password rules and sign-on limits
  UNION ALL
  SELECT 'S1', 'Settings',
         CASE WHEN V IN ('10', '20', '30') THEN 1 ELSE 0 END,
         CASE WHEN V NOT IN ('10', '20', '30', '40', '50') THEN 'SKIPPED' ELSE 'SCORED' END,
         'Security level (QSECURITY) is below 40',
         'Plan a move to level 40.'
    FROM SV WHERE N = 'QSECURITY'
  UNION ALL
  SELECT 'S2', 'Settings',
         CASE WHEN NUM IS NOT NULL AND (NUM < 8) THEN 1 ELSE 0 END,
         CASE WHEN NUM IS NULL THEN 'SKIPPED' ELSE 'SCORED' END,
         'Minimum password length (QPWDMINLEN) is under 8',
         'Raise QPWDMINLEN to 8 or more. Check QPWDRULES too, because it can override this.'
    FROM SV WHERE N = 'QPWDMINLEN'
  UNION ALL
  SELECT 'S3', 'Settings',
         CASE WHEN V IN ('*NOMAX', '361', '362', '363', '364', '365', '366') THEN 1 ELSE 0 END,
         CASE WHEN V = '' THEN 'SKIPPED' ELSE 'REVIEW' END,
         'Passwords never expire by default, or only after more than 360 days (QPWDEXPITV)',
         'Frequent forced changes are no longer advised. If you leave this off, make sure passwords are long and that you change them after any suspected exposure. Otherwise a long backstop such as 360 days is reasonable.'
    FROM SV WHERE N = 'QPWDEXPITV'
  UNION ALL
  SELECT 'S4', 'Settings',
         CASE WHEN V NOT IN ('1', '2', '3', '4', '5') THEN 1 ELSE 0 END,
         CASE WHEN V = '' THEN 'SKIPPED' ELSE 'SCORED' END,
         'Too many wrong-password tries allowed (QMAXSIGN is not 1 to 5, or is *NOMAX)',
         'Set QMAXSIGN to 3 to 5.'
    FROM SV WHERE N = 'QMAXSIGN'
  UNION ALL
  SELECT 'S5', 'Settings',
         CASE WHEN V = '1' THEN 1 ELSE 0 END,
         CASE WHEN V NOT IN ('1', '2', '3') THEN 'SKIPPED' ELSE 'SCORED' END,
         'Wrong-password limit does not disable the profile (QMAXSGNACN)',
         'Set QMAXSGNACN to 2 or 3.'
    FROM SV WHERE N = 'QMAXSGNACN'
  UNION ALL
  SELECT 'S6', 'Settings', COUNT(*), 'SCORED',
         'Idle screens are never signed off (QINACTITV is *NONE)',
         'Set QINACTITV to 30 minutes or less.'
    FROM SV WHERE N = 'QINACTITV' AND CHR = '*NONE'
  UNION ALL
  SELECT 'S7', 'Settings', COUNT(*), 'SCORED',
         'Powerful profiles can sign on from any screen (QLMTSECOFR is not 1)',
         'Set QLMTSECOFR to 1.'
    FROM SV WHERE N = 'QLMTSECOFR' AND CHR <> '1'
  UNION ALL
  SELECT 'S8', 'Secrets', COUNT(*), 'SCORED',
         'The system keeps stored passwords for other servers (QRETSVRSEC is 1)',
         'Set QRETSVRSEC to 0 unless you know which jobs depend on it. Report: mismanaged secrets and keys added 199K USD per breach.'
    FROM SV WHERE N = 'QRETSVRSEC' AND (CHR = '1' OR NUM = 1)
  UNION ALL
  SELECT 'S9', 'Settings', COUNT(*), 'SCORED',
         'Anyone may restore programs from tape or CD (QALWOBJRST is *ALL)',
         'Set QALWOBJRST to *NONE and change it only during a restore.'
    FROM SV WHERE N = 'QALWOBJRST' AND LOCATE('*ALL', CHR) > 0

  -- Auditing. QAUDCTL and QAUDLVL are hidden from profiles without *ALLOBJ or
  -- *AUDIT (the value comes back as *NOTAVL). When that happens the audit
  -- checks A1 to A4 are marked SKIPPED and left out of the score, and A0
  -- explains why. The journal check A2 is skipped too, because without that
  -- authority the journal may be invisible even though it exists.
  UNION ALL
  SELECT 'A0', 'Auditing', COUNT(*), 'REVIEW',
         'Your profile is not allowed to read the audit settings, so checks A1 to A4 were skipped',
         'Run this script again with a profile that has *ALLOBJ or *AUDIT authority.'
    FROM SV WHERE N IN ('QAUDCTL', 'QAUDLVL', 'QAUDLVL2') AND CHR = '*NOTAVL'
  UNION ALL
  SELECT 'A1', 'Auditing',
         CASE WHEN CHR <> '*NOTAVL' AND LOCATE('*AUDLVL', CHR) = 0 THEN 1 ELSE 0 END,
         CASE WHEN CHR = '*NOTAVL' THEN 'SKIPPED' ELSE 'SCORED' END,
         'Security auditing is switched off (QAUDCTL does not include *AUDLVL)',
         'Create the QAUDJRN journal, then set QAUDCTL to *AUDLVL and QAUDLVL to the values you want recorded.'
    FROM SV WHERE N = 'QAUDCTL'
  UNION ALL
  SELECT 'A2', 'Auditing',
         1 - COUNT(*),
         CASE WHEN (SELECT COUNT(*) FROM SV WHERE N = 'QAUDCTL' AND CHR = '*NOTAVL') > 0
              THEN 'SKIPPED' ELSE 'SCORED' END,
         'The audit journal (QAUDJRN) does not exist',
         'Without it there is no record of who did what. Create it with CRTJRNRCV and CRTJRN, then turn auditing on.'
    FROM TABLE(QSYS2.OBJECT_STATISTICS('QSYS', 'JRN', 'QAUDJRN')) AS J
  UNION ALL
  SELECT 'A3', 'Auditing',
         CASE WHEN CHR <> '*NOTAVL' AND LOCATE('*AUTFAIL', CHR) = 0
               AND (SELECT COUNT(*) FROM SV WHERE N = 'QAUDLVL2' AND LOCATE('*AUTFAIL', CHR) > 0) = 0
              THEN 1 ELSE 0 END,
         CASE WHEN CHR = '*NOTAVL' THEN 'SKIPPED' ELSE 'SCORED' END,
         'Failed access attempts are not recorded (*AUTFAIL missing from QAUDLVL)',
         'Add *AUTFAIL to QAUDLVL. It is the first thing to look at after an incident.'
    FROM SV WHERE N = 'QAUDLVL'
  UNION ALL
  SELECT 'A4', 'Auditing',
         CASE WHEN CHR <> '*NOTAVL' AND LOCATE('*SECURITY', CHR) = 0
               AND (SELECT COUNT(*) FROM SV WHERE N = 'QAUDLVL2' AND LOCATE('*SECURITY', CHR) > 0) = 0
              THEN 1 ELSE 0 END,
         CASE WHEN CHR = '*NOTAVL' THEN 'SKIPPED' ELSE 'SCORED' END,
         'Security changes are not recorded (*SECURITY missing from QAUDLVL)',
         'Add *SECURITY to QAUDLVL so new profiles and changed authority leave a trail.'
    FROM SV WHERE N = 'QAUDLVL'

  -- Network
  UNION ALL
  SELECT 'N1', 'Network', COUNT(DISTINCT LOCAL_PORT), 'REVIEW',
         'Plain-text services are in use (FTP, Telnet, HTTP or unencrypted host servers)',
         'Move partners and staff to the encrypted version of each. See the PLAIN-TEXT SERVICES section of this file for the list.'
    FROM QSYS2.NETSTAT_INFO
   WHERE TCP_STATE = 'LISTEN'
     AND LOCAL_PORT IN (21, 23, 80, 8470, 8471, 8472, 8473, 8474, 8475, 8476)
)
SELECT ID,
       AREA,
       CASE WHEN KIND = 'SKIPPED' THEN 'SKIPPED'
            WHEN BAD = 0 THEN 'PASS'
            WHEN KIND = 'REVIEW' THEN 'REVIEW'
            ELSE 'FAIL' END AS RESULT,
       BAD AS HOW_MANY,
       FINDING,
       CASE WHEN BAD = 0 OR KIND = 'SKIPPED' THEN '' ELSE FIX END AS WHAT_TO_DO,
       -- Percent of scored checks that passed, as a whole number
       CAST(ROUND(100.0 * SUM(CASE WHEN KIND = 'SCORED' AND BAD = 0 THEN 1 ELSE 0 END) OVER ()
             / NULLIF(SUM(CASE WHEN KIND = 'SCORED' THEN 1 ELSE 0 END) OVER (), 0), 0) AS INTEGER) AS SCORE
  FROM CHECKS
 ORDER BY CASE WHEN KIND = 'SKIPPED' THEN 3 WHEN BAD = 0 THEN 2 ELSE 1 END, ID;

-- ============================================================
-- DETAIL: USER PROFILES
-- ============================================================
-- AuditNinja 01: User profiles
-- READ ONLY. Every statement below is a SELECT.
-- Source: QSYS2.USER_INFO
-- IBM i profiles that start with Q are shipped by IBM and are skipped.
-- Report link: IBM Cost of a Data Breach 2026 (Figure 10) puts breaches that
-- abused valid accounts at 5.07M USD on average.

-- 1A. Enabled profiles that have no password at all
SELECT AUTHORIZATION_NAME, USER_CLASS_NAME, PREVIOUS_SIGNON, TEXT_DESCRIPTION
  FROM QSYS2.USER_INFO
 WHERE STATUS = '*ENABLED'
   AND NO_PASSWORD_INDICATOR = 'YES'
   AND AUTHORIZATION_NAME NOT LIKE 'Q%'
 ORDER BY AUTHORIZATION_NAME;

-- 1B. Enabled profiles whose password never expires
SELECT AUTHORIZATION_NAME, USER_CLASS_NAME, PASSWORD_CHANGE_DATE, PREVIOUS_SIGNON, TEXT_DESCRIPTION
  FROM QSYS2.USER_INFO
 WHERE STATUS = '*ENABLED'
   AND NO_PASSWORD_INDICATOR = 'NO'
   AND DATE_PASSWORD_EXPIRES IS NULL
   AND AUTHORIZATION_NAME NOT LIKE 'Q%'
 ORDER BY PASSWORD_CHANGE_DATE;

-- 1C. Dormant profiles: enabled, but nobody has signed on in 180 days (or ever)
SELECT AUTHORIZATION_NAME, USER_CLASS_NAME, PREVIOUS_SIGNON, TEXT_DESCRIPTION
  FROM QSYS2.USER_INFO
 WHERE STATUS = '*ENABLED'
   AND AUTHORIZATION_NAME NOT LIKE 'Q%'
   AND (PREVIOUS_SIGNON IS NULL
        OR PREVIOUS_SIGNON < CURRENT TIMESTAMP - 180 DAYS)
 ORDER BY CASE WHEN PREVIOUS_SIGNON IS NULL THEN 0 ELSE 1 END, PREVIOUS_SIGNON;

-- 1D. Profiles that can see and change everything (*ALLOBJ) or manage
--     other profiles (*SECADM)
-- Report link: excessive privileges added 177K USD per breach (Figure 33).
SELECT AUTHORIZATION_NAME, USER_CLASS_NAME, SPECIAL_AUTHORITIES, STATUS, PREVIOUS_SIGNON, TEXT_DESCRIPTION
  FROM QSYS2.USER_INFO
 WHERE AUTHORIZATION_NAME NOT LIKE 'Q%'
   AND (LOCATE('*ALLOBJ', COALESCE(SPECIAL_AUTHORITIES, '')) > 0
     OR LOCATE('*SECADM', COALESCE(SPECIAL_AUTHORITIES, '')) > 0)
 ORDER BY AUTHORIZATION_NAME;

-- 1E. Profiles with a command line and powerful authority together
--     (the most useful profile for an attacker to steal)
SELECT AUTHORIZATION_NAME, USER_CLASS_NAME, SPECIAL_AUTHORITIES, LIMIT_CAPABILITIES, PREVIOUS_SIGNON
  FROM QSYS2.USER_INFO
 WHERE STATUS = '*ENABLED'
   AND AUTHORIZATION_NAME NOT LIKE 'Q%'
   AND LOCATE('*ALLOBJ', COALESCE(SPECIAL_AUTHORITIES, '')) > 0
   AND LIMIT_CAPABILITIES IN ('*NO', '*PARTIAL')
 ORDER BY AUTHORIZATION_NAME;

-- ============================================================
-- DETAIL: SECURITY SYSTEM VALUES
-- ============================================================
-- AuditNinja 02: Security system values
-- READ ONLY. Source: QSYS2.SYSTEM_VALUE_INFO
-- One row per setting, with what we suggest and whether yours matches.
-- Suggested values follow common IBM i hardening guidance. Change the
-- numbers to match your own company policy.

SELECT SYSTEM_VALUE_NAME AS SETTING,
       COALESCE(CAST(CURRENT_NUMERIC_VALUE AS VARCHAR(20)), CURRENT_CHARACTER_VALUE) AS YOUR_VALUE,
       CASE SYSTEM_VALUE_NAME
         WHEN 'QSECURITY'   THEN '40 or higher (50 is best)'
         WHEN 'QPWDLVL'     THEN '2 or higher (3 is best)'
         WHEN 'QPWDMINLEN'  THEN '8 or more'
         WHEN 'QPWDEXPITV'  THEN '1 to 360 days (or never, if you use long passphrases and MFA)'
         WHEN 'QMAXSIGN'    THEN '3 to 5 tries'
         WHEN 'QMAXSGNACN'  THEN '2 or 3 (disable the profile)'
         WHEN 'QINACTITV'   THEN 'Not *NONE'
         WHEN 'QLMTSECOFR'  THEN '1 (limit *ALLOBJ users to secure devices)'
         WHEN 'QRETSVRSEC'  THEN '0 (do not keep stored passwords)'
         WHEN 'QALWOBJRST'  THEN 'Not *ALL'
         WHEN 'QAUDCTL'     THEN 'Includes *AUDLVL'
       END AS SUGGESTED
  FROM QSYS2.SYSTEM_VALUE_INFO
 WHERE SYSTEM_VALUE_NAME IN ('QSECURITY', 'QPWDLVL', 'QPWDMINLEN', 'QPWDEXPITV',
                             'QMAXSIGN', 'QMAXSGNACN', 'QINACTITV', 'QLMTSECOFR',
                             'QRETSVRSEC', 'QALWOBJRST', 'QAUDCTL')
 ORDER BY SYSTEM_VALUE_NAME;

-- ============================================================
-- DETAIL: AUDITING
-- ============================================================
-- AuditNinja 03: Is anyone watching?
-- READ ONLY. Sources: QSYS2.SYSTEM_VALUE_INFO, QSYS2.OBJECT_STATISTICS
-- Report link: breaches took 247 days on average to find and contain
-- (183 to find, 64 to contain, Figure 5). Without an audit journal you
-- cannot answer "what happened" at all.

-- 3A. Is auditing switched on, and what does it record?
SELECT SYSTEM_VALUE_NAME AS SETTING,
       COALESCE(CAST(CURRENT_NUMERIC_VALUE AS VARCHAR(20)), CURRENT_CHARACTER_VALUE) AS YOUR_VALUE
  FROM QSYS2.SYSTEM_VALUE_INFO
 WHERE SYSTEM_VALUE_NAME IN ('QAUDCTL', 'QAUDLVL', 'QAUDLVL2')
 ORDER BY SYSTEM_VALUE_NAME;

-- 3B. Does the audit journal exist? (No row back means no audit trail.)
SELECT OBJNAME, OBJLIB, OBJCREATED
  FROM TABLE(QSYS2.OBJECT_STATISTICS('QSYS', 'JRN', 'QAUDJRN')) AS J;

-- ============================================================
-- DETAIL: OUTSIDE CONNECTIONS
-- ============================================================
-- AuditNinja 04: Who is connected from outside right now?
-- READ ONLY. Sources: QSYS2.ACTIVE_JOB_INFO, QSYS2.NETSTAT_JOB_INFO, QSYS2.NETSTAT_INFO
-- This is a snapshot of this moment. Run it at a busy time of day, and
-- again later, to catch integrations that only connect at night.
-- Report link: supply chain compromise was the #2 way in and added
-- 227,250 USD to the average breach (Figures 10 and 33).

-- 4A. Profiles currently connected through ODBC, JDBC, FTP and other
--     host servers (these run in subsystem QUSRWRK)
SELECT AUTHORIZATION_NAME AS PROFILE_USED,
       COUNT(*) AS OPEN_CONNECTIONS,
       MIN(JOB_NAME) AS EXAMPLE_JOB
  FROM TABLE(QSYS2.ACTIVE_JOB_INFO(SUBSYSTEM_LIST_FILTER => 'QUSRWRK', DETAILED_INFO => 'NONE')) AS A
 WHERE JOB_NAME LIKE '%/QZ%'
 GROUP BY AUTHORIZATION_NAME
 ORDER BY OPEN_CONNECTIONS DESC;

-- 4B. Connections from other machines, with the address they came from
SELECT REMOTE_ADDRESS, LOCAL_PORT, AUTHORIZATION_NAME AS PROFILE_USED, JOB_NAME
  FROM QSYS2.NETSTAT_JOB_INFO
 WHERE REMOTE_ADDRESS IS NOT NULL
   AND REMOTE_ADDRESS NOT IN ('*', '0.0.0.0', '::', '127.0.0.1', '::1')
 ORDER BY REMOTE_ADDRESS, LOCAL_PORT;

-- 4C. Profiles that look like they belong to a machine or an outside company
--     and not a person, going by the name or description. Edit the name
--     patterns to fit your shop.
SELECT AUTHORIZATION_NAME, USER_CLASS_NAME, SPECIAL_AUTHORITIES, STATUS,
       PREVIOUS_SIGNON, TEXT_DESCRIPTION
  FROM QSYS2.USER_INFO
 WHERE AUTHORIZATION_NAME NOT LIKE 'Q%'
   AND (AUTHORIZATION_NAME LIKE '%EDI%' OR AUTHORIZATION_NAME LIKE '%FTP%'
     OR AUTHORIZATION_NAME LIKE '%ODBC%' OR AUTHORIZATION_NAME LIKE '%SVC%'
     OR AUTHORIZATION_NAME LIKE '%VENDOR%' OR AUTHORIZATION_NAME LIKE '%SUPPORT%'
     OR AUTHORIZATION_NAME LIKE '%API%' OR AUTHORIZATION_NAME LIKE '%BATCH%'
     OR UPPER(COALESCE(TEXT_DESCRIPTION, '')) LIKE '%VENDOR%'
     OR UPPER(COALESCE(TEXT_DESCRIPTION, '')) LIKE '%CONSULT%')
 ORDER BY AUTHORIZATION_NAME;

-- ============================================================
-- DETAIL: PLAIN-TEXT SERVICES
-- ============================================================
-- AuditNinja 05: Readable on the wire?
-- READ ONLY. Source: QSYS2.NETSTAT_INFO (only sockets in LISTEN state, meaning
-- the service is switched on and accepting connections)
-- Report link: 53% of breached organizations had not encrypted sensitive data
-- at rest and in motion (Figure 9). 61% lacked controls over keys and
-- certificates (Figure 44).
--
-- Ports that carry passwords and data in plain text, and the encrypted
-- twin to use instead:
--   21 FTP        -> 990 FTPS or SFTP over SSH (22)
--   23 Telnet     -> 992 Telnet over TLS
--   8470 to 8476  -> 9470 to 9476 IBM i host servers over TLS (ODBC, JDBC and others)
--   80 HTTP       -> 443 HTTPS

SELECT LOCAL_PORT,
       CASE LOCAL_PORT
         WHEN 21   THEN 'FTP (plain text)'
         WHEN 23   THEN 'Telnet 5250 (plain text)'
         WHEN 80   THEN 'HTTP (plain text)'
         WHEN 8470 THEN 'Host server central (plain text)'
         WHEN 8471 THEN 'Host server database (plain text)'
         WHEN 8472 THEN 'Host server data queue (plain text)'
         WHEN 8473 THEN 'Host server file (plain text)'
         WHEN 8474 THEN 'Host server network print (plain text)'
         WHEN 8475 THEN 'Host server remote command (plain text)'
         WHEN 8476 THEN 'Host server sign-on (plain text)'
       END AS WHAT_IT_IS,
       COUNT(*) AS LISTENING_SOCKETS
  FROM QSYS2.NETSTAT_INFO
 WHERE TCP_STATE = 'LISTEN'
   AND LOCAL_PORT IN (21, 23, 80, 8470, 8471, 8472, 8473, 8474, 8475, 8476)
 GROUP BY LOCAL_PORT
 ORDER BY LOCAL_PORT;

