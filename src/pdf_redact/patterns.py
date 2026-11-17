"""Detection vocabulary: regexes, label tables and shared text helpers.

Everything in here is pure data / pure functions with no PDF dependency, so it
can be unit-tested without touching a document.
"""
from __future__ import annotations

import hashlib
import re

# --------------------------------------------------------------------------
# Value detectors. Order matters: when spans overlap, the earlier label wins
# (the merged placeholder then reads as the more specific category).
# --------------------------------------------------------------------------

SSN_RE = re.compile(
    r"(?<![\w-])(?:"
    r"\d{3}[-. ]\d{2}[-. ]\d{4}"          # 123-45-6789
    r"|[Xx*]{3}[-. ][Xx*]{2}[-. ]\d{4}"   # XXX-XX-6789 (already masked at source)
    r"|\d{9}"                             # bare 9 digits
    r")(?![\w-])"
)

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

PHONE_RE = re.compile(
    r"(?<![\w])(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}(?!\w)"
)

ZIP_RE = re.compile(r"(?<![\w\-/])\d{5}(?:-\d{4})?(?![\w\-/])")

ADDRESS_RE = re.compile(
    r"(?<![\w])(?:"
    r"P\.?\s?O\.?\s?BOX\s+\d+"
    r"|\d{1,6}\s+(?:[A-Z0-9][\w.'’-]*\s+){0,5}"
    r"(?:STREET|ST|AVENUE|AVE|ROAD|RD|DRIVE|DR|LANE|LN|BOULEVARD|BLVD|COURT|CT"
    r"|CIRCLE|CIR|PLACE|PL|PARKWAY|PKWY|HIGHWAY|HWY|TERRACE|TER|TRAIL|TRL|WAY"
    r"|LOOP|SQUARE|SQ|APT|UNIT|SUITE|STE)\b\.?"
    r"(?:\s*(?:#|APT\.?|UNIT|STE\.?|SUITE)\s*[\w-]+)?"
    r")",
    re.I,
)

# Long alphanumeric identifiers: account numbers, member IDs, reference numbers.
NUMBER_RE = re.compile(
    r"(?<![\w\-/])(?=[A-Za-z0-9\-]*\d)[A-Za-z0-9][A-Za-z0-9\-]{7,}(?![\w\-/])"
)

# Masked identifier tails: "#2756", "XXXXXX8393", "••••1234".
MASK_TAIL_RE = re.compile(r"(?:#\s?\d{3,6}\b|[Xx*•·]{3,}\s?\d{2,4}\b)")

DATE_RE = re.compile(
    r"(?<!\d)(?:0?[1-9]|1[0-2])[/-](?:0?[1-9]|[12]\d|3[01])[/-](?:\d{4}|\d{2})(?!\d)"
)

PATTERNS = [
    ("SSN", SSN_RE),
    ("EMAIL", EMAIL_RE),
    ("PHONE", PHONE_RE),
    ("ADDRESS", ADDRESS_RE),
    ("ZIP", ZIP_RE),
    ("NUMBER", NUMBER_RE),
    ("NUMBER", MASK_TAIL_RE),
]

# --------------------------------------------------------------------------
# OCR-only detectors. Tesseract confuses glyphs that look alike (0/O, 1/I/l,
# 5/S, 8/B, 2/Z, 6/G), so an SSN read as "512-84-993I" matches nothing in the
# strict patterns above. These variants accept the confusable classes and then
# demand enough real digits to avoid matching words.
# --------------------------------------------------------------------------
_CONFUSABLE = r"0-9OoIlSsBbZzGg"
SSN_OCR_RE = re.compile(
    rf"(?<![\w-])[{_CONFUSABLE}]{{3}}[-. ][{_CONFUSABLE}]{{2}}[-. ][{_CONFUSABLE}]{{4}}(?![\w-])"
)
PHONE_OCR_RE = re.compile(
    rf"(?<![\w])(?:1[-.\s])?\(?[{_CONFUSABLE}]{{3}}\)?[-.\s]"
    rf"[{_CONFUSABLE}]{{3}}[-.\s][{_CONFUSABLE}]{{4}}(?!\w)"
)
OCR_PATTERNS = [
    ("SSN", SSN_OCR_RE, 5),      # (label, regex, minimum real digits in the match)
    ("PHONE", PHONE_OCR_RE, 8),
]
DIGIT_RE = re.compile(r"\d")


def digit_count(text: str) -> int:
    return len(DIGIT_RE.findall(text))


DOB_CTX_RE = re.compile(
    r"\b(dob|date\s+of\s+birth|born|birth\s*(?:date|year)|year\s+of\s+birth|yob)\b",
    re.I,
)
YEAR_RE = re.compile(r"(?<!\d)(?:19[2-9]\d|20[01]\d)(?!\d)")

# "1387 CENTRAL" -- house number + street name whose suffix cell was split off
# into its own cell, so the normal ADDRESS_RE never sees the suffix.
ADDRESS_FRAG_RE = re.compile(
    r"^\d{1,6}\s+[A-Za-z][A-Za-z.'\u2019\-]*(?:\s+[A-Za-z][A-Za-z.'\u2019\-]*){0,3}$"
)

# --------------------------------------------------------------------------
# Field labels. A cell that is nothing but a label, or a "Label: value" prefix,
# makes everything after it a value to redact wholesale.
# --------------------------------------------------------------------------
LABELS = [
    ("NAME", [r"consumer\s+name", r"names?", r"former\s+names?", r"also\s+known\s+as",
              r"a\.k\.a\.?", r"aka", r"formerly\s+known\s+as", r"previous\s+names?",
              r"other\s+names?", r"reported\s+names?", r"your\s+name", r"full\s+name",
              r"named\s+as"]),
    ("SSN", [r"social\s+security\s*(?:number|#|no\.?)?", r"ssn", r"ss\s*#"]),
    ("EMAIL", [r"e-?mail(?:\s+address)?"]),
    ("PHONE", [r"phones?(?:\s+numbers?)?", r"phone\s+numbers?", r"former\s+phones?",
               r"telephone", r"cell(?:ular)?(?:\s+phone)?", r"mobile(?:\s+phone)?"]),
    ("DOB", [r"date\s+of\s+birth", r"dob", r"birth\s*date", r"year\s+of\s+birth",
             r"birth\s+year", r"yob"]),
    ("ADDRESS", [r"current\s+address", r"previous\s+address", r"prior\s+address",
                 r"former\s+address", r"mailing\s+address", r"home\s+address",
                 r"address(?:es)?", r"residence"]),
    ("EMPLOYER", [r"employers?", r"employer\s+names?", r"employment(?:\s+information)?"]),
    ("ACCT", [r"account\s*(?:number|#|no\.?)", r"acct\.?\s*(?:number|#|no\.?)",
              r"acct\b", r"loan\s*(?:number|#)", r"member\s*(?:id|number)",
              r"file\s*(?:number|#)", r"control\s*(?:number|#)",
              r"reference\s*(?:number|#)", r"case\s*(?:number|#)",
              r"identification\s*(?:number|#)", r"driver'?s?\s*licen[cs]e",
              r"passport(?:\s*(?:number|#))?", r"routing\s*(?:number|#)"]),
]

# Whole cell == a bare label ("Account Number", "Employers:", "Name(s)")
LABEL_RES = [
    (lab, [(pat, re.compile(rf"^\s*{pat}\s*:?\s*$", re.I)) for pat in pats])
    for lab, pats in LABELS
]

# "Label: value" inside one cell
LABEL_PREFIX_RES = [
    (lab, [(pat, re.compile(rf"(?<![\w]){pat}\s*:\s*", re.I)) for pat in pats])
    for lab, pats in LABELS
]

# Preceding words that mean a "name" label is talking about companies, not people.
ORG_LABEL_CONTEXT_RE = re.compile(
    r"(creditor|original|company|business|merchant|subscriber|bank|furnisher|"
    r"agency|also|other|previous|prior)\s*$"
)

# --------------------------------------------------------------------------
# Heuristic vocabulary for person names.
# --------------------------------------------------------------------------
NAME_STOP = set("""
a an and the of for to in on at by with from or as is are was were be been
annual credit report reports experian equifax transunion trans union bureau
consumer information personal summary profile file account accounts creditor
creditors balance balances status past due high limit limits open closed date
dates opened reported updated remarks payment payments satisfactory current
paid charge chargeoff off placed collection collections original bank banks
card cards services service financial funding llc inc incorporated corp
corporation company co ltd lp llp na n a usa us united states america american
street st avenue ave road rd drive dr lane ln boulevard blvd court ct circle
cir place pl parkway pkwy highway hwy terrace ter trail trl way loop square sq
apt unit suite ste po box address city state zip county country phone email
dob ssn inquiry inquiries requester employer employment position
number no page of score scores rating risk factor factors reason reasons key
code codes navigation menu print home back next previous continue log out
logout sign session dashboard welcome my your you all any none not
yes total totals amount amounts pastdue monthly term terms length type types
apr rate loan loans mortgage auto student revolving installment debt debts
utilization available used recent oldest newest history inquiry authorized
user dispute disputes statement statements federal trade commission fcra
identify theft victims rights notice notices law laws act section
new mexico texas california florida georgia virginia maryland etc months years
days weeks january february march april may june july august september october
november december mon tue wed thu fri sat sun am pm est cst pst mst edt pdt
""".split())

ORG_MARKERS = set("""
bank banks banking corp corporation company co llc inc ltd lp llp na n.a. plc
financial finance services service solutions systems group holdings trust
capital funding fund funds loans loan mortgage mortgages auto cars credit card
cards collection collections agency agencies associates association
receivables portfolio management mfg manufacturing industries
store stores retail market markets insurance casualty mutual union savings
bureau enterprises partners partner network technologies
telecom wireless utilities utility hospital health care clinic pharmacy
university college school district county city state department federal
government authority board office center centre institute foundation
society club hotel restaurant cafe shop inc. dba
""".split())

TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z'\u2019\-.]*")
GAP_OK_RE = re.compile(r"^[ ,.&/'\u2019\-\s]*$")

EDGE_PUNCT = " \t.,:;()[]{}\"'!?*-"

# Tokens that are filler rather than values, so they must not enter the
# "this value must never reappear" set.
_TOKEN_FOR_HASH_RE = re.compile(r"[A-Za-z0-9][\w'\u2019@.\-]{2,}")
PLACEHOLDER_RE = re.compile(r"\[[A-Z]+\]")


def norm(s: str) -> str:
    """Canonical form used for both hashing and the leak self-check, so a token
    with a trailing colon or comma compares equal to the bare token."""
    return re.sub(r"\s+", " ", s).strip().lower().strip(EDGE_PUNCT)


def h(s: str) -> str:
    """Short, stable digest. Values are never stored in plain text."""
    return hashlib.sha256(norm(s).encode()).hexdigest()[:16]


def sensitive_tokens(s: str) -> list[str]:
    """Tokens worth remembering as 'must not reappear': skip filler vocabulary."""
    out = []
    for t in _TOKEN_FOR_HASH_RE.findall(s):
        if t.lower().strip(".") in NAME_STOP:
            continue
        out.append(t)
    return out
