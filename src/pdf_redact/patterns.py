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

EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+\-]+\s?@\s?[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"
)

# An address clipped by a screenshot edge or a narrow column: "x.y@corp.e".
# Runs after EMAIL_RE so a complete address keeps the strict match.
EMAIL_TRUNC_RE = re.compile(
    r"[A-Za-z0-9._%+\-]+@\s?[A-Za-z0-9\-]+(?:[.\-][A-Za-z0-9\-]+)*"
)

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

# Payment-card numbers: 13-19 digits, with or without 4-digit grouping.
# Runs after NUMBER_RE so a bare long number keeps its more generic label.
CARD_RE = re.compile(
    r"(?<![\w\-])(?:\d{4}[ \-]){3}\d{1,4}(?![\w\-])"
    r"|(?<![\w\-])\d{13,19}(?![\w\-])"
)

# Masked identifier tails: "#2756", "XXXXXX8393", "••••1234", "XXXX XXXX XXXX 4412".
MASK_TAIL_RE = re.compile(
    r"(?:#\s?\d{3,6}\b|[Xx*•·]{3,}(?:[ \-][Xx*•·]{2,4})*\s?\d{2,4}\b)"
)

DATE_RE = re.compile(
    r"(?<!\d)(?:0?[1-9]|1[0-2])[/-](?:0?[1-9]|[12]\d|3[01])[/-](?:\d{4}|\d{2})(?!\d)"
)

# "October 24, 1983" -- the written date of birth that escapes DATE_RE.
MONTH_DATE_RE = re.compile(
    r"(?<![A-Za-z])(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.?"
    r"\s+\d{1,2}(?:st|nd|rd|th)?,?\s+(?:19|20)\d{2}(?!\d)",
    re.I,
)

PATTERNS = [
    ("SSN", SSN_RE),
    ("EMAIL", EMAIL_RE),
    ("EMAIL", EMAIL_TRUNC_RE),
    ("PHONE", PHONE_RE),
    ("ADDRESS", ADDRESS_RE),
    ("ZIP", ZIP_RE),
    ("NUMBER", NUMBER_RE),
    ("NUMBER", CARD_RE),
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


_DATE_TOKEN_RE = re.compile(
    r"\d{4}[-/.]\d{1,2}[-/.]\d{1,2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}")


def is_date_like(token: str) -> bool:
    """True for "2023-10-04" / "10/04/2023": a NUMBER_RE hit that is a date."""
    return bool(_DATE_TOKEN_RE.fullmatch(token))


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

# Form vocabulary that disqualifies an address fragment: "3 Social security
# wages" is a W-2 box, not somewhere anybody lives.
FORM_WORDS = set("""
security wages wage tax taxed withheld medicare insurance number name address
code date amount total balance employee employer patient member group policy
claim description quantity qty charge charges period rate hours units
""".split())

# --------------------------------------------------------------------------
# Field labels. A cell that is nothing but a label, or a "Label: value" prefix,
# makes everything after it a value to redact wholesale.
# --------------------------------------------------------------------------
LABELS = [
    ("NAME", [
        r"consumer\s+names?", r"names?", r"former\s+names?", r"previous\s+names?",
        r"other\s+names?", r"reported\s+names?", r"also\s+known\s+as",
        r"a\.?k\.?a\.?", r"formerly\s+known\s+as", r"your\s+name", r"full\s+name",
        r"legal\s+name", r"printed\s+name", r"signature\s+name", r"named\s+as",
        r"name\s+of\s+(?:consumer|patient|applicant|employee|member|borrower)",
        # the person slots that show up on real forms
        r"(?:patient|member|employee|applicant|co-?applicant|borrower|"
        r"insured|subscriber|student|taxpayer|cardholder|card\s+holder|"
        r"account\s+holder|acct\.?\s+holder|guarantor|responsible\s+party|"
        r"parent|guardian|spouse|dependent|payee|recipient|signer|"
        r"contact|reference|supervisor|manager|emergency\s+contact|"
        r"authorized\s+user|customer|client|owner|tenant|landlord|"
        r"witness|notary)\s+names?",
        # "Employee's name, address, and ZIP code" (form boxes)
        r"employee'?s?\s+name(?:,?\s*address)?(?:,?\s*and\s+zip\s*code)?",
        # any qualifier + "name" -- but never a company qualifier, or a
        # "Creditor Names:" field would start redacting creditors
        r"(?!(?:creditor|company|business|merchant|bank|furnisher|agency|"
        r"employer|original|collection|school|institution|provider)\b)"
        r"(?:[A-Za-z][A-Za-z.'’\-]*\s+){1,3}names?",
        # a bare role word as the label: "Patient:", "Borrower", "Supervisor:"
        # ("reference" is deliberately absent: it is a column header far more
        # often than a person, and a header label opens a value block)
        r"patient|applicant|co-?applicant|borrower|employee|member|insured|"
        r"subscriber|cardholder|guarantor|supervisor|manager|contact(?:\s+person)?|"
        r"reference\s+names?|signer|witness|notary|tenant|landlord|claimant|"
        r"policyholder|student|customer|client|spouse|dependent|parent|guardian|"
        r"recipient|attn|attention|capacity|signature\s+of|"
        # a salutation or signature cue alone in its cell, value underneath
        r"dear|sincerely|regards|best\s+regards|kind\s+regards|thanks|"
        r"thank\s+you|signed|signature|cc",
    ]),
    ("SSN", [r"(?:employee'?s?|taxpayer'?s?|patient'?s?|spouse'?s?)?\s*"
             r"social\s+security\s*(?:number|#|no\.?|id|nbr)",
             r"ssn", r"ss\s*#", r"soc\.?\s*sec\.?(?:\s*(?:number|#|no\.?))?",
             r"social\s+insurance\s+number"]),
    ("EMAIL", [r"e-?mail(?:\s+address)?"]),
    ("PHONE", [r"phones?(?:\s+numbers?)?", r"phone\s+numbers?",
               r"former\s+phones?", r"telephone(?:\s+number)?", r"tel\.?",
               r"cell(?:ular)?(?:\s+phone)?(?:\s+number)?",
               r"mobile(?:\s+phone)?(?:\s+number)?",
               r"(?:work|home|direct|contact|office|fax)\s+(?:phone|number|#|tel)",
               r"fax(?:\s+number)?"]),
    ("DOB", [r"date\s+of\s+birth", r"dob", r"birth\s*date", r"year\s+of\s+birth",
             r"birth\s+year", r"yob", r"born"]),
    ("ADDRESS", [r"(?:current|previous|prior|former|mailing|home|service|property|"
                 r"billing|shipping|permanent|street|residence|residential)"
                 r"\s+address(?:es)?",
                 r"address(?:es)?", r"residence"]),
    ("EMPLOYER", [r"employers?", r"employer\s+names?", r"place\s+of\s+employment",
                  r"employment(?:\s+information)?", r"employed\s+by"]),
    ("ACCT", [r"account\s*(?:number|#|no\.?|id)", r"acct\.?\s*(?:number|#|no\.?)?",
              r"loan\s*(?:number|#|id)", r"member\s*(?:id|number|#)",
              r"policy\s*(?:number|#|no\.?|id)",
              r"group\s*(?:number|#|no\.?|id|code)",
              r"claim\s*(?:number|#|no\.?|id)",
              r"mrn", r"medical\s+record\s*(?:number|#|no\.?|id)",
              r"patient\s*(?:id|number|#)", r"employee\s*(?:id|number|#)",
              r"subscriber\s*(?:id|number|#)", r"invoice\s*(?:number|#|no\.?)?",
              r"purchase\s+order\s*(?:number|#|no\.?)?", r"po\s*(?:number|#|no\.?)",
              r"file\s*(?:number|#)", r"control\s*(?:number|#)",
              r"reference\s*(?:number|#|id|code)", r"case\s*(?:number|#|id)",
              r"docket\s*(?:number|#|no\.?)", r"permit\s*(?:number|#|no\.?)",
              r"identification\s*(?:number|#|no\.?)",
              r"(?:tax|taxpayer)\s*(?:id|identification)\s*(?:number|#|no\.?)?",
              r"ein", r"itin", r"tin",
              r"driver'?s?\s*licen[cs]e(?:\s*(?:number|#|no\.?))?",
              r"passport(?:\s*(?:number|#|no\.?))?",
              r"routing\s*(?:number|#|no\.?)", r"aba\s*(?:number|#|no\.?)?",
              r"(?:credit\s+)?card\s*(?:number|#|no\.?)",
              r"vin", r"vehicle\s+identification\s*(?:number|#)",
              r"license\s+plate(?:\s*(?:number|#))?",
              r"confirmation\s*(?:number|#|code)"]),
]

# Inline person slots: a salutation, a signature line, a "requested by" clause,
# or a bare role word ("Borrower Priya O'Brien"). The cue is followed by the name
# in the same cell, or the next cell down when the layout split them.
PERSON_CTX_RE = re.compile(
    r"(?<![A-Za-z])(?:dear|sincerely|regards|signed\s+by|signed|signature(?:\s+of)?|"
    r"prepared\s+by|prepared\s+for|submitted\s+by|completed\s+by|filled\s+by|"
    r"referred\s+by|requested\s+by|reviewed\s+by|attn|attention|cc|contact(?:ed)?|"
    r"supervisor|manager|authorized\s+user|guarantor|responsible\s+party|"
    r"customer|client|representative|advisor|adjuster|specialist|"
    r"beneficiary|witness|notary|borrower|applicant|patient|employee|member|"
    r"insured|subscriber|cardholder|tenant|landlord|claimant|policyholder|"
    r"student|resident|spouse|dependent|parent|guardian|recipient|payee|"
    r"remit\s+to|payable\s+to|pay\s+to|bill\s+to|ship\s+to|sold\s+to|"
    r"issued\s+to|belongs\s+to|by)(?![A-Za-z])[\s,:'\"]*",
    re.I,
)

# A salutation or signature cue standing alone in its cell. The name is the next
# cell down -- and it is a name, not a section header, so it must not open a block.
SALUTATION_RE = re.compile(
    r"^\s*(?:dear|sincerely|regards|best\s+regards|kind\s+regards|thanks|"
    r"thank\s+you|signed|signature|attn|attention|cc|prepared\s+by|"
    r"submitted\s+by|approved\s+by|reviewed\s+by|signature\s+of)\s*[:,]?\s*$",
    re.I,
)

# A field label that ends a "Name: <value>" run when several fields share one cell
# ("Patient: Jane Doe  DOB: 03/14/1979").
FIELD_STOP_RE = re.compile(
    r"\s+(?:dob|d\.o\.b\.?|ssn|mrn|phone|tel|fax|e-?mail|address|account|acct|"
    r"member|group|policy|claim|date|ref|reference|id|no|num|amount|balance)\b"
    r"\s*[:#]",
    re.I,
)

# Whole cell == a bare label ("Account Number", "Employers:", "Name(s)")
# The non-capturing group matters: without it `^`/`$` bind to the first/last
# alternative only, and "Reference Id #2756" matches the bare "reference" rule.
LABEL_RES = [
    (lab, [(pat, re.compile(rf"^\s*(?:{pat})\s*[:,]?\s*$", re.I)) for pat in pats])
    for lab, pats in LABELS
]

# "Label: value" inside one cell
LABEL_PREFIX_RES = [
    (lab, [(pat, re.compile(rf"(?<![\w])(?:{pat})\s*:\s*", re.I)) for pat in pats])
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
mrn member members group policy claim claims insurer guarantor applicant
co-applicant borrower insured subscriber cardholder recipient payee supervisor
manager reference references attn attention signature signed prepared dear
sincerely regards cc ein itin routing aba cpt hcpcs usage billed portal
screenshot holder patient employee number numbers id ids
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

# All-caps runs are headings, transaction descriptions and org names far more
# often than they are people. These words disqualify an all-caps candidate even
# when the same run repeats across the batch.
ALLCAPS_STOP = set("""
pos ach purchase purchases deposit deposits transfer transfers withdrawal
withdrawals recurring payment payroll wire wires atm debit credit online mobile
savings checking balance balance_due fee fees interest check cheque cheques
statement summary details information total subtotal description qty invoice
""".split())

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
