//! Detection vocabulary: regexes, label tables and shared text helpers.
//!
//! Direct port of src/desensitize/patterns.py (v0.9.0). fancy-regex backs the
//! patterns that need lookbehind/lookahead (same backtracking semantics as
//! Python `re`); the `regex` crate backs everything else. Byte offsets are
//! used throughout -- they line up with Python's character offsets for ASCII
//! documents, and multi-byte chars only ever *widen* a redaction.

use std::collections::HashSet;
use std::sync::OnceLock;

use fancy_regex::{Regex as Fancy, RegexBuilder as FancyBuilder};
use regex::Regex;
use sha2::{Digest, Sha256};

pub struct Patterns {
    // value detectors, in priority order: (label, regex, needs_digit)
    pub patterns: Vec<(&'static str, Re, bool)>,
    pub ocr_patterns: Vec<(&'static str, Fancy, usize)>,
    /// raw regex-crate email pattern -- used for filename scrubbing
    pub email_re: regex::Regex,
    pub zip_re: Fancy,
    pub address_re: Fancy,
    pub date_re: Fancy,
    pub month_date_re: Fancy,
    pub year_re: Fancy,
    pub dob_ctx_re: Fancy,
    pub address_frag_re: Re,
    pub person_ctx_re: Fancy,
    pub salutation_re: Re,
    pub field_stop_re: Re,
    pub org_label_context_re: Re,
    pub label_res: Vec<(&'static str, Vec<Re>)>,
    pub label_prefix_res: Vec<(&'static str, Vec<Fancy>)>,
    pub token_re: Re,
    pub gap_ok_re: Re,
    pub placeholder_re: Re,
    pub vocab_re: Re,
    pub token_for_hash_re: Re,
    pub word_re: Re,
    pub date_token_re: Re,
    pub state_abbr_re: Re,
    pub header_cell_re: Re,
    pub name_stop: HashSet<&'static str>,
    pub org_markers: HashSet<&'static str>,
    pub allcaps_stop: HashSet<&'static str>,
    pub form_words: HashSet<&'static str>,
}

/// A compiled pattern on either engine, with a uniform match API.
#[derive(Clone, Debug)]
pub enum Re {
    R(regex::Regex),
    F(Fancy),
}

pub struct M {
    pub start: usize,
    pub end: usize,
}

impl Re {
    pub fn find_iter(&self, text: &str) -> Vec<M> {
        match self {
            Re::R(r) => r
                .find_iter(text)
                .map(|m| M { start: m.start(), end: m.end() })
                .collect(),
            Re::F(f) => f
                .find_iter(text)
                .filter_map(|r| r.ok())
                .map(|m| M { start: m.start(), end: m.end() })
                .collect(),
        }
    }

    pub fn is_match(&self, text: &str) -> bool {
        match self {
            Re::R(r) => r.is_match(text),
            Re::F(f) => f.is_match(text).unwrap_or(false),
        }
    }

    /// first match starting at or after `from` (Python re.search(text, pos))
    pub fn find_at(&self, text: &str, from: usize) -> Option<M> {
        match self {
            Re::R(r) => r
                .find_at(text, from)
                .map(|m| M { start: m.start(), end: m.end() }),
            // unanchored search from a position, like Python re.search(text, pos)
            Re::F(f) => f
                .find_from_pos(text, from)
                .ok()
                .flatten()
                .map(|m| M { start: m.start(), end: m.end() }),
        }
    }

    pub fn as_str<'t>(&self, span: &M, text: &'t str) -> &'t str {
        &text[span.start..span.end]
    }
}

fn fancy(pat: &str) -> Fancy {
    FancyBuilder::new(pat).build().expect("fancy-regex compiles")
}

fn fancy_i(pat: &str) -> Fancy {
    // NB: fancy-regex 0.14's RegexBuilder::case_insensitive() silently fails to
    // match patterns that need case folding (probed: builder-CI on
    // \b(dob|date\s+of\s+birth)\b finds nothing; inline (?i) finds it). So the
    // Python re.I equivalent is an inline (?i), exactly what Python does.
    FancyBuilder::new(&format!("(?i){pat}"))
        .build()
        .expect("fancy-regex compiles")
}

fn re(pat: &str) -> Re {
    Re::R(Regex::new(pat).expect("regex compiles"))
}

fn re_i(pat: &str) -> Re {
    Re::R(
        regex::RegexBuilder::new(pat)
            .case_insensitive(true)
            .build()
            .expect("regex compiles"),
    )
}

fn words(s: &'static str) -> HashSet<&'static str> {
    s.split_whitespace().collect()
}

/// bool match on a fancy-regex pattern (fancy's is_match is fallible)
pub fn fmatch(re: &Fancy, text: &str) -> bool {
    re.is_match(text).unwrap_or(false)
}

pub fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| {
        let ssn = fancy(
            r"(?<![\w-])(?:\d{3}[-. ]\d{2}[-. ]\d{4}|[Xx*]{3}[-. ][Xx*]{2}[-. ]\d{4}|\d{9})(?![\w-])",
        );
        let email = re(r"[A-Za-z0-9._%+\-]+\s?@\s?[A-Za-z0-9.\-]+\.[A-Za-z]{2,}");
        let email_trunc =
            re(r"[A-Za-z0-9._%+\-]+@\s?[A-Za-z0-9\-]+(?:[.\-][A-Za-z0-9\-]+)*");
        let phone =
            fancy(r"(?<![\w])(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}(?!\w)");
        let address = fancy_i(
            r"(?<![\w])(?:P\.?\s?O\.?\s?BOX\s+\d+|\d{1,6}\s+(?:[A-Z0-9][\w.'’-]*\s+){0,5}(?:STREET|ST|AVENUE|AVE|ROAD|RD|DRIVE|DR|LANE|LN|BOULEVARD|BLVD|COURT|CT|CIRCLE|CIR|PLACE|PL|PARKWAY|PKWY|HIGHWAY|HWY|TERRACE|TER|TRAIL|TRL|WAY|LOOP|SQUARE|SQ|APT|UNIT|SUITE|STE)\b\.?(?:\s*(?:#|APT\.?|UNIT|STE\.?|SUITE)\s*[\w-]+)?)",
        );
        let zip = fancy(r"(?<![\w\-/])\d{5}(?:-\d{4})?(?![\w\-/])");
        let number =
            fancy(r"(?<![\w\-/])(?=[A-Za-z0-9\-]*\d)[A-Za-z0-9][A-Za-z0-9\-]{7,}(?![\w\-/])");
        let card = fancy(
            r"(?<![\w\-])(?:\d{4}[ \-]){3}\d{1,4}(?![\w\-])|(?<![\w\-])\d{13,19}(?![\w\-])",
        );
        let mask_tail =
            re(r"(?:#\s?\d{3,6}\b|[Xx*•·]{3,}(?:[ \-][Xx*•·]{2,4})*\s?\d{2,4}\b)");
        let date =
            fancy(r"(?<!\d)(?:0?[1-9]|1[0-2])[/-](?:0?[1-9]|[12]\d|3[01])[/-](?:\d{4}|\d{2})(?!\d)");
        let month_date = fancy_i(
            r"(?<![A-Za-z])(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.?\s+\d{1,2}(?:st|nd|rd|th)?,?\s+(?:19|20)\d{2}(?!\d)",
        );

        // needs_digit: every value pattern except the email pair contains \d
        // (ADDRESS too: both its alternatives require digits) -- cells with no
        // digit can skip them outright. Same matches, far less work.
        let patterns: Vec<(&'static str, Re, bool)> = vec![
            ("SSN", Re::F(ssn), true),
            ("EMAIL", email.clone(), false),
            ("EMAIL", email_trunc, false),
            ("PHONE", Re::F(phone), true),
            ("ADDRESS", Re::F(address.clone()), true),
            ("ZIP", Re::F(zip.clone()), true),
            ("NUMBER", Re::F(number), true),
            ("NUMBER", Re::F(card), true),
            ("NUMBER", mask_tail, true),
        ];

        // tesseract confuses 0/O, 1/I/l, 5/S, 8/B, 2/Z, 6/G -- accept the
        // confusable classes but demand enough real digits (see patterns.py)
        let ssn_ocr = fancy(r"(?<![\w-])[0-9OoIlSsBbZzGg]{3}[-. ][0-9OoIlSsBbZzGg]{2}[-. ][0-9OoIlSsBbZzGg]{4}(?![\w-])");
        let phone_ocr = fancy(r"(?<![\w])(?:1[-.\s])?\(?[0-9OoIlSsBbZzGg]{3}\)?[-.\s][0-9OoIlSsBbZzGg]{3}[-.\s][0-9OoIlSsBbZzGg]{4}(?!\w)");
        let ocr_patterns = vec![
            ("SSN", ssn_ocr, 5usize),
            ("PHONE", phone_ocr, 8usize),
        ];

        let dob_ctx = fancy_i(
            r"\b(dob|date\s+of\s+birth|born|birth\s*(?:date|year)|year\s+of\s+birth|yob)\b",
        );
        let year = fancy(r"(?<!\d)(?:19[2-9]\d|20[01]\d)(?!\d)");
        let address_frag = re(
            r"^\d{1,6}\s+[A-Za-z][A-Za-z.'’\-]*(?:\s+[A-Za-z][A-Za-z.'’\-]*){0,3}$",
        );

        let person_ctx = fancy_i(
            r#"(?<![A-Za-z])(?:dear|sincerely|regards|signed\s+by|signed|signature(?:\s+of)?|prepared\s+by|prepared\s+for|submitted\s+by|completed\s+by|filled\s+by|referred\s+by|requested\s+by|reviewed\s+by|attn|attention|cc|contact(?:ed)?|supervisor|manager|authorized\s+user|guarantor|responsible\s+party|customer|client|representative|advisor|adjuster|specialist|beneficiary|witness|notary|borrower|applicant|patient|employee|member|insured|subscriber|cardholder|tenant|landlord|claimant|policyholder|student|resident|spouse|dependent|parent|guardian|recipient|payee|remit\s+to|payable\s+to|pay\s+to|bill\s+to|ship\s+to|sold\s+to|issued\s+to|belongs\s+to|account\s+holder|acct\.?\s+holder|card\s+holder|by)(?![A-Za-z])[\s,:'"]*"#,
        );
        let salutation = re_i(
            r"^\s*(?:dear|sincerely|regards|best\s+regards|kind\s+regards|thanks|thank\s+you|signed|signature|attn|attention|cc|prepared\s+by|submitted\s+by|approved\s+by|reviewed\s+by|signature\s+of)\s*[:,]?\s*$",
        );
        let field_stop = re_i(
            r"\s+(?:dob|d\.o\.b\.?|ssn|mrn|phone|tel|fax|e-?mail|address|account|acct|member|group|policy|claim|date|ref|reference|id|no|num|amount|balance)\b\s*[:#]",
        );
        let org_label_ctx = re(
            r"(creditor|original|company|business|merchant|subscriber|bank|furnisher|agency|also|other|previous|prior)\s*$",
        );

        // ---- field label tables (verbatim from patterns.py) ----
        let labels: Vec<(&'static str, Vec<&'static str>)> = vec![
            ("NAME", vec![
                r"consumer\s+names?", r"names?", r"former\s+names?", r"previous\s+names?",
                r"other\s+names?", r"reported\s+names?", r"also\s+known\s+as",
                r"a\.?k\.?a\.?", r"formerly\s+known\s+as", r"your\s+name", r"full\s+name",
                r"legal\s+name", r"printed\s+name", r"signature\s+name", r"named\s+as",
                r"name\s+of\s+(?:consumer|patient|applicant|employee|member|borrower)",
                r"(?:borrower|owner|holder|trustor|grantor|grantee|trustee|party|person|payee|mortgagor)\s+of\s+record",
                r"(?:patient|member|employee|applicant|co-?applicant|borrower|insured|subscriber|student|taxpayer|cardholder|card\s+holder|account\s+holder|acct\.?\s+holder|guarantor|responsible\s+party|parent|guardian|spouse|dependent|payee|recipient|signer|contact|reference|supervisor|manager|emergency\s+contact|authorized\s+user|customer|client|owner|tenant|landlord|witness|notary)\s+names?",
                r"employee'?s?\s+name(?:,?\s*address)?(?:,?\s*and\s+zip\s*code)?",
                r"(?!(?:creditor|company|business|merchant|bank|furnisher|agency|employer|original|collection|school|institution|provider)\b)(?:[A-Za-z][A-Za-z.'’\-]*\s+){1,3}names?",
                r"patient|applicant|co-?applicant|borrower|employee|member|insured|subscriber|cardholder|guarantor|supervisor|manager|contact(?:\s+person)?|reference\s+names?|signer|witness|notary|tenant|landlord|claimant|policyholder|student|customer|client|spouse|dependent|parent|guardian|recipient|attn|attention|capacity|signature\s+of|account\s+holder|acct\.?\s+holder|card\s+holder|holder|dear|sincerely|regards|best\s+regards|kind\s+regards|thanks|thank\s+you|signed|signature|cc",
            ]),
            ("SSN", vec![
                r"(?:employee'?s?|taxpayer'?s?|patient'?s?|spouse'?s?)?\s*social\s+security\s*(?:number|#|no\.?|id|nbr)",
                r"ssn", r"ss\s*#", r"soc\.?\s*sec\.?(?:\s*(?:number|#|no\.?))?",
                r"social\s+insurance\s+number",
            ]),
            ("EMAIL", vec![r"e-?mail(?:\s+address)?"]),
            ("PHONE", vec![
                r"phones?(?:\s+numbers?)?", r"phone\s+numbers?",
                r"former\s+phones?", r"telephone(?:\s+number)?", r"tel\.?",
                r"cell(?:ular)?(?:\s+phone)?(?:\s+number)?",
                r"mobile(?:\s+phone)?(?:\s+number)?",
                r"(?:work|home|direct|contact|office|fax)\s+(?:phone|number|#|tel)",
                r"fax(?:\s+number)?",
            ]),
            ("DOB", vec![
                r"date\s+of\s+birth", r"dob", r"birth\s*date", r"year\s+of\s+birth",
                r"birth\s+year", r"yob", r"born",
            ]),
            ("ADDRESS", vec![
                r"(?:current|previous|prior|former|mailing|home|service|property|billing|shipping|permanent|street|residence|residential)\s+address(?:es)?",
                r"address(?:es)?", r"residence",
            ]),
            ("EMPLOYER", vec![
                r"employers?", r"employer\s+names?", r"place\s+of\s+employment",
                r"employment(?:\s+information)?", r"employed\s+by",
            ]),
            ("ACCT", vec![
                r"account\s*(?:number|#|no\.?|id)", r"acct\.?\s*(?:number|#|no\.?)?",
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
                r"confirmation\s*(?:number|#|code)",
            ]),
        ];

        let label_res: Vec<(&'static str, Vec<Re>)> = labels
            .iter()
            .map(|(lab, pats)| {
                (
                    *lab,
                    // fancy, not the regex crate: one NAME entry has a lookahead
                    pats.iter()
                        .map(|p| {
                            Re::F(fancy_i(&format!(r"^\s*(?:{p})\s*[:,]?\s*$")))
                        })
                        .collect(),
                )
            })
            .collect();
        let label_prefix_res: Vec<(&'static str, Vec<Fancy>)> = labels
            .iter()
            .map(|(lab, pats)| {
                (
                    *lab,
                    pats.iter()
                        .map(|p| fancy_i(&format!(r"(?<![\w])(?:{p})\s*:\s*")))
                        .collect(),
                )
            })
            .collect();

        Patterns {
            patterns,
            ocr_patterns,
            email_re: Regex::new(r"[A-Za-z0-9._%+\-]+\s?@\s?[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
                .unwrap(),
            zip_re: zip,
            address_re: address,
            date_re: date,
            month_date_re: month_date,
            year_re: year,
            dob_ctx_re: dob_ctx,
            address_frag_re: address_frag,
            person_ctx_re: person_ctx,
            salutation_re: salutation,
            field_stop_re: field_stop,
            org_label_context_re: org_label_ctx,
            label_res,
            label_prefix_res,
            token_re: re(r"[A-Za-z][A-Za-z'’\-.]*"),
            gap_ok_re: re(r"^[ ,.&/'’\-\s]*$"),
            placeholder_re: re(r"\[[A-Z]+\]"),
            vocab_re: re(r"[A-Za-z0-9][\w'’@.\-]*"),
            token_for_hash_re: re(r"[A-Za-z0-9][\w'’@.\-]{2,}"),
            word_re: re(r"\S+"),
            date_token_re: re(r"\d{4}[-/.]\d{1,2}[-/.]\d{1,2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}"),
            state_abbr_re: re(r"\b[A-Z]{2}\b"),
            header_cell_re: re(r"^[A-Z][A-Z /&.'()\-]{1,19}$"),
            name_stop: words(
                r"a an and the of for to in on at by with from or as is are was were be been
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
                screenshot holder patient employee number numbers id ids",
            ),
            org_markers: words(
                r"bank banks banking corp corporation company co llc inc ltd lp llp na n.a. plc
                financial finance services service solutions systems group holdings trust
                capital funding fund funds loans loan mortgage mortgages auto cars credit card
                cards collection collections agency agencies associates association
                receivables portfolio management mfg manufacturing industries
                store stores retail market markets insurance casualty mutual union savings
                bureau enterprises partners partner network technologies
                telecom wireless utilities utility hospital health care clinic pharmacy
                university college school district county city state department federal
                government authority board office center centre institute foundation
                society club hotel restaurant cafe shop inc. dba",
            ),
            allcaps_stop: words(
                r"pos ach purchase purchases deposit deposits transfer transfers withdrawal
                withdrawals recurring payment payroll wire wires atm debit credit online mobile
                savings checking balance balance_due fee fees interest check cheque cheques
                statement summary details information total subtotal description qty invoice",
            ),
            form_words: words(
                r"security wages wage tax taxed withheld medicare insurance number name address
                code date amount total balance employee employer patient member group policy
                claim description quantity qty charge charges period rate hours units",
            ),
        }
    })
}

/// Canonical form used for hashing and the leak self-check (patterns.norm).
pub fn norm(s: &str) -> String {
    static WS: OnceLock<Regex> = OnceLock::new();
    let ws = WS.get_or_init(|| Regex::new(r"\s+").unwrap());
    let collapsed = ws.replace_all(s, " ");
    const EDGE: &[char] = &[
        ' ', '\t', '.', ',', ':', ';', '(', ')', '[', ']', '{', '}', '"', '\'', '!', '?', '*', '-',
    ];
    collapsed.trim().to_lowercase().trim_matches(EDGE).to_string()
}

/// Short, stable digest; values are never stored in plain text (patterns.h).
pub fn h(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(norm(s).as_bytes());
    let out = format!("{:x}", hasher.finalize());
    out[..16].to_string()
}

/// Tokens worth remembering as "must not reappear" (patterns.sensitive_tokens).
pub fn sensitive_tokens(s: &str) -> Vec<String> {
    let p = patterns();
    let mut out = Vec::new();
    for m in p.token_for_hash_re.find_iter(s) {
        let t = p.token_for_hash_re.as_str(&m, s);
        let low = t.to_lowercase();
        let low = low.trim_matches('.');
        if p.name_stop.contains(low) {
            continue;
        }
        out.push(t.to_string());
    }
    out
}

/// True for "2023-10-04" / "10/04/2023" (patterns.is_date_like).
pub fn is_date_like(token: &str) -> bool {
    static FULL: OnceLock<Regex> = OnceLock::new();
    let full = FULL.get_or_init(|| {
        Regex::new(r"^(?:\d{4}[-/.]\d{1,2}[-/.]\d{1,2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4})$")
            .unwrap()
    });
    full.is_match(token)
}

/// Number of digit characters (patterns.digit_count).
pub fn digit_count(text: &str) -> usize {
    static DIG: OnceLock<Regex> = OnceLock::new();
    let dig = DIG.get_or_init(|| Regex::new(r"\d").unwrap());
    dig.find_iter(text).count()
}

/// Python `str.isupper()`: at least one cased char, all cased chars uppercase.
pub fn py_isupper(s: &str) -> bool {
    let mut any = false;
    for c in s.chars() {
        if c.is_lowercase() {
            return false;
        }
        if c.is_uppercase() {
            any = true;
        }
    }
    any
}

/// Byte offset `n` characters after `from` (clamped to len; never mid-char).
pub fn char_offset(text: &str, from: usize, n: usize) -> usize {
    let mut off = from.min(text.len());
    if !text.is_char_boundary(off) {
        off = floor_boundary(text, off);
    }
    let mut count = 0usize;
    for (i, _) in text[off..].char_indices() {
        if count == n {
            return off + i;
        }
        count += 1;
    }
    text.len()
}

/// Byte offset `n` characters *before* `from`, never mid-char.
pub fn char_offset_back(text: &str, from: usize, n: usize) -> usize {
    let mut off = from.min(text.len());
    if !text.is_char_boundary(off) {
        off = floor_boundary(text, off);
    }
    let mut count = 0usize;
    for (i, _) in text[..off].char_indices().rev() {
        if count == n {
            return i;
        }
        count += 1;
    }
    0
}

pub fn floor_boundary(text: &str, mut b: usize) -> usize {
    while b > 0 && !text.is_char_boundary(b) {
        b -= 1;
    }
    b
}
