"""Generate synthetic, PII-bearing PDFs plus a ground-truth manifest.

Every value is fabricated (seeded RNG), so the outputs are safe to keep around.

    python eval/gen.py DATA_DIR [--count 40] [--seed 7]

Writes DATA_DIR/docs/<nn>_<type>.pdf and DATA_DIR/truth.json. The truth file
lists, per document, every planted value with the probes used to look for it in
the redacted copy, the strings that must *survive*, and every embedded picture
(page, rect, whether it holds PII, sha256 of the stored image).
"""
from __future__ import annotations

import hashlib
import json
import random
import re
import sys
from pathlib import Path

import pymupdf

W, H = 612.0, 792.0
M = 54.0
LINE = 14.0

FIRST = ["Marisol", "Devereaux", "Ilse", "Tobias", "Priya", "Emerick", "Nadja",
         "Callum", "Xiomara", "Ravi", "Greta", "Ansel", "Delphine", "Kwame",
         "Ines", "Bartholomew", "Saoirse", "Yusuf", "Maribel", "Cyrus",
         "Astrid", "Desmond", "Lucinda", "Emeka", "Rosalind", "Terrence",
         "Beatriz", "Nikolai", "Odalys", "Gideon", "Anne-Marie", "Jean-Luc"]
LAST = ["Vantorre", "Okonkwo", "Halloran", "Petrakis", "Ferreira", "Nakamura",
        "Bergstrom", "Oyelaran", "Kowalski", "Lindqvist", "Bhattacharya",
        "Moreau", "Zielinski", "Sandoval", "Fitzgerald", "O'Brien", "Mbeki",
        "Rasmussen", "Duquesne", "Halvorsen", "Achterberg", "Osei", "Ricci",
        "Novak", "Thibodeaux", "Yamashita", "Blomqvist", "Cavalcanti"]
STREETS = ["Central", "Hawthorn", "Larkspur", "Kestrel", "Juniper", "Willowbrook",
           "Sandpiper", "Coldwater", "Brookline", "Maplewood", "Foxglove",
           "Quarry", "Alder", "Bramble", "Chestnut"]
SUFFIX = ["Ave", "Street", "Road", "Drive", "Lane", "Court", "Way", "Terrace"]
CITY = ["Wexington", "Fair Oaks", "Maple Grove", "Riverton", "Cedar Falls",
        "Lake Bluff", "Pinehurst", "Ashford", "Brookhaven", "Elmhurst",
        "Coldspring", "Harlow"]
STATE = ["IL", "TX", "CA", "FL", "GA", "VA", "MD", "NY", "OH", "AZ", "OR", "MN"]
EMPLOYERS = ["Northwind Logistics LLC", "Cobalt Ridge Manufacturing",
             "Sunrise Dental Group", "Harborline Freight Co",
             "Ironwood Analytics", "Blue Ridge Electrical",
             "Tessellate Studios", "Fairmont Foods Inc", "Quarry Lane Schools",
             "Redstone Property Group"]
CREDITORS = ["NORTHWIND BANK", "CASCADE CARD SERVICES", "MERIDIAN AUTO FINANCE",
             "SUMMIT MORTGAGE", "HARBORVIEW CREDIT UNION",
             "PINNACLE RETAIL CARD", "ATLAS STUDENT LOAN",
             "BLUEWATER UTILITIES", "LUMEN HEALTH PLAN", "TRAILHEAD STORES"]
DOMAINS = ["example.org", "mail.example.net", "corp.example.com"]


# ---------------------------------------------------------------------------
# truth recorder
# ---------------------------------------------------------------------------
def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def _alnum(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "", s)


def _tokens(s: str) -> list[str]:
    return re.findall(r"[A-Za-z][A-Za-z'\-]*", s)


def auto_probes(cat: str, text: str) -> list[dict]:
    """Probes: how the checker looks for this value in the redacted copy."""
    out: list[dict] = []
    if cat in {"SSN", "PHONE", "ROUTING", "EIN", "TIN", "ZIP", "CARD", "DOB"}:
        d = _digits(text)
        if d:
            # four digits are a year to everyone else: report, don't fail on it
            out.append({"kind": "digits", "text": d, "critical": len(d) >= 6})
        if cat == "SSN" and re.match(r"^[Xx*]", text):
            out.append({"kind": "text", "text": text.lower(), "critical": True})
        if cat == "DOB":
            m = re.search(r"(?:19|20)\d{2}", text)
            if m and not re.fullmatch(r"\d{4}", text):
                out.append({"kind": "digits", "text": m.group(0), "critical": False})
        a = _alnum(text)
        if len(a) > len(d) + 1:
            out.append({"kind": "alnum", "text": a, "critical": True})
    elif cat in {"ACCT", "POLICY", "MEMBER", "GROUP", "CLAIM", "MRN", "PASSPORT",
                 "DL", "UID", "RECORD_ID"}:
        a = _alnum(text)
        if len(a) >= 5:
            out.append({"kind": "alnum", "text": a, "critical": True})
        else:
            out.append({"kind": "text", "text": text.lower(), "critical": True})
    elif cat == "EMAIL":
        out.append({"kind": "text", "text": text.lower(), "critical": True})
    elif cat == "ADDRESS":
        street = text.split(",")[0].strip()
        toks = _tokens(street)
        if toks:
            out.append({"kind": "tokens", "text": street, "critical": True})
        if len(toks) >= 2:
            out.append({"kind": "tokens", "text": " ".join(toks[:2]), "critical": True})
        m = re.search(r"\b\d{5}(?:-\d{4})?\b", text)
        if m:
            out.append({"kind": "digits", "text": _digits(m.group(0)), "critical": True})
    elif cat in {"NAME", "AKA", "SIGNATURE"}:
        toks = _tokens(text)
        if toks:
            out.append({"kind": "tokens", "text": " ".join(toks), "critical": True})
        if len(toks) >= 2:
            out.append({"kind": "tokens", "text": toks[-1], "critical": True})
            out.append({"kind": "tokens", "text": toks[0], "critical": False})
    elif cat in {"EMPLOYER"}:
        out.append({"kind": "tokens", "text": text, "critical": True})
    else:
        out.append({"kind": "text", "text": text.lower(), "critical": True})
    return out


class Truth:
    def __init__(self, name: str, kind: str, seed: int):
        self.name = name
        self.kind = kind
        self.seed = seed
        self.values: list[dict] = []
        self.keep: list[str] = []
        self.images: list[dict] = []
        self.pages = 0

    def add(self, cat: str, text: str, page: int | None = None,
            probes: list[dict] | None = None) -> str:
        self.values.append({
            "cat": cat, "value": text, "page": page,
            "probes": probes if probes is not None else auto_probes(cat, text),
        })
        return text

    def keep_it(self, *texts: str) -> None:
        for t in texts:
            if t and t not in self.keep:
                self.keep.append(t)

    def image(self, page_no: int, rect, pii: bool) -> dict:
        entry = {"page": page_no, "rect": [round(v, 2) for v in rect], "pii": pii,
                 "sha256": None}
        self.images.append(entry)
        return entry


# ---------------------------------------------------------------------------
# fake person / values
# ---------------------------------------------------------------------------
class Person:
    def __init__(self, rng: random.Random):
        self.first = rng.choice(FIRST)
        self.last = rng.choice(LAST)
        mid = rng.choice(["", "", rng.choice("JKMQRA") + "."])
        self.name = " ".join(x for x in (self.first, mid, self.last) if x)
        self.aka = f"{self.first[0]}. {self.last}" if rng.random() < 0.4 else \
                   f"{rng.choice(FIRST)} {self.last}"
        if self.aka == self.name:
            self.aka = f"{self.first} {rng.choice(LAST) if rng.random()<.5 else self.last}"
        self.ssn = f"{rng.randint(101,899)}-{rng.randint(10,99)}-{rng.randint(1000,9999)}"
        self.ssn_bare = self.ssn.replace("-", "")
        self.ssn_masked = f"XXX-XX-{self.ssn[-4:]}"
        self.dob_m, self.dob_d, self.dob_y = (rng.randint(1, 12), rng.randint(1, 28),
                                              rng.randint(1952, 1998))
        self.dob = f"{self.dob_m:02d}/{self.dob_d:02d}/{self.dob_y}"
        months = ["January", "February", "March", "April", "May", "June", "July",
                  "August", "September", "October", "November", "December"]
        self.dob_text = f"{months[self.dob_m - 1]} {self.dob_d}, {self.dob_y}"
        self.dob_iso = f"{self.dob_y}-{self.dob_m:02d}-{self.dob_d:02d}"
        self.num = str(rng.randint(1001, 9899))
        self.street_name = rng.choice(STREETS)
        self.street = f"{self.num} {self.street_name} {rng.choice(SUFFIX)}"
        self.city = rng.choice(CITY)
        self.state = rng.choice(STATE)
        self.zip = f"{rng.randint(10000, 98999)}"
        self.city_line = f"{self.city}, {self.state} {self.zip}"
        self.full_address = f"{self.street}, {self.city_line}"
        self.phone_d = f"555{rng.randint(200,999)}{rng.randint(1000,9999)}"
        self.phone = rng.choice([
            f"(555) {self.phone_d[3:6]}-{self.phone_d[6:]}",
            f"555-{self.phone_d[3:6]}-{self.phone_d[6:]}",
            f"555.{self.phone_d[3:6]}.{self.phone_d[6:]}",
            f"+1 555 {self.phone_d[3:6]} {self.phone_d[6:]}",
            f"555{self.phone_d[3:]}",
        ])
        self.phone_digits = self.phone_d
        self.email = f"{self.first.lower()}.{self.last.lower().replace(chr(39), '')}@" \
                     f"{rng.choice(DOMAINS)}"
        self.employer = rng.choice(EMPLOYERS)
        self.routing = "021000021"
        self.acct = f"{rng.randint(1000,9999)}-{rng.randint(1000,9999)}-" \
                    f"{rng.randint(1000,9999)}"
        self.acct2 = f"{rng.randint(10**9, 10**10 - 1)}"
        self.card = (f"{rng.randint(4000,4999)} {rng.randint(1000,9999)} "
                     f"{rng.randint(1000,9999)} {rng.randint(1000,9999)}")
        self.card_masked = f"XXXX XXXX XXXX {self.card[-4:]}"
        self.member = f"M{rng.randint(10**7, 10**8 - 1)}"
        self.group = f"GRP-{rng.randint(10000,99999)}"
        self.policy = f"POL-{rng.randint(10,99)}-{rng.randint(10**5, 10**6 - 1)}"
        self.claim = f"CLM{rng.randint(10**6, 10**7 - 1)}"
        self.mrn = f"MRN-{rng.randint(10**5, 10**6 - 1)}"
        self.ein = f"{rng.randint(10,99)}-{rng.randint(1000000, 9999999)}"
        self.dl = f"S{rng.randint(100,999)}-{rng.randint(100,999)}-{rng.randint(10,99)}-{rng.randint(100,999)}-0"
        self.passport = f"X{rng.randint(10**6, 10**7 - 1)}"
        self.case = f"CV-2023-{rng.randint(10000,99999)}"
        self.po = f"PO-{rng.randint(1000,9999)}-{rng.choice('ABCDEFG')}{rng.choice('XYZ')}"
        self.invoice = f"INV-2023-{rng.randint(1000,9999)}"
        self.report_no = f"CR-{rng.randint(10**7, 10**8 - 1)}"
        self.agent = rng.choice(FIRST) + " " + rng.choice(LAST)
        self.roommate = rng.choice(FIRST) + " " + rng.choice(LAST)


# ---------------------------------------------------------------------------
# drawing helpers
# ---------------------------------------------------------------------------
def T(page, x, y, text, size=10.0, font="helv", color=(0, 0, 0), rotate=0):
    page.insert_text((x, y), text, fontsize=size, fontname=font, color=color,
                     rotate=rotate)


def para(page, rect, text, size=9.5, font="tiro", leading=1.35):
    rc = pymupdf.Rect(rect)
    page.insert_textbox(rc, text, fontsize=size, fontname=font,
                        lineheight=leading, align=0)
    return rc


def band(page, y, text, size=10, fill=(0.90, 0.90, 0.94)):
    page.draw_rect(pymupdf.Rect(M, y - 10, W - M, y + 5), color=None, fill=fill)
    T(page, M + 4, y, text, size=size, font="hebo")


def table(page, x, y, cols, rows, widths, size=8.5, row_h=13.0):
    """cols: header labels; rows: list of lists. Returns y after the table."""
    cx = x
    page.draw_rect(pymupdf.Rect(x, y - 9, x + sum(widths), y + 5), color=None,
                   fill=(0.88, 0.88, 0.92))
    for label, w in zip(cols, widths):
        T(page, cx + 2, y, label, size=size, font="hebo")
        cx += w
    yy = y
    for row in rows:
        yy += row_h
        cx = x
        for cell, w in zip(row, widths):
            T(page, cx + 2, yy, str(cell), size=size)
            cx += w
        page.draw_line(pymupdf.Point(x, yy + 3), pymupdf.Point(x + sum(widths), yy + 3),
                       color=(0.8, 0.8, 0.8), width=0.4)
    return yy


def boxed(page, rect, label, value, size=8.5):
    r = pymupdf.Rect(rect)
    page.draw_rect(r, color=(0.25, 0.25, 0.25), width=0.7)
    T(page, r.x0 + 3, r.y0 + 9, label, size=size - 1.5, font="hebo")
    T(page, r.x0 + 3, r.y0 + 22, value, size=11, font="cour")


def render_png(width_pt, height_pt, draw_fn, dpi=200, rotation=0) -> bytes:
    doc = pymupdf.open()
    p = doc.new_page(width=width_pt, height=height_pt)
    draw_fn(p)
    if rotation:
        p.set_rotation(rotation)   # rotate the page, then render it
    pix = p.get_pixmap(dpi=dpi, alpha=False)
    data = pix.tobytes("png")
    doc.close()
    return data


def place_image(page, rect, data: bytes, truth: Truth, page_no: int, pii: bool = True,
                rotate: int = 0):
    page.insert_image(pymupdf.Rect(rect), stream=data, rotate=rotate)
    truth.image(page_no, pymupdf.Rect(rect), pii)


# ---------------------------------------------------------------------------
# document builders
# ---------------------------------------------------------------------------
def build_credit_report(rng, p: Person, t: Truth) -> pymupdf.Doc:
    doc = pymupdf.open()
    pg = doc.new_page(width=W, height=H)
    t.add("RECORD_ID", p.report_no, 0)
    T(pg, M, 50, "VERIDATA ANALYTICS", size=14, font="hebo")
    T(pg, M, 66, "Consumer Credit Report", size=10, font="heit")
    T(pg, W - M - 150, 50, f"Report Number: {p.report_no}", size=8.5)
    T(pg, W - M - 150, 62, "Report Date: 01/07/2023", size=8.5)
    t.keep_it("VERIDATA ANALYTICS", "Report Date: 01/07/2023")

    y = 96
    for label, value, cat in [
        ("Consumer Name:", p.name, "NAME"),
        ("Also Known As:", p.aka, "AKA"),
        ("Social Security Number:", p.ssn, "SSN"),
        ("Date of Birth:", p.dob_text, "DOB"),
        ("Current Address:", p.full_address, "ADDRESS"),
        ("E-mail:", p.email, "EMAIL"),
        ("Phone:", p.phone, "PHONE"),
        ("Employer:", p.employer, "EMPLOYER"),
    ]:
        T(pg, M, y, label, size=9, font="hebo")
        T(pg, M + 132, y, value, size=9)
        t.add(cat, value, 0)
        if cat == "DOB":
            t.add("DOB", p.dob_text, 0)
        y += LINE + 3

    band(pg, 250, "ACCOUNT SUMMARY")
    rows = []
    for i in range(5):
        rows.append([rng.choice(CREDITORS), p.acct if i == 0 else
                     f"{rng.randint(1000,9999)}-{rng.randint(1000,9999)}",
                     f"${rng.randint(200, 24000):,}.00", rng.choice(["OPEN", "PAID"]),
                     f"0{rng.randint(1,9)}/{rng.randint(10,28)}/202{rng.randint(0,2)}"])
    table(pg, M, 274, ["CREDITOR", "ACCOUNT NUMBER", "BALANCE", "STATUS", "OPENED"],
          rows, [150, 120, 90, 70, 74])
    for r in rows:
        t.add("ACCT", r[1], 0)
        t.keep_it(r[0], r[2], r[3], r[4])
    para(pg, (M, 620, W - M, 700),
         f"This report was prepared for {p.name} at {p.full_address}. Inquiries "
         f"about this file should quote reference {p.report_no}. Contact the "
         f"consumer at {p.phone} or {p.email}.", size=8.5)

    # page 2: section headers with values underneath
    pg2 = doc.new_page(width=W, height=H)
    T(pg2, M, 48, f"{p.name} - Report {p.report_no}", size=8, font="heit")
    t.add("NAME", p.name, 1)
    T(pg2, 70, 90, "Names", size=9, font="hebo")
    for i, variant in enumerate([p.name, p.aka]):
        T(pg2, 83, 110 + i * 13, variant, size=8.5)
        t.add("NAME" if i == 0 else "AKA", variant, 1)
    T(pg2, 70, 170, "Addresses", size=9, font="hebo")
    T(pg2, 83, 188, f"{p.num} {p.street_name}", size=8.5)
    T(pg2, 206, 188, p.street.split()[-1], size=8.5)
    T(pg2, 83, 201, p.city_line, size=8.5)
    t.add("ADDRESS", p.full_address, 1)
    T(pg2, 70, 240, "Employers", size=9, font="hebo")
    T(pg2, 83, 258, p.employer, size=8.5)
    t.add("EMPLOYER", p.employer, 1)
    T(pg2, 70, 300, "Prior SSN on file:", size=9, font="hebo")
    T(pg2, 190, 300, p.ssn_masked, size=9)
    t.add("SSN", p.ssn_masked, 1)
    para(pg2, (M, 330, W - M, 380),
         f"Alternate SSN {p.ssn_bare} reported by furnisher. If this is not your "
         f"Social Security number, write to us at the address above.", size=8.5)
    t.add("SSN", p.ssn_bare, 1)
    T(pg2, M, H - 40, f"{p.name} / {p.acct2} / page 2", size=7.5, font="heit")
    t.add("NAME", p.name, 1)
    t.add("ACCT", p.acct2, 1)
    t.pages = 2
    return doc


def build_bank_statement(rng, p: Person, t: Truth) -> pymupdf.Doc:
    doc = pymupdf.open()
    for pno in range(2):
        pg = doc.new_page(width=W, height=H)
        T(pg, M, 52, "HARBORVIEW CREDIT UNION", size=13, font="hebo")
        T(pg, M, 66, "1200 Harbor Road, Wexington, IL 60001", size=8)
        T(pg, W - M - 170, 52, f"Statement {pno + 1} of 2", size=8)
        t.keep_it("HARBORVIEW CREDIT UNION", "Statement")
        if pno == 0:
            band(pg, 100, "ACCOUNT HOLDER")
            y = 122
            for label, value, cat in [
                ("Account Holder:", p.name, "NAME"),
                ("Mailing Address:", p.street, "ADDRESS"),
                ("", p.city_line, "ADDRESS"),
                ("Account Number:", p.acct, "ACCT"),
                ("Routing Number:", p.routing, "ROUTING"),
                ("Telephone:", p.phone, "PHONE"),
                ("Email:", p.email, "EMAIL"),
                ("Statement Period:", "03/01/2023 - 03/31/2023", None),
            ]:
                if label:
                    T(pg, M, y, label, size=8.5, font="hebo")
                T(pg, M + 120, y, value, size=8.5)
                if cat:
                    t.add(cat, value, pno)
                    if cat == "ADDRESS" and value == p.city_line:
                        t.add("ADDRESS", f"{p.street}, {value}", pno)
                y += LINE
            t.keep_it("03/01/2023 - 03/31/2023")
            band(pg, 262, "TRANSACTIONS")
            rows = [[f"03/{d:02d}", desc, f"-${rng.randint(4, 480)}.{rng.randint(10,99)}"]
                    for d, desc in [(3, "POS PURCHASE NORTHSIDE MARKET"),
                                    (7, "ACH PAYROLL DEPOSIT"),
                                    (11, "ONLINE TRANSFER TO SAVINGS"),
                                    (19, "RECURRING PAYMENT UTILITIES"),
                                    (27, "CHECK 1043 CLEARED")]]
            table(pg, M, 284, ["DATE", "DESCRIPTION", "AMOUNT"], rows, [70, 300, 100])
            for r in rows:
                t.keep_it(r[1], r[2])
        else:
            para(pg, (M, 100, W - M, 200),
                 f"Wire instructions: ABA {p.routing}, account {p.acct2}, "
                 f"beneficiary {p.name}. For questions call {p.phone} or email "
                 f"{p.email}. Please quote your account number {p.acct} in all "
                 f"correspondence.", size=9)
            t.add("ROUTING", p.routing, pno)
            t.add("ACCT", p.acct2, pno)
            t.add("NAME", p.name, pno)
            t.add("PHONE", p.phone, pno)
            t.add("EMAIL", p.email, pno)
            t.add("ACCT", p.acct, pno)
            rows = [[f"{rng.randint(10**9, 10**10 - 1)}", "WIRE IN", f"2023-03-2{rng.randint(0, 8)}",
                     f"${rng.randint(100, 9000)}.00"] for _ in range(4)]
            table(pg, M, 240, ["REFERENCE", "TYPE", "DATE", "AMOUNT"], rows,
                  [120, 100, 100, 100])
            for r in rows:
                t.keep_it(r[1], r[3])
        T(pg, M, H - 34, f"{p.name}  |  {p.email}  |  {p.phone}", size=7.5)
        t.add("NAME", p.name, pno)
        t.add("EMAIL", p.email, pno)
        t.add("PHONE", p.phone, pno)
    t.pages = 2
    return doc


def build_w2(rng, p: Person, t: Truth) -> pymupdf.Doc:
    doc = pymupdf.open()
    pg = doc.new_page(width=W, height=H)
    T(pg, M, 50, "FORM W-2  Wage and Tax Statement  2023", size=12, font="hebo")
    t.keep_it("Wage and Tax Statement", "2023")
    boxed(pg, (M, 70, M + 250, 105), "Employee's social security number", p.ssn)
    t.add("SSN", p.ssn, 0)
    boxed(pg, (M + 260, 70, W - M, 105), "Employer identification number (EIN)",
          p.ein)
    t.add("EIN", p.ein, 0)
    boxed(pg, (M, 115, M + 380, 165), "Employee's name, address, and ZIP code",
          p.name)
    t.add("NAME", p.name, 0)
    T(pg, M + 3, 148, f"{p.street}, {p.city_line}", size=9, font="cour")
    t.add("ADDRESS", p.full_address, 0)
    emp_id = f"E{rng.randint(10**5, 10**6 - 1)}"
    boxed(pg, (M + 390, 115, W - M, 165), "Employee ID", emp_id)
    t.add("UID", emp_id, 0)
    y = 200
    for label, value in [("1  Wages, tips, other compensation", "84,912.44"),
                         ("2  Federal income tax withheld", "9,204.10"),
                         ("3  Social security wages", "84,912.44"),
                         ("4  Social security tax withheld", "5,264.57")]:
        boxed(pg, (M, y, M + 300, y + 34), label, value)
        t.keep_it(label.split("  ")[1], value)
        y += 44
    para(pg, (M, y + 10, W - M, y + 90),
         f"Employer: {p.employer}. Prepared for {p.name}, SSN {p.ssn}. Keep this "
         f"copy with your tax records; a duplicate can be requested by phone at "
         f"{p.phone} or from {p.email}.", size=8.5)
    t.add("EMPLOYER", p.employer, 0)
    t.add("NAME", p.name, 0)
    t.add("SSN", p.ssn, 0)
    t.add("PHONE", p.phone, 0)
    t.add("EMAIL", p.email, 0)
    t.pages = 1
    return doc


def build_insurance_letter(rng, p: Person, t: Truth) -> pymupdf.Doc:
    doc = pymupdf.open()
    pg = doc.new_page(width=W, height=H)
    T(pg, M, 50, "LUMEN HEALTH PLAN", size=13, font="hebo")
    T(pg, M, 64, "P.O. Box 4471, Ashford, OR 97001", size=8)
    t.keep_it("LUMEN HEALTH PLAN")
    t.add("ADDRESS", "P.O. Box 4471, Ashford, OR 97001", 0)
    T(pg, M, 96, "November 3, 2023", size=9)
    t.keep_it("November 3, 2023")
    y = 116
    for line in [p.name, p.street, p.city_line]:
        T(pg, M, y, line, size=9)
        y += LINE
    t.add("NAME", p.name, 0)
    t.add("ADDRESS", p.full_address, 0)
    body = (f"Dear {p.first} {p.last},\n\n"
            f"We have completed our review of claim {p.claim} for services "
            f"rendered on 09/18/2023. Our records show date of birth {p.dob} and "
            f"Social Security number {p.ssn} on file for you.\n\n"
            f"Your policy {p.policy}, member ID {p.member} (group {p.group}), was "
            f"active on the date of service. A payment of $1,204.00 has been "
            f"issued to the provider.\n\n"
            f"If any of the details above are incorrect, please contact us at "
            f"{p.phone} or {p.email}. You may also write to us at the address on "
            f"this letter, or update your details online.")
    para(pg, (M, y + 16, W - M, y + 16 + 260), body, size=9.5)
    y2 = y + 300
    for cat, val in [("CLAIM", p.claim), ("DOB", p.dob), ("SSN", p.ssn),
                     ("POLICY", p.policy), ("MEMBER", p.member), ("GROUP", p.group),
                     ("PHONE", p.phone), ("EMAIL", p.email)]:
        t.add(cat, val, 0)
    t.keep_it("$1,204.00", "09/18/2023")
    T(pg, M, y2, "Sincerely,", size=9.5)
    T(pg, M, y2 + 20, p.agent, size=9.5)
    T(pg, M, y2 + 32, "Claims Specialist", size=8.5)
    t.add("SIGNATURE", p.agent, 0)
    T(pg, M, y2 + 60, f"cc: {p.name}, {p.full_address}", size=8)
    t.add("NAME", p.name, 0)
    t.add("ADDRESS", p.full_address, 0)
    t.pages = 1
    return doc


def build_invoice(rng, p: Person, t: Truth) -> pymupdf.Doc:
    doc = pymupdf.open()
    pg = doc.new_page(width=W, height=H)
    T(pg, M, 52, "TESSELATE STUDIOS", size=13, font="hebo")
    T(pg, M, 66, "billing@tessellate.example.com  |  (555) 771-2043", size=8)
    t.keep_it("TESSELATE STUDIOS", "INVOICE")
    T(pg, W - M - 190, 52, f"INVOICE {p.invoice}", size=11, font="hebo")
    T(pg, W - M - 190, 66, "Issued: 2023-10-04   Due: 2023-11-03", size=8)
    t.add("RECORD_ID", p.invoice, 0)
    t.keep_it("2023-10-04", "2023-11-03")
    band(pg, 96, "BILL TO")
    y = 116
    for line in [p.name, p.street, p.city_line, p.phone, p.email]:
        T(pg, M, y, line, size=9)
        y += LINE
    t.add("NAME", p.name, 0)
    t.add("ADDRESS", p.full_address, 0)
    t.add("PHONE", p.phone, 0)
    t.add("EMAIL", p.email, 0)
    T(pg, M, y + 10, "PO Number:", size=8.5, font="hebo")
    T(pg, M + 90, y + 10, p.po, size=8.5)
    t.add("RECORD_ID", p.po, 0)
    rows = [["Design retainer", "1", "$2,400.00"],
            ["Asset production", "6", "$1,080.00"],
            ["Hosting (annual)", "1", "$801.50"]]
    table(pg, M, 230, ["DESCRIPTION", "QTY", "AMOUNT"], rows, [300, 60, 100])
    for r in rows:
        t.keep_it(r[0], r[2])
    T(pg, M + 300, 300, "Balance Due: $4,281.50", size=10, font="hebo")
    t.keep_it("$4,281.50")
    para(pg, (M, 340, W - M, 420),
         f"Remit to {p.name} via ABA {p.routing} / account {p.acct2}. Please "
         f"include the invoice number in the memo line. Questions? Call "
         f"{p.phone} or email {p.email}.", size=9)
    t.add("ROUTING", p.routing, 0)
    t.add("ACCT", p.acct2, 0)
    t.add("NAME", p.name, 0)
    t.add("PHONE", p.phone, 0)
    t.add("EMAIL", p.email, 0)
    t.pages = 1
    return doc


def build_medical(rng, p: Person, t: Truth) -> pymupdf.Doc:
    doc = pymupdf.open()
    pg = doc.new_page(width=W, height=H)
    T(pg, M, 52, "PINNACLE GROVE HOSPITAL", size=13, font="hebo")
    T(pg, M, 66, "Statement of Account - Patient Responsibility", size=9, font="heit")
    t.keep_it("PINNACLE GROVE HOSPITAL", "Statement of Account")
    y = 100
    for label, value, cat in [
        ("Patient Name:", p.name, "NAME"),
        ("Date of Birth:", p.dob_iso, "DOB"),
        ("Address:", p.street, "ADDRESS"),
        ("", p.city_line, "ADDRESS"),
        ("MRN:", p.mrn, "MRN"),
        ("Insurance Member ID:", p.member, "MEMBER"),
        ("Group Number:", p.group, "GROUP"),
        ("Claim Number:", p.claim, "CLAIM"),
        ("Guarantor SSN:", p.ssn, "SSN"),
        ("Phone:", p.phone, "PHONE"),
    ]:
        if label:
            T(pg, M, y, label, size=8.5, font="hebo")
        T(pg, M + 140, y, value, size=8.5)
        t.add(cat, value, 0)
        if cat == "ADDRESS" and value == p.city_line:
            t.add("ADDRESS", f"{p.street}, {value}", 0)
        y += LINE + 2
    tr = [["09/18/2023", "99213", "Office visit established patient", "$210.00"],
          ["09/18/2023", "80053", "Comprehensive metabolic panel", "$142.00"],
          ["10/02/2023", "71046", "Chest X-ray two views", "$188.00"]]
    table(pg, M, y + 20, ["DATE", "CPT", "DESCRIPTION", "CHARGE"], tr,
          [80, 60, 250, 80])
    for r in tr:
        t.keep_it(r[1], r[2], r[3])
    T(pg, M + 300, y + 90, "Balance Due: $540.00", size=10, font="hebo")
    t.keep_it("$540.00")
    para(pg, (M, y + 120, W - M, y + 200),
         f"Payments can be made by calling {p.phone} or visiting "
         f"billing.example.com. Reference your MRN {p.mrn} on any payment. "
         f"An itemized copy can be mailed to {p.full_address}.", size=9)
    t.add("PHONE", p.phone, 0)
    t.add("MRN", p.mrn, 0)
    t.add("ADDRESS", p.full_address, 0)
    t.pages = 1
    return doc


def build_lease(rng, p: Person, t: Truth) -> pymupdf.Doc:
    doc = pymupdf.open()
    pg = doc.new_page(width=W, height=H)
    T(pg, M, 50, "REDSTONE PROPERTY GROUP", size=12, font="hebo")
    T(pg, M, 64, "Rental Application", size=10, font="heit")
    t.keep_it("REDSTONE PROPERTY GROUP", "Rental Application")
    band(pg, 92, "APPLICANT INFORMATION")
    y = 112
    for label, value, cat in [
        ("Applicant Full Name", p.name, "NAME"),
        ("Date of Birth", p.dob, "DOB"),
        ("Social Security #", p.ssn, "SSN"),
        ("Present Address", p.full_address, "ADDRESS"),
        ("Employer", p.employer, "EMPLOYER"),
        ("Employer Phone", p.phone, "PHONE"),
        ("Supervisor", p.agent, "NAME"),
        ("Driver's License", p.dl, "DL"),
        ("Passport Number", p.passport, "PASSPORT"),
        ("E-mail", p.email, "EMAIL"),
    ]:
        T(pg, M, y, label, size=8.5, font="hebo")
        T(pg, M + 150, y, value, size=8.5)
        t.add(cat, value, 0)
        y += LINE
    band(pg, y + 18, "REFERENCES")
    y += 40
    for _i in range(2):
        ref = rng.choice(FIRST) + " " + rng.choice(LAST)
        rph = f"(555) {rng.randint(200,999)}-{rng.randint(1000,9999)}"
        T(pg, M, y, f"Name: {ref}", size=8.5)
        T(pg, M + 220, y, f"Phone: {rph}", size=8.5)
        t.add("NAME", ref, 0)
        t.add("PHONE", rph, 0)
        y += LINE
    band(pg, y + 18, "AUTHORIZATION")
    para(pg, (M, y + 30, W - M, y + 70),
         f"I authorize verification of the information above. Signed by "
         f"{p.name} on 10/12/2023.", size=9)
    t.add("NAME", p.name, 0)
    t.keep_it("10/12/2023")
    T(pg, M, y + 92, "Signature:", size=8.5, font="hebo")
    T(pg, M + 70, y + 92, p.name, size=12, font="tiit")
    T(pg, M, y + 108, "Printed Name:", size=8.5, font="hebo")
    T(pg, M + 90, y + 108, p.name, size=9)
    t.add("SIGNATURE", p.name, 0)
    t.pages = 1
    return doc


def build_utility(rng, p: Person, t: Truth) -> pymupdf.Doc:
    doc = pymupdf.open()
    pg = doc.new_page(width=W, height=H)
    T(pg, M, 50, "BLUEWATER UTILITIES", size=13, font="hebo")
    t.keep_it("BLUEWATER UTILITIES", "Amount Due")
    T(pg, W - M - 150, 50, "Amount Due: $184.22", size=10, font="hebo")
    T(pg, W - M - 150, 64, "Due Date: 11/28/2023", size=8)
    t.keep_it("$184.22", "11/28/2023")
    y = 100
    T(pg, M, y, p.name, size=9.5, font="hebo")
    T(pg, M, y + 14, p.street, size=9)
    T(pg, M, y + 28, p.city_line, size=9)
    t.add("NAME", p.name, 0)
    t.add("ADDRESS", p.full_address, 0)
    for label, value, cat in [
        ("Service Address", p.full_address, "ADDRESS"),
        ("Account Number", p.acct2, "ACCT"),
        ("Phone", p.phone, "PHONE"),
        ("Email", p.email, "EMAIL"),
    ]:
        y += 46
        T(pg, M, y, label, size=8.5, font="hebo")
        T(pg, M + 130, y, value, size=8.5)
        t.add(cat, value, 0)
    T(pg, M, y + 40, "Usage history", size=9, font="hebo")
    rows = [[m, f"{rng.randint(120, 480)} kWh", f"${rng.randint(40, 190)}.00"]
            for m in ["Aug 2023", "Sep 2023", "Oct 2023"]]
    table(pg, M, y + 56, ["MONTH", "USAGE", "BILLED"], rows, [110, 110, 110])
    for r in rows:
        t.keep_it(r[0], r[1], r[2])
    t.pages = 1
    return doc


def build_scanned(rng, p: Person, t: Truth, dpi=200) -> pymupdf.Doc:
    """Text page rasterised into an image-only PDF (a scan)."""
    src = build_bank_statement(rng, p, t)
    out = pymupdf.open()
    for pno, page in enumerate(src):
        pix = page.get_pixmap(dpi=dpi, alpha=False)
        new = out.new_page(width=page.rect.width, height=page.rect.height)
        new.insert_image(new.rect, stream=pix.tobytes("jpeg", jpg_quality=88))
        t.image(pno, new.rect, True)
    src.close()
    t.pages = out.page_count
    return out


def build_mixed(rng, p: Person, t: Truth) -> pymupdf.Doc:
    """Text page with a pasted screenshot holding its own PII."""
    doc = pymupdf.open()
    pg = doc.new_page(width=W, height=H)
    T(pg, M, 50, "CASCADE CARD SERVICES", size=12, font="hebo")
    T(pg, M, 64, "Monthly statement summary", size=9, font="heit")
    t.keep_it("CASCADE CARD SERVICES", "Monthly statement summary")
    para(pg, (M, 84, W - M, 160),
         f"Cardholder {p.name} - {p.full_address}. Payment due 11/20/2023. "
         f"A copy of your statement image is reproduced below.", size=9)
    t.add("NAME", p.name, 0)
    t.add("ADDRESS", p.full_address, 0)
    t.keep_it("11/20/2023")

    def draw(sp):
        T(sp, 10, 18, "CASCADE CARD SERVICES - STATEMENT", size=8, font="hebo")
        T(sp, 10, 34, f"Cardholder: {p.aka}", size=9)
        T(sp, 10, 48, f"SSN: {p.ssn}", size=9)
        T(sp, 10, 62, f"Card Number: {p.card}", size=9)
        T(sp, 10, 76, f"Address: {p.street}", size=9)
        T(sp, 10, 90, p.city_line, size=9)
        T(sp, 10, 108, "Balance Due: $3,204.18  (keep me)", size=9)
        T(sp, 260, 34, f"Phone {p.phone}", size=9)
        T(sp, 260, 48, f"Email {p.email}", size=9)
        T(sp, 260, 62, f"DOB {p.dob_text}", size=9)

    png = render_png(400, 120, draw, dpi=250)
    place_image(pg, (M, 180, M + 400, 300), png, t, 0)
    for cat, val in [("NAME", p.aka), ("SSN", p.ssn), ("CARD", p.card),
                     ("ADDRESS", f"{p.street}, {p.city_line}"),
                     ("PHONE", p.phone), ("EMAIL", p.email), ("DOB", p.dob_text)]:
        t.add(cat, val, 0)
        if cat == "DOB":
            t.add("DOB", p.dob_text, 0)
    T(pg, M, 340, "Closing balance: $3,204.18", size=9)
    t.keep_it("$3,204.18")
    t.pages = 1
    return doc


def build_small_image(rng, p: Person, t: Truth) -> pymupdf.Doc:
    """Text page with an ID card crop: one region big enough for `default`,
    one icon-sized region that only `full` looks at."""
    doc = pymupdf.open()
    pg = doc.new_page(width=W, height=H)
    T(pg, M, 50, "MERIDIAN AUTO FINANCE", size=12, font="hebo")
    T(pg, M, 64, "Insurance card image on file", size=9, font="heit")
    para(pg, (M, 84, W - M, 130),
         f"Borrower {p.name} provided the card image below. Loan number "
         f"{p.acct2}, balance $11,204.55.", size=9)
    t.add("NAME", p.name, 0)
    t.add("ACCT", p.acct2, 0)
    t.keep_it("MERIDIAN AUTO FINANCE", "$11,204.55")

    def big(sp):
        T(sp, 6, 14, "MEMBER ID", size=6, font="hebo")
        T(sp, 6, 26, p.member, size=9, font="cour")
        T(sp, 6, 40, f"SSN {p.ssn}", size=8)
        T(sp, 6, 52, p.name, size=8)

    png = render_png(140, 60, big, dpi=300)
    place_image(pg, (M, 160, M + 140, 220), png, t, 0)

    def small(sp):
        T(sp, 1, 8, f"SSN {p.ssn}", size=6)

    tiny = render_png(58, 16, small, dpi=300)
    place_image(pg, (M, 250, M + 58, 266), tiny, t, 0)
    t.add("MEMBER", p.member, 0)
    t.add("SSN", p.ssn, 0)
    t.add("NAME", p.name, 0)
    t.pages = 1
    return doc


def build_dark_image(rng, p: Person, t: Truth) -> pymupdf.Doc:
    """White-on-dark screenshot: tesseract usually needs help here."""
    doc = pymupdf.open()
    pg = doc.new_page(width=W, height=H)
    T(pg, M, 50, "ATLAS STUDENT LOAN", size=12, font="hebo")
    T(pg, M, 64, "Account portal screenshot (dark mode)", size=9, font="heit")
    t.keep_it("ATLAS STUDENT LOAN", "Account portal screenshot")

    def draw(sp):
        sp.draw_rect(sp.rect, color=None, fill=(0.08, 0.09, 0.12))
        T(sp, 10, 20, "ACCOUNT DETAILS", size=8, font="hebo", color=(1, 1, 1))
        T(sp, 10, 38, f"Borrower {p.name}", size=10, color=(0.95, 0.95, 0.95))
        T(sp, 10, 54, f"Loan {p.acct2}", size=10, color=(0.95, 0.95, 0.95))
        T(sp, 10, 70, f"SSN {p.ssn}", size=10, color=(0.95, 0.95, 0.95))
        T(sp, 10, 86, f"Address {p.full_address}", size=9, color=(0.9, 0.9, 0.9))

    png = render_png(380, 100, draw, dpi=250)
    place_image(pg, (M, 100, M + 380, 200), png, t, 0)
    t.add("NAME", p.name, 0)
    t.add("ACCT", p.acct2, 0)
    t.add("SSN", p.ssn, 0)
    t.add("ADDRESS", p.full_address, 0)
    t.pages = 1
    return doc


def build_rotated(rng, p: Person, t: Truth) -> pymupdf.Doc:
    """Page with rotated text and a rotated image."""
    doc = pymupdf.open()
    pg = doc.new_page(width=W, height=H)
    T(pg, M, 50, "TRAILHEAD STORES", size=12, font="hebo")
    T(pg, M, 64, "Credit application (side label)", size=9, font="heit")
    t.keep_it("TRAILHEAD STORES", "Credit application")
    for i, (label, value, cat) in enumerate([
        ("Applicant", p.name, "NAME"),
        ("SSN", p.ssn, "SSN"),
        ("DOB", p.dob, "DOB"),
        ("Account", p.acct, "ACCT"),
    ]):
        T(pg, M + 40 + i * 14, 380, f"{label}: {value}", size=9, rotate=90)
        t.add(cat, value, 0)
    T(pg, M, 480, "Scan of signature card (rotated):", size=8.5)

    def draw(sp):
        T(sp, 8, 16, "SIGNATURE CARD", size=7, font="hebo")
        T(sp, 8, 30, f"{p.name}", size=9)
        T(sp, 8, 44, f"SSN {p.ssn_bare}", size=8)
        T(sp, 8, 58, f"Member {p.member}", size=8)

    png = render_png(240, 62, draw, dpi=300, rotation=90)
    place_image(pg, (M, 500, M + 62, 740), png, t, 0)
    t.add("NAME", p.name, 0)
    t.add("SSN", p.ssn_bare, 0)
    t.add("MEMBER", p.member, 0)
    t.pages = 1
    return doc


def build_header_footer(rng, p: Person, t: Truth) -> pymupdf.Doc:
    """Three pages: identity in header/footer, surname mentioned once in prose."""
    doc = pymupdf.open()
    for pno in range(3):
        pg = doc.new_page(width=W, height=H)
        T(pg, M, 40, f"Patient: {p.name}   DOB: {p.dob}   MRN {p.mrn}", size=8)
        t.add("NAME", p.name, pno)
        t.add("DOB", p.dob, pno)
        t.add("MRN", p.mrn, pno)
        t.keep_it("Continuity of Care Record")
        T(pg, M, 64, "Continuity of Care Record", size=12, font="hebo")
        body = [
            f"Section {pno + 1}. The patient was seen for follow-up. Records were "
            f"requested by {p.agent} of the referring practice.",
            f"Insurance: {p.policy}, member {p.member}, group {p.group}. Claims "
            f"should reference {p.claim}.",
            f"Contact the patient at {p.phone} or {p.email}. Mailing address on "
            f"file is {p.street}, {p.city_line}.",
        ]
        para(pg, (M, 90, W - M, 420), "\n\n".join(body), size=9.5)
        for cat, val in [("NAME", p.agent), ("POLICY", p.policy),
                         ("MEMBER", p.member), ("GROUP", p.group),
                         ("CLAIM", p.claim), ("PHONE", p.phone),
                         ("EMAIL", p.email),
                         ("ADDRESS", f"{p.street}, {p.city_line}")]:
            t.add(cat, val, pno)
        T(pg, M, H - 34, f"{p.last}, {p.first} - page {pno + 1} of 3", size=7.5)
        t.add("NAME", f"{p.first} {p.last}", pno)
    t.pages = 3
    return doc


BUILDERS = {
    "credit_report": build_credit_report,
    "bank_statement": build_bank_statement,
    "w2": build_w2,
    "insurance_letter": build_insurance_letter,
    "invoice": build_invoice,
    "medical_bill": build_medical,
    "lease_application": build_lease,
    "utility_bill": build_utility,
    "scanned_statement": build_scanned,
    "mixed_screenshot": build_mixed,
    "small_image": build_small_image,
    "dark_image": build_dark_image,
    "rotated_text": build_rotated,
    "header_footer": build_header_footer,
}


def hash_images(path: Path, truth: Truth) -> None:
    """Fill in sha256 for each recorded image, read from the saved file."""
    with pymupdf.open(path) as doc:
        for entry in truth.images:
            page = doc[entry["page"]]
            target = pymupdf.Rect(entry["rect"])
            try:
                infos = page.get_image_info(xrefs=True)
            except Exception:
                continue
            for info in infos:
                bb = pymupdf.Rect(info["bbox"])
                if (bb - target).get_area() < 4.0:
                    base = doc.extract_image(info["xref"])
                    entry["sha256"] = hashlib.sha256(base["image"]).hexdigest()
                    break


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    out = Path(argv[0]) if argv else Path("eval/data")
    count = 40
    seed = 7
    if "--count" in argv:
        count = int(argv[argv.index("--count") + 1])
    if "--seed" in argv:
        seed = int(argv[argv.index("--seed") + 1])

    docs_dir = out / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)
    for old in docs_dir.glob("*.pdf"):
        old.unlink()

    rng = random.Random(seed)
    kinds = list(BUILDERS)
    truths = []
    for i in range(count):
        kind = kinds[i % len(kinds)] if i < len(kinds) else rng.choice(kinds)
        person = Person(rng)
        name = f"{i:02d}_{kind}.pdf"
        truth = Truth(name, kind, seed * 1000 + i)
        doc = BUILDERS[kind](rng, person, truth)
        path = docs_dir / name
        doc.save(path)
        doc.close()
        hash_images(path, truth)
        truth.name = name
        truths.append(truth.__dict__)
        print(f"  {name:<34} {truth.pages}p values={len(truth.values)} "
              f"imgs={len(truth.images)} keep={len(truth.keep)}")

    (out / "truth.json").write_text(json.dumps(
        {"seed": seed, "count": count, "docs": truths}, indent=1))
    total_values = sum(len(d["values"]) for d in truths)
    print(f"\n{count} documents, {total_values} planted values -> {out / 'truth.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
