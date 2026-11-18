"""Generate synthetic, PII-bearing PDFs plus a ground-truth manifest.

Every value is fabricated (seeded RNG), so the outputs are safe to keep around.

    python eval/gen.py DATA_DIR [--count 40] [--seed 7]

Writes DATA_DIR/docs/<nn>_<type>.pdf and DATA_DIR/truth.json. The truth file
lists, per document, every planted value with the probes used to look for it in
the redacted copy, the strings that must *survive*, and every embedded picture
(page, rect, whether it holds PII, sha256 of the stored image).
"""
from __future__ import annotations

import base64
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


# ---------------------------------------------------------------------------
# Tricky documents: the layouts and the objects that a redactor gets wrong
# ---------------------------------------------------------------------------
UNICODE_FONT = "/usr/share/fonts/TTF/DejaVuSans.ttf"


def build_split_values(rng, p: Person, t: Truth) -> pymupdf.Doc:
    """A value wrapped across two lines, and one split across a page break."""
    doc = pymupdf.open()
    pg = doc.new_page(width=W, height=H)
    T(pg, M, 50, "MERIDIAN AUTO FINANCE", size=12, font="hebo")
    T(pg, M, 64, "Credit application - continuation sheet", size=9, font="heit")
    t.keep_it("MERIDIAN AUTO FINANCE", "Credit application")

    T(pg, M, 110, "Social Security Number:", size=9, font="hebo")
    T(pg, M, 124, p.ssn[:7], size=9)          # "616-37-"
    T(pg, M, 138, p.ssn[7:], size=9)          # "4632"
    # half a value is a leak too: probe the fragments, not just the whole
    t.add("SSN", p.ssn, 0, probes=[
        {"kind": "text", "text": p.ssn[:7], "critical": True},
        {"kind": "text", "text": p.ssn[7:], "critical": False}])

    T(pg, M, 172, "Account Number:", size=9, font="hebo")
    T(pg, M, 186, p.acct[:9], size=9)
    T(pg, M, 200, p.acct[9:], size=9)
    t.add("ACCT", p.acct, 0, probes=[
        {"kind": "text", "text": p.acct[:9], "critical": True},
        {"kind": "text", "text": p.acct[9:], "critical": False}])

    para(pg, (M, 230, W - M, 300),
         f"Borrower {p.name}, of {p.full_address}, signed the application on "
         f"09/22/2023. Employment: {p.employer}. Questions: {p.phone}.", size=9)
    for cat, val in (("NAME", p.name), ("ADDRESS", p.full_address),
                     ("EMPLOYER", p.employer), ("PHONE", p.phone)):
        t.add(cat, val, 0)
    t.keep_it("09/22/2023")

    T(pg, M, H - 40, "Member ID:", size=9, font="hebo")
    T(pg, M + 70, H - 40, p.member[:4], size=9)
    pg2 = doc.new_page(width=W, height=H)
    T(pg2, M, 40, p.member[4:], size=9)
    T(pg2, M, 60, "continued from previous page", size=8, font="heit")
    t.add("MEMBER", p.member, 1, probes=[
        {"kind": "text", "text": p.member[:4], "critical": True},
        {"kind": "text", "text": p.member[4:], "critical": False}])
    t.keep_it("continued from previous page")
    t.pages = 2
    return doc


def build_fake_redaction(rng, p: Person, t: Truth) -> pymupdf.Doc:
    """Black boxes and strikethroughs painted over live text: the classic fake."""
    doc = pymupdf.open()
    pg = doc.new_page(width=W, height=H)
    T(pg, M, 50, "NORTHWIND BANK", size=12, font="hebo")
    T(pg, M, 64, "Statement copy (as supplied by the customer)", size=9, font="heit")
    t.keep_it("NORTHWIND BANK", "Statement copy")

    T(pg, M, 120, f"Social Security Number: {p.ssn}", size=10)
    pg.draw_rect(pymupdf.Rect(M + 128, 112, M + 220, 124), color=None,
                 fill=(0, 0, 0))
    t.add("SSN", p.ssn, 0)

    T(pg, M, 150, f"Telephone: {p.phone}", size=10)
    pg.draw_line(pymupdf.Point(M + 66, 147), pymupdf.Point(M + 190, 147),
                 color=(0, 0, 0), width=1.4)
    t.add("PHONE", p.phone, 0)

    T(pg, M, 180, f"Account Holder: {p.name}", size=10)
    pg.draw_rect(pymupdf.Rect(M + 92, 172, M + 260, 186), color=None,
                 fill=(1, 1, 1))
    t.add("NAME", p.name, 0)

    T(pg, M, 210, f"Account {p.acct2}   E-mail {p.email}", size=10)
    pg.draw_rect(pymupdf.Rect(M + 50, 202, M + 175, 214), color=None, fill=(0.1, 0.1, 0.1))
    t.add("ACCT", p.acct2, 0)
    t.add("EMAIL", p.email, 0)

    para(pg, (M, 250, W - M, 320),
         "The copy above was redacted by the customer with a marker before being "
         "sent on. Ink on paper is not redaction: the glyphs are still in the "
         "file.", size=9)
    t.pages = 1
    return doc


def build_white_ink(rng, p: Person, t: Truth) -> pymupdf.Doc:
    """White-on-white text and 1.6 pt text: invisible on screen, present in the file."""
    doc = pymupdf.open()
    pg = doc.new_page(width=W, height=H)
    T(pg, M, 50, "SUMMIT MORTGAGE", size=12, font="hebo")
    T(pg, M, 64, "Loan estimate", size=9, font="heit")
    t.keep_it("SUMMIT MORTGAGE", "Loan estimate")
    T(pg, M, 110, "Borrower", size=9, font="hebo")
    T(pg, M + 90, 110, p.name, size=9, color=(1, 1, 1))           # white on white
    t.add("NAME", p.name, 0)
    T(pg, M, 130, "SSN", size=9, font="hebo")
    T(pg, M + 90, 130, p.ssn, size=9, color=(1, 1, 1))
    t.add("SSN", p.ssn, 0)
    T(pg, M, 150, "Loan", size=9, font="hebo")
    T(pg, M + 90, 150, p.acct2, size=9, color=(0.99, 0.99, 0.99))
    t.add("ACCT", p.acct2, 0)
    T(pg, M, 170, "Rate 6.25%  APR 6.41%  Term 30 years", size=9)
    t.keep_it("Rate 6.25%", "APR 6.41%", "Term 30 years")
    # 1.6 pt speck of text at the foot of the page
    T(pg, M, H - 20, f"{p.name} / {p.ssn} / {p.email}", size=1.6, color=(0.85, 0.85, 0.85))
    t.add("EMAIL", p.email, 0)
    t.pages = 1
    return doc


def build_unicode_names(rng, p: Person, t: Truth) -> pymupdf.Doc:
    """Accented names and addresses, embedded TrueType rather than base-14."""
    doc = pymupdf.open()
    pg = doc.new_page(width=W, height=H)
    pg.insert_font(fontname="dejavu", fontfile=UNICODE_FONT)
    name = "José Müller-Ångström"
    street = "Calle Ñandú 4480"
    city = "San José, CA 95110"
    T(pg, M, 50, "BANCO DEL SOL", size=12, font="hebo")
    t.keep_it("BANCO DEL SOL", "Customer record")
    T(pg, M, 64, "Customer record", size=9, font="heit")
    T(pg, M, 110, f"Customer Name: {name}", size=10, font="dejavu")
    T(pg, M, 130, f"Address: {street}, {city}", size=10, font="dejavu")
    T(pg, M, 150, "E-mail: jose.muller@example.org", size=10, font="dejavu")
    T(pg, M, 170, f"Telephone: {p.phone}", size=10, font="dejavu")
    t.add("NAME", name, 0, probes=[
        {"kind": "text", "text": name.lower(), "critical": True},
        {"kind": "text", "text": "müller", "critical": True},
        {"kind": "text", "text": "ångström", "critical": True}])
    t.add("ADDRESS", f"{street}, {city}", 0, probes=[
        {"kind": "text", "text": street.lower(), "critical": True},
        {"kind": "text", "text": "95110", "critical": True}])
    t.add("EMAIL", "jose.muller@example.org", 0)
    t.add("PHONE", p.phone, 0)
    para(pg, (M, 210, W - M, 280),
         "El cliente solicitó una copia de su expediente. Los datos anteriores "
         "deben permanecer en el archivo original únicamente.", size=9,
         font="dejavu")
    t.pages = 1
    return doc


def build_annotations(rng, p: Person, t: Truth) -> pymupdf.Doc:
    """PII in a free-text annotation, a sticky note and a form text field."""
    doc = pymupdf.open()
    pg = doc.new_page(width=W, height=H)
    T(pg, M, 50, "CASCADE CARD SERVICES", size=12, font="hebo")
    T(pg, M, 64, "Dispute form (annotated)", size=9, font="heit")
    t.keep_it("CASCADE CARD SERVICES", "Dispute form")

    pg.add_freetext_annot(pymupdf.Rect(M, 100, M + 330, 140),
                          f"Please verify SSN {p.ssn} before processing",
                          fontsize=9)
    t.add("SSN", p.ssn, 0)
    try:
        pg.add_text_annot(pymupdf.Point(M + 340, 110), f"call {p.phone} first",
                          icon="Comment")
        t.add("PHONE", p.phone, 0)
    except Exception:
        pass

    widget = pymupdf.Widget()
    widget.field_name = "cardholder_name"
    widget.field_type = pymupdf.PDF_WIDGET_TYPE_TEXT
    widget.rect = pymupdf.Rect(M, 160, M + 220, 182)
    widget.field_value = p.name
    widget.text_fontsize = 9
    pg.add_widget(widget)
    t.add("NAME", p.name, 0)

    widget2 = pymupdf.Widget()
    widget2.field_name = "member_id"
    widget2.field_type = pymupdf.PDF_WIDGET_TYPE_TEXT
    widget2.rect = pymupdf.Rect(M, 190, M + 220, 212)
    widget2.field_value = p.member
    widget2.text_fontsize = 9
    pg.add_widget(widget2)
    t.add("MEMBER", p.member, 0)

    T(pg, M, 250, "Cardholder name", size=8.5, font="hebo")
    T(pg, M, 280, "Member ID", size=8.5, font="hebo")
    t.pages = 1
    return doc


def build_bookmarks_attach(rng, p: Person, t: Truth) -> pymupdf.Doc:
    """PII in the outline, the XMP packet and an attached file."""
    doc = pymupdf.open()
    pg = doc.new_page(width=W, height=H)
    T(pg, M, 50, "TRAILHEAD STORES", size=12, font="hebo")
    T(pg, M, 64, "Account packet", size=9, font="heit")
    t.keep_it("TRAILHEAD STORES", "Account packet")
    para(pg, (M, 100, W - M, 200),
         "This packet contains the account summary, the signed agreement and the "
         "identity documents supplied with the application.", size=9)
    doc.set_toc([[1, f"{p.name} - SSN {p.ssn}", 1],
                 [1, "Account summary", 1]])
    t.add("NAME", p.name, 0)
    t.add("SSN", p.ssn, 0)
    try:
        doc.set_xml_metadata(
            '<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF '
            'xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
            '<rdf:Description xmlns:dc="http://purl.org/dc/elements/1.1/">'
            f"<dc:description><rdf:Alt><rdf:li>{p.ssn}</rdf:li></rdf:Alt>"
            f"</dc:description><dc:creator><rdf:Seq><rdf:li>{p.name}</rdf:li>"
            "</rdf:Seq></dc:creator></rdf:Description></rdf:RDF></x:xmpmeta>")
    except Exception:
        pass
    t.add("SSN", p.ssn, 0)
    try:
        doc.embfile_add("customer_notes.txt",
                        f"Name: {p.name}\nSSN: {p.ssn}\nPhone: {p.phone}\n"
                        .encode())
        t.add("SSN", p.ssn, 0)
        t.add("PHONE", p.phone, 0)
    except Exception:
        pass
    t.pages = 1
    return doc


def build_two_column(rng, p: Person, t: Truth) -> pymupdf.Doc:
    """Newspaper columns: labels in one column, values in the other."""
    doc = pymupdf.open()
    pg = doc.new_page(width=W, height=H)
    T(pg, M, 50, "THE RECORD GAZETTE", size=13, font="hebo")
    T(pg, M, 64, "Public notice - foreclosure", size=9, font="heit")
    t.keep_it("THE RECORD GAZETTE", "Public notice")
    left = (M, 90, 290, 520)
    right = (320, 90, 560, 520)
    para(pg, left,
         "NOTICE IS HEREBY GIVEN that the undersigned will sell at public auction "
         "the property described below. Borrower name and current address on "
         "file:", size=8.5)
    para(pg, right, f"{p.name}\n{p.street}\n{p.city_line}", size=8.5)
    t.add("NAME", p.name, 0)
    t.add("ADDRESS", p.full_address, 0)
    para(pg, (M, 540, 290, 700),
         "Social Security Number of record, per the affidavit:", size=8.5)
    T(pg, 320, 545, p.ssn, size=8.5)
    t.add("SSN", p.ssn, 0)
    para(pg, (320, 560, 560, 700),
         f"Loan {p.acct2}, dated 03/14/2019. Trustee may be reached at "
         f"{p.phone}.", size=8.5)
    t.add("ACCT", p.acct2, 0)
    t.add("PHONE", p.phone, 0)
    t.keep_it("03/14/2019")
    t.pages = 1
    return doc


def build_rotated_page(rng, p: Person, t: Truth) -> pymupdf.Doc:
    """The whole page is rotated 180 degrees; another block is set at 270 degrees."""
    doc = pymupdf.open()
    pg = doc.new_page(width=W, height=H)
    T(pg, M, 50, "ALDER CREDIT UNION", size=12, font="hebo")
    T(pg, M, 64, "Share account record", size=9, font="heit")
    t.keep_it("ALDER CREDIT UNION", "Share account record")
    for i, (label, value, cat) in enumerate([
            ("Member", p.name, "NAME"),
            ("SSN", p.ssn, "SSN"),
            ("Account", p.acct, "ACCT"),
            ("Phone", p.phone, "PHONE")]):
        T(pg, M, 110 + i * 20, f"{label}: {value}", size=9)
        t.add(cat, value, 0)
    T(pg, 585, 60, f"Branch copy - {p.email} - {p.member}", size=9, rotate=270)
    t.add("EMAIL", p.email, 0)
    t.add("MEMBER", p.member, 0)
    pg.set_rotation(180)
    t.pages = 1
    return doc


def build_noisy_scan(rng, p: Person, t: Truth) -> pymupdf.Doc:
    """A 120 dpi grey scan, skewed a degree and speckled."""
    src = pymupdf.open()
    sp = src.new_page(width=W, height=H)
    T(sp, M, 60, "COLDWATER MUTUAL", size=12, font="hebo",
      color=(0.35, 0.35, 0.35))
    T(sp, M, 80, f"Policy {p.policy}", size=9, color=(0.4, 0.4, 0.4))
    T(sp, M, 100, f"Insured: {p.name}", size=9, color=(0.4, 0.4, 0.4))
    T(sp, M, 118, f"SSN: {p.ssn}", size=9, color=(0.4, 0.4, 0.4))
    para(sp, (M, 140, W - M, 260),
         f"Coverage for the dwelling at {p.full_address}. Claims line "
         f"{p.phone}.", size=9, font="tiro")
    low = sp.get_pixmap(dpi=200).tobytes("jpeg", jpg_quality=75)

    mid = pymupdf.open()
    mp = mid.new_page(width=W, height=H)
    mp.insert_image(mp.rect, stream=low)
    for _ in range(90):
        x, y = rng.uniform(0, W), rng.uniform(0, H)
        mp.draw_circle(pymupdf.Point(x, y), 0.6, color=None,
                       fill=(0.55, 0.55, 0.55))
    noisy = mp.get_pixmap(dpi=200).tobytes("jpeg", jpg_quality=70)
    src.close()
    mid.close()

    doc = pymupdf.open()
    pg = doc.new_page(width=W, height=H)
    pg.insert_image(pg.rect, stream=noisy)
    pg.set_rotation(1)
    t.image(0, pg.rect, True)
    for cat, val in (("NAME", p.name), ("SSN", p.ssn), ("ADDRESS", p.full_address),
                     ("PHONE", p.phone), ("POLICY", p.policy)):
        t.add(cat, val, 0)
    t.pages = 1
    return doc


def build_dense_table(rng, p: Person, t: Truth) -> pymupdf.Doc:
    """Sixty rows at 6 pt: 240 cells of PII in one block of the page."""
    doc = pymupdf.open()
    pg = doc.new_page(width=W, height=H)
    T(pg, M, 40, "ATLAS STUDENT LOAN", size=11, font="hebo")
    T(pg, M, 52, "Portfolio extract", size=8, font="heit")
    t.keep_it("ATLAS STUDENT LOAN", "Portfolio extract")
    cols = [M, M + 150, M + 250, M + 360]
    for x, head in zip(cols, ("BORROWER", "SSN", "LOAN", "PHONE")):
        T(pg, x, 72, head, size=6, font="hebo")
    for i in range(60):
        y = 84 + i * 11.6
        name = f"{rng.choice(FIRST)} {rng.choice(LAST)}"
        ssn = f"{rng.randint(101,899)}-{rng.randint(10,99)}-{rng.randint(1000,9999)}"
        loan = f"L{rng.randint(10**7, 10**8 - 1)}"
        phone = f"(555) {rng.randint(200,999)}-{rng.randint(1000,9999)}"
        for x, val in zip(cols, (name, ssn, loan, phone)):
            T(pg, x, y, val, size=6)
        t.add("NAME", name, 0)
        t.add("SSN", ssn, 0)
        t.add("ACCT", loan, 0)
        t.add("PHONE", phone, 0)
    t.pages = 1
    return doc


def build_offscreen(rng, p: Person, t: Truth) -> pymupdf.Doc:
    """Text placed outside the crop box: invisible, still extractable."""
    doc = pymupdf.open()
    pg = doc.new_page(width=W, height=H)
    T(pg, M, 50, "PINEHURST SAVINGS", size=12, font="hebo")
    T(pg, M, 64, "Certificate of deposit advice", size=9, font="heit")
    t.keep_it("PINEHURST SAVINGS", "Certificate of deposit advice")
    para(pg, (M, 100, W - M, 180),
         f"Account holder {p.name}, certificate {p.acct2}, maturity 06/30/2024.",
         size=9)
    t.add("NAME", p.name, 0)
    t.add("ACCT", p.acct2, 0)
    t.keep_it("06/30/2024")
    # inside the media box but outside the crop box: a reader never sees it,
    # pdftotext reads it, so a copy that ignored the strip would leak
    T(pg, M, H - 6, f"Phone {p.phone}", size=9)
    t.add("PHONE", p.phone, 0)
    T(pg, M, H - 20, f"SSN {p.ssn}", size=9)
    t.add("SSN", p.ssn, 0)
    pg.set_cropbox(pymupdf.Rect(0, 0, W, H - 30))
    t.pages = 1
    return doc


def build_packed_fields(rng, p: Person, t: Truth) -> pymupdf.Doc:
    """Several fields on one line, with and without separators."""
    doc = pymupdf.open()
    pg = doc.new_page(width=W, height=H)
    T(pg, M, 50, "IRONWOOD ANALYTICS", size=12, font="hebo")
    T(pg, M, 64, "Intake summary", size=9, font="heit")
    t.keep_it("IRONWOOD ANALYTICS", "Intake summary")
    T(pg, M, 100, f"Name: {p.name}   SSN: {p.ssn}   DOB: {p.dob}", size=9)
    for cat, val in (("NAME", p.name), ("SSN", p.ssn), ("DOB", p.dob)):
        t.add(cat, val, 0)
    T(pg, M, 120, f"SSN:{p.ssn} ACCT:{p.acct2} TEL:{p.phone}", size=9)
    for cat, val in (("SSN", p.ssn), ("ACCT", p.acct2), ("PHONE", p.phone)):
        t.add(cat, val, 0)
    T(pg, M, 140, f"Verified: identity of {p.name} confirmed by {p.agent}",
      size=9)
    t.add("NAME", p.name, 0)
    t.add("NAME", p.agent, 0)
    # a partial: last four only
    T(pg, M, 170, f"SSN on file ends in {p.ssn[-4:]}; see sealed attachment.",
      size=9)
    t.add("SSN", p.ssn[-4:], 0, probes=[
        {"kind": "text", "text": p.ssn[-4:], "critical": False}])
    t.pages = 1
    return doc


TRICKY = {
    "tricky_split_values": build_split_values,
    "tricky_fake_redaction": build_fake_redaction,
    "tricky_white_ink": build_white_ink,
    "tricky_unicode": build_unicode_names,
    "tricky_annotations": build_annotations,
    "tricky_bookmarks_attach": build_bookmarks_attach,
    "tricky_two_column": build_two_column,
    "tricky_rotated_page": build_rotated_page,
    "tricky_noisy_scan": build_noisy_scan,
    "tricky_dense_table": build_dense_table,
    "tricky_offscreen": build_offscreen,
    "tricky_packed_fields": build_packed_fields,
}


# ---------------------------------------------------------------------------
# Image-only documents: no text layer anywhere, the ink is the document
# ---------------------------------------------------------------------------
# A QR code is a PNG of "SSN 616-37-4632" (segno, scale 5). Nothing in this
# pipeline decodes a barcode, so it is here to be counted as the known gap it is.
QR_PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAGkAAABpAQAAAAAR+TCXAAAAqklEQVR42s2UMQ4DIQwEl6Sg5An8"
    "5O5jJ4GUj8FP7gmUFCechTRJGdnFuUBysxqvF0O+K+MubQHgazuir5If+Km/WkilopfPo5VqiH5MNB"
    "spQp3dmUgVHLHvJl4NJAOv1gZHeAnUA66aVAYDtnT2DU/R2z6ownRyg2qqQpu8NBOqcEVsgYZVPVVm"
    "0PkHseupMqlmRJ1FROGaRUQpENcGbY4MB0xWab/ZQX4DW4GbuocGmCcAAAAASUVORK5CYII=")


def _raster_page(doc, img_bytes, width=None, height=None):
    """Put a whole scan on a page as the only content (no text layer)."""
    page = doc.new_page(width=width or W, height=height or H)
    page.insert_image(page.rect, stream=img_bytes)
    return page


def _scan_of(draw, dpi=200, jpeg=70, page_wh=(W, H)):
    """Render a drawn page to JPEG bytes: what a scanner would hand you."""
    src = pymupdf.open()
    sp = src.new_page(width=page_wh[0], height=page_wh[1])
    draw(sp)
    data = sp.get_pixmap(dpi=dpi).tobytes("jpeg", jpg_quality=jpeg)
    src.close()
    return data


def _body(sp, p: Person, heading="COLDWATER MUTUAL", size=9, color=(0, 0, 0)):
    T(sp, 72, 80, heading, size=14, font="hebo", color=color)
    T(sp, 72, 104, f"Policy {p.policy}", size=size, color=color)
    T(sp, 72, 122, f"Insured: {p.name}", size=size, color=color)
    T(sp, 72, 140, f"SSN: {p.ssn}", size=size, color=color)
    T(sp, 72, 158, f"Address: {p.street}, {p.city_line}", size=size, color=color)
    T(sp, 72, 176, f"Telephone {p.phone}", size=size, color=color)
    T(sp, 72, 194, "Premium $184.22   Term 12 months", size=size, color=color)


def build_image_photo(rng, p: Person, t: Truth) -> pymupdf.Doc:
    """A photograph of a page: skewed, shadowed, warm cast."""
    raw = _scan_of(lambda sp: _body(sp, p), dpi=150, jpeg=80)
    mid = pymupdf.open()
    mp = mid.new_page(width=W, height=H)
    mp.insert_image(pymupdf.Rect(6, 6, W - 6, H - 6), stream=raw)
    for i in range(40):                     # shadow gradient down the page
        y = i * (H / 40)
        mp.draw_rect(pymupdf.Rect(0, y, W, y + H / 40), color=None,
                     fill=(0, 0, 0), fill_opacity=0.02 * (i / 40))
    mp.draw_rect(mp.rect, color=None, fill=(1.0, 0.94, 0.84), fill_opacity=0.18)
    for _ in range(60):
        mp.draw_circle(pymupdf.Point(rng.uniform(0, W), rng.uniform(0, H)), 0.8,
                       color=None, fill=(0.5, 0.5, 0.5), fill_opacity=0.25)
    photo = mp.get_pixmap(dpi=200).tobytes("jpeg", jpg_quality=72)
    mid.close()

    doc = pymupdf.open()
    pg = _raster_page(doc, photo)
    pg.set_rotation(1.4)                    # the sheet was not square to the lens
    t.image(0, pg.rect, True)
    for cat, val in (("NAME", p.name), ("SSN", p.ssn), ("ADDRESS", p.full_address),
                     ("PHONE", p.phone), ("POLICY", p.policy)):
        t.add(cat, val, 0)
    t.pages = 1
    return doc


def _rotated_scan(rng, p, t, rotate: int, name: str):
    raw = _scan_of(lambda sp: _body(sp, p))
    if rotate in (90, 270):
        doc = pymupdf.open()
        pg = doc.new_page(width=H, height=W)
        pg.insert_image(pg.rect, stream=raw, rotate=rotate)
    else:
        doc = pymupdf.open()
        pg = doc.new_page(width=W, height=H)
        pg.insert_image(pg.rect, stream=raw, rotate=rotate)
    t.image(0, pg.rect, True)
    for cat, val in (("NAME", p.name), ("SSN", p.ssn), ("ADDRESS", p.full_address),
                     ("PHONE", p.phone), ("POLICY", p.policy)):
        t.add(cat, val, 0)
    t.pages = 1
    return doc


def build_image_rot90(rng, p: Person, t: Truth) -> pymupdf.Doc:
    """A sheet fed sideways: the ink is upright only at 90 degrees."""
    return _rotated_scan(rng, p, t, 90, "rot90")


def build_image_rot180(rng, p: Person, t: Truth) -> pymupdf.Doc:
    """A sheet fed upside down."""
    return _rotated_scan(rng, p, t, 180, "rot180")


def build_image_rot270(rng, p: Person, t: Truth) -> pymupdf.Doc:
    """The other sideways."""
    return _rotated_scan(rng, p, t, 270, "rot270")


def build_image_fax(rng, p: Person, t: Truth) -> pymupdf.Doc:
    """A fax: 120 dpi, thin ink, streaks."""
    raw = _scan_of(lambda sp: _body(sp, p, color=(0.25, 0.25, 0.25)), dpi=120,
                   jpeg=35)
    mid = pymupdf.open()
    mp = mid.new_page(width=W, height=H)
    mp.insert_image(mp.rect, stream=raw)
    for _ in range(14):                     # fax streaks
        y = rng.uniform(0, H)
        mp.draw_line(pymupdf.Point(0, y), pymupdf.Point(W, y + rng.uniform(-3, 3)),
                     color=(0.6, 0.6, 0.6), width=0.4)
    fax = mp.get_pixmap(dpi=140).tobytes("jpeg", jpg_quality=45)
    mid.close()
    doc = pymupdf.open()
    pg = _raster_page(doc, fax)
    t.image(0, pg.rect, True)
    for cat, val in (("NAME", p.name), ("SSN", p.ssn), ("ADDRESS", p.full_address),
                     ("PHONE", p.phone), ("POLICY", p.policy)):
        t.add(cat, val, 0)
    t.pages = 1
    return doc


def build_image_lowcontrast(rng, p: Person, t: Truth) -> pymupdf.Doc:
    """Beige paper, pale ink: a scan of a photocopy of a fax."""
    def draw(sp):
        sp.draw_rect(sp.rect, color=None, fill=(0.95, 0.92, 0.84))
        _body(sp, p, color=(0.62, 0.62, 0.62), size=10)
    raw = _scan_of(draw, dpi=180, jpeg=65)
    doc = pymupdf.open()
    pg = _raster_page(doc, raw)
    t.image(0, pg.rect, True)
    for cat, val in (("NAME", p.name), ("SSN", p.ssn), ("ADDRESS", p.full_address),
                     ("PHONE", p.phone), ("POLICY", p.policy)):
        t.add(cat, val, 0)
    t.pages = 1
    return doc


def build_image_watermark(rng, p: Person, t: Truth) -> pymupdf.Doc:
    """A big diagonal watermark laid over the content."""
    def draw(sp):
        _body(sp, p)
        sp.insert_text((70, 470), "CONFIDENTIAL - COPY", fontsize=54, fontname="hebo",
                       color=(0.86, 0.86, 0.86),
                       morph=(pymupdf.Point(70, 470), pymupdf.Matrix(-38)))
        sp.insert_text((140, 600), "DO NOT DISTRIBUTE", fontsize=30, fontname="hebo",
                       color=(0.88, 0.88, 0.88),
                       morph=(pymupdf.Point(140, 600), pymupdf.Matrix(-38)))
    raw = _scan_of(draw, dpi=190, jpeg=70)
    doc = pymupdf.open()
    pg = _raster_page(doc, raw)
    t.image(0, pg.rect, True)
    for cat, val in (("NAME", p.name), ("SSN", p.ssn), ("ADDRESS", p.full_address),
                     ("PHONE", p.phone), ("POLICY", p.policy)):
        t.add(cat, val, 0)
    t.pages = 1
    return doc


def build_image_stamp(rng, p: Person, t: Truth) -> pymupdf.Doc:
    """A rubber stamp struck across the SSN line."""
    def draw(sp):
        _body(sp, p)
        sp.draw_rect(pymupdf.Rect(60, 118, 330, 168), color=(0.7, 0.1, 0.1), width=2)
        T(sp, 80, 155, "PAID 09/22/2023", size=22, font="hebo", color=(0.7, 0.1, 0.1))
    raw = _scan_of(draw, dpi=190, jpeg=70)
    doc = pymupdf.open()
    pg = _raster_page(doc, raw)
    t.image(0, pg.rect, True)
    for cat, val in (("NAME", p.name), ("SSN", p.ssn), ("ADDRESS", p.full_address),
                     ("PHONE", p.phone), ("POLICY", p.policy)):
        t.add(cat, val, 0)
    t.keep_it("PAID 09/22/2023")
    t.pages = 1
    return doc


def build_image_two_column(rng, p: Person, t: Truth) -> pymupdf.Doc:
    """A scanned newspaper notice: two columns, PII on the right."""
    def draw(sp):
        T(sp, 72, 70, "THE RECORD GAZETTE", size=18, font="hebo")
        T(sp, 72, 88, "Public notice", size=9, font="heit")
        para(sp, (72, 110, 290, 500),
             "NOTICE IS HEREBY GIVEN that the undersigned trustee will sell at "
             "public auction the property described in the deed of trust. "
             "Bidders must register in advance with the trustee's office.",
             size=8.5, font="tiro")
        para(sp, (320, 110, 540, 260),
             f"Borrower of record: {p.name}", size=8.5, font="tiro")
        para(sp, (320, 270, 540, 420),
             f"Property: {p.full_address}\nLoan number {p.acct2}\n"
             f"Trustee: {p.phone}", size=8.5, font="tiro")
    raw = _scan_of(draw, dpi=200, jpeg=72)
    doc = pymupdf.open()
    pg = _raster_page(doc, raw)
    t.image(0, pg.rect, True)
    for cat, val in (("NAME", p.name), ("ADDRESS", p.full_address),
                     ("ACCT", p.acct2), ("PHONE", p.phone)):
        t.add(cat, val, 0)
    t.pages = 1
    return doc


def build_image_idcard(rng, p: Person, t: Truth) -> pymupdf.Doc:
    """A photographed ID card filling the page: colour, tiny type, an MRZ-ish strip."""
    def draw(sp):
        sp.draw_rect(sp.rect, color=None, fill=(0.86, 0.89, 0.93))
        sp.draw_rect(pymupdf.Rect(40, 40, W - 40, H - 40), color=(0.2, 0.3, 0.5),
                     fill=(0.97, 0.97, 0.99), width=2)
        T(sp, 60, 80, "STATE IDENTIFICATION CARD", size=14, font="hebo",
          color=(0.2, 0.3, 0.5))
        sp.draw_rect(pymupdf.Rect(60, 100, 220, 260), color=None, fill=(0.75, 0.75, 0.78))
        T(sp, 70, 180, "PHOTO", size=12, font="hebo", color=(0.4, 0.4, 0.45))
        T(sp, 250, 120, f"DL {p.dl}", size=10, font="cour")
        T(sp, 250, 145, p.last.upper(), size=14, font="hebo")
        T(sp, 250, 165, p.first.upper(), size=12)
        T(sp, 250, 190, f"DOB {p.dob}", size=9)
        T(sp, 250, 210, f"SSN {p.ssn}", size=9)
        T(sp, 250, 230, p.street, size=9)
        T(sp, 250, 248, p.city_line, size=9)
        T(sp, 60, 300, f"{p.dl}<<{p.last.upper()}<<{p.first.upper()}<<{p.dob}", size=8,
          font="cour")
    raw = _scan_of(draw, dpi=190, jpeg=75)
    doc = pymupdf.open()
    pg = _raster_page(doc, raw)
    t.image(0, pg.rect, True)
    for cat, val in (("NAME", p.name), ("NAME", f"{p.last} {p.first}"),
                     ("SSN", p.ssn), ("DOB", p.dob), ("ADDRESS", p.full_address),
                     ("DL", p.dl)):
        t.add(cat, val, 0)
    t.pages = 1
    return doc


def build_image_mrz(rng, p: Person, t: Truth) -> pymupdf.Doc:
    """A passport data page: printed fields plus two machine-readable lines."""
    last = p.last.upper().replace("'", "")
    first = p.first.upper().replace("-", "<")
    mrz1 = f"P<USA{last}<<{first}" + "<" * max(0, 44 - len(last) - len(first) - 6)
    mrz2 = f"{p.passport.ljust(9, '<')}USA{p.dob_y % 100:02d}{p.dob_m:02d}{p.dob_d:02d}" \
           f"{'F'}20301231<<<<<<<<<<<<<<06"

    def draw(sp):
        T(sp, 72, 70, "UNITED STATES OF AMERICA", size=13, font="hebo")
        T(sp, 72, 88, "PASSPORT", size=10, font="heit")
        T(sp, 72, 120, f"Surname: {p.last}", size=10)
        T(sp, 72, 138, f"Given names: {p.first}", size=10)
        T(sp, 72, 156, f"Passport No: {p.passport}", size=10)
        T(sp, 72, 174, f"Date of birth: {p.dob}", size=10)
        T(sp, 72, 192, f"Place of birth: {p.city}, USA", size=10)
        T(sp, 40, 640, mrz1[:44], size=9, font="cour")
        T(sp, 40, 656, mrz2[:44], size=9, font="cour")
    raw = _scan_of(draw, dpi=200, jpeg=70)
    doc = pymupdf.open()
    pg = _raster_page(doc, raw)
    t.image(0, pg.rect, True)
    for cat, val in (("NAME", p.name), ("PASSPORT", p.passport), ("DOB", p.dob),
                     ("ADDRESS", f"{p.city}, USA")):
        t.add(cat, val, 0)
    t.add("NAME", last, 0, probes=[{"kind": "text", "text": last.lower(),
                                    "critical": True}])
    t.pages = 1
    return doc


def build_image_handwriting(rng, p: Person, t: Truth) -> pymupdf.Doc:
    """A signed form: printed body, the signature written in italic script."""
    def draw(sp):
        _body(sp, p)
        T(sp, 72, 330, "Signature of insured:", size=9, font="hebo")
        T(sp, 72, 380, p.name, size=26, font="tiit", color=(0.1, 0.1, 0.35))
        T(sp, 72, 400, "Date: 09/22/2023", size=9)
    raw = _scan_of(draw, dpi=200, jpeg=75)
    doc = pymupdf.open()
    pg = _raster_page(doc, raw)
    t.image(0, pg.rect, True)
    for cat, val in (("NAME", p.name), ("SSN", p.ssn), ("ADDRESS", p.full_address),
                     ("PHONE", p.phone), ("POLICY", p.policy)):
        t.add(cat, val, 0)
    t.keep_it("Signature of insured:", "Date: 09/22/2023")
    t.pages = 1
    return doc


def build_image_qr(rng, p: Person, t: Truth) -> pymupdf.Doc:
    """A barcode: the SSN is in the pixels and nothing in this pipeline decodes it."""
    qr = base64.b64decode(QR_PNG_B64)

    def draw(sp):
        _body(sp, p)
        sp.insert_image(pymupdf.Rect(380, 380, 520, 520), stream=qr)
        T(sp, 380, 540, "Scan to verify", size=8)
    raw = _scan_of(draw, dpi=200, jpeg=80)
    doc = pymupdf.open()
    pg = _raster_page(doc, raw)
    t.image(0, pg.rect, True)
    for cat, val in (("NAME", p.name), ("SSN", p.ssn), ("PHONE", p.phone)):
        t.add(cat, val, 0)
    # known gap: nothing here reads a QR code, so this is reported, not failed
    t.add("SSN", "616-37-4632", 0, probes=[
        {"kind": "text", "text": "616-37-4632", "critical": False}])
    t.pages = 1
    return doc


def build_image_email(rng, p: Person, t: Truth) -> pymupdf.Doc:
    """A screenshot of an email: header block, quoted body, grey rule."""
    def draw(sp):
        sp.draw_rect(sp.rect, color=None, fill=(0.98, 0.98, 0.98))
        T(sp, 60, 70, "Subject: Your account documents", size=11, font="hebo")
        T(sp, 60, 90, f"From: {p.name} <{p.email}>", size=9)
        T(sp, 60, 106, "To: support@coldwater.example", size=9)
        T(sp, 60, 122, "Date: 22 September 2023 at 09:14", size=9)
        sp.draw_line(pymupdf.Point(60, 136), pymupdf.Point(560, 136),
                     color=(0.7, 0.7, 0.7), width=0.8)
        para(sp, (60, 150, 560, 330),
             "Hello,\n\nPlease find my details below for the claim. My social "
             f"security number is {p.ssn} and the policy is {p.policy}. You can "
             f"reach me on {p.phone}.\n\nThanks,\n{p.name}", size=9.5, font="tiro")
        sp.draw_rect(pymupdf.Rect(60, 340, 62, 420), color=None, fill=(0.8, 0.8, 0.8))
        T(sp, 72, 360, f"Member ID {p.member}", size=9)
    raw = _scan_of(draw, dpi=200, jpeg=78)
    doc = pymupdf.open()
    pg = _raster_page(doc, raw)
    t.image(0, pg.rect, True)
    for cat, val in (("NAME", p.name), ("SSN", p.ssn), ("EMAIL", p.email),
                     ("PHONE", p.phone), ("POLICY", p.policy), ("MEMBER", p.member)):
        t.add(cat, val, 0)
    t.pages = 1
    return doc


IMAGES = {
    "image_photo": build_image_photo,
    "image_rot90": build_image_rot90,
    "image_rot180": build_image_rot180,
    "image_rot270": build_image_rot270,
    "image_fax": build_image_fax,
    "image_lowcontrast": build_image_lowcontrast,
    "image_watermark": build_image_watermark,
    "image_stamp": build_image_stamp,
    "image_two_column": build_image_two_column,
    "image_idcard": build_image_idcard,
    "image_mrz": build_image_mrz,
    "image_handwriting": build_image_handwriting,
    "image_qr": build_image_qr,
    "image_email": build_image_email,
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
    which = "normal"
    if "--count" in argv:
        count = int(argv[argv.index("--count") + 1])
    if "--seed" in argv:
        seed = int(argv[argv.index("--seed") + 1])
    if "--set" in argv:
        which = argv[argv.index("--set") + 1]
    registry = {"normal": BUILDERS, "tricky": TRICKY, "images": IMAGES,
                "mixed": {**BUILDERS, **TRICKY, **IMAGES}}.get(which)
    if registry is None:
        print(f"!! --set must be normal, tricky, images or mixed (got {which})",
              file=sys.stderr)
        return 1

    docs_dir = out / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)
    for old in docs_dir.glob("*.pdf"):
        old.unlink()

    rng = random.Random(seed)
    kinds = list(registry)
    truths = []
    for i in range(count):
        kind = kinds[i % len(kinds)] if i < len(kinds) else rng.choice(kinds)
        person = Person(rng)
        name = f"{i:02d}_{kind}.pdf"
        truth = Truth(name, kind, seed * 1000 + i)
        doc = registry[kind](rng, person, truth)
        path = docs_dir / name
        doc.save(path)
        doc.close()
        hash_images(path, truth)
        truth.name = name
        truths.append(truth.__dict__)
        print(f"  {name:<34} {truth.pages}p values={len(truth.values)} "
              f"imgs={len(truth.images)} keep={len(truth.keep)}")

    (out / "truth.json").write_text(json.dumps(
        {"seed": seed, "count": count, "set": which, "docs": truths}, indent=1))
    total_values = sum(len(d["values"]) for d in truths)
    print(f"\n{count} documents, {total_values} planted values -> {out / 'truth.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
