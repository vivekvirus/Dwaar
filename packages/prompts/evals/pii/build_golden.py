#!/usr/bin/env python3
"""Build the SYNTHETIC Indian-identifier PII golden set (PRD 11.3 'PII redaction: 500 samples', AI-SYS-05, PRIV-14).

HONESTY / PROVENANCE
* Every identifier is invented. Phone numbers use fictional prefixes (99999 00xxx, 88888 00xxx, 77777 00xxx, 66666 00xxx),
  never a real subscriber range. Aadhaar, PAN, GSTIN, account and plate values are random strings in the right SHAPE; some
  Aadhaar values carry a valid Verhoeff check digit and some do not (typos are real). No real person is described.
* This generator and its output were written BEFORE the redactor existed and are pinned by MANIFEST.json (sha256). They must
  NOT be edited to fit the redactor. If the redactor misses something, the redactor is fixed and the miss is reported; if the
  set must grow, publish a NEW version (golden_v2.jsonl) and keep v1's numbers.
* The set is deterministic (seed in MANIFEST.json).

Sample = {id, lang, text, spans: [{type, start, end, value}], decoys: [{kind, start, end, value}]}.
``spans`` are identifiers that MUST be tokenised; ``decoys`` look similar but are NOT personal identifiers (amounts, dates, unit
labels, invoice numbers, OTP-like numbers, PIN codes, UTR/reference numbers ...) and must NOT be tokenised.

Usage: python build_golden.py [--out golden.jsonl]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import string
from pathlib import Path

SEED = 20261006
GENERATOR_VERSION = 1
N_SAMPLES = 500
HERE = Path(__file__).resolve().parent

_DEVA = str.maketrans("0123456789", "०१२३४५६७८९")
STATE_CODES = [f"{i:02d}" for i in range(1, 38)]
RTO = [
    "MH12",
    "MH14",
    "MH01",
    "KA01",
    "KA05",
    "DL01",
    "GJ01",
    "TN09",
    "UP32",
    "RJ14",
    "MH43",
    "MH04",
]
BANKS = ["HDFC", "SBIN", "ICIC", "UTIB", "PUNB", "KKBK", "BARB", "CNRB"]
EMAIL_USERS = [
    "asha.kulkarni",
    "r.deshmukh",
    "meera_p",
    "sunil.more",
    "joshi.family",
    "neha.s1988",
    "ops-desk",
]
EMAIL_DOMAINS = ["example.in", "example.com", "mailbox.example.org", "test.example.co.in"]
PHONE_PREFIX = ["99999", "88888", "77777", "66666"]


def verhoeff_check(digits: str) -> str:
    d = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],
         [5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]]  # fmt: skip
    p = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],
         [4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]  # fmt: skip
    inv = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = d[c][p[(i + 1) % 8][int(ch)]]
    return str(inv[c])


class Gen:
    def __init__(self, rng: random.Random) -> None:
        self.r = rng

    def digits(self, n: int, first: str = "0123456789") -> str:
        return self.r.choice(first) + "".join(self.r.choice(string.digits) for _ in range(n - 1))

    # ---- identifiers: each returns (canonical value as it appears in text, type)
    def phone(self) -> str:
        r = self.r
        core = r.choice(PHONE_PREFIX) + "0" + self.digits(4)
        form = r.choice(
            [
                "plain",
                "plus91",
                "plus91sp",
                "zero",
                "split55",
                "hyph",
                "dotted",
                "plus91hyph",
                "paren",
                "91",
            ]
        )
        if form == "plain":
            return core
        if form == "plus91":
            return "+91" + core
        if form == "plus91sp":
            return f"+91 {core[:5]} {core[5:]}"
        if form == "zero":
            return "0" + core
        if form == "split55":
            return f"{core[:5]} {core[5:]}"
        if form == "hyph":
            return f"{core[:5]}-{core[5:]}"
        if form == "dotted":
            return f"{core[:3]}.{core[3:6]}.{core[6:]}"
        if form == "plus91hyph":
            return f"+91-{core[:5]}-{core[5:]}"
        if form == "paren":
            return f"(+91) {core[:5]} {core[5:]}"
        return "91" + core

    def aadhaar(self) -> str:
        r = self.r
        base = self.digits(11, "23456789")
        num = base + (verhoeff_check(base) if r.random() < 0.6 else r.choice(string.digits))
        form = r.choice(["plain", "sp", "hy", "sp"])
        if form == "plain":
            return num
        sep = " " if form == "sp" else "-"
        return sep.join([num[:4], num[4:8], num[8:]])

    def pan(self) -> str:
        r = self.r
        s = "".join(r.choice(string.ascii_uppercase) for _ in range(3)) + r.choice("PCHFATBLJG")
        s += r.choice(string.ascii_uppercase) + self.digits(4) + r.choice(string.ascii_uppercase)
        form = r.choice(["plain", "plain", "lower", "spaced"])
        if form == "lower":
            return s.lower()
        if form == "spaced":
            return f"{s[:5]} {s[5:9]} {s[9]}"
        return s

    def gstin(self) -> str:
        r = self.r
        pan = (
            "".join(r.choice(string.ascii_uppercase) for _ in range(3))
            + r.choice("PCHFATBLJG")
            + r.choice(string.ascii_uppercase)
            + self.digits(4)
            + r.choice(string.ascii_uppercase)
        )
        s = (
            r.choice(STATE_CODES)
            + pan
            + r.choice("123456789")
            + "Z"
            + r.choice(string.digits + string.ascii_uppercase)
        )
        return s.lower() if r.random() < 0.1 else s

    def account(self) -> str:
        n = self.r.choice([9, 10, 11, 12, 14, 15, 16, 18])
        num = self.digits(n, "123456789")
        if n >= 12 and self.r.random() < 0.3:
            return f"{num[:4]} {num[4:8]} {num[8:]}"
        return num

    def ifsc(self) -> str:
        r = self.r
        return (
            r.choice(BANKS)
            + "0"
            + "".join(r.choice(string.ascii_uppercase + string.digits) for _ in range(6))
        )

    def email(self) -> str:
        return f"{self.r.choice(EMAIL_USERS)}{self.r.choice(['', str(self.r.randint(1, 99))])}@{self.r.choice(EMAIL_DOMAINS)}"

    def plate(self) -> str:
        r = self.r
        form = r.choice(["plain", "space", "hyph", "single", "bh"])
        rto = r.choice(RTO)
        series = "".join(r.choice(string.ascii_uppercase) for _ in range(r.choice([1, 2])))
        num = f"{r.randint(1, 9999):04d}"
        if form == "plain":
            return f"{rto}{series}{num}"
        if form == "space":
            return f"{rto[:2]} {rto[2:]} {series} {num}"
        if form == "hyph":
            return f"{rto[:2]}-{rto[2:]}-{series}-{num}"
        if form == "single":
            return f"{rto} {series} {num}"
        return f"{r.randint(21, 29)}BH{num}{''.join(r.choice(string.ascii_uppercase) for _ in range(2))}"

    # ---- decoys
    def decoy(self) -> tuple[str, str]:
        r = self.r
        kind = r.choice(["amount", "amount_lakh", "date", "date_deva", "unit", "invoice", "ticket", "pin", "otp", "utr",
                         "year", "qty", "percent", "time", "flat_deva", "count"])  # fmt: skip
        if kind == "amount":
            return kind, r.choice(
                [
                    f"₹{r.randint(100, 99999):,}",
                    f"Rs. {r.randint(100, 99999):,}",
                    f"₹{r.randint(100, 9999)}.50",
                ]
            )
        if kind == "amount_lakh":
            return kind, f"₹{r.randint(1, 99)},{r.randint(10, 99)},{r.randint(100, 999)}"
        if kind == "date":
            return kind, f"{r.randint(1, 28):02d}/{r.randint(1, 12):02d}/2026"
        if kind == "date_deva":
            return kind, f"{r.randint(1, 28):02d}-{r.randint(1, 12):02d}-2026".translate(_DEVA)
        if kind == "unit":
            return kind, f"{r.choice('ABCDE')}-{r.randint(101, 1204)}"
        if kind == "invoice":
            return kind, f"INV-2026-{r.randint(1, 999999):06d}"
        if kind == "ticket":
            return kind, f"TKT-{r.randint(1000000, 9999999)}"
        if kind == "pin":
            return kind, f"{r.choice(['4110', '4000', '5600', '1100'])}{r.randint(10, 99)}"
        if kind == "otp":
            return kind, "".join(r.choice(string.digits) for _ in range(6))
        if kind == "utr":
            return kind, f"UTR {r.choice('23456789')}{self.digits(11)}"
        if kind == "year":
            return kind, f"FY {r.randint(2019, 2027)}-{r.randint(20, 28)}"
        if kind == "qty":
            return kind, f"{r.randint(1, 500)}.{r.randint(0, 9)} kL"
        if kind == "percent":
            return kind, f"{r.randint(1, 18)}.{r.randint(0, 9)}%"
        if kind == "time":
            return kind, f"{r.randint(1, 12):02d}:{r.randint(0, 59):02d} PM"
        if kind == "flat_deva":
            return kind, f"{r.choice('ABC')}-{r.randint(101, 804)}".translate(_DEVA)
        return kind, f"{r.randint(2, 40)} members"


# context templates; {0},{1},{2} are slots for identifiers. lang -> list of (kinds, template)
T_EN = [
    ("phone", "Please call me on {0} before the plumber comes."),
    ("phone", "My number is {0}, WhatsApp is fine."),
    ("aadhaar", "Aadhaar no. {0} was shown at the office for verification."),
    ("pan", "PAN: {0} is on the vendor invoice."),
    ("gstin", "Vendor GSTIN {0} is printed on the bill."),
    ("account,ifsc", "Transfer to A/c no {0}, IFSC {1}."),
    ("email", "Send the receipt to {0} please."),
    ("plate", "The tanker with plate {0} is waiting at gate 2."),
    ("phone,email", "Contact: {0} / {1}"),
    ("plate,phone", "Vehicle {0}, driver phone {1}"),
    ("pan,gstin", "Society PAN {0}, GSTIN {1}"),
    ("phone,aadhaar,plate", "Visitor {2} came in car, ID {1}, phone {0}"),
    ("account", "Bank account number {0} for the refund."),
]
T_HI = [
    ("phone", "कृपया मुझे {0} पर कॉल करें, प्लंबर आने वाला है।"),
    ("phone", "मेरा मोबाइल नंबर {0} है।"),
    ("aadhaar", "आधार संख्या {0} कार्यालय में जमा की गई।"),
    ("pan", "विक्रेता का पैन {0} बिल पर छपा है।"),
    ("gstin", "जीएसटी नंबर {0} बिल पर दिया है।"),
    ("account,ifsc", "खाता क्र. {0} में पैसे डालें, आईएफएससी {1}।"),
    ("email", "रसीद {0} पर भेज दें।"),
    ("plate", "वाहन नंबर {0} गेट पर खड़ा है।"),
    ("phone,email", "संपर्क: {0} और {1}"),
    ("plate,phone", "गाड़ी {0}, ड्राइवर का फोन {1}"),
    ("phone,aadhaar", "फोन {0} और आधार {1} दर्ज किया गया।"),
]
T_MR = [
    ("phone", "कृपया मला {0} वर फोन करा, प्लंबर येणार आहे."),
    ("phone", "माझा मोबाईल नंबर {0} आहे."),
    ("aadhaar", "आधार क्रमांक {0} कार्यालयात दिला."),
    ("pan", "विक्रेत्याचा पॅन {0} बिलावर आहे."),
    ("gstin", "जीएसटी क्रमांक {0} बिलावर छापलेला आहे."),
    ("account,ifsc", "खाते क्र. {0} मध्ये पैसे जमा करा, आयएफएससी {1}."),
    ("email", "पावती {0} वर पाठवा."),
    ("plate", "वाहन क्रमांक {0} गेटवर थांबले आहे."),
    ("phone,plate", "फोन {0}, गाडी {1}"),
    ("phone,email", "संपर्क: {0} आणि {1}"),
]
DECOY_EN = [
    "The maintenance of {0} is due on {1}.",
    "Ticket {0} about the lift in {1} was closed.",
    "Total payable {0} for {1}.",
    "Please quote {0} at the office, ref {1}.",
    "Water used {0} against {1} last month.",
]
DECOY_HI = ["{0} का रखरखाव शुल्क {1} तक देय है।", "टिकट {0} लिफ्ट {1} के बारे में बंद हुआ।", "कुल देय {0}, {1}।"]
DECOY_MR = [
    "{0} ची देखभाल फी {1} पर्यंत देय आहे.",
    "तिकीट {0} लिफ्ट {1} बद्दल बंद झाले.",
    "एकूण देय {0}, {1}.",
]


def build(seed: int = SEED) -> list[dict[str, object]]:
    rng = random.Random(seed)
    g = Gen(rng)
    samples: list[dict[str, object]] = []
    langs = ["en", "hi", "mr"]
    for i in range(N_SAMPLES):
        lang = langs[i % 3] if i % 7 else rng.choice(langs)
        deva_digits = lang != "en" and rng.random() < 0.35
        mixed_code = (
            rng.random() < 0.15
        )  # a Hindi/Marathi sentence carrying an English-style clause
        decoy_only = i % 5 == 4  # 100 samples have no identifier at all
        if decoy_only:
            tmpl = rng.choice({"en": DECOY_EN, "hi": DECOY_HI, "mr": DECOY_MR}[lang])
            items: list[tuple[str, str, str]] = []
            for _ in range(2):
                k, v = g.decoy()
                items.append(("decoy", k, v))
            samples.append(_assemble(i, lang, tmpl, items, deva_digits))
            continue
        kinds, tmpl = rng.choice(
            {"en": T_EN, "hi": T_HI, "mr": T_MR}[lang if not mixed_code else "en"]
            if mixed_code
            else {"en": T_EN, "hi": T_HI, "mr": T_MR}[lang]
        )  # noqa: E501
        items = []
        for kind in kinds.split(","):
            items.append(("id", kind, getattr(g, kind)()))
        # a third of identifier samples also carry a decoy sentence (the redactor must leave it alone)
        if rng.random() < 0.35:
            k, v = g.decoy()
            tmpl = (
                tmpl
                + " "
                + {"en": "Amount {%d}.", "hi": "राशि {%d}।", "mr": "रक्कम {%d}."}[
                    lang if not mixed_code else "en"
                ]
                % len(items)
            )
            items.append(("decoy", k, v))
        samples.append(_assemble(i, lang, tmpl, items, deva_digits))
    return samples


def _deva(value: str) -> str:
    return value.translate(_DEVA)


def _assemble(
    i: int, lang: str, tmpl: str, items: list[tuple[str, str, str]], deva_digits: bool
) -> dict[str, object]:
    # Devanagari digits only for digit-only identifier kinds (phone, aadhaar, account) and the decoys that are numbers
    values: list[str] = []
    for role, kind, value in items:
        v = value
        if deva_digits and (kind in {"phone", "aadhaar", "account", "amount", "pin", "otp", "qty"}):
            v = _deva(v)
        values.append(v)
    text = ""
    spans: list[dict[str, object]] = []
    decoys: list[dict[str, object]] = []
    pos = 0
    out = []
    import re

    for m in re.finditer(r"\{(\d+)\}", tmpl):
        out.append(tmpl[pos : m.start()])
        text_so_far = "".join(out)
        idx = int(m.group(1))
        role, kind, _ = items[idx]
        v = values[idx]
        start = len(text_so_far)
        out.append(v)
        rec = {"start": start, "end": start + len(v), "value": v}
        if role == "id":
            spans.append({"type": kind, **rec})
        else:
            decoys.append({"kind": kind, **rec})
        pos = m.end()
    out.append(tmpl[pos:])
    text = "".join(out)
    for s in [*spans, *decoys]:
        assert text[int(s["start"]) : int(s["end"])] == s["value"]  # type: ignore[call-overload]
    return {
        "id": f"pii-{i:04d}",
        "lang": lang,
        "devanagari_digits": deva_digits,
        "text": text,
        "spans": spans,
        "decoys": decoys,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(HERE / "golden.jsonl"))
    ap.add_argument(
        "--seed",
        type=int,
        default=SEED,
        help="another seed = another, unseen sample (v1 uses the default)",
    )
    args = ap.parse_args()
    samples = build(args.seed)
    body = "".join(json.dumps(s, ensure_ascii=False, sort_keys=True) + "\n" for s in samples)
    Path(args.out).write_text(body, encoding="utf-8")
    per_type: dict[str, int] = {}
    for s in samples:
        for sp in s["spans"]:  # type: ignore[attr-defined]
            per_type[sp["type"]] = per_type.get(sp["type"], 0) + 1
    manifest = {
        "set": "pii-golden-v1",
        "samples": len(samples),
        "identifier_spans": sum(per_type.values()),
        "per_type": dict(sorted(per_type.items())),
        "decoys": sum(len(s["decoys"]) for s in samples),  # type: ignore[arg-type]
        "seed": args.seed,
        "generator_version": GENERATOR_VERSION,
        "sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        "synthetic": True,
        "authored_before_redactor": True,
        "note": "Frozen. Do not edit to fit the redactor; publish golden_v2 instead (see build_golden.py).",
    }
    manifest_name = "MANIFEST.json" if args.seed == SEED else Path(args.out).stem + ".manifest.json"
    Path(args.out).with_name(manifest_name).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
