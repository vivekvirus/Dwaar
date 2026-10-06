#!/usr/bin/env python3
"""Build the small SYNTHETIC scaffolds for the PRD 11.3 sets that M1 features touch, plus placeholders for the sets that are not M1.

HONEST SCOPE: the real sets need hundreds of reviewed items per language, annotated by people (PRD 11.3 'keep held-out sets and measure
annotator agreement'). What exists here:
* classification (AI-F01): 27 tickets per language, labelled by the build team (NOT independent annotators: agreement not measured);
* voice (AI-R02): location-resolution cases against a fixed unit directory: the resolver is deterministic code, so this is a real test of it
  (a wrong block or flat is a CRITICAL error). There are no recordings: ASR was never run;
* translation (AI-R07): notices with the automatic checks that need no reviewer (numbers kept, legal/safety text flagged); meaning preservation
  needs bilingual reviewers and is NOT measured;
* groundedness, ocr, matching: placeholders (not M1 features), so the runner lists them honestly as 'not built'.
Every file carries ``annotator_agreement`` with ``status: not_measured``.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

HERE = Path(__file__).resolve().parent
rng = random.Random(20261009)
AGREE = {
    "annotators": 1,
    "method": "single author (build team)",
    "cohens_kappa": None,
    "status": "not_measured",
}

TICKETS = {
    "plumbing": {
        "en": [
            "Water leaking from the pipe under the kitchen sink",
            "The tap in the bathroom is leaking all day",
            "Drain is blocked and sewage smell near the toilet",
        ],
        "hi": [
            "रसोई के सिंक के नीचे पाइप से पानी लीक हो रहा है",
            "बाथरूम का नल पूरे दिन टपक रहा है",
            "नाली जाम है और टॉयलेट के पास बदबू आ रही है",
        ],
        "mr": [
            "स्वयंपाकघरातील पाईपमधून पाणी गळती होत आहे",
            "बाथरूमचा नळ दिवसभर गळत आहे",
            "नाली तुंबली आहे आणि शौचालयाजवळ दुर्गंधी आहे",
        ],
    },
    "electrical": {
        "en": [
            "The switch board in the living room is not working",
            "Wiring near the meter box looks loose",
            "Power cut only in my flat since morning",
        ],
        "hi": [
            "बैठक की स्विच बोर्ड काम नहीं कर रही",
            "मीटर बॉक्स के पास तार ढीले दिख रहे हैं",
            "सुबह से सिर्फ मेरे फ्लैट में बिजली नहीं है",
        ],
        "mr": [
            "हॉलमधील स्विच बोर्ड चालत नाही",
            "मीटर बॉक्सजवळ तार सैल दिसत आहेत",
            "सकाळपासून फक्त माझ्या फ्लॅटमध्ये वीज नाही",
        ],
    },
    "lift": {
        "en": [
            "Lift is making a grinding noise",
            "The lift door does not close properly",
            "Lift stops between floors sometimes",
        ],
        "hi": [
            "लिफ्ट से घिसने की आवाज आ रही है",
            "लिफ्ट का दरवाज़ा ठीक से बंद नहीं होता",
            "लिफ्ट कभी कभी बीच में रुक जाती है",
        ],
        "mr": [
            "लिफ्टमधून घासल्याचा आवाज येतो",
            "लिफ्टचा दरवाजा नीट बंद होत नाही",
            "लिफ्ट कधी कधी मध्येच थांबते",
        ],
    },
    "parking": {
        "en": [
            "A stranger's car is parked in my slot",
            "Visitor parking is always full of resident bikes",
            "Parking line markings have faded",
        ],
        "hi": [
            "मेरी पार्किंग जगह पर किसी की गाड़ी खड़ी है",
            "विज़िटर पार्किंग हमेशा बाइक से भरी रहती है",
            "पार्किंग की लाइनें मिट गई हैं",
        ],
        "mr": [
            "माझ्या पार्किंगच्या जागी दुसऱ्याची गाडी उभी आहे",
            "पाहुण्यांची पार्किंग नेहमी बाईकने भरलेली असते",
            "पार्किंगच्या रेषा पुसल्या आहेत",
        ],
    },
    "housekeeping": {
        "en": [
            "Garbage is not collected from the dustbin",
            "The staircase cleaning has not happened this week",
            "Dirty floor near the lobby",
        ],
        "hi": [
            "डस्टबिन से कचरा नहीं उठाया गया",
            "इस हफ्ते सीढ़ियों की सफाई नहीं हुई",
            "लॉबी के पास फर्श गंदा है",
        ],
        "mr": [
            "कचरा कुंडीतून कचरा उचलला गेला नाही",
            "या आठवड्यात जिन्याची स्वच्छता झाली नाही",
            "लॉबीजवळ फरशी घाणेरडी आहे",
        ],
    },
    "noise": {
        "en": [
            "Loud music from the party next door at midnight",
            "Construction noise continues after 9 pm",
            "Neighbours shouting and noise every night",
        ],
        "hi": [
            "आधी रात को पड़ोस की पार्टी में तेज़ संगीत",
            "रात 9 बजे के बाद भी निर्माण का शोर",
            "हर रात पड़ोसियों का शोर",
        ],
        "mr": [
            "मध्यरात्री शेजारच्या पार्टीत मोठे संगीत",
            "रात्री ९ नंतरही बांधकामाचा गोंगाट",
            "दररोज रात्री शेजाऱ्यांचा आवाज",
        ],
    },
    "civil": {
        "en": [
            "A crack has appeared in the bedroom wall",
            "Paint is peeling and seepage on the ceiling",
            "Tiles in the passage wall are loose",
        ],
        "hi": [
            "शयनकक्ष की दीवार में दरार आ गई है",
            "छत पर पेंट उखड़ रहा है और सीलन है",
            "गलियारे की दीवार की टाइलें ढीली हैं",
        ],
        "mr": [
            "बेडरूमच्या भिंतीला तडा गेला आहे",
            "छतावर रंग उखडत आहे आणि ओलावा आहे",
            "पॅसेजच्या भिंतीच्या फरशा सैल आहेत",
        ],
    },
    "security": {
        "en": [
            "A stranger entered the building without the guard noticing",
            "Gate light is off and security is lax",
            "Theft of a bicycle from the podium",
        ],
        "hi": [
            "एक अजनबी गार्ड के बिना देखे इमारत में घुस गया",
            "गेट की लाइट बंद है और सुरक्षा ढीली है",
            "पोडियम से साइकिल की चोरी हुई",
        ],
        "mr": [
            "एक अनोळखी व्यक्ती गार्डला न दिसता इमारतीत शिरली",
            "गेटचा दिवा बंद आहे आणि सुरक्षा ढिसाळ आहे",
            "पोडियममधून सायकलची चोरी झाली",
        ],
    },
}
EMERGENCY = {
    "en": [
        "There is smoke and fire in the electrical room",
        "Strong gas smell in the corridor",
        "Someone is stuck in the lift",
    ],
    "hi": ["बिजली के कमरे में धुआं और आग है", "गलियारे में गैस की तेज़ गंध है", "कोई लिफ्ट में फंस गया है"],
    "mr": ["इलेक्ट्रिक रूममध्ये धूर आणि आग आहे", "कॉरिडॉरमध्ये गॅसचा तीव्र वास आहे", "कोणीतरी लिफ्टमध्ये अडकले आहे"],
}
EM_CAT = {
    "en": ["electrical", "other", "lift"],
    "hi": ["electrical", "other", "lift"],
    "mr": ["electrical", "other", "lift"],
}

cls = []
for lang in ("en", "hi", "mr"):
    for cat, per in TICKETS.items():
        for t in per[lang]:
            cls.append(
                {
                    "id": f"cls-{len(cls) + 1:04d}",
                    "lang": lang,
                    "text": t,
                    "category": cat,
                    "emergency": False,
                }
            )
    for t, c in zip(EMERGENCY[lang], EM_CAT[lang], strict=True):
        cls.append(
            {
                "id": f"cls-{len(cls) + 1:04d}",
                "lang": lang,
                "text": t,
                "category": c,
                "emergency": True,
            }
        )
(HERE / "classification" / "cases.json").write_text(
    json.dumps(
        {
            "set": "classification-synthetic-v0",
            "prd_minimum": "500 labelled tickets per language",
            "gate": "macro-F1 >= 0.90; emergency false negatives reviewed separately",
            "status": f"scaffold: {len(cls)} of 1500 cases authored; labelled by the build team; circular for the simulator (same author as its rules)",
            "annotator_agreement": AGREE,
            "cases": cls,
        },
        ensure_ascii=False,
        indent=1,
    )
    + "\n",
    encoding="utf-8",
)

DIRECTORY = [["A", "101"], ["A", "102"], ["B", "402"], ["B", "403"]]
voice = []
V = [
    ("en", "Water is leaking in flat B-402 bathroom pipe", "B-402"),
    ("en", "my flat 402 in B wing has a power cut", "B-402"),
    ("en", "lift is making noise", "common:lift"),
    ("en", "garbage near the lobby is not cleared", "common:lobby"),
    ("en", "leak in A 101 kitchen", "A-101"),
    ("en", "tap leaking in flat 405 in B wing", "UNRESOLVED"),
    ("en", "noise from C-301 every night", "UNRESOLVED"),
    ("hi", "बी-४०२ के बाथरूम में पाइप से पानी लीक हो रहा है", "B-402"),
    ("hi", "४०२ बी विंग में बिजली नहीं है", "B-402"),
    ("hi", "लॉबी में कचरा पड़ा है", "common:lobby"),
    ("hi", "फ्लैट ए १०१ में नल टपक रहा है", "A-101"),
    ("hi", "डी-२०१ में शोर है", "UNRESOLVED"),
    ("mr", "बी-४०२ मध्ये पाईप गळत आहे", "B-402"),
    ("mr", "४०२ बी विंग मध्ये वीज नाही", "B-402"),
    ("mr", "पार्किंगमध्ये गाडी उभी आहे", "common:parking"),
    ("mr", "ए १०१ मध्ये नळ गळतो", "A-101"),
    ("mr", "सी-३०१ मध्ये गोंगाट आहे", "UNRESOLVED"),
    ("en", "Water leaking in flat 402", "UNRESOLVED"),
    ("en", "pipe burst in A-102 and B-403 both", "UNRESOLVED"),
]
for lang, text, exp in V:
    voice.append(
        {"id": f"voice-{len(voice) + 1:04d}", "lang": lang, "transcript": text, "expected": exp}
    )
(HERE / "voice" / "cases.json").write_text(
    json.dumps(
        {
            "set": "voice-location-synthetic-v0",
            "prd_minimum": "100 recordings per language across noise and accents",
            "gate": ">=95% correct critical fields after confirmation; raw extraction accuracy reported separately; a wrong block or flat is a CRITICAL error",
            "status": "scaffold: TRANSCRIPTS ONLY (no recordings, ASR never run). Tests the deterministic location resolver and the simulator extractor.",
            "directory": DIRECTORY,
            "authorised_units_of_caller": ["A-101", "B-402"],
            "annotator_agreement": AGREE,
            "cases": voice,
        },
        ensure_ascii=False,
        indent=1,
    )
    + "\n",
    encoding="utf-8",
)

NOTICES = [
    (
        "en",
        "Water supply will be off on 12/10 from 10 am to 2 pm for tank cleaning. Please store water.",
        False,
    ),
    (
        "en",
        "As per the bye-law a penalty of 500 rupees applies to late maintenance payment after 15/10.",
        True,
    ),
    (
        "en",
        "Fire safety drill will be held on Sunday at 11 am. Everyone must evacuate using the stairs.",
        True,
    ),
    ("en", "The clubhouse will be closed for painting from 20/10 to 22/10.", False),
    ("hi", "टैंक की सफाई के लिए 12/10 को सुबह 10 से दोपहर 2 बजे तक पानी बंद रहेगा।", False),
    ("hi", "उपनियम के अनुसार 15/10 के बाद देर से भुगतान पर 500 रुपये का जुर्माना लगेगा।", True),
    ("mr", "टाकी स्वच्छतेसाठी १२/१० रोजी सकाळी १० ते दुपारी २ पाणी बंद राहील.", False),
    ("mr", "उपविधीनुसार १५/१० नंतर उशिरा भरणा केल्यास ५०० रुपये दंड लागेल.", True),
]
(HERE / "translation" / "cases.json").write_text(
    json.dumps(
        {
            "set": "translation-synthetic-v0",
            "prd_minimum": "200 notices per language pair",
            "gate": ">=95% meaning preservation by bilingual reviewers",
            "status": "scaffold: 8 notices; automatic checks only (numbers preserved, legal/safety flagged). MEANING PRESERVATION IS NOT MEASURED (needs bilingual reviewers).",
            "annotator_agreement": AGREE | {"annotators": 0},
            "cases": [
                {
                    "id": f"tr-{i + 1:04d}",
                    "lang": lang,
                    "text": t,
                    "legal_or_safety": f,
                    "reviewer_scores": [],
                }
                for i, (lang, t, f) in enumerate(NOTICES)
            ],
        },
        ensure_ascii=False,
        indent=1,
    )
    + "\n",
    encoding="utf-8",
)

for name, prd, gate, why in [
    (
        "groundedness",
        "300 authorised questions plus 100 absent or conflicting cases",
        ">=95% supported answers; >=95% correct abstention",
        "AI-R01 grounded Q&A is M2",
    ),
    (
        "ocr",
        "200 varied redacted vendor bills; 100 IDs and RCs",
        ">=98% exact key fields; 100% arithmetic checks; uncertain fields surfaced",
        "AI-A01/AI-G04 OCR is M2",
    ),
    (
        "matching",
        "500 labelled matched and ambiguous records",
        "top-3 recall >=95%; no autonomous ambiguous posting",
        "AI-A02 reconciliation is M2",
    ),
]:
    (HERE / name / "cases.json").write_text(
        json.dumps(
            {
                "set": f"{name}-placeholder",
                "prd_minimum": prd,
                "gate": gate,
                "status": f"NOT BUILT: {why}; no cases authored",
                "annotator_agreement": AGREE | {"annotators": 0},
                "cases": [],
            },
            ensure_ascii=False,
            indent=1,
        )
        + "\n",
        encoding="utf-8",
    )
print("sets written")
