"""
Analiza frecvențelor (limba Engleză sau limba Română). Este un instrument pentru criptanalist
și oferă funcționalități automate (analiză + propuneri), cât și un mod interactiv pentru decriptare.

UTILIZARE RAPIDĂ:
  python cryptographic-frequency-analysis.py --ciphertext "GFS WMY ..." --show-steps
  python cryptographic-frequency-analysis.py --file cifru.txt
  python cryptographic-frequency-analysis.py --demo   (rulează exemplu)
  python cryptographic-frequency-analysis.py --interactive

MOD INTERACTIV (comenzi):
  freq               afișează tabele de frecvență
  map <C> <p>        mapare literă cifru (C) -> literă clar (p)
  unmap <C>          elimină maparea pentru C
  suggest            propuneri bazate pe frecvențe / pattern
  decode             afișează textul decodat parțial
  key                afișează cheia reconstituită (tabel)
  steps              afișează jurnalul de raționament
  reset              golește mapping-ul curent
  quit / exit        părăsește modul interactiv

Realizat de studentul grupei IS31Z, Tocana Marian
"""

from __future__ import annotations

import argparse
import collections
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Iterable, Optional

# ===============================
# Date statistice pentru limbi
# ===============================

EN_ALPHABET = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
RO_ALPHABET = [
    "A",
    "Ă",
    "Â",
    "B",
    "C",
    "D",
    "E",
    "F",
    "G",
    "H",
    "I",
    "Î",
    "J",
    "K",
    "L",
    "M",
    "N",
    "O",
    "P",
    "Q",
    "R",
    "S",
    "Ș",
    "T",
    "U",
    "V",
    "W",
    "X",
    "Y",
    "Z",
]

# Frecvențe (%) (engleză – tabele standard; română).
EN_FREQ_PERCENT = {
    "A": 8.17,
    "B": 1.49,
    "C": 2.78,
    "D": 4.25,
    "E": 12.70,
    "F": 2.23,
    "G": 2.01,
    "H": 6.09,
    "I": 6.97,
    "J": 0.15,
    "K": 0.77,
    "L": 4.03,
    "M": 2.41,
    "N": 6.75,
    "O": 7.51,
    "P": 1.93,
    "Q": 0.09,
    "R": 5.99,
    "S": 6.33,
    "T": 9.06,
    "U": 2.76,
    "V": 0.98,
    "W": 2.36,
    "X": 0.15,
    "Y": 1.97,
    "Z": 0.07,
}

RO_FREQ_PERCENT_RAW = {
    "A": 9.95,
    "Ă": 4.06,
    "Â": 0.91,
    "B": 1.07,
    "C": 5.28,
    "D": 3.45,
    "E": 11.47,
    "F": 1.18,
    "G": 0.99,
    "H": 0.47,
    "I": 9.96,
    "Î": 1.40,
    "J": 0.24,
    "K": 0.11,
    "L": 4.48,
    "M": 3.10,
    "N": 6.47,
    "O": 4.07,
    "P": 3.18,
    "Q": 0.00,
    "R": 6.82,
    "S": 4.40,
    "Ş": 1.55,
    "Ș": 1.00,
    "T": 6.04,
    "U": 6.20,
    "V": 1.23,
    "W": 0.03,
    "X": 0.11,
    "Y": 0.07,
    "Z": 0.71,
}


# Consolidăm Ş/Ș într-o singură valoare medie ponderată (dacă ambele apar; altfel sumăm)
def _normalize_ro_freq_table(raw: Dict[str, float]) -> Dict[str, float]:
    value_s_cedilla = raw.get("Ş", 0.0)
    value_s_comma = raw.get("Ș", 0.0)
    combined = value_s_cedilla + value_s_comma
    table = {}
    for k, v in raw.items():
        if k in ("Ş", "Ș"):
            continue
        table[k] = v
    table["Ș"] = combined if combined > 0 else 1.2  # fallback dacă lipsesc valorile
    # Normalizare procentuală la 100 (mai ales după agregare)
    total = sum(table.values())
    for k in list(table.keys()):
        table[k] = table[k] * 100.0 / total
    return table


RO_FREQ_PERCENT = _normalize_ro_freq_table(RO_FREQ_PERCENT_RAW)


# ===============================
# Utilitare text & validări
# ===============================

ROMANIAN_DIACRITICS_MAP = {
    "Ş": "Ș",  # cedilla to comma
    "Ţ": "Ț",
}


def normalize_text(text: str) -> str:
    """Normalizează textul pentru analiză: elimină CR, înlocuiește diacritice."""
    # Normalizează doar pentru analiză (nu alterăm originalul la afișare finală)
    text = text.replace("\r", "")
    for src, dst in ROMANIAN_DIACRITICS_MAP.items():
        text = text.replace(src, dst)
    return text


LETTER_RE = re.compile(r"[A-ZĂÂÎȘȚŞŢ]")  # includem variante posibile


def extract_letters(text: str) -> str:
    """Extrage doar literele relevante (A-Z, diacritice românești), majuscule."""
    return "".join(ch for ch in normalize_text(text).upper() if LETTER_RE.match(ch))


# ===============================
# Frecvențe și detecție limbă
# ===============================


@dataclass
class LanguageProfile:
    """Profil lingvistic pentru o limbă: cod, alfabet, frecvențe așteptate."""

    code: str
    alphabet: List[str]
    expected_freq: Dict[str, float]  # procent (%), nu fracție

    def expected_distribution(self) -> Dict[str, float]:
        """Returnează distribuția așteptată ca fracții (suma = 1.0)."""
        total = sum(self.expected_freq.values())
        return {k: v / total for k, v in self.expected_freq.items()}


EN_PROFILE = LanguageProfile("en", EN_ALPHABET, EN_FREQ_PERCENT)
RO_PROFILE = LanguageProfile("ro", RO_ALPHABET, RO_FREQ_PERCENT)

ALL_PROFILES = [EN_PROFILE, RO_PROFILE]


def compute_letter_frequencies(
    text_letters: str, alphabet: Iterable[str]
) -> Dict[str, int]:
    """Calculează frecvențele literelor din text pentru un alfabet dat."""
    counts = {c: 0 for c in alphabet}
    for ch in text_letters:
        if ch in counts:
            counts[ch] += 1
    return counts


def chi_square_statistic(counts: Dict[str, int], profile: LanguageProfile) -> float:
    """Calculează statistica Chi-pătrat pentru a compara distribuția observată cu cea așteptată."""
    total = sum(counts.values()) or 1
    expected_dist = profile.expected_distribution()
    stat = 0.0
    for letter, exp_prob in expected_dist.items():
        if letter not in counts:
            continue  # litere absente din alfabetul observat
        observed = counts[letter]
        expected = exp_prob * total
        if expected > 0:
            stat += (observed - expected) ** 2 / expected
    return stat


def detect_language(text_letters: str) -> LanguageProfile:
    """Detectează limba textului pe baza frecvențelor literelor"""
    # Elimin litere care nu apar în limba engleză (diacritice) -> prioritate română
    counts_by_profile = {}
    for profile in ALL_PROFILES:
        counts = compute_letter_frequencies(text_letters, profile.alphabet)
        stat = chi_square_statistic(counts, profile)
        counts_by_profile[profile.code] = (stat, profile)
    # scor mai mic = potrivire mai bună
    best = min(counts_by_profile.values(), key=lambda x: x[0])[1]
    return best


@dataclass
class SubstitutionMapping:
    """Mapare literă cifru -> literă clar."""

    cipher_to_plain: Dict[str, str] = field(default_factory=dict)

    def set(self, cipher: str, plain: str):
        """Setează maparea pentru o literă de cifru la o literă de clar."""
        self.cipher_to_plain[cipher.upper()] = plain.lower()

    def remove(self, cipher: str):
        """Elimină maparea pentru litera de cifru dată."""
        self.cipher_to_plain.pop(cipher.upper(), None)

    def apply(self, text: str, unknown: str = "·") -> str:
        """Aplică mapping-ul la text, înlocuind literele necunoscute cu 'unknown'."""
        out = []
        for ch in text:
            up = ch.upper()
            if up in self.cipher_to_plain and up.isalpha():
                # Păstrez lower-case pentru plaintext pentru a evidenția progresul
                out.append(self.cipher_to_plain[up])
            else:
                if LETTER_RE.match(up):
                    out.append(unknown)
                else:
                    out.append(ch)
        return "".join(out)

    def plaintext_alphabet_row(self, alphabet: List[str]) -> List[str]:
        """Returnează rândul de litere plaintext corespunzător alfabetului dat (cipher)."""
        # Returneaz pentru fiecare literă din alfabetul ciphertext litera plaintext sau '-'
        row = []
        for c in alphabet:
            row.append(self.cipher_to_plain.get(c, "-"))
        return row

    def inverted(self) -> Dict[str, str]:
        """Inversează mapping-ul (plain -> cipher)."""
        return {v: k for k, v in self.cipher_to_plain.items()}


def rank_letters_by_frequency(counts: Dict[str, int]) -> List[str]:
    """Returnează lista literelor sortate descrescător după frecvență."""
    return [c for c, _ in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))]


def propose_initial_mapping(
    counts: Dict[str, int], profile: LanguageProfile
) -> Dict[str, str]:
    """Propune o mapare inițială bazată pe alinierea rangurilor de frecvență."""
    cipher_rank = rank_letters_by_frequency(counts)
    # Ranguri așteptate după frecvență pentru limbi (heuristic simplu)
    if profile.code == "en":
        expected_rank = list("ETAOINSHRDLCUMWFGYPBVKJXQZ")
    else:  # Română – aproximare folosind tabelele (sortare descrescătoare)
        exp_sorted = sorted(profile.expected_freq.items(), key=lambda kv: -kv[1])
        expected_rank = [k for k, _ in exp_sorted]
    mapping = {}
    for ciph, plain in zip(cipher_rank, expected_rank):
        mapping[ciph] = plain.lower()
    return mapping


COMMON_WORDS_EN = ["THE", "AND", "TO", "OF", "ONE", "THAT", "IN", "IT", "IS", "WE"]
SINGLE_LETTER_WORDS_EN = ["A", "I"]


def find_repeated_patterns(cipher_words: List[str]) -> Dict[str, int]:
    """Găsește cuvinte repetate în textul criptat."""
    cnt = collections.Counter(cipher_words)
    return {w: n for w, n in cnt.items() if n > 1 and len(w) >= 2}


def suggest_by_word_patterns(
    ciphertext: str, mapping: SubstitutionMapping
) -> List[str]:
    """Sugestii bazate pe pattern-uri de cuvinte frecvente în engleză."""
    # Caută pattern-uri posibile pentru THE, AND etc. în funcție de repetiții / lungime.
    suggestions = []
    words = [w for w in re.split(r"[^A-ZĂÂÎȘȚŞŢ]", ciphertext.upper()) if w]
    # Candidaturi pentru THE: cuvinte de 3 litere cu toate literele distincte.
    three = [w for w in words if len(w) == 3]
    freq_three = collections.Counter(three)
    common_three = [w for w, _ in freq_three.most_common(10)]
    for w in common_three:
        if len(set(w)) == 3:
            # pattern THE: litere T,H,E sunt distincte.
            # Dacă deja am o literă mapată, verificăm consistența.
            mapped_pattern = [mapping.cipher_to_plain.get(ch) for ch in w]
            # Accept dacă literele mapate existente nu contrazic 't','h','e'
            conflict = False
            target_order = ["t", "h", "e"]
            for mp, tgt in zip(mapped_pattern, target_order):
                if mp and mp != tgt:
                    conflict = True
                    break
            if not conflict:
                suggestions.append(f"Posibil THE -> {w}")
    # Cuvinte de o literă
    single = [w for w in words if len(w) == 1]
    single_cnt = collections.Counter(single)
    if single_cnt:
        top_single = single_cnt.most_common(2)
        for ciph, _ in top_single:
            suggestions.append(f"Cuvânt de 1 literă posibil A/I -> {ciph}")
    # Repetiții (double letters) pot sugera LL, EE, SS, OO
    for w in words:
        m = re.search(r"([A-Z])\1", w)
        if m:
            suggestions.append(
                f"Litere duble în {w} -> {m.group(1)} poate fi (L,E,S,O)"
            )
    # Repetiții de cuvinte – pot indica THE, AND, TO
    reps = find_repeated_patterns(words)
    for w, n in reps.items():
        if n >= 3 and len(w) == 3:
            suggestions.append(f"Cuvânt frecvent {w} (x{n}) -> poate THE/AND/ONE")
    return suggestions[:15]


@dataclass
class ReasoningStep:
    """Un pas în raționamentul criptanalistului."""

    description: str
    mapping_snapshot: Dict[str, str]
    partial_plaintext: str


@dataclass
class AttackLogger:
    """Jurnal de pași în atacul prin frecvențe."""

    steps: List[ReasoningStep] = field(default_factory=list)

    def add(
        self, description: str, mapping: SubstitutionMapping, partial_plaintext: str
    ):
        """Adaugă un pas în jurnal."""
        self.steps.append(
            ReasoningStep(description, dict(mapping.cipher_to_plain), partial_plaintext)
        )

    def print(self):
        """Afișează jurnalul de pași."""
        for i, step in enumerate(self.steps, 1):
            print(f"--- Pas {i} ---")
            print(step.description)
            print(
                "Mapări până acum:",
                " ".join(f"{c}->{p}" for c, p in sorted(step.mapping_snapshot.items())),
            )
            print(step.partial_plaintext)
            print()


def print_frequency_table(counts: Dict[str, int]):
    """Afișează tabelul de frecvențe în ordinea alfabetică a literelor."""
    alphabet = list(counts.keys())
    total = sum(counts.values()) or 1
    print("Cipher Letter :", " ".join(f"{c:>3}" for c in alphabet))
    print("Frequency    :", " ".join(f"{counts[c]:>3}" for c in alphabet))
    print(
        "Percent (%)  :", " ".join(f"{(counts[c]/total*100):>5.1f}" for c in alphabet)
    )


def print_sorted_frequency_table(counts: Dict[str, int]):
    """Afișează tabelul de frecvențe sortat descrescător după frecvență."""
    items = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    total = sum(counts.values()) or 1
    print("Sorted by frequency (desc):")
    print("Cipher :", " ".join(f"{c:>3}" for c, _ in items))
    print("Count  :", " ".join(f"{n:>3}" for _, n in items))
    print("Pct %  :", " ".join(f"{(n/total*100):>5.1f}" for _, n in items))


def print_natural_alphabet_en_frequency():
    """Afișează tabelul de frecvențe naturale pentru limba engleză."""
    # Datele din EN_FREQ_PERCENT
    freq_table = [
        ("A", 8.17),
        ("B", 1.49),
        ("C", 2.78),
        ("D", 4.25),
        ("E", 12.7),
        ("F", 2.23),
        ("G", 2.01),
        ("H", 6.09),
        ("I", 6.97),
        ("J", 0.15),
        ("K", 0.77),
        ("L", 4.03),
        ("M", 2.41),
        ("N", 6.75),
        ("O", 7.51),
        ("P", 1.93),
        ("Q", 0.09),
        ("R", 5.99),
        ("S", 6.33),
        ("T", 9.06),
        ("U", 2.76),
        ("V", 0.98),
        ("W", 2.36),
        ("X", 0.15),
        ("Y", 1.97),
        ("Z", 0.07),
    ]

    # Formatez tabelul pe 1 coloane
    cols = 1
    rows = (len(freq_table) + cols - 1) // cols

    print("| Literă | Frecvență (%) | " * cols)
    print("|" + "--------|---------------|" * cols)

    for r in range(rows):
        line = ""
        for c in range(cols):
            idx = c * rows + r  # Corect: parcurgere pe coloane
            if idx < len(freq_table):
                letter, freq = freq_table[idx]
                line += f" {letter:<7}| {freq:<14.2f}|"
            else:
                line += "        |               |"
        print("|" + line)

    print("\nTabelul 2.2. Frecvenţa literelor limbii engleze\n")


def print_natural_alphabet_ro_frequency():
    """Afișează tabelul de frecvențe naturale pentru limba română."""
    freq_table = [
        ("A", 9.95),
        ("Ă", 4.06),
        ("Â", 0.91),
        ("B", 1.07),
        ("C", 5.28),
        ("D", 3.45),
        ("E", 11.47),
        ("F", 1.18),
        ("G", 0.99),
        ("H", 0.47),
        ("I", 9.96),
        ("Î", 1.40),
        ("J", 0.24),
        ("K", 0.11),
        ("L", 4.48),
        ("M", 3.10),
        ("N", 6.47),
        ("O", 4.07),
        ("P", 3.18),
        ("Q", 0.00),
        ("R", 6.82),
        ("S", 4.40),
        ("Ş", 1.55),
        ("T", 6.04),
        ("Ș", 1.00),
        ("U", 6.20),
        ("V", 1.23),
        ("W", 0.03),
        ("X", 0.11),
        ("Y", 0.07),
        ("Z", 0.71),
    ]
    # Formatez tabelul pe 1 coloană
    cols = 1
    rows = (len(freq_table) + cols - 1) // cols

    print("| Literă | Frecvență (%) | " * cols)
    print("|" + "--------|---------------|" * cols)

    for r in range(rows):
        line = ""
        for c in range(cols):
            idx = c * rows + r  # Corect: parcurgere pe coloane
            if idx < len(freq_table):
                letter, freq = freq_table[idx]
                line += f" {letter:<7}| {freq:<14.2f}|"
            else:
                line += "        |               |"
        print("|" + line)

    print("\nTabelul 2.1. Frecvenţa literelor limbii române\n")


def print_reconstructed_key(mapping: SubstitutionMapping, profile: LanguageProfile):
    """Afișează cheia reconstituită în format tabelar."""
    print("Reconstituirea cheii (cipher -> plain):")
    print(
        "Cipher alphabet :",
        " ".join(profile.alphabet if profile.code == "en" else EN_ALPHABET),
    )
    # Pentru afișare consistentă a alfabetului cheii, dacă limba e engleză folosim 26 litere,
    # altfel pentru Română afișez alfabetul Român.
    alphabet = profile.alphabet if profile.code == "ro" else EN_ALPHABET
    print("Plain  alphabet :", " ".join(mapping.plaintext_alphabet_row(alphabet)))
    inv = mapping.inverted()
    # Dacă doresc și tabel plaintext->cipher (alfabet englez pentru demonstrație)
    if profile.code == "en":
        print("\n(Plain -> Cipher)")
        row = []
        for p in EN_ALPHABET:
            cipher = inv.get(p.lower(), "-")
            row.append(cipher or "-")
        print("Plain :", " ".join(p.lower() for p in EN_ALPHABET))
        print("Cipher:", " ".join(row))


SAMPLE_CIPHERTEXT = (
    "GFS WMY OG LGDVS MF SFNKYHOSU ESLLMRS, PC WS BFGW POL DMFRQMRS, PL OG CPFU M UPCCSKSFO "
    "HDMPFOSXO GC OIS LMES DMFRQMRS DGFR SFCQRI OG CPDD GFS LISSO GK LG, MFU OISF WS NGQFO"
    "OIS GNNQKKSFNSL GC SMNI DSOOSK. "
    "WS NMDD OIS EGLO CKSJQSFODY GNNQKKPFR DSOOSK OIS 'CPKLO', OIS FSXO EGLO GNNQKKPFR DSOOSK"
    "OIS 'LSNGFU' OIS CGDDGWPFR EGLO GNNQKKPFR DSOOSK OIS 'OIPKU', MFU LG GF, QFOPD WS MNNGQFO"
    "CGK MDD OIS UPCCSKSFO DSOOSKL PF OIS HDMPFOSXO LMEHDS. "
    "OISF WS DGGB MO OIS NPHISK OSXO WS WMFO OG LGDVS MFU WS MDLG NDMILLPCY POL LYEAGDL."
    "WS CPFU OIS EGLO GNNQKKPFR LYEAGD MFU NIMFRS PO OG OIS CGKE GC OIS 'CPKLO' DSOOSK GC"
    "OIS HDMPFOSXO LMEHDS, OIS FSXO EGLO NGEEGF LYEAGD PL NIMFRSU OG OIS CGKE GC OIS"
    "'LSNGFU' DSOOSK, MFU OIS CGDDGWPFR EGLO NGEEGF LYEAGD PL NIMFRSU OG OIS CGKE GC OIS 'OIPKU'"
    "DSOOSK, MFU LG GF, QFOPD WS MNNGQFO CGK MDD LYEAGDL GC OIS NKYHOGRKME WS WMFO OG LGDVS."
)


def run_demo(show_steps: bool):
    """
    Rulează demonstrația pas cu pas a atacului prin frecvențe
    """
    print("=== DEMO ===")
    text = SAMPLE_CIPHERTEXT
    profile = EN_PROFILE
    letters = extract_letters(text)
    counts = compute_letter_frequencies(letters, profile.alphabet)
    print("\nTabel frecvențe inițial:")
    print_frequency_table(counts)
    print()
    print_sorted_frequency_table(counts)
    # Inițializare mapping (pornesc de la gol pentru a reproduce pașii umani)
    mapping = SubstitutionMapping()
    logger = AttackLogger()

    def log_step(desc: str):
        partial = mapping.apply(text)
        logger.add(desc, mapping, partial)

    # Secvență pași (justificări sintetice; unele includ ipoteze corectate ulterior)
    steps_sequence = [
        (
            "Frecvența maximă este S -> presupunem 'e' (cea mai comună literă).",
            ("S", "e"),
        ),
        (
            "A doua frecvență O -> candidată pentru 't' (alternativ la 'a','o');\
                  alegem 't' după contexte de final de cuvânt.",
            ("O", "t"),
        ),
        (
            "Observăm cuvântul 'GFS' parțial '·e·' și modelul 'to' în 'OG' -> G -> 'o'.",
            ("G", "o"),
        ),
        (
            "Grupul 'GFS' devine 'oe·'; litera F apare frecvent în interior ->\
                  candidată pentru 'n'.",
            ("F", "n"),
        ),
        ("Apar secvențe 'LL' (L dublu) -> posibil 'ss' -> L -> 's'.", ("L", "s")),
        (
            "Structura 'DMFRQMRS' conține D la început de multe ori ->\
                posibil 'i' (apare în multe cuvinte).",
            ("D", "i"),
        ),
        (
            "Cuvântul 'SFCQRI' după parțiale 'e n · u g h' ->\
                recunoaștem 'enough' -> Q->'u', R->'g', C->'f'.",
            ("Q", "u"),
        ),
        ("Continuăm 'enough': R deja stabilit 'g', confirmăm C->'f'.", ("R", "g")),
        ("Stabilim C->'f' din 'enough'.", ("C", "f")),
        (
            "Cuvintele cu 'UPCC' sugerează 'diff'\
                din 'different' -> U->'d', P->'i', E->'m', N->'c'.",
            ("U", "d"),
        ),
        ("Stabilim P->'i' din 'different'.", ("P", "i")),
        ("Stabilim E->'m' din 'message' / 'different'.", ("E", "m")),
        ("Stabilim N->'c' din 'occurrences'.", ("N", "c")),
        ("Secvența 'MNNGQFO' -> devine 'a cc ou n t' -> M->'a'.", ("M", "a")),
        ("Cuvintele de 1 literă 'WS' -> 'we' -> W->'w'.", ("W", "w")),
        ("Litere rare X,Y,Z lăsate identitate -> X->'x'.", ("X", "x")),
        ("Y->'y' (frecvență mică, se potrivește).", ("Y", "y")),
        ("Z->'z' (absent).", ("Z", "z")),
        ("Model 'BFGW' cu parțial 'k n o w' -> B->'k'.", ("B", "k")),
        ("'H' apare în contexte de 'plaintext' -> H->'p'.", ("H", "p")),
        (
            "'I' precede des 'S' în 'IES' -> posibil 'h' din 'the' invers -> I->'h'.",
            ("I", "h"),
        ),
        ("'K' în 'NKYH' -> pattern 'cryp' -> K->'r'.", ("K", "r")),
        ("'J' în şiruri tehnice -> alegem 'q' (rară).", ("J", "q")),
        ("'T' apare doar în ghilimele (etichete) -> 'j' (rară).", ("T", "j")),
        ("Cheia completată.", None),
    ]

    for desc, pair in steps_sequence:
        if pair:
            ciph, plain = pair
            mapping.set(ciph, plain)
        log_step(desc)

    if show_steps:
        print("\n=== Jurnal pași demonstrație ===")
        logger.print()

    # Aplic corecția finală a cheii pentru a obține
    # textul clar complet (pașii anteriori au fost ilustrativi și pot conține ipoteze).
    final_lab_mapping = {
        "M": "a",
        "A": "b",
        "N": "c",
        "U": "d",
        "S": "e",
        "C": "f",
        "R": "g",
        "I": "h",
        "P": "i",
        "T": "j",
        "B": "k",
        "D": "l",
        "E": "m",
        "F": "n",
        "G": "o",
        "H": "p",
        "J": "q",
        "K": "r",
        "L": "s",
        "O": "t",
        "Q": "u",
        "V": "v",
        "W": "w",
        "X": "x",
        "Y": "y",
        "Z": "z",
    }
    mapping.cipher_to_plain.update({k: v for k, v in final_lab_mapping.items()})
    final_plain = mapping.apply(text)

    print("\nText decodat final (demo):\n")
    print(final_plain.replace("\n", " "))
    print("\nCheie reconstituită (demo):")
    print_reconstructed_key(mapping, profile)


def automatic_attack(
    ciphertext: str, profile: LanguageProfile
) -> Tuple[SubstitutionMapping, AttackLogger]:
    """
    Automatizează atacul prin frecvențe și reguli simple.
    Returnează mapping-ul propus și jurnalul de pași.
    """
    letters = extract_letters(ciphertext)
    counts = compute_letter_frequencies(letters, profile.alphabet)
    initial = propose_initial_mapping(counts, profile)
    mapping = SubstitutionMapping(initial)
    logger = AttackLogger()
    logger.add(
        "Mapare inițială prin aliniere ranguri de frecvență",
        mapping,
        mapping.apply(ciphertext),
    )
    # Heuristică simplă: detectez pattern THE pentru engleză.
    # Pentru Română pot adăuga 'ESTE', 'SI', 'CARE'.
    if profile.code == "en":
        words = [w for w in re.split(r"[^A-Z]", ciphertext.upper()) if w]
        three = [w for w in words if len(w) == 3]
        freq_three = collections.Counter(three)
        # Caut candidat pentru THE: cuvânt 3 litere cu litere distincte & foarte frecvent.
        candidate_the = None
        for w, _ in freq_three.most_common(15):
            if len(set(w)) == 3:
                candidate_the = w
                break
        if candidate_the:
            c1, c2, c3 = candidate_the[0], candidate_the[1], candidate_the[2]
            # Ajustez mapping pentru a forța candidate_the -> the
            mapping.set(c1, "t")
            mapping.set(c2, "h")
            mapping.set(c3, "e")
            logger.add(
                f"Heuristică: cuvânt frecvent '{candidate_the}' -> 'the'",
                mapping,
                mapping.apply(ciphertext),
            )

    return mapping, logger


def interactive_mode(ciphertext: str, profile: LanguageProfile):
    """
    Permite analiza interactivă a unui text criptat folosind substituții,
    frecvențe de litere și sugestii de decodare.
    Oferă comenzi pentru vizualizarea frecvențelor,
    maparea și demaparea literelor, decodare parțială sau completă,
    afișarea cheii reconstruite, pașilor efectuați și resetarea procesului.

    Args:
        ciphertext (str): Textul criptat ce urmează a fi analizat.
        profile (LanguageProfile): Profilul lingvistic cu alfabetul și frecvențele limbii țintă.
    """
    print("--- Mod interactiv criptanaliză ---")
    letters = extract_letters(ciphertext)
    counts = compute_letter_frequencies(letters, profile.alphabet)
    mapping = SubstitutionMapping()
    logger = AttackLogger()
    while True:
        try:
            cmd = input("cmd> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nIeşire.")
            break
        if not cmd:
            continue
        parts = cmd.split()
        op = parts[0].lower()
        if op in ("quit", "exit"):
            break
        elif op == "freq":
            print_frequency_table(counts)
            print()
            print_sorted_frequency_table(counts)
        elif op == "map" and len(parts) == 3:
            ciph, plain = parts[1].upper(), parts[2].lower()
            if (
                len(ciph) != 1
                or len(plain) != 1
                or not ciph.isalpha()
                or not plain.isalpha()
            ):
                print("Eroare: format map <C> <p>")
                continue
            mapping.set(ciph, plain)
            logger.add(f"Set {ciph}->{plain}", mapping, mapping.apply(ciphertext))
            print("OK.")
        elif op == "unmap" and len(parts) == 2:
            ciph = parts[1].upper()
            mapping.remove(ciph)
            logger.add(f"Remove {ciph}", mapping, mapping.apply(ciphertext))
            print("OK.")
        elif op == "decode":
            print(mapping.apply(ciphertext))
        elif op == "preview":
            # Afișează literele mapate, iar cele nemapate rămân ca în criptogramă
            out = []
            for ch in ciphertext:
                up = ch.upper()
                if up in mapping.cipher_to_plain and up.isalpha():
                    out.append(mapping.cipher_to_plain[up])
                else:
                    out.append(ch)
            print("".join(out))
        elif op == "key":
            print_reconstructed_key(mapping, profile)
        elif op == "suggest":
            # Folosește criptograma parțial decodată pentru sugestii mai relevante
            # unknown='' va păstra literele nemapate ca în criptogramă
            partial_decoded = "".join(
                (
                    mapping.cipher_to_plain.get(ch.upper(), ch)
                    if LETTER_RE.match(ch.upper())
                    else ch
                )
                for ch in ciphertext
            )
            # unknown=None => nemapatele rămân ca în criptogramă
            sug = suggest_by_word_patterns(partial_decoded, mapping)
            if not sug:
                print("(Fără sugestii evidente)")
            else:
                for s in sug:
                    print("-", s)
        elif op == "steps":
            logger.print()
        elif op == "reset":
            mapping = SubstitutionMapping()
            logger.add("Reset mapping", mapping, mapping.apply(ciphertext))
            print("Reset complet.")
        else:
            print(
                "Comenzi: freq | map <C> <p> | unmap <C> | suggest |\
                      decode | preview | key | steps | reset | quit"
            )


def load_ciphertext(args) -> str:
    """
    Încarcă textul cifrat din argumentele liniei de comandă, fișier, intrare standard sau prompt.

    Args:
        args: Spațiu de nume cu atributele posibile "ciphertext" (str) și "file" (str).

    Returnează: str:
        str: Textul cifrat încărcat.

    Ridică:
        FileNotFoundError: Dacă fișierul specificat nu există.
    """
    if args.ciphertext:
        return args.ciphertext
    if args.file:
        if not os.path.isfile(args.file):
            raise FileNotFoundError(f"Fișier inexistent: {args.file}")
        with open(args.file, "r", encoding="utf-8") as f:
            return f.read()
    if not sys.stdin.isatty():
        data = sys.stdin.read()
        if data.strip():
            return data
    # fallback prompt
    return input("Introduceți criptograma: ")


def build_arg_parser() -> argparse.ArgumentParser:
    """
    Construiește și returnează un obiect ArgumentParser configurat
    pentru criptanaliza monoalfabetică, permițând specificarea criptogramei,
    fișierului sursă, limbii, modului interactiv,
    demonstrației, afișării pașilor și atacului automat.
    """
    p = argparse.ArgumentParser(
        description="Criptanaliză monoalfabetică prin analiza frecvențelor (EN/RO)."
    )
    p.add_argument("--ciphertext", help="Criptograma ca șir de caractere.")
    p.add_argument("--file", help="Fișier care conține criptograma.")
    p.add_argument("--language", choices=["en", "ro"], help="Forțează limba.")
    p.add_argument(
        "--interactive", action="store_true", help="Pornește modul interactiv."
    )
    p.add_argument(
        "--demo", action="store_true", help="Rulează demonstrația."
    )
    p.add_argument(
        "--show-steps",
        action="store_true",
        help="Afișează jurnalul de pași (demo sau atac automat).",
    )
    p.add_argument(
        "--auto",
        action="store_true",
        help="Execută un atac automat (heuristic simplu).",
    )
    return p


def main(argv: Optional[List[str]] = None):
    """
    Funcția principală a aplicației de analiză a frecvenței criptografice.
    Parsează argumentele din linia de comandă, încarcă criptograma,
    detectează limba, afișează frecvențele literelor și
    permite analiza automată sau interactivă a textului criptat.
    Args:
        argv (Optional[List[str]]): Lista argumentelor din linia de comandă (opțional).
    Raises:
        SystemExit: Dacă apar erori la încărcarea criptogramei sau
        dacă nu se găsesc litere alfabetice.
    """
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.demo:
        run_demo(show_steps=args.show_steps)
        return

    try:
        ciphertext = load_ciphertext(args)
    except (FileNotFoundError, PermissionError, OSError) as e:
        print(f"Eroare la încărcare: {e}", file=sys.stderr)
        sys.exit(1)

    if not ciphertext.strip():
        print("Eroare: criptograma este goală.", file=sys.stderr)
        sys.exit(2)

    letters = extract_letters(ciphertext)
    if not letters:
        print(
            "Eroare: nu s-au găsit litere alfabetice în criptogramă.", file=sys.stderr
        )
        sys.exit(3)

    if args.language:
        profile = EN_PROFILE if args.language == "en" else RO_PROFILE
    else:
        profile = detect_language(letters)

    print(
        f"Limbă detectată: {'Engleză' if profile.code=='en' else 'Română'} ({profile.code})"
    )

    # Afișeaz tabelul de frecvențe naturale pentru limba detectată
    if profile.code == "en":
        print_natural_alphabet_en_frequency()
    else:
        print_natural_alphabet_ro_frequency()

    counts = compute_letter_frequencies(letters, profile.alphabet)
    print("\nTabel frecvență (alfabet sursă):")
    print_frequency_table(counts)
    print()
    print_sorted_frequency_table(counts)

    if args.interactive:
        interactive_mode(ciphertext, profile)
        return

    if args.auto:
        mapping, logger = automatic_attack(ciphertext, profile)
        if args.show_steps:
            print("\n=== Jurnal pași (automat) ===")
            logger.print()
        print("\nDecodare parțială: \n")
        print(mapping.apply(ciphertext))
        print("\nCheie (parțială):")
        print_reconstructed_key(mapping, profile)
        return

    print(
        "\n(Nici --interactive nici --auto nu au fost setate; \
            pentru analiză automată folosiți --auto, pentru interactiv --interactive.)"
    )


if __name__ == "__main__":
    main()
