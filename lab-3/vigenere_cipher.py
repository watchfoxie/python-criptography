# -*- coding: utf-8 -*-
"""
Implementarea cifrului Vigenère pentru alfabetul Român (31 caractere).

Realizat de studentul grupei IS31Z, Tocana Marian
"""

from __future__ import annotations

import logging
import sys
import time
import unicodedata
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Sequence, Tuple

# Alfabetul Român (31 de caractere) în ordinea consecutivă
ROMANIAN_ALPHABET: Tuple[str, ...] = (
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
    "Ț",
    "U",
    "V",
    "W",
    "X",
    "Y",
    "Z",
)

MODULO: int = len(ROMANIAN_ALPHABET)

# Limite de siguranță pentru intrare (pentru a evita consum excesiv de memorie)
MAX_TEXT_LENGTH: int = 32_767
MAX_KEY_LENGTH: int = 65_534
MIN_KEY_LENGTH: int = 7

# Praguri pentru feedback de progres
PROGRESS_MIN_LENGTH: int = 50_000  # peste acest prag, se afișează progres la procesare
PROGRESS_STEP_PERCENTAGES: int = 5  # la câte procente să se raporteze progresul


# ------------------------------------------------------------
# Logging
# ------------------------------------------------------------

logger = logging.getLogger("vigenere")
logger.setLevel(logging.INFO)

_handler = logging.FileHandler("vigenere.log", encoding="utf-8")
_formatter = logging.Formatter(
    fmt="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
_handler.setFormatter(_formatter)
if not logger.handlers:
    logger.addHandler(_handler)


# ------------------------------------------------------------
# Excepții personalizate
# ------------------------------------------------------------


class ValidationTextError(Exception):
    """Excepție pentru erori de validare text (input)."""

    def __init__(
        self, nume: str, erori: List[Tuple[int, str]], mesaj: Optional[str] = None
    ) -> None:
        self.nume = nume
        self.erori = erori  # listă de (pozitia_in_textul_original, caracter)
        self.mesaj = mesaj or "Input invalid pentru text."
        super().__init__(self.__str__())

    def __str__(self) -> str:
        if not self.erori:
            return self.mesaj
        # Construiesc un mesaj care include toate erorile
        detalii = ", ".join(
            f"caracter {repr(ch)} la poziția {pos}" for pos, ch in self.erori
        )
        return (
            f"{self.mesaj} (Câmp: {self.nume})\n"
            f"Caractere permise: {''.join(ROMANIAN_ALPHABET)}\n"
            f"Erori identificate: {detalii}"
        )


class ValidationKeyError(Exception):
    """Excepție pentru erori de validare cheie."""

    def __init__(self, mesaj: str) -> None:
        super().__init__(mesaj)


class EncryptionError(Exception):
    pass


# ------------------------------------------------------------
# Mapări caracter <-> număr (funcții pure)
# ------------------------------------------------------------

CHAR_TO_INDEX: Dict[str, int] = {ch: i for i, ch in enumerate(ROMANIAN_ALPHABET)}
INDEX_TO_CHAR: Dict[int, str] = {i: ch for i, ch in enumerate(ROMANIAN_ALPHABET)}


def char_to_number(character: str) -> int:
    """Funcție pură: întoarce indexul caracterului în alfabetul român.

    Ridică KeyError dacă caracterul nu există în alfabet.
    """
    return CHAR_TO_INDEX[character]


def number_to_char(number: int) -> str:
    """Funcție pură: întoarce caracterul pentru indexul dat (0..30)."""
    return INDEX_TO_CHAR[number % MODULO]


# ------------------------------------------------------------
# Utilitare de normalizare & preprocesare
# ------------------------------------------------------------

_NORMALIZE_MAP = {
    "Ş": "Ș",  # S cu sedilă -> S cu virgulă dedesubt (corect Românește)
    "Ţ": "Ț",  # T cu sedilă -> T cu virgulă dedesubt (corect Românește)
    "ş": "ș",
    "ţ": "ț",
}


def _normalize_unicode(s: str) -> str:
    # Normalizează la NFC și corectează variațiile Ş/Ţ -> Ș/Ț
    s = unicodedata.normalize("NFC", s)
    # Înlocuiri țintite
    for k, v in _NORMALIZE_MAP.items():
        s = s.replace(k, v)
    return s


@dataclass
class PreprocessingResult:
    """Rezultatul preprocesării unui text: textul procesat și maparea indicilor."""

    text: str
    mapare_idx_proc_la_idx_orig: List[int]


def _preprocess_text(text: str) -> PreprocessingResult:
    """Elimină spațiile, convertește la majuscule, normalizează unicode.

    Returnează textul procesat și o mapare a indicilor din textul procesat
    către pozițiile din textul original, pentru raportarea erorilor.
    """
    if text is None:
        text = ""

    text_original = text
    text = _normalize_unicode(text_original)

    result: List[str] = []
    mapping: List[int] = []
    for i, ch in enumerate(text):
        if ch.isspace():
            continue  # eliminăm complet spațiile
        up = ch.upper()
        result.append(up)
        mapping.append(i)
    return PreprocessingResult("".join(result), mapping)


# ------------------------------------------------------------
# Criptarea Vigenère (OOP)
# ------------------------------------------------------------


class VigenereCipher:
    """Implementarea algoritmului Vigenère pentru alfabetul român (31 chars)."""

    def __init__(self) -> None:
        self._alphabet: Tuple[str, ...] = ROMANIAN_ALPHABET
        self._char_to_idx = CHAR_TO_INDEX
        self._idx_to_char = INDEX_TO_CHAR

    # ------- Validări -------
    def validate_text(
        self, text_original: str, nume: str = "text"
    ) -> Tuple[bool, List[str]]:
        """Validează textul: toate caracterele (după preprocesare) trebuie să fie în alfabet.

        Returnează (ok, lista_mesaje_eroare). NU aruncă excepții aici, doar colectează.
        """
        pre = _preprocess_text(text_original)
        text_proc = pre.text

        erori: List[Tuple[int, str]] = []
        for idx_proc, ch in enumerate(text_proc):
            if ch not in self._char_to_idx:
                pos_orig = pre.mapare_idx_proc_la_idx_orig[idx_proc]
                erori.append((pos_orig, ch))

        mesaje: List[str] = []
        if len(text_proc) == 0:
            mesaje.append(
                f"{nume.capitalize()} este gol după preprocesare (eliminare spații)."
            )

        if len(text_proc) > MAX_TEXT_LENGTH:
            mesaje.append(
                f"{nume.capitalize()} depășește lungimea maximă permisă\
                      de {MAX_TEXT_LENGTH} caractere."
            )

        if erori:
            # Construiesc mesaj sumar despre erori de alfabet
            detalii = ", ".join(f"{repr(ch)}@{pos}" for pos, ch in erori)
            mesaje.append(
                f"{nume.capitalize()} conține caractere în afara alfabetului românesc: {detalii}"
            )

        return (len(mesaje) == 0, mesaje)

    def validate_key(self, cheie_originala: str) -> Tuple[bool, str]:
        """Validează cheia (minim 7 caractere, numai litere din alfabet, după preprocesare)."""
        pre = _preprocess_text(cheie_originala)
        cheie = pre.text

        if len(cheie) < MIN_KEY_LENGTH:
            return False, (
                f"Cheia este prea scurtă: {len(cheie)}. Lungime minimă necesară: {MIN_KEY_LENGTH}."
            )
        if len(cheie) > MAX_KEY_LENGTH:
            return False, (
                f"Cheia este prea lungă: {len(cheie)}. Lungime maximă permisă: {MAX_KEY_LENGTH}."
            )

        erori: List[Tuple[int, str]] = []
        for idx_proc, ch in enumerate(cheie):
            if ch not in self._char_to_idx:
                pos_orig = pre.mapare_idx_proc_la_idx_orig[idx_proc]
                erori.append((pos_orig, ch))

        if erori:
            detalii = ", ".join(f"{repr(ch)}@{pos}" for pos, ch in erori)
            return False, (
                "Cheia conține caractere în afara alfabetului românesc: " + detalii
            )

        return True, "OK"

    # ------- Operații de codificare -------
    def _key_indices(self, cheie_proc: str) -> List[int]:
        return [self._char_to_idx[c] for c in cheie_proc]

    def _process_generator(
        self,
        text_proc: str,
        key_indices: Sequence[int],
        operation: str,
        display_progress: bool = False,
    ) -> Iterator[str]:
        """Procesează caracter cu caracter folosind generator (memorie eficientă).

        operation: "encrypt" | "decrypt"
        """
        if operation not in {"encrypt", "decrypt"}:
            raise ValueError("operation trebuie să fie 'encrypt' sau 'decrypt'")

        L = len(text_proc)
        Lk = len(key_indices)
        if Lk == 0:
            raise EncryptionError("Cheia preprocesată este vidă.")

        next_percent = PROGRESS_STEP_PERCENTAGES
        for i, ch in enumerate(text_proc):
            try:
                m = self._char_to_idx[ch]
            except KeyError as exc:
                # Nu ar trebui să se întâmple după validare
                raise EncryptionError(
                    f"Caracter invalid întâlnit la procesare: {repr(ch)}"
                ) from exc
            k = key_indices[i % Lk]
            if operation == "encrypt":
                c = (m + k) % MODULO
            else:
                c = (m - k) % MODULO
            yield self._idx_to_char[c]

            if display_progress and L >= PROGRESS_MIN_LENGTH:
                pct = (i + 1) * 100 // L
                if pct >= next_percent:
                    print(f"  Progres: ~{pct}% ({i+1}/{L})", file=sys.stderr)
                    next_percent += PROGRESS_STEP_PERCENTAGES

    def encrypt(self, text_clar: str, cheie: str, *, feedback: bool = False) -> str:
        """Criptează textul clar cu cheia dată."""
        logger.info("Criptare inițiată")
        # Preprocesează și validează text
        pre_text = _preprocess_text(text_clar)
        pre_key = _preprocess_text(cheie)
        ok_t, msg_t = self.validate_text(text_clar, nume="text clar")
        if not ok_t:
            raise ValidationTextError("text clar", [], "\n".join(msg_t))
        ok_k, msg_k = self.validate_key(cheie)
        if not ok_k:
            raise ValidationKeyError(msg_k)

        key_indices = self._key_indices(pre_key.text)

        t0 = time.perf_counter()
        result_iter = self._process_generator(
            pre_text.text, key_indices, operation="encrypt", display_progress=feedback
        )
        result = "".join(result_iter)
        duration = time.perf_counter() - t0
        logger.info(
            "Criptare finalizată în %.3fs (lungime=%d)", duration, len(pre_text.text)
        )
        return result

    def decrypt(
        self, criptograma: str, cheie: str, *, feedback: bool = False
    ) -> str:
        """Decriptează criptograma cu cheia dată."""
        logger.info("Decriptare inițiată")
        pre_text = _preprocess_text(criptograma)
        pre_key = _preprocess_text(cheie)
        ok_t, msg_t = self.validate_text(criptograma, nume="criptogramă")
        if not ok_t:
            raise ValidationTextError("criptogramă", [], "\n".join(msg_t))
        ok_k, msg_k = self.validate_key(cheie)
        if not ok_k:
            raise ValidationKeyError(msg_k)

        key_indices = self._key_indices(pre_key.text)

        t0 = time.perf_counter()
        result_iter = self._process_generator(
            pre_text.text, key_indices, operation="decrypt", display_progress=feedback
        )
        result = "".join(result_iter)
        duration = time.perf_counter() - t0
        logger.info(
            "Decriptare finalizată în %.3fs (lungime=%d)", duration, len(pre_text.text)
        )
        return result


# ------------------------------------------------------------
# Interfață Utilizator (CLI)
# ------------------------------------------------------------


def _read_input(prompt: str) -> str:
    try:
        return input(prompt)
    except EOFError:
        return ""


def display_menu() -> None:
    """Afișează meniul principal."""
    print("\n=== Cifrul Vigenère (alfabet român, 31 caractere) ===")
    print("1) Criptează un mesaj")
    print("2) Decriptează o criptogramă")
    print("0) Ieșire")


def get_user_selection() -> str:
    """Obține selecția utilizatorului din meniu."""
    while True:
        opt = _read_input("Alege opțiunea [0-2]: ").strip()
        if opt in {"0", "1", "2"}:
            return opt
        print("Selecție invalidă. Te rog alege 0, 1 sau 2.")


def get_key(criptor: VigenereCipher) -> str:
    """Obține cheia de la utilizator, cu validare."""
    while True:
        cheie = _read_input(
            f"Introdu cheia (minim {MIN_KEY_LENGTH} caractere, doar litere din alfabetul românesc):\n> "
        )
        ok, mesaj = criptor.validate_key(cheie)
        if ok:
            # Întoarcem forma preprocesată (fără spații, majuscule)
            return _preprocess_text(cheie).text
        print(f"Eroare cheie: {mesaj}\nÎncearcă din nou.\n")


def get_text(criptor: VigenereCipher) -> str:
    """Obține textul clar de la utilizator, cu validare."""
    while True:
        text = _read_input(
            "Introdu textul (spațiile vor fi eliminate, se permit doar litere din alfabetul românesc):\n> "
        )
        ok, mesaje = criptor.validate_text(text, nume="text")
        if ok:
            return _preprocess_text(text).text
        print("Au fost identificate probleme:")
        for m in mesaje:
            print(" - ", m)
        print("Încearcă din nou.\n")


def get_cryptogram(criptor: VigenereCipher) -> str:
    """Obține criptograma de la utilizator, cu validare."""
    while True:
        text = _read_input(
            "Introdu criptograma (spațiile vor fi eliminate, se permit doar litere din alfabetul românesc):\n> "
        )
        ok, mesaje = criptor.validate_text(text, nume="criptogramă")
        if ok:
            return _preprocess_text(text).text
        print("Au fost identificate probleme:")
        for m in mesaje:
            print(" - ", m)
        print("Încearcă din nou.\n")


def run_cli() -> None:
    """Rulează interfața CLI pentru criptare/decriptare Vigenère."""
    criptor = VigenereCipher()
    print(
        "Bun venit! Acest program implementează cifrul Vigenère (alfabet românesc).\n"
    )

    while True:
        display_menu()
        opt = get_user_selection()

        if opt == "0":
            print("La revedere!")
            return

        if opt == "1":  # criptare
            cheie = get_key(criptor)
            text = get_text(criptor)
            print(
                f"\nConfirmi criptarea a {len(text)} caractere cu cheia de {len(cheie)}? (da/nu)"
            )
            conf = _read_input("> ").strip().lower()
            if conf not in {"da", "d", "y", "yes"}:
                print("Operația a fost anulată.")
                continue
            try:
                feedback = len(text) >= PROGRESS_MIN_LENGTH
                result = criptor.encrypt(text, cheie, feedback=feedback)
                print("\n--- Criptogramă ---")
                print(result)
                print("-------------------\n")
            except (
                ValidationTextError,
                ValidationKeyError,
                EncryptionError,
                ValueError,
            ) as exc:
                logger.exception("Eroare la criptare")
                print(f"A apărut o eroare: {exc}")
            finally:
                # Curățare referințe sensibile
                result = None  # type: ignore
                cheie = None  # type: ignore
                text = None  # type: ignore

        elif opt == "2":  # Decriptare
            cheie = get_key(criptor)
            criptograma = get_cryptogram(criptor)
            print(
                f"\nConfirmi decriptarea a {len(criptograma)} caractere\
                      cu cheia de {len(cheie)}? (da/nu)"
            )
            conf = _read_input("> ").strip().lower()
            if conf not in {"da", "d", "y", "yes"}:
                print("Operația a fost anulată.")
                continue
            try:
                feedback = len(criptograma) >= PROGRESS_MIN_LENGTH
                result = criptor.decrypt(criptograma, cheie, feedback=feedback)
                print("\n--- Text clar ---")
                print(result)
                print("-----------------\n")
            except (
                ValidationTextError,
                ValidationKeyError,
                EncryptionError,
                ValueError,
            ) as exc:
                logger.exception("Eroare la decriptare")
                print(f"A apărut o eroare: {exc}")
            finally:
                result = None  # type: ignore
                cheie = None  # type: ignore
                criptograma = None  # type: ignore


# ------------------------------------------------------------
# Punct de intrare
# ------------------------------------------------------------

if __name__ == "__main__":
    try:
        run_cli()
    except KeyboardInterrupt:
        print("\nOperație întreruptă de utilizator. La revedere!")
