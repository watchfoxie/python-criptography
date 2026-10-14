"""des-cipher.py
Implementare algoritmului DES (Data Encryption Standard)

Realizat de studentul grupei IS31Z, Tocana Marian
"""

from __future__ import annotations

import argparse
import logging
import sys
from dataclasses import dataclass, field
from typing import List, Tuple, Iterable, Optional

# ==============================================================
# Configurare logging
# ==============================================================
logger = logging.getLogger("des")
if not logger.handlers:
    logger.setLevel(logging.INFO)
    _handler = logging.FileHandler("des.log", encoding="utf-8")
    _formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )
    _handler.setFormatter(_formatter)
    logger.addHandler(_handler)


# ==============================================================
# Excepții personalizate
# ==============================================================
class DESKeyError(ValueError):
    """Eroare legată de validarea sau procesarea cheii DES."""


class DESTextError(ValueError):
    """Eroare legată de textul de intrare (hex, lungime, padding)."""


class DESEncryptionError(RuntimeError):
    """Eroare apărută în timpul procesului de criptare / decriptare."""


# ==============================================================
# Tabele DES
# ==============================================================
PC1: Tuple[int, ...] = (
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
)

PC2: Tuple[int, ...] = (
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
)

IP: Tuple[int, ...] = (
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
)

IP_INV: Tuple[int, ...] = (
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25,
)

E_BOX: Tuple[int, ...] = (
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1,
)

P_BOX: Tuple[int, ...] = (
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25,
)

S_BOXES: Tuple[Tuple[Tuple[int, ...], ...], ...] = (
    (
        (14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7),
        (0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8),
        (4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0),
        (15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13),
    ),
    (
        (15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10),
        (3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5),
        (0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15),
        (13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9),
    ),
    (
        (10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8),
        (13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1),
        (13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7),
        (1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12),
    ),
    (
        (7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15),
        (13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9),
        (10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4),
        (3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14),
    ),
    (
        (2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9),
        (14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6),
        (4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14),
        (11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3),
    ),
    (
        (12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11),
        (10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8),
        (9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6),
        (4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13),
    ),
    (
        (4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1),
        (13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6),
        (1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2),
        (6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12),
    ),
    (
        (13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7),
        (1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2),
        (7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8),
        (2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11),
    ),
)

ROTATIONS: Tuple[int, ...] = (
    1, 1, 2, 2, 2, 2, 2, 2,
    1, 2, 2, 2, 2, 2, 2, 1,
)

# ==============================================================
# Funcții utilitare bit / permutări
# ==============================================================
def _hex_to_bitstring(hex_text: str) -> str:
    return ''.join(f"{int(ch, 16):04b}" for ch in hex_text.upper())


def _bitstring_to_hex(bits: str) -> str:
    # Aliniază la multiplu de 4
    if len(bits) % 4 != 0:
        raise ValueError("Lungimea bitstring-ului nu este multiplu de 4")
    out = []
    for i in range(0, len(bits), 4):
        out.append(f"{int(bits[i:i+4], 2):X}")
    return ''.join(out)


def _permute(bits: str, table: Iterable[int]) -> str:
    return ''.join(bits[i - 1] for i in table)


def _left_rotate(bits: str, n: int) -> str:
    n_mod = n % len(bits)
    return bits[n_mod:] + bits[:n_mod]


def _xor_bits(a: str, b: str) -> str:
    return ''.join('1' if x != y else '0' for x, y in zip(a, b))


HEX_VALIDATION_MESSAGE = (
    "Șirul nu este un șir hexazecimal valid. Caractere permise: "
    "[a-fA-F0-9 \\n\\r\\t\\-] și șirul trebuie să aibă lungime pară."
)


def _sanitize_hex(s: str, field_name: str, require_even: bool = True) -> str:
    """Curăță un șir potențial formatat (spații, newline, tab, '-') și validează hex.

    Returnează șirul hex normalizat (uppercase) fără separatori.
    Aruncă DESTextError / DESKeyError cu mesajul standard în caz de neconformitate.
    """
    if s is None:
        raise DESTextError(HEX_VALIDATION_MESSAGE + f" (câmp: {field_name})")
    allowed_separators = {' ', '\n', '\r', '\t', '-'}
    cleaned_chars: List[str] = []
    for ch in s:
        if ch in allowed_separators:
            continue
        if ch.lower() in '0123456789abcdef':
            cleaned_chars.append(ch)
        else:
            raise DESTextError(HEX_VALIDATION_MESSAGE + f" (câmp: {field_name})")
    if not cleaned_chars:
        raise DESTextError(HEX_VALIDATION_MESSAGE + f" (câmp: {field_name})")
    if require_even and len(cleaned_chars) % 2 != 0:
        raise DESTextError(HEX_VALIDATION_MESSAGE + f" (câmp: {field_name})")
    return ''.join(cleaned_chars).upper()

# ==============================================================
# Scheduler Chei DES
# ==============================================================

@dataclass
class DESKeyScheduler:
    """Generare și stocare sub-chei DES."""
    cheie_hex: str
    subchei: List[str] = field(default_factory=list)  # 16 sub-chei (bitstring de 48 biți)

    def __post_init__(self) -> None:
        # Curățare / validare inițială conform regulilor
        self.cheie_hex = _sanitize_hex(self.cheie_hex, "cheie", require_even=True)
        self.subchei = []
        self._validate_key()

    # -------- Funcții cerute în specificație --------
    def DES_Key_Permut_PC10(self, cheie_hex: str) -> str:
        """Aplică PC-1 (elimină biții de paritate) -> 56 biți."""
        if len(cheie_hex) != 16:
            raise DESKeyError("Cheia trebuie să aibă exact 16 caractere hex (64 biți).")
        try:
            int(cheie_hex, 16)
        except ValueError as exc:
            raise DESKeyError("Cheia conține caractere non-hex.") from exc
        bits64 = _hex_to_bitstring(cheie_hex)
        if len(bits64) != 64:
            raise DESKeyError("Conversia la 64 de biți a eșuat.")
        k_plus = _permute(bits64, PC1)
        logger.info("PC-1 aplicat: %s", k_plus)
        return k_plus

    def DES_Key_Divide_C0_D0(self, cheie_permutata_56: str) -> Tuple[str, str]:
        if len(cheie_permutata_56) != 56:
            raise DESKeyError("Cheia permutată (PC-1) trebuie să aibă 56 de biți.")
        return cheie_permutata_56[:28], cheie_permutata_56[28:]

    def DES_Key_Divide_Ci_Di(self, C_prev: str, D_prev: str, n: int) -> Tuple[str, str]:
        if not (1 <= n <= 16):
            raise DESKeyError("Numărul rundei trebuie să fie între 1 și 16.")
        if len(C_prev) != 28 or len(D_prev) != 28:
            raise DESKeyError("Blocurile C și D trebuie să aibă 28 de biți.")
        rot = ROTATIONS[n - 1]
        Cn = _left_rotate(C_prev, rot)
        Dn = _left_rotate(D_prev, rot)
        return Cn, Dn

    def DES_Key_Permut_PC20(self, C_D_concat: str) -> str:
        if len(C_D_concat) != 56:
            raise DESKeyError("Concatenarea C||D trebuie să aibă 56 de biți pentru PC-2.")
        subkey = _permute(C_D_concat, PC2)
        if len(subkey) != 48:
            raise DESKeyError("PC-2 nu a generat 48 de biți.")
        return subkey

    def DES_Key_CreateSubKeys(self) -> List[str]:
        logger.info("Generare sub-chei pentru cheia: %s", self.cheie_hex)
        k_plus = self.DES_Key_Permut_PC10(self.cheie_hex)
        C, D = self.DES_Key_Divide_C0_D0(k_plus)
        for n in range(1, 17):
            C, D = self.DES_Key_Divide_Ci_Di(C, D, n)
            subkey = self.DES_Key_Permut_PC20(C + D)
            self.subchei.append(subkey)
            logger.info("Sub-cheie K%-2d (bin): %s", n, subkey)
        return self.subchei

    # -------- Utilitar intern --------
    def _validate_key(self) -> None:
        if len(self.cheie_hex) != 16:
            # Folosim mesajul global + precizare lungime
            raise DESKeyError(HEX_VALIDATION_MESSAGE + " Cheia DES trebuie să aibă exact 16 caractere hex (64 biți).")
        try:
            int(self.cheie_hex, 16)
        except ValueError as exc:
            raise DESKeyError(HEX_VALIDATION_MESSAGE) from exc


# ==============================================================
# Clasa principală DES
# ==============================================================
class DES:
    def __init__(self, cheie_hex: str, padding: str = "zero") -> None:
        """Initializează instanța DES.

        padding: "zero" (implicit) - completează ultimul bloc scurt cu octeți 0x00.
                 "pkcs7" - aplică padding PKCS#7 pe întreg mesajul dacă nu este multiplu de 8.
                 "none"  - NU aplică padding (eroare dacă lungimea nu este multiplu de 8).
        """
        if padding not in {"zero", "pkcs7", "none"}:
            raise ValueError("Mod de padding invalid (permise: zero, pkcs7, none).")
        self.padding_mode = padding
        self.key_scheduler = DESKeyScheduler(cheie_hex)
        self.subchei = self.key_scheduler.DES_Key_CreateSubKeys()  # listă de 16 (bin)

    # ------------------ Funcții publice ------------------
    def encrypt_hex(self, text_hex: str) -> str:
        """Criptează un text (hex) arbitrar.
        Comportament padding în funcție de self.padding_mode:
          zero  - ultimul bloc scurt (<8) este completat cu 0x00 până la 8 octeți (NU se adaugă bloc suplimentar).
          pkcs7 - se aplică PKCS#7 standard (compatibil pentru mesaje > 1 bloc); dacă deja multiplu de 8 rămâne așa.
          none  - se aruncă eroare dacă lungimea nu e multiplu de 8.
        """
        text_hex_clean = _sanitize_hex(text_hex, "text de intrare", require_even=True)
        data = bytes.fromhex(text_hex_clean)
        out_blocks: List[bytes] = []
        if self.padding_mode == "pkcs7":
            if len(data) % 8 != 0:
                data = self._apply_pkcs7(data)
                logger.info("Aplicat padding PKCS#7. Lungime finală=%d", len(data))
        elif self.padding_mode == "none":
            if len(data) % 8 != 0:
                raise DESTextError("Lungimea datelor nu este multiplu de 64 biți și padding=none.")
        # zero padding: tratăm în buclă ultimul rest
        full_blocks = len(data) // 8
        for i in range(full_blocks):
            bloc = data[i * 8 : (i + 1) * 8]
            out_blocks.append(self._encrypt_block(bloc))
        remainder = len(data) % 8
        if remainder:
            if self.padding_mode == "pkcs7":
                # deja tratat mai sus; nu ar trebui să existe remainder
                raise DESEncryptionError("Stare internă neașteptată: remainder după PKCS#7.")
            # zero padding remainder
            last = data[-remainder:] + b"\x00" * (8 - remainder)
            logger.info(
                "Zero padding aplicat pe ultimul bloc (rest=%d) -> completat cu %d octeți 0x00",
                remainder, 8 - remainder
            )
            out_blocks.append(self._encrypt_block(last))
        # Dacă lungimea exactă multiplu de 8 și pkcs7 a fost cerut, nu adăugăm bloc suplimentar (compat cerințe)
        return b"".join(out_blocks).hex().upper()

    def decrypt_hex(self, text_hex: str) -> str:
        """Decriptează un text (hex) arbitrar.
        Dacă padding_mode=pkcs7: încercăm eliminare PKCS#7 (strictă).
        Dacă padding_mode=zero: NU eliminăm octeți 0 finali (ar produce ambiguitate).
        Dacă padding_mode=none: doar returnăm hex direct.
        """
        text_hex_clean = _sanitize_hex(text_hex, "text cifrat", require_even=True)
        data = bytes.fromhex(text_hex_clean)
        if len(data) % 8 != 0:
            raise DESTextError("Textul cifrat trebuie să aibă lungime multiplu de 8 bytes (64 biți).")
        logger.info("Decriptare text lungime %d bytes", len(data))
        out_blocks: List[bytes] = []
        total_blocks = len(data) // 8
        for i in range(total_blocks):
            bloc = data[i * 8 : (i + 1) * 8]
            out_blocks.append(self._decrypt_block(bloc))
            if total_blocks > 128 and (i + 1) % 50 == 0:
                print(f"Progres decriptare: {i + 1}/{total_blocks} blocuri", file=sys.stderr)
        plaintext = b"".join(out_blocks)
        if self.padding_mode == "pkcs7":
            try:
                stripped = self._maybe_remove_pkcs7(plaintext)
                logger.info("Padding PKCS#7 eliminat (lungime %d -> %d)", len(plaintext), len(stripped))
                plaintext = stripped
            except DESTextError:
                logger.warning("Padding PKCS#7 invalid sau absent. Returnez date brute.")
        return plaintext.hex().upper()

    # ------------------ Blocs ------------------
    def _encrypt_block(self, block8: bytes) -> bytes:
        if len(block8) != 8:
            raise DESEncryptionError("Blocul pentru criptare nu are 8 bytes.")
        bits = f"{int.from_bytes(block8, 'big'):064b}"
        logger.info("Bloc inițial (hex=%s) bits=%s", block8.hex().upper(), bits)
        perm = _permute(bits, IP)
        L = perm[:32]
        R = perm[32:]
        for rnd in range(16):
            prevL, prevR = L, R
            L = R
            f_out = self._feistel(R, self.subchei[rnd])
            R = _xor_bits(prevL, f_out)
            logger.info(
                "Runda %02d: L_prev=%s R_prev=%s K=%s f=%s L=%s R=%s",
                rnd + 1,
                prevL,
                prevR,
                self.subchei[rnd],
                f_out,
                L,
                R,
            )
        preoutput = R + L  # swap final
        cipher_bits = _permute(preoutput, IP_INV)
        cipher_int = int(cipher_bits, 2)
        return cipher_int.to_bytes(8, 'big')

    def _decrypt_block(self, block8: bytes) -> bytes:
        if len(block8) != 8:
            raise DESEncryptionError("Blocul pentru decriptare nu are 8 bytes.")
        bits = f"{int.from_bytes(block8, 'big'):064b}"
        perm = _permute(bits, IP)
        L = perm[:32]
        R = perm[32:]
        for rnd in range(16):
            prevL = L
            L = R
            f_out = self._feistel(R, self.subchei[15 - rnd])
            R = _xor_bits(prevL, f_out)
        preoutput = R + L
        plain_bits = _permute(preoutput, IP_INV)
        plain_int = int(plain_bits, 2)
        return plain_int.to_bytes(8, 'big')

    # ------------------ Feistel ------------------
    def _feistel(self, R: str, subkey48: str) -> str:
        # 1. Expansiune
        expanded = _permute(R, E_BOX)
        # 2. XOR cu sub-cheia
        xored = _xor_bits(expanded, subkey48)
        # 3. S-box-uri
        s_out_parts: List[str] = []
        for i in range(8):
            bloc6 = xored[i * 6 : (i + 1) * 6]
            row = int(bloc6[0] + bloc6[-1], 2)
            col = int(bloc6[1:5], 2)
            val = S_BOXES[i][row][col]
            s_out_parts.append(f"{val:04b}")
        s_out = ''.join(s_out_parts)
        # 4. Permutare P
        return _permute(s_out, P_BOX)

    # ------------------ Padding ------------------
    @staticmethod
    def _apply_pkcs7(data: bytes, blocksize: int = 8) -> bytes:
        rem = len(data) % blocksize
        if rem == 0:  # conform cerinței: nu adăugăm bloc suplimentar
            return data
        pad_len = blocksize - rem
        return data + bytes([pad_len] * pad_len)

    @staticmethod
    def _maybe_remove_pkcs7(data: bytes, blocksize: int = 8) -> bytes:
        if not data or len(data) % blocksize != 0:
            raise DESTextError("Datele pentru eliminare padding invalide.")
        pad_len = data[-1]
        if pad_len < 1 or pad_len > blocksize:
            return data  # nu pare padding valid
        if data[-pad_len:] != bytes([pad_len] * pad_len):
            return data
        return data[:-pad_len]

    def hex_to_ascii(self, hex_str: str) -> str:
        """Convertește un șir hex în text ASCII, eliminând padding-ul zero de la sfârșit."""
        try:
            data = bytes.fromhex(hex_str)
            # Elimină octeții zero de la sfârșit (padding zero)
            data = data.rstrip(b'\x00')
            return data.decode('utf-8')
        except (ValueError, UnicodeDecodeError) as exc:
            logger.warning("Conversie hex la ASCII eșuată: %s", exc)
            return "[EROARE] Nu se poate converti la ASCII"


# ==============================================================
# CLI
# ==============================================================
def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Implementare educațională DES (criptare / decriptare) în limba română.",
        epilog="Exemplu: python des-cipher.py --mode encrypt --key 133457799BBCDFF1 --text 0123456789ABCDEF",
    )
    p.add_argument("--mode", choices=["encrypt", "decrypt"], help="Mod operare: encrypt / decrypt")
    p.add_argument("--key", help="Cheie hex de 16 caractere (64 biți, includ biți de paritate)")
    p.add_argument("--text", help="Text hex (pentru encrypt: plaintext, pentru decrypt: ciphertext)")
    p.add_argument("--demo", action="store_true", help="Rulează exemplul clasic din documentație.")
    p.add_argument(
        "--padding",
        choices=["zero", "pkcs7", "none"],
        default="zero",
        help="Mod de padding pentru criptare/decriptare (implicit: zero).",
    )
    p.add_argument("--no-log-rounds", action="store_true", help="(Opțional) Reduce log-ul (NU dezactivează complet).")
    return p


def run_demo() -> None:
    """Rulează exemplul clasic din documentație pentru verificare."""
    print("=== DEMO DES (exemplu din documentație) ===")
    key = "133457799BBCDFF1"
    plaintext = "0123456789ABCDEF"
    expected_cipher = "85E813540F0AB405"
    des = DES(key)
    cipher = des.encrypt_hex(plaintext)
    print(f"Cheie:          {key}")
    print(f"Plaintext:      {plaintext}")
    print(f"Cipher (obținut): {cipher}")
    print(f"Cipher (așteptat): {expected_cipher}")
    if cipher == expected_cipher:
        print("[OK] Criptarea corespunde exemplului standard.")
    else:
        print("[EROARE] Rezultatul nu corespunde! Verificați implementarea.")
    back = des.decrypt_hex(cipher)
    print(f"Decriptare -> {back}")
    if back[:len(plaintext)] == plaintext:
        print("[OK] Decriptarea restabilește plaintext-ul (după eliminarea padding-ului).")
    else:
        print("[EROARE] Decriptarea nu corespunde plaintext-ului.")


def run_interactive() -> None:
    """Interfață interactivă simplă.

    Îmbunătățiri:
      - Acceptă plaintext ASCII sau hex la criptare. Dacă șirul introdus nu este hex valid,
        dar este ASCII imprimabil, este convertit automat în hex (UTF-8) și se afișează
        utilizatorului conversia pentru transparență.
      - Mesajele de eroare pentru text nu mai menționează "Cheia" generic, fiind neutre.
    """
    print("=== Interfață interactivă DES ===")
    print("1. Criptare (plaintext poate fi HEX sau ASCII)")
    print("2. Decriptare (input HEX)")
    print("3. Demo")
    print("0. Ieșire")
    opt = input("Alegeți opțiunea: ").strip()
    if opt == '1':
        key_raw = input("Introduceți cheia (hex 16 caractere): ").strip()
        text_raw = input("Introduceți plaintext (hex sau ASCII): ").strip()
        try:
            key = _sanitize_hex(key_raw, "cheie", require_even=True)
            des = DES(key, padding="zero")
            # Încearcă interpretare directă ca hex
            try:
                text_hex = _sanitize_hex(text_raw, "text de intrare", require_even=True)
                ascii_converted = False
            except DESTextError:
                # Dacă nu e hex valid, încearcă ASCII imprimabil
                if text_raw and all(ch.isprintable() and ch not in "\r\n\t" for ch in text_raw):
                    text_hex = text_raw.encode('utf-8').hex().upper()
                    ascii_converted = True
                else:
                    raise  # propagă eroarea originală
            cipher = des.encrypt_hex(text_hex)
            if ascii_converted:
                print(f"[INFO] Plaintext ASCII a fost convertit automat la hex: {text_hex}")
            print(f"Text cifrat: {cipher}")
        except (DESKeyError, DESTextError, DESEncryptionError) as exc:
            print(f"[EROARE] {exc}")
    elif opt == '2':
        key_raw = input("Introduceți cheia (hex 16 caractere): ").strip()
        text_raw = input("Introduceți ciphertext (hex): ").strip()
        try:
            key = _sanitize_hex(key_raw, "cheie", require_even=True)
            des = DES(key, padding="zero")
            plain = des.decrypt_hex(text_raw)
            print(f"Text decriptat (hex fără padding): {plain}")
            ascii_text = des.hex_to_ascii(plain)
            print(f"Text decriptat (ASCII): {ascii_text}")
        except (DESKeyError, DESTextError, DESEncryptionError) as exc:
            print(f"[EROARE] {exc}")
    elif opt == '3':
        run_demo()
    elif opt == '0':
        print("La revedere.")
    else:
        print("Opțiune invalidă.")


def main(argv: Optional[List[str]] = None) -> int:
    """Punctul de intrare principal."""
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    # Opțiune demo
    if args.demo:
        run_demo()
        return 0

    # Fără parametri -> interactiv
    if not args.mode:
        run_interactive()
        return 0

    if not args.key or not args.text:
        parser.error("--key și --text sunt necesare pentru modurile encrypt/decrypt.")

    try:
        des = DES(args.key.upper(), padding=args.padding)
        if args.mode == 'encrypt':
            result = des.encrypt_hex(args.text.upper())
            print(result)
        else:
            result = des.decrypt_hex(args.text.upper())
            print(result)
            ascii_result = des.hex_to_ascii(result)
            print(f"Text decriptat (ASCII): {ascii_result}")
    except (DESKeyError, DESTextError, DESEncryptionError) as exc:
        print(f"[EROARE] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
