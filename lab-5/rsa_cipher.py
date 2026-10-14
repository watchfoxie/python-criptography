"""Interfață CLI pentru criptare și decriptare RSA în cadrul cursului de criptografie.

Programul oferă trei moduri: criptare, decriptare și generator de chei. Implementarea
este orientată spre uz educațional și folosește algoritmul RSA fără scheme avansate de
padding, motiv pentru care blocurile sunt manipulate explicit. Pentru texte lungi, se
realizează segmentarea în funcție de dimensiunea cheii.

Realizat de studentul grupei IS31Z, Tocana Marian
"""

from __future__ import annotations

import base64
import binascii
import logging
import math
import secrets
import struct

import unicodedata
from dataclasses import dataclass
from pathlib import Path

from typing import List, Optional, Sequence, Tuple


# --------------------------- Configurație generală --------------------------- #

LOGGER = logging.getLogger("rsa_cli")
LOGGER.setLevel(logging.INFO)

_LOG_FILE = Path(__file__).resolve().parent / "rsa-cli.log"
_HANDLER = logging.FileHandler(_LOG_FILE, encoding="utf-8")
_FORMATTER = logging.Formatter(
    fmt="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
_HANDLER.setFormatter(_FORMATTER)
LOGGER.addHandler(_HANDLER)


# ----------------------------- Clase de erori ------------------------------ #


class ValidationTextError(ValueError):
    """Ridicată atunci când textul introdus nu respectă cerințele."""


class ValidationKeyError(ValueError):
    """Ridicată atunci când cheile RSA nu sunt valide."""


class EncryptionError(RuntimeError):
    """Ridicată pentru erori apărute în timpul criptării."""


class DecryptionError(RuntimeError):
    """Ridicată pentru erori apărute în timpul decriptării."""


class KeyGenerationError(RuntimeError):
    """Ridicată atunci când generarea cheilor nu poate fi finalizată."""


# ----------------------------- Structuri de date --------------------------- #


@dataclass
class RSAParameters:
    """Pachet minimal de parametri RSA."""

    n: int
    e: int
    d: int
    p: Optional[int]
    q: Optional[int]

    @property
    def key_size_bits(self) -> int:
        """Dimensiunea în biți a modulului n."""

        return self.n.bit_length()

    @property
    def key_size_bytes(self) -> int:
        """Dimensiunea în octeți a modulului n."""

        return (self.n.bit_length() + 7) // 8


# ----------------------------- Funcții utilitare --------------------------- #


def _normalize_text(text: str) -> str:
    """Normalizează textul conform convențiilor proiectului."""

    return unicodedata.normalize("NFC", text)


def _gcd(a: int, b: int) -> int:
    """Calculează cel mai mare divizor comun folosind algoritmul Euclid."""

    return math.gcd(a, b)


def _extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Aplică algoritmul extins Euclid pentru a determina inversul modular."""

    if b == 0:
        return a, 1, 0
    gcd_value, x1, y1 = _extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return gcd_value, x, y


def _mod_inverse(value: int, modulo: int) -> int:
    """Determină inversul modular al unui număr în raport cu un modul."""

    gcd_value, x, _ = _extended_gcd(value, modulo)
    if gcd_value != 1:
        raise ValidationKeyError("Nu există invers modular pentru exponentul ales.")
    return x % modulo


_SMALL_PRIMES: Tuple[int, ...] = (
    3,
    5,
    7,
    11,
    13,
    17,
    19,
    23,
    29,
    31,
    37,
    41,
    43,
    47,
    53,
    59,
    61,
    67,
    71,
    73,
    79,
    83,
    89,
    97,
    101,
    103,
    107,
    109,
    113,
)


def _is_probable_prime(candidate: int, rounds: int = 20) -> bool:
    """Verifică dacă valoarea este probabil primă folosind Miller-Rabin."""

    if candidate < 2:
        return False
    for prime in (2,) + _SMALL_PRIMES:
        if candidate == prime:
            return True
        if candidate % prime == 0:
            return False

    d = candidate - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = secrets.randbelow(candidate - 3) + 2
        x = pow(a, d, candidate)
        if x in (1, candidate - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, candidate)
            if x == candidate - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits: int) -> int:
    """Generează un număr prim cu lungimea dorită în biți."""

    if bits < 2:
        raise KeyGenerationError("Dimensiunea minimă pentru un prim este de 2 biți.")

    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            LOGGER.debug("Prim generat cu %s biți", bits)
            return candidate


def _choose_public_exponent(phi: int) -> int:
    """Selectează exponentul public conform bunelor practici."""

    preferred_exponents = (65537, 257, 17, 5, 3)
    for exponent in preferred_exponents:
        if exponent < phi and _gcd(exponent, phi) == 1:
            return exponent

    # Căutare fallback pentru cazul exotic în care toate valorile eșuează.
    candidate = 3
    while candidate < phi:
        if _gcd(candidate, phi) == 1:
            return candidate
        candidate += 2

    raise ValidationKeyError("Nu s-a putut găsi un exponent public valid.")


def _build_rsa_parameters(p: int, q: int, e: Optional[int] = None, display_phi: bool = False) -> RSAParameters:
    """Construiește parametrii RSA pe baza numerelor prime p și q."""

    if p <= 1 or q <= 1:
        raise ValidationKeyError("p și q trebuie să fie mai mari decât 1.")
    if p == q:
        raise ValidationKeyError("p și q trebuie să fie distincte.")
    if not _is_probable_prime(p):
        raise ValidationKeyError("Valoarea p introdusă nu este un număr prim.")
    if not _is_probable_prime(q):
        raise ValidationKeyError("Valoarea q introdusă nu este un număr prim.")

    n = p * q
    phi = (p - 1) * (q - 1)
    if display_phi:
        print(f"\nphi = {phi}\n")
    exponent = e if e is not None else _choose_public_exponent(phi)
    if _gcd(exponent, phi) != 1:
        raise ValidationKeyError(
            "Exponentul public ales nu este coprim cu funcția lui Euler φ(n)."
        )

    d = _mod_inverse(exponent, phi)
    return RSAParameters(n=n, e=exponent, d=d, p=p, q=q)


def _generate_key_pair(bit_size: int) -> RSAParameters:
    """Generează o pereche de chei RSA cu dimensiunea specificată."""

    half = bit_size // 2
    remainder = bit_size - half
    LOGGER.info("Generare chei RSA cu dimensiunea %s biți", bit_size)
    for attempt in range(1, 200):
        p = _generate_prime(half)
        q = _generate_prime(remainder)
        if p == q:
            continue
        try:
            params = _build_rsa_parameters(p, q)
        except ValidationKeyError:
            continue
        if params.key_size_bits < bit_size:
            continue
        LOGGER.info("Chei generate după %s încercări", attempt)
        return params
    raise KeyGenerationError("Nu s-au putut genera chei RSA după multiple încercări.")


def _validate_manual_modulus(n: int) -> None:
    """Validează dimensiunea modulului specificat manual."""

    bit_len = n.bit_length()
    if bit_len < 2048 or bit_len > 4096:
        raise ValidationKeyError(
            "Modulul n trebuie să aibă o dimensiune între 2048 și 4096 de biți."
        )


def _chunk_sizes(n: int) -> Tuple[int, int]:
    """Calculează dimensiunile blocurilor pentru criptare și decriptare."""

    key_bytes = (n.bit_length() + 7) // 8
    plain_chunk = max(1, (n.bit_length() - 1) // 8)
    if plain_chunk <= 0 or key_bytes <= 0:
        raise EncryptionError(
            "Modulul cheii este prea mic pentru a realiza operații de criptare."
        )
    return plain_chunk, key_bytes


def encrypt_message(message: str, n: int, e: int) -> str:
    """Criptează un mesaj cu parametrii publici ai algoritmului RSA."""

    normalized = _normalize_text(message)
    if not normalized.strip():
        raise ValidationTextError("Textul pentru criptare nu poate fi gol.")

    plain_bytes = normalized.encode("utf-8")
    plain_chunk, key_bytes = _chunk_sizes(n)

    if len(plain_bytes) > plain_chunk * 65535:
        raise EncryptionError(
            "Text prea mare pentru a fi procesat într-un singur flux RSA."
        )

    blocks: List[bytes] = []
    for index in range(0, len(plain_bytes), plain_chunk):
        block = plain_bytes[index : index + plain_chunk]
        block_int = int.from_bytes(block, byteorder="big", signed=False)
        if block_int >= n:
            raise EncryptionError(
                "Textul clar depășește limita impusă de dimensiunea cheii."
            )
        cipher_int = pow(block_int, e, n)
        cipher_block = cipher_int.to_bytes(key_bytes, byteorder="big")
        blocks.append(struct.pack(">H", len(block)) + cipher_block)

    ciphertext = b"".join(blocks)
    return base64.b64encode(ciphertext).decode("ascii")


def decrypt_message(ciphertext_b64: str, n: int, d: int) -> str:
    """Decriptează un mesaj în format Base64 folosind cheia privată RSA."""

    if not ciphertext_b64.strip():
        raise ValidationTextError("Textul criptat nu poate fi gol.")

    try:
        ciphertext_bytes = base64.b64decode(ciphertext_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DecryptionError(
            "Textul criptat furnizat nu este un Base64 valid."
        ) from exc

    plain_chunk, key_bytes = _chunk_sizes(n)
    if len(ciphertext_bytes) % (key_bytes + 2) != 0:
        raise DecryptionError("Structura textului criptat nu corespunde cheii alese.")

    plaintext_parts: List[bytes] = []
    offset = 0
    total_length = len(ciphertext_bytes)
    while offset < total_length:
        chunk_length = struct.unpack(">H", ciphertext_bytes[offset : offset + 2])[0]
        offset += 2
        cipher_block = ciphertext_bytes[offset : offset + key_bytes]
        if len(cipher_block) != key_bytes:
            raise DecryptionError(
                "Blocul criptat are o dimensiune incompatibilă cu cheia privată."
            )
        offset += key_bytes
        cipher_int = int.from_bytes(cipher_block, byteorder="big", signed=False)
        plain_int = pow(cipher_int, d, n)
        block_bytes = plain_int.to_bytes(plain_chunk, byteorder="big")
        plaintext_parts.append(block_bytes[-chunk_length:])

    try:
        return b"".join(plaintext_parts).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecryptionError(
            "Decriptarea a eșuat – rezultatul nu este un text UTF-8 valid."
        ) from exc


# ----------------------- Persistența cheilor la nivel de fișier ----------------------- #

ROOT_DIR = Path(__file__).resolve().parent
KEYS_PATH = ROOT_DIR / "keys.txt"
GENERATOR_PATH = ROOT_DIR / "generator.txt"


def _write_key_file(path: Path, params: RSAParameters) -> bool:
    """Scrie fișierul de chei în formatul cerut."""

    lines = [f"{params.e},{params.n}", "", f"{params.d},{params.n}"]
    try:
        path.write_text("\n".join(lines), encoding="utf-8")
        LOGGER.info("Fișierul %s a fost actualizat.", path.name)
        return True
    except OSError as exc:
        LOGGER.error("Nu s-a putut scrie fișierul %s: %s", path, exc)
        return False


def _read_keys_from_file(path: Path) -> Tuple[int, int, int]:
    """Citește valorile e, d și n din fișierul specificat."""

    if not path.exists():
        raise FileNotFoundError("Fișierul keys.txt nu există sau este corupt.")

    content = path.read_text(encoding="utf-8").splitlines()
    parsed = [line.strip() for line in content if line.strip()]
    if len(parsed) < 2:
        raise ValueError("Conținutul fișierului de chei este incomplet.")

    try:
        e_str, n_pub_str = parsed[0].split(",", maxsplit=1)
        d_str, n_priv_str = parsed[1].split(",", maxsplit=1)
    except ValueError as exc:
        raise ValueError("Format invalid în fișierul de chei.") from exc

    if n_pub_str != n_priv_str:
        raise ValueError(
            "Valorile modulului din fișierul de chei nu corespund între ele."
        )

    try:
        e_val = int(e_str)
        d_val = int(d_str)
        n_val = int(n_pub_str)
    except ValueError as exc:
        raise ValueError("Valorile din fișier nu sunt numere întregi valide.") from exc

    return e_val, d_val, n_val


# ----------------------------- Funcții de input CLI ----------------------------- #


def _prompt_choice(message: str, options: Sequence[str]) -> str:
    """Solicită o opțiune de la utilizator dintr-o listă precizată."""

    lowered = {option.lower(): option for option in options}
    numeric_map = {str(index + 1): option for index, option in enumerate(options)}

    while True:
        print(message)
        for index, option in enumerate(options, start=1):
            print(f"  {index}. {option}")
        response = input("Introduceți opțiunea dorită: ").strip().lower()
        if response in lowered:
            print("\n")
            return lowered[response]
        if response in numeric_map:
            print("\n")
            return numeric_map[response]
        print("Opțiune invalidă. Încercați din nou.\n")


def _prompt_yes_no(message: str) -> bool:
    """Primește un răspuns de tip Da/Nu din partea utilizatorului."""

    while True:
        response = input(message).strip().lower()
        if response in {"da", "d", "yes", "y"}:
            return True
        if response in {"nu", "n", "no"}:
            return False
        print("Răspuns invalid. Introduceți 'Da' sau 'Nu'.")


def _prompt_bigint(message: str) -> int:
    """Solicită o valoare întreagă (potențial foarte mare)."""

    while True:
        value = input(message).strip()
        try:
            return int(value)
        except ValueError:
            print(
                "Valoarea introdusă nu este un număr întreg valid. Încercați din nou."
            )


def _prompt_plaintext() -> str:
    """Solicită textul clar pentru criptare."""

    text = input("Introduceți textul clar (UTF-8): ")
    normalized = _normalize_text(text)
    if not normalized.strip():
        raise ValidationTextError("Textul nu poate fi gol.")
    print("\n")
    return normalized


def _prompt_ciphertext() -> str:
    """Solicită textul criptat în format Base64."""

    result = input("Introduceți textul criptat (Base64): ").strip()
    print("\n")
    return result


# ----------------------------- Module operaționale ----------------------------- #


def _handle_key_generation(bit_mode: str) -> RSAParameters:
    """Gestionează alegerea dintre lista standard și introducerea manuală."""

    if bit_mode.lower() == "lista standard":
        bit_choice = _prompt_choice(
            "Selectați dimensiunea cheii (biți):", ["2048", "3072", "4096"]
        )
        return _generate_key_pair(int(bit_choice))

    if bit_mode.lower() == "manual":
        p = _prompt_bigint("Introduceți p (prim): ")
        q = _prompt_bigint("Introduceți q (prim, distinct de p): ")
        params = _build_rsa_parameters(p, q, display_phi=True)
        _validate_manual_modulus(params.n)
        return params

    raise ValidationKeyError("Mod de generare necunoscut.")


def _handle_encryption() -> None:
    """Gestionează modul de criptare."""

    key_mode = _prompt_choice(
        "Selectați modul de generare a cheilor:",
        [
            "lista standard",
            "manual",
        ],
    )
    params = _handle_key_generation(key_mode)

    if _write_key_file(KEYS_PATH, params):
        print("Fișierul keys.txt a fost creat cu succes.")
        print("\n")
    else:
        print("Eroare: Nu s-a putut crea fișierul keys.txt.")

    plaintext = _prompt_plaintext()

    public_mode = _prompt_choice(
        "Alegeți cheia publică de utilizat:",
        ["cheia publică generată", "cheia publică manuală"],
    )

    if public_mode.lower() == "cheia publică generată":
        public_e = params.e
        public_n = params.n
    else:
        raw_public = input("Introduceți cheia publică (format e,n): ").strip()
        try:
            e_str, n_str = (
                piece.strip() for piece in raw_public.split(",", maxsplit=1)
            )
            public_e = int(e_str)
            public_n = int(n_str)
        except (ValueError, AttributeError) as exc:
            raise ValidationKeyError("Formatul cheii publice este invalid.") from exc
        if public_e <= 1 or public_n <= 1:
            raise ValidationKeyError(
                "Cheia publică trebuie să conțină valori pozitive."
            )
        if public_e >= public_n:
            raise ValidationKeyError(
                "Exponentul public trebuie să fie mai mic decât n."
            )
        if _gcd(public_e, public_n) != 1:
            raise ValidationKeyError("Exponentul public trebuie să fie coprim cu n.")

    ciphertext_b64 = encrypt_message(plaintext, public_n, public_e)
    print("Text criptat (Base64):")
    print(ciphertext_b64)
    print("\n")


def _handle_decryption() -> None:
    """Gestionează modul de decriptare."""

    ciphertext = _prompt_ciphertext()
    key_mode = _prompt_choice(
        "Selectați cheia privată de utilizat:",
        ["cheia privată generată", "cheia privată manuală"],
    )

    if key_mode.lower() == "cheia privată generată":
        try:
            _, d_val, n_val = _read_keys_from_file(KEYS_PATH)
        except (OSError, ValueError, FileNotFoundError) as exc:
            raise DecryptionError(
                "Eroare: Fișierul keys.txt nu există sau este corupt."
            ) from exc
        private_d = d_val
        private_n = n_val
    else:
        raw_private = input("Introduceți cheia privată (format d,n): ").strip()
        try:
            d_str, n_str = (
                piece.strip() for piece in raw_private.split(",", maxsplit=1)
            )
            private_d = int(d_str)
            private_n = int(n_str)
        except (ValueError, AttributeError) as exc:
            raise ValidationKeyError("Formatul cheii private este invalid.") from exc
        if private_d <= 1 or private_n <= 1:
            raise ValidationKeyError(
                "Cheia privată trebuie să fie alcătuită din valori pozitive."
            )
        if private_d >= private_n:
            raise ValidationKeyError(
                "Exponentul privat trebuie să fie mai mic decât n."
            )

    plaintext = decrypt_message(ciphertext, private_n, private_d)
    print("Text decriptat:")
    print(plaintext)
    print("\n")


def _handle_key_generator() -> None:
    """Gestionarea modului de generator de chei."""

    bit_mode = _prompt_choice(
        "Selectați modul de generare a cheilor:", ["lista standard", "manual"]
    )
    params = _handle_key_generation(bit_mode)

    if _write_key_file(GENERATOR_PATH, params):
        print("Fișierul generator.txt a fost creat cu succes.")
        print("\n")
    else:
        print("Eroare: Nu s-a putut crea fișierul generator.txt.")


# ----------------------------- Bucla principală CLI ----------------------------- #


def run_cli() -> None:
    """Rulează bucla interactivă a programului."""

    print("Criptografie. Cifrarea RSA: criptare, decriptare, generator chei")
    while True:
        try:
            mode = _prompt_choice(
                "Alegeți modul de operare:",
                ["criptare", "decriptare", "generator chei"],
            )
            if mode.lower() == "criptare":
                _handle_encryption()
            elif mode.lower() == "decriptare":
                _handle_decryption()
            elif mode.lower() == "generator chei":
                _handle_key_generator()
            else:
                print("Opțiune necunoscută.")
        except (
            ValidationTextError,
            ValidationKeyError,
            EncryptionError,
            DecryptionError,
            KeyGenerationError,
        ) as exc:
            LOGGER.warning("Operațiune eșuată: %s", exc)
            print(f"Eroare: {exc}")
            print("\n")
        except KeyboardInterrupt:
            print("\nOperațiune întreruptă de utilizator.")
            LOGGER.info("Execuție întreruptă manual de utilizator")
        except EOFError:
            print("\nIntrare neașteptată de tip EOF. Programul se închide.")
            break

        if not _prompt_yes_no("Doriți să executați o nouă operațiune? (Da/Nu): "):
            print("\n")
            print("Programul s-a încheiat. La revedere!")
            break


def main() -> None:
    """Punctul de intrare principal pentru rularea din linia de comandă."""

    try:
        run_cli()
    finally:
        for handler in list(LOGGER.handlers):
            handler.flush()


if __name__ == "__main__":
    main()
