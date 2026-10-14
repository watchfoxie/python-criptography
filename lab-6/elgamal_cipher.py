"""Program pentru sistemul de criptare ElGamal.

Implementare conform specificației: generare chei (prime sigure 2048-4096 biți),
criptare și decriptare cu serializare Base64 a perechilor (A, B) și gestionare
interactivă/argumente CLI.

Lucru efectuat:
- Adăugat suport pentru sys.set_int_max_str_digits pentru chei mari.
- Tratare a erorilor de 'Overflow' la decriptarea cu chei greșite.
- Curățare input manual pentru chei.
- Eliminat generarea automată a unei chei private arbitrare în recipient.txt;
  acum cerem/validăm explicit cheia privată dacă utilizatorul dorește să o salveze.
- Validare matematică (y == alpha^a mod p) atunci când sunt prezente cheie publică și privată.

Realizat de studentul grupei IS31Z, Tocana Marian
"""

from __future__ import annotations

import argparse
import base64
import secrets
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple


# --- Configurare mediu Python (pentru chei mari) ---
try:
    # Cheile criptografice mari depășesc frecvent acest lucru la debug/afisare.
    sys.set_int_max_str_digits(0)  # 0 dezactivează limita
except AttributeError:
    pass 

# --- Constante și mesaje standard ---
MIN_BITS = 2048
MAX_BITS = 4096
MR_ROUNDS = 40
DEFAULT_KEY_SIZES = (2048, 3072, 4096)
PROGRESS_LOG_EVERY = 20

ERR_PREFIX = "[EROARE]"
INFO_PREFIX = "[INFO]"
ROOT_DIR = Path(__file__).resolve().parent
KEY_FILE = ROOT_DIR / "keys.txt"
GENERATOR_FILE = ROOT_DIR / "generator.txt"
RECIPIENT_FILE = ROOT_DIR / "recipient.txt"


# --- Tipuri de date ---
@dataclass
class PublicKey:
    p: int
    g: int  # alias pentru alpha
    y: int


@dataclass
class PrivateKey:
    p: int
    a: int


@dataclass
class CipherBlock:
    A: int
    B: int
    plain_len: int  # lungimea în bytes a blocului de text clar


# --- Utilitare aritmetice ---
SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97,
]


def is_probable_prime(n: int, rounds: int = MR_ROUNDS) -> bool:
    """Test probabilistic Miller–Rabin (întoarce True pentru "probabil prim")."""
    if n < 2:
        return False
    for p in SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def factorize_phi(n: int) -> List[int]:
    """Întoarce factorii primi unici ai lui n (parțial pentru numere mari)."""
    factors: List[int] = []
    temp = n
    for p in SMALL_PRIMES:
        if temp % p == 0:
            factors.append(p)
            while temp % p == 0:
                temp //= p
    f = 101
    limit = 100_000
    while f * f <= temp and f <= limit:
        if temp % f == 0:
            factors.append(f)
            while temp % f == 0:
                temp //= f
        f += 2
    if temp > 1:
        factors.append(temp)
    return factors


def generate_prime(bits: int, *, show_progress: bool = False) -> int:
    """Generează un prim p de dimensiunea bits, folosind CSPRNG."""
    if bits < MIN_BITS or bits > MAX_BITS:
        raise ValueError(
            f"Dimensiunea cheii trebuie să fie între {MIN_BITS} și {MAX_BITS} biți."
        )

    attempts = 0
    start = time.perf_counter()
    while True:
        attempts += 1
        p = secrets.randbits(bits) | 1
        p |= 1 << (bits - 1)

        if is_probable_prime(p):
            return p
        if show_progress and attempts % PROGRESS_LOG_EVERY == 0:
            elapsed = time.perf_counter() - start
            print(f"{INFO_PREFIX} Încercare {attempts}: se continuă căutarea unui prim... ({elapsed:.1f}s)")


def find_generator(p: int) -> int:
    """Caută un generator (rădăcină primitivă) pentru p prim."""
    factors = factorize_phi(p - 1)
    while True:
        g = secrets.randbelow(p - 3) + 2
        if all(pow(g, (p - 1) // q, p) != 1 for q in factors):
            return g


def mod_inverse(a: int, p: int) -> int:
    """Invers modular folosind teorema lui Fermat (p este prim)."""
    return pow(a, p - 2, p)


def validate_key_match(pub: PublicKey, priv: PrivateKey) -> None:
    """Verifică dacă y == g^a mod p; aruncă ValueError dacă nu corespunde."""
    if pow(pub.g, priv.a, pub.p) != pub.y:
        raise ValueError(
            f"{ERR_PREFIX} Cheia privată nu corespunde cheii publice: y != alpha^a mod p."
        )


# --- Conversii text <-> număr & segmentare ---
def chunk_plaintext(message: str, p: int) -> List[Tuple[int, int]]:
    """Împarte mesajul în blocuri (int, len_bytes) potrivite pentru p."""
    data = message.encode("utf-8")
    if not data:
        raise ValueError("Textul de criptat nu poate fi gol.")

    # Se scade 1 bit pentru siguranță (m < p)
    max_block_bytes = max(1, (p.bit_length() - 1) // 8)
    blocks: List[Tuple[int, int]] = []
    for i in range(0, len(data), max_block_bytes):
        chunk = data[i : i + max_block_bytes]
        blocks.append((int.from_bytes(chunk, "big"), len(chunk)))
    return blocks


def blocks_to_plaintext(blocks: Iterable[Tuple[int, int]]) -> str:
    """Reconstruiește textul UTF-8 din blocuri (int, len_bytes)."""
    buf = bytearray()
    for value, ln in blocks:
        if ln == 0:
            continue
        try:
            # Dacă cheia e greșită, 'value' (m) este un număr random imens (modulo p),
            # care nu încape în 'ln' bytes (lungimea originală a mesajului).
            chunk_bytes = value.to_bytes(ln, "big")
            buf.extend(chunk_bytes)
        except OverflowError as exc:
            raise ValueError(
                "Eșec matematic la decriptare. Cheia privată este probabil incorectă "
                "sau criptotextul este corupt."
            ) from exc
    try:
        return buf.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(
            "Mesajul decriptat nu este text UTF-8 valid. Cheia privată este probabil incorectă."
        ) from exc


# --- Serializare / deserializare criptotext ---
def serialize_cipher(blocks: Sequence[CipherBlock]) -> str:
    """Serializează lista (A,B,len) în binar + Base64."""
    parts = bytearray()
    for blk in blocks:
        # Calculăm numărul de bytes necesari pentru A și B
        a_len_bytes = (blk.A.bit_length() + 7) // 8 or 1
        b_len_bytes = (blk.B.bit_length() + 7) // 8 or 1

        a_bytes = blk.A.to_bytes(a_len_bytes, "big")
        b_bytes = blk.B.to_bytes(b_len_bytes, "big")

        parts.extend(len(a_bytes).to_bytes(4, "big"))
        parts.extend(a_bytes)
        parts.extend(len(b_bytes).to_bytes(4, "big"))
        parts.extend(b_bytes)
        parts.extend(blk.plain_len.to_bytes(2, "big"))
    return base64.b64encode(parts).decode("ascii")


def deserialize_cipher(payload: str) -> List[Tuple[int, int, int]]:
    """Decodifică Base64 și extrage lista (A, B, plain_len)."""
    try:
        data = base64.b64decode(payload, validate=True)
    except Exception as exc:
        raise ValueError("Formatul Base64 al criptotextului este invalid.") from exc

    idx = 0
    out: List[Tuple[int, int, int]] = []

    # Parsing al structurii binare
    while idx < len(data):
        # Citire lungime A
        if idx + 4 > len(data):
            break
        len_a = int.from_bytes(data[idx : idx + 4], "big")
        idx += 4

        # Citire A
        if idx + len_a > len(data):
            raise ValueError("Criptotext trunchiat: A lipsește.")
        A = int.from_bytes(data[idx : idx + len_a], "big")
        idx += len_a

        # Citire lungime B
        if idx + 4 > len(data):
            raise ValueError("Criptotext trunchiat: lungime B lipsește.")
        len_b = int.from_bytes(data[idx : idx + 4], "big")
        idx += 4

        # Citire B
        if idx + len_b > len(data):
            raise ValueError("Criptotext trunchiat: B lipsește.")
        B = int.from_bytes(data[idx : idx + len_b], "big")
        idx += len_b

        # Citire lungime clar
        if idx + 2 > len(data):
            raise ValueError("Criptotext trunchiat: lungime bloc clar lipsește.")
        plain_len = int.from_bytes(data[idx : idx + 2], "big")
        idx += 2

        out.append((A, B, plain_len))

    if not out:
        raise ValueError("Criptotextul este gol sau invalid.")

    return out


# --- Chei & fișiere ---
def save_keys(public_key: PublicKey, private_key: PrivateKey, filename: Path) -> None:
    """Salvează cheile în fișier (ini-style)."""
    content = (
        "[Cheie Publică]\n"
        f"p={public_key.p}\n"
        f"alpha={public_key.g}\n"
        f"y={public_key.y}\n\n"
        "[Cheie Privată]\n"
        f"a={private_key.a}\n"
    )
    filename.write_text(content, encoding="utf-8")


def parse_key_file(text: str) -> dict:
    """Helper pentru parsarea fișierelor de chei (ini-style)."""
    data = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("[") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        if key in ["p", "alpha", "y", "a"]:
            data[key] = int(val.strip())
    return data


def load_public_key(path: Path) -> PublicKey:
    """Încarcă cheia publică din fișier."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"{ERR_PREFIX} Fișierul '{path.name}' nu există.") from exc

    data = parse_key_file(text)
    try:
        return PublicKey(p=data["p"], g=data["alpha"], y=data["y"])
    except KeyError as exc:
        raise ValueError(f"{ERR_PREFIX} Fișierul '{path.name}' este incomplet. Lipsește: {exc}")


def load_private_key(path: Path) -> PrivateKey:
    """Încarcă cheia privată din fișier."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"{ERR_PREFIX} Fișierul '{path.name}' nu există.") from exc

    data = parse_key_file(text)
    try:
        priv = PrivateKey(p=data["p"], a=data["a"])
    except KeyError as exc:
        raise ValueError(f"{ERR_PREFIX} Fișierul '{path.name}' este incomplet. Lipsește: {exc}")

    # Dacă în fișier există și alpha/y, verificăm consistența pentru a evita chei greșite.
    if "alpha" in data and "y" in data:
        validate_key_match(PublicKey(p=data["p"], g=data["alpha"], y=data["y"]), priv)

    return priv


# --- Logica ElGamal ---
def generate_keypair(
    bits: Optional[int] = None,
    prime: Optional[int] = None,
    *,
    show_progress: bool = False,
) -> Tuple[PublicKey, PrivateKey]:
    """Generează o pereche de chei ElGamal."""
    if prime is not None:
        p = prime
    elif bits is not None:
        p = generate_prime(bits, show_progress=show_progress)
    else:
        raise ValueError("Trebuie specificat bits sau prime pentru generarea cheii.")

    g = find_generator(p)
    a = secrets.randbelow(p - 3) + 2
    y = pow(g, a, p)
    return PublicKey(p=p, g=g, y=y), PrivateKey(p=p, a=a)


def encrypt_message(public_key: PublicKey, message: str) -> str:
    """Criptează mesajul folosind cheia publică ElGamal."""
    blocks = chunk_plaintext(message, public_key.p)
    cipher_blocks: List[CipherBlock] = []
    for m, ln in blocks:
        if m >= public_key.p:
            raise ValueError(
                "Mesajul este prea lung pentru dimensiunea cheii. Utilizați o cheie mai mare."
            )
        k = secrets.randbelow(public_key.p - 3) + 2
        A = pow(public_key.g, k, public_key.p)
        B = (pow(public_key.y, k, public_key.p) * m) % public_key.p
        cipher_blocks.append(CipherBlock(A=A, B=B, plain_len=ln))
    return serialize_cipher(cipher_blocks)


def decrypt_message(private_key: PrivateKey, payload: str) -> str:
    """Decriptează mesajul folosind cheia privată ElGamal."""
    triples = deserialize_cipher(payload)
    blocks: List[Tuple[int, int]] = []
    for A, B, ln in triples:
        if ln <= 0:
            continue
        # Verificare limite matematice de bază
        if not (1 < A < private_key.p):
            # Dacă A > p, cheia p folosită la decriptare e mai mică decât cea de criptare
            # sau criptotextul e corupt.
            raise ValueError("Blocul A nu este valid modulo p. Chei nepotrivite?")

        s = pow(A, private_key.a, private_key.p)
        m = (B * mod_inverse(s, private_key.p)) % private_key.p
        blocks.append((m, ln))
    return blocks_to_plaintext(blocks)


# --- CLI interactiv ---
WELCOME = (
    "Criptografie. Sistemul de Criptare ElGamal: criptare, decriptare, generator chei."
)


def prompt_choice(prompt: str, choices: Sequence[str]) -> int:
    """Afișează un meniu și returnează indexul opțiunii alese (1-based)."""
    while True:
        print(prompt)
        for idx, label in enumerate(choices, 1):
            print(f"{idx}. {label}")
        sel = input("Opțiunea dumneavoastră: ").strip()
        if not sel.isdigit():
            print(f"{ERR_PREFIX} Introduceți un număr valid.")
            continue
        val = int(sel)
        if 1 <= val <= len(choices):
            return val
        print(f"{ERR_PREFIX} Opțiune invalidă.")


def choose_file_from_candidates(candidates: List[Path]) -> Path:
    """Alege un fișier din lista de candidați, afișând un meniu."""
    if not candidates:
        raise FileNotFoundError("Nu există fișiere disponibile.")
    if len(candidates) == 1:
        return candidates[0]
    print("Selectați fișierul:")
    for idx, path in enumerate(candidates, 1):
        print(f"{idx}. {path.name}")
    while True:
        sel = input("Opțiunea dumneavoastră: ").strip()
        if not sel.isdigit():
            print(f"{ERR_PREFIX} Introduceți un număr valid.")
            continue
        val = int(sel)
        if 1 <= val <= len(candidates):
            return candidates[val - 1]
        print(f"{ERR_PREFIX} Opțiune invalidă.")


def clean_input_int(prompt_text: str) -> int:
    """Citește un întreg mare, curățând spațiile și caracterele invizibile."""
    raw = input(prompt_text).strip()
    # Elimină spații interne care pot apărea la copy-paste
    raw = raw.replace(" ", "").replace("\t", "").replace("\n", "")
    if not raw.isdigit():
        raise ValueError("Valoarea introdusă nu este un număr valid.")
    return int(raw)


def select_prime_for_generation() -> int:
    """Selectează un prim pentru generarea cheii (din listă sau manual)."""
    options = [f"{size} biți (prim)" for size in DEFAULT_KEY_SIZES] + ["Manual (introduceți p prim)"]
    choice = prompt_choice("Selectați dimensiunea cheii:", options)
    if choice <= len(DEFAULT_KEY_SIZES):
        bits = DEFAULT_KEY_SIZES[choice - 1]
        print(f"Generare prim de {bits} biți... poate dura câteva momente.")
        return generate_prime(bits, show_progress=True)

    while True:
        try:
            p = clean_input_int("Introduceți numărul prim p: ")
        except ValueError:
            print(f"{ERR_PREFIX} Valoarea introdusă nu este numerică.")
            continue

        bits = p.bit_length()
        if bits < MIN_BITS or bits > MAX_BITS:
            print(f"{ERR_PREFIX} Avertisment: Cheia are {bits} biți (recomandat {MIN_BITS}-{MAX_BITS}).")

        print(f"{INFO_PREFIX} Se verifică primalitatea...")
        if not is_probable_prime(p):
            print(f"{ERR_PREFIX} Valoarea introdusă nu este un număr prim valid.")
            continue
        return p


def interactive_generate_keys(default_filename: Path = GENERATOR_FILE) -> None:
    """Generează o pereche de chei ElGamal interactiv și le salvează într-un fișier."""
    print("\n=== Generator Chei ElGamal ===")
    try:
        p = select_prime_for_generation()
        bits = p.bit_length()
        print(f"Generare pereche de chei {bits}-biți în curs... Vă rugăm așteptați.")
    except KeyboardInterrupt:
        print(f"{INFO_PREFIX} Operațiune anulată de utilizator.")
        return
    try:
        pub, priv = generate_keypair(prime=p)
        save_keys(pub, priv, default_filename)
        print("Cheile au fost generate cu succes!")
        print(f"Cheia Publică:\np={pub.p}\nα={pub.g}\ny={pub.y}")
        print(f"Fișierul {default_filename.name} a fost creat cu succes.")
    except Exception as exc:
        print(f"{ERR_PREFIX} Nu s-a putut crea fișierul {default_filename.name}. Detalii: {exc}")


def save_recipient_file(public_key: PublicKey, private_key: Optional[PrivateKey] = None) -> None:
    """Salvează cheile în recipient.txt; secțiunea privată este inclusă doar dacă este furnizată."""
    content = (
        "[Cheie Publică]\n"
        f"p={public_key.p}\n"
        f"alpha={public_key.g}\n"
        f"y={public_key.y}\n"
    )
    if private_key is not None:
        content += (
            "\n[Cheie Privată]\n"
            f"a={private_key.a}\n"
        )
    RECIPIENT_FILE.write_text(content, encoding="utf-8")
    if private_key is not None:
        print(f"Fișierul {RECIPIENT_FILE.name} (publică + privată) a fost creat cu succes.")
    else:
        print(f"Fișierul {RECIPIENT_FILE.name} (doar cheie publică) a fost creat cu succes.")


def load_public_key_interactive() -> PublicKey:
    """Încarcă cheia publică interactiv (din fișier, manual sau generare nouă)."""
    choice = prompt_choice(
        "Selectați sursa cheii publice:",
        [
            "Din fișier (generator.txt sau keys.txt)",
            "Introducere manuală",
            "Generează cheie nouă",
        ],
    )
    if choice == 1:
        candidates = [path for path in (KEY_FILE, GENERATOR_FILE) if path.exists()]
        if not candidates:
            raise FileNotFoundError(f"{ERR_PREFIX} Niciun fișier de chei nu a fost găsit.")
        chosen_file = choose_file_from_candidates(candidates)
        return load_public_key(chosen_file)
    if choice == 3:
        interactive_generate_keys(KEY_FILE)
        return load_public_key(KEY_FILE)

    # Manual
    try:
        p = clean_input_int("p = ")
        g = clean_input_int("alpha = ")
        y = clean_input_int("y = ")
    except ValueError as e:
        raise ValueError(f"{ERR_PREFIX} {e}")

    if not is_probable_prime(p):
        raise ValueError(f"{ERR_PREFIX} Valoarea 'p' introdusă nu este un număr prim valid.")
    if not (1 < g < p) or not (1 < y < p):
        raise ValueError(f"{ERR_PREFIX} Valorile alpha și y trebuie să fie în intervalul (1, p-1).")

    # Întrebăm dacă utilizatorul are cheia privată asociată pentru a salva un fișier complet.
    add_priv = input("Doriți să introduceți și cheia privată asociată (a) pentru a salva un fișier complet? (Da/Nu): ").strip().lower()
    priv: Optional[PrivateKey] = None
    if add_priv in {"da", "d", "y", "yes"}:
        try:
            a_val = clean_input_int("a = ")
        except ValueError as e:
            raise ValueError(f"{ERR_PREFIX} {e}")
        if not (1 < a_val < p - 1):
            raise ValueError(f"{ERR_PREFIX} Cheia privată 'a' trebuie să fie în intervalul (1, p-1).")
        priv = PrivateKey(p=p, a=a_val)
        validate_key_match(PublicKey(p, g, y), priv)

    save_recipient_file(PublicKey(p, g, y), priv)
    return PublicKey(p=p, g=g, y=y)


def load_private_key_interactive() -> PrivateKey:
    """Încarcă cheia privată interactiv (din fișier sau manual)."""
    choice = prompt_choice(
        "Selectați sursa cheii private:",
        ["Din fișier (generator.txt/keys.txt/recipient.txt)", "Introducere manuală"],
    )
    if choice == 1:
        candidates = [path for path in (KEY_FILE, GENERATOR_FILE, RECIPIENT_FILE) if path.exists()]
        if not candidates:
            raise FileNotFoundError(f"{ERR_PREFIX} Niciun fișier de chei nu a fost găsit.")
        chosen_file = choose_file_from_candidates(candidates)
        return load_private_key(chosen_file)

    try:
        p = clean_input_int("p = ")
        a = clean_input_int("a = ")
    except ValueError as e:
        raise ValueError(f"{ERR_PREFIX} {e}")

    if not is_probable_prime(p):
        raise ValueError(f"{ERR_PREFIX} Valoarea 'p' nu este un număr prim valid.")
    if not (1 < a < p - 1):
        raise ValueError(f"{ERR_PREFIX} Cheia privată 'a' trebuie să fie în intervalul (1, p-1).")

    return PrivateKey(p=p, a=a)


def interactive_encrypt() -> None:
    """Interfață interactivă pentru criptarea unui mesaj."""
    print("\n=== Criptare ElGamal ===")
    try:
        pub = load_public_key_interactive()
    except Exception as exc:
        print(exc)
        return

    message = input("Introduceți mesajul de criptat: ")
    try:
        cipher = encrypt_message(pub, message)
        print("Criptare în curs...")
        print("Textul criptat (Base64):")
        print(cipher)
    except Exception as exc:
        print(f"{ERR_PREFIX} {exc}")


def interactive_decrypt() -> None:
    """Interfață interactivă pentru decriptarea unui mesaj."""
    print("\n=== Decriptare ElGamal ===")
    payload = input("Introduceți criptotextul (Base64): ").strip()
    if not payload:
        print(f"{ERR_PREFIX} Criptotext gol.")
        return

    try:
        priv = load_private_key_interactive()
    except Exception as exc:
        print(exc)
        return

    try:
        plain = decrypt_message(priv, payload)
        print("Mesaj decriptat:")
        print(plain)
    except ValueError as exc:
        print(f"{ERR_PREFIX} {exc}")
    except Exception as exc:
        print(f"{ERR_PREFIX} Eroare neașteptată la decriptare: {exc}")


def interactive_menu() -> None:
    """Meniu interactiv principal."""
    print(f"\n=== {WELCOME} ===\n")
    while True:
        choice = prompt_choice(
            "Selectați modul de operare:",
            ["Criptare", "Decriptare", "Generator Chei", "Ieșire"],
        )
        if choice == 1:
            interactive_encrypt()
        elif choice == 2:
            interactive_decrypt()
        elif choice == 3:
            interactive_generate_keys()
        else:
            print("Programul s-a încheiat. La revedere!")
            return

        again = input("Doriți să efectuați o altă operațiune? (Da/Nu): ").strip().lower()
        if again not in {"da", "d", "y", "yes"}:
            print("Programul s-a încheiat. La revedere!")
            return


# --- CLI non-interactiv prin argumente ---
def build_arg_parser() -> argparse.ArgumentParser:
    """Construiește parserul de argumente pentru CLI."""
    parser = argparse.ArgumentParser(description=WELCOME)
    sub = parser.add_subparsers(dest="command")

    gen = sub.add_parser("gen-keys", help="Generează chei ElGamal")
    gen.add_argument(
        "--bits",
        type=int,
        choices=DEFAULT_KEY_SIZES,
        default=3072,
        help="Dimensiunea cheii (biți)",
    )
    gen.add_argument("--out", type=Path, default=GENERATOR_FILE, help="Fișier ieșire chei")

    enc = sub.add_parser("encrypt", help="Criptează un mesaj")
    enc.add_argument("--message", required=True, help="Mesajul de criptat")
    enc.add_argument("--p", type=int, help="Parametrul p")
    enc.add_argument("--alpha", type=int, help="Generatorul alpha")
    enc.add_argument("--y", type=int, help="Componenta publică y")
    enc.add_argument(
        "--pub", type=Path, help="Fișier cheie publică (keys.txt/generator.txt)"
    )

    dec = sub.add_parser("decrypt", help="Decriptează un criptotext Base64")
    dec.add_argument("--cipher", required=True, help="Criptotext Base64")
    dec.add_argument("--p", type=int, help="Parametrul p")
    dec.add_argument("--a", type=int, help="Cheia privată a")
    dec.add_argument(
        "--priv", type=Path, help="Fișier cheie privată (keys.txt/generator.txt/recipient.txt)"
    )

    return parser


def handle_args(args: argparse.Namespace) -> None:
    """Procesează argumentele CLI și apelează funcțiile corespunzătoare."""
    if args.command == "gen-keys":
        try:
            pub, priv = generate_keypair(bits=args.bits, show_progress=True)
            save_keys(pub, priv, args.out)
            print(f"Chei generate în {args.out}")
        except Exception as exc:
            print(f"{ERR_PREFIX} {exc}")
        return

    if args.command == "encrypt":
        try:
            if args.pub:
                pub = load_public_key(args.pub)
            else:
                if args.p is None or args.alpha is None or args.y is None:
                    raise ValueError("Furnizați p, alpha, y sau un fișier public.")
                pub = PublicKey(p=args.p, g=args.alpha, y=args.y)
            cipher = encrypt_message(pub, args.message)
            print(cipher)
        except Exception as exc:
            print(f"{ERR_PREFIX} {exc}")
        return

    if args.command == "decrypt":
        try:
            if args.priv:
                priv = load_private_key(args.priv)
            else:
                if args.p is None or args.a is None:
                    raise ValueError("Furnizați p și a sau un fișier privat.")
                priv = PrivateKey(p=args.p, a=args.a)
            plain = decrypt_message(priv, args.cipher)
            print(plain)
        except Exception as exc:
            print(f"{ERR_PREFIX} {exc}")
        return

    # Fără comandă -> interactiv
    interactive_menu()


def main(argv: Optional[Sequence[str]] = None) -> None:
    """Punctul de intrare principal al programului."""
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    handle_args(args)


if __name__ == "__main__":
    main()
