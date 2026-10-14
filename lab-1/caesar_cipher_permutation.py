"""
Program pentru criptarea și decriptarea textelor folosind cifrul Cezar
cu permutare personalizată a alfabetului.

Realizat de studentul grupei IS31Z, Tocana Marian
"""


def validate_k1(k1):
    """Validează cheia k1 (număr întreg între 1 și 25)."""
    try:
        k1 = int(k1)
        if 1 <= k1 <= 25:
            return k1
        else:
            print("Cheia k1 trebuie să fie între 1 și 25.")
            return None
    except ValueError:
        print("Cheia k1 trebuie să fie un număr întreg.")
        return None


def validate_k2(k2):
    """Validează cheia k2 (șir de litere cu lungimea ≥ 7 după eliminarea duplicatelor)."""
    k2 = "".join(c for c in k2.upper() if "A" <= c <= "Z")

    seen = set()
    unique_k2 = "".join(c for c in k2 if not (c in seen or seen.add(c)))

    if len(unique_k2) >= 7:
        return unique_k2
    else:
        print("Cheia k2 trebuie să aibă ≥ 7 litere unice (doar A-Z).")
        print(f"Actualmente: {len(unique_k2)} litere unice.")
        return None


def validate_text(text):
    """Validează textul de intrare (doar litere A-Z)."""
    text = "".join(c for c in text.upper() if c != " ")

    if all("A" <= c <= "Z" for c in text):
        return text
    else:
        invalid_chars = set(c for c in text if not "A" <= c <= "Z")
        print("Textul trebuie să conțină doar litere.")
        print(f"Caractere invalide găsite: {', '.join(invalid_chars)}")
        return None


def generate_permuted_alphabet(k2):
    """Generează alfabetul permutat pe baza cheii k2."""
    natural_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    permuted = ""
    for c in k2:
        if c not in permuted:
            permuted += c

    for c in natural_alphabet:
        if c not in permuted:
            permuted += c

    return permuted


def display_alphabets(permuted_alphabet, k1):
    """Afișează ambele alfabete pentru referință."""
    print("\nAlfabetul natural cu cheia k2 introdusă (alfabet permutat):")
    print(" ".join(permuted_alphabet))
    print(" ".join(f"{i:2d}" for i in range(26)))

    print(f"\nAlfabetul permutat cu cheia k1={k1} (alfabet deplasat):")
    shifted_alphabet = [permuted_alphabet[(i + k1) % 26] for i in range(26)]
    shifted_indices = [(i + k1) % 26 for i in range(26)]
    print(" ".join(f"{char:2s}" for char in shifted_alphabet))
    print(" ".join(f"{idx:2d}" for idx in shifted_indices))
    print()


def encrypt(text, k1, permuted_alphabet):
    """Criptează textul folosind cifrul Cezar cu permutare."""
    result = ""
    steps = []

    for c in text:
        i = permuted_alphabet.index(c)

        j = (i + k1) % 26

        encrypted_char = permuted_alphabet[j]
        result += encrypted_char

        steps.append(
            f"{c} (poziția {i} în alfabetul natural cu cheia \
            k2 introdusă [alfabet permutat]) -> {i}+{k1}={j} -> "
            f"{encrypted_char} (poziția {j} în alfabetul permutat cu cheia \
            k1={k1} [alfabet deplasat])"
        )

    return result, steps


def decrypt(text, k1, permuted_alphabet):
    """Decriptează textul folosind cifrul Cezar cu permutare."""
    result = ""
    steps = []

    for c in text:
        j = permuted_alphabet.index(c)

        i = (j - k1) % 26

        decrypted_char = permuted_alphabet[i]
        result += decrypted_char

        steps.append(
            f"{c} (poziția {j} în alfabetul natural cu cheia \
            k2 introdusă [alfabet permutat]) -> {j}-{k1}={i} -> "
            f"{decrypted_char} (poziția {i} în alfabetul permutat)"
        )

    return result, steps


def display_steps(operation, steps):
    """Afișează pașii de criptare/decriptare."""
    print(f"\nPași de {operation}:")
    for i, step in enumerate(steps, 1):
        print(f"Pasul {i}: {step}")
    print()


def main():
    """Funcția principală pentru rularea programului."""

    while True:
        print("\nCifrul lui Cezar cu permutare")
        print("------------------------------")

        while True:
            operation = input("Operație (criptare/decriptare): ").upper()
            if operation in ["CRIPTARE", "DECRIPTARE", "C", "D"]:
                break
            print("Operație invalidă. Introduceți 'criptare' sau 'decriptare'.")

        while True:
            k1 = validate_k1(input("Introduceți cheia k1: "))
            if k1 is not None:
                break

        while True:
            k2_input = input("Introduceți cheia k2: ")
            k2 = validate_k2(k2_input)
            if k2 is not None:
                break

        permuted_alphabet = generate_permuted_alphabet(k2)
        print(f"\nCheia k2 normalizată: {k2}")

        show_alphabets = input("Doriți să vizualizați alfabetele? (da/nu): ").lower()
        if show_alphabets.startswith("d") or show_alphabets.startswith("y"):
            display_alphabets(permuted_alphabet, k1)

        prompt = (
            "Introduceți mesajul: "
            if operation == "CRIPTARE" or operation == "C"
            else "Introduceți criptograma: "
        )
        while True:
            text_input = input(prompt)
            text = validate_text(text_input)
            if text is not None:
                break

        if operation == "CRIPTARE" or operation == "C":
            result, steps = encrypt(text, k1, permuted_alphabet)
            print(f"\nText criptat: {result}")
        else:  # decriptare
            result, steps = decrypt(text, k1, permuted_alphabet)
            print(f"\nText decriptat: {result}")

        show_steps = input(
            "Doriți să vizualizați pașii de procesare? (da/nu): "
        ).lower()
        if show_steps.startswith("d") or show_steps.startswith("y"):
            display_steps(operation, steps)

        continue_op = input(
            "\nDoriți să continuați cu o altă operație? (da/nu): "
        ).lower()
        if not (continue_op.startswith("d") or continue_op.startswith("y")):
            print("Program finalizat. La revedere!")
            break


if __name__ == "__main__":
    main()
