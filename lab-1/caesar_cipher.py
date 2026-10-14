"""
Program Python pentru criptarea și decriptarea textului folosind cifrul lui Cezar.
Solicită utilizatorului operația, cheia și textul, apoi afișează rezultatul.

Realizat de studentul grupei IS31Z, Tocana Marian
"""

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def preprocess_text(text):
    """
    Convertește textul în majuscule și elimină spațiile.
    Verifică dacă textul conține doar caractere permise.
    """
    processed_text = ""
    for char in text:
        if char.isalpha():
            processed_text += char.upper()
        elif char.isspace():
            continue
        else:
            raise ValueError("Textul poate conține doar litere (A-Z, a-z) și spații.")
    return processed_text


def validate_key(key):
    """Validează ca cheia să fie un număr întreg între 1 și 25."""
    try:
        key_int = int(key)
        if 1 <= key_int <= 25:
            return key_int
        else:
            raise ValueError("Cheia trebuie să fie un număr întreg între 1 și 25.")
    except ValueError as exc:
        raise ValueError("Cheia trebuie să fie un număr întreg între 1 și 25.") from exc


def caesar_encrypt(plaintext, key):
    """Implementează criptarea Cezar folosind formula c = (x + k) mod 26."""
    ciphertext = ""
    for char in plaintext:
        index = ALPHABET.index(char)
        new_index = (index + key) % 26
        ciphertext += ALPHABET[new_index]
    return ciphertext


def caesar_decrypt(ciphertext, key):
    """Implementează decriptarea Cezar folosind formula m = (y - k) mod 26."""
    plaintext = ""
    for char in ciphertext:
        index = ALPHABET.index(char)
        new_index = (index - key) % 26
        plaintext += ALPHABET[new_index]
    return plaintext


def main():
    """
    Punctul de intrare pentru programul cifrului Caesar.

    Această funcție interacționează cu utilizatorul pentru
    a realiza criptarea sau decriptarea utilizând cifrul Caesar.
    Solicită utilizatorului să selecteze tipul de operațiune (criptare sau decriptare),
    să introducă o cheie (un număr întreg între 1 și 25),
    și să introducă textul care urmează să fie procesat.
    Textul este preprocesat înainte de aplicarea cifrului.

    Rezultatul este afișat utilizatorului.
    Pași:
        1. Solicită tipul de operațiune: 'C' pentru criptare, 'D' pentru decriptare.
        2. Solicită și validează cheia.
        3. Solicită și preprocesează textul de intrare.
        4. Realizează operațiunea selectată și afișează rezultatul.
    Ridică:
        ValueError: Dacă cheia sau textul de intrare este invalid.
    """

    while True:
        print("\n=== CIFRUL LUI CEZAR ===\n")

        while True:
            operation = input("Operație (C-criptare/D-decriptare): ").upper()
            if operation in ["CRIPTARE", "DECRIPTARE", "C", "D"]:
                break
            print("Eroare: Introduceți 'C' pentru criptare sau 'D' pentru decriptare.")

        while True:
            try:
                key_input = input("Cheia (1-25): ")
                key = validate_key(key_input)
                break
            except ValueError as e:
                print(f"Eroare: {e}")

        while True:
            try:
                if operation == "CRIPTARE" or operation == "C":
                    text_input = input("Textul de criptat: ")
                else:
                    text_input = input("Textul de decriptat: ")

                processed_text = preprocess_text(text_input)

                if not processed_text:
                    print("Eroare: Textul nu poate fi gol după preprocesare.")
                    continue

                break
            except ValueError as e:
                print(f"Eroare: {e}")

        if operation in ["C", "CRIPTARE"]:
            result = caesar_encrypt(processed_text, key)
            print(f"\nText criptat: {result}")
        else:
            result = caesar_decrypt(processed_text, key)
            print(f"\nText decriptat: {result}")

        while True:
            additional = (
                input("\nDoriți să efectuați operație adițională: (DA/NU): ")
                .strip()
                .upper()
            )
            if additional in ["DA", "NU"]:
                break
            print("Eroare: Răspundeți cu 'DA' sau 'NU'.")
        if additional == "NU":
            print("Programul s-a încheiat.")
            break


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nProgramul a fost întrerupt.")
