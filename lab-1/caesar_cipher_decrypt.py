"""
Program Python pentru decriptarea textului folosind cifrul lui Caesar
pentru toate cele 25 de chei posibile.
Solicită utilizatorului textul criptat, validează și afișează 
un tabel cu toate variantele de text clar.

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

def caesar_decrypt(ciphertext, key):
    """
    Implementează decriptarea Cezar folosind formula m = (y - k) mod 26.
    """
    plaintext = ""
    for char in ciphertext:
        index = ALPHABET.index(char)
        new_index = (index - key) % 26
        plaintext += ALPHABET[new_index]
    return plaintext


def main():
    """
    Rulează instrumentul de decriptare a cifrului Caesar
    """
    print("\n=== CIFRUL LUI CEZAR - DECRIPTARE ===\n")
    while True:
        try:
            text_input = input("Introduceți textul criptat: ")
            processed_text = preprocess_text(text_input)
            if not processed_text:
                print("Eroare: Textul nu poate fi gol după preprocesare.")
                continue
            break
        except ValueError as e:
            print(f"Eroare: {e}")

    print("\n+-------------------------------+")
    print("|        Text clar              |")
    print("+-------------------------------+")
    for key in range(1, 26):
        try:
            decrypted = caesar_decrypt(processed_text, key)
            print(f"| {decrypted.ljust(28)}|")
        except ValueError as e:
            print(f"| Eroare la cheia {key}: {e}")
    print("+-------------------------------+")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nProgramul a fost întrerupt.")
