"""
Acest exemplu demonstrează cum să se utilizeze algoritmul
de hash HAVAL folosind biblioteca Chilkat.
"""
import chilkat # type: ignore

# This example requires the Chilkat API to have been previously unlocked.
# See Global Unlock Sample for sample code.

crypt = chilkat.CkCrypt2()

S = "The quick brown fox jumps over the lazy dog"

# Hash using HAVAL
# There are two additional properties relevant to HAVAL:
# HavalRounds, and KeyLength.
# HavalRounds can have values of 3, 4, or 5.
# KeyLength can have values of 128, 160, 192, 224, or 256
crypt.put_HashAlgorithm("haval")
crypt.put_HavalRounds(3)
crypt.put_KeyLength(192)
genhash = crypt.hashStringENC(S)
print("Haval: " + genhash)
