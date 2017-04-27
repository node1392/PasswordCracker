# PasswordCracker
The goal of this program is to break passwords hashed with the SHA‐256 hash function. Three different types of attacks are used: dictionary, brute-force, and a combination of both. 

Two password files are given. The 1st one has just hashed passwords (passwords_nosalt.txt). The 2nd one has passwords hashed after appending a salt with the value “_1984” (passwords_salt.txt).

When the cracker completes, it prints out how long it ran, how many different passwords it generated and tried, and how many user passwords it attempted to crack using at least one generated password.
         
