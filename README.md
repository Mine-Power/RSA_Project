# RSA_Project

# Bielencheier attack on PKC#1 V1.5
## Motivation
We want to highlight that although strong RSA is secure, NOT weak protocol can used it unsecurely.

We choose the Bielencheier attack on PKCS1 V1.5 because this highlighted the weak use case of RSA protocol

## PKCS1 V1.5 RSA
The blocktype 2 for encryption:

* 00 | 02 | padding string || 00 || data blocks 
* The padding string length is at least 8 blocks

For message encryption, the data is padding in the structure above. 

## The attack
In the Bleichenbacher attacks define that an encryption block is PKCS conforming if it can be parsed in the block 2 format above, i.e it is in this form

EB = EB1 || EB2 || ... || EBk
* EB1 = 00
* EB2 = 02
* EB3 to EB10 are non-zero
* At least one of the bytes from EB11 through EBk is 00

And the cipher text c of a PKCS conforming encryption block is PKCS conforming

With an orcale that allow attacker know whether a cipher text is PKCS conforming or not, he can do an adaptive chosen cipher text attacks to figure out the cipher text with the time complexity of 2^20 + O(k)
where k is the number of bits of public modulus n, which is much smaller then 2^20 (for current standard which is 1024 bits n)

## Access to the oracle
This is some ways that attacker can access to an oracle that enable the attacks:

### Plain encryption without integrity checks

### Detailed Error Messages that state if a cipher text is PKCS conforming
### Timing attack: by measure time if the system check the decrypted message PKCS before valid signature and have different amount of times

# How to use
## Requirement package
Pycryptodome and cryptography packages are require

Install: 

## Run a test

## Run oracle and time statistic

