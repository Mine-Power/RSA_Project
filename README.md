# Bielencheier attack on PKC#1 V1.5

## Motivation
We want to highlight that although strong RSA is secure (with properly generated primes and exponent), weak implementations of the cipher can result in security issues.

We chose the Bielencheier attack on PKCS1 V1.5 because this highlights a weak use case of the RSA protocol on a popular standard, which leads to improvements in the ways RSA is used.

## PKCS1 V1.5 - RSA block type 2

The standard defined 3 block types and the attack focus on the **blocktype 2** for message encryption:

* 00 || 02 || padding string || 00 || data blocks
* The padding string length is at least 8 blocks

## The attack
In the Bleichenbacher attack, we define that an **encryption block EB** is **PKCS conforming** if it can be parsed into the block format above, i.e

> EB = EB1 || EB2 || ... || EBk
* EB1 = 00
* EB2 = 02
* EB3 to EB10 are non-zero
* At least one of the bytes from EB11 through EBk is 00

And the cipher text c of a PKCS conforming encryption block EB is **PKCS conforming** as well.

With an **orcale** that allows the adversary to know whether a cipher text is **PKCS conforming** or not, he can do an **adaptive chosen cipher text attack** to figure out the cipher text.

The number of **chosen cipher texts** required is about **2^20**. The full proof is detailed in the [Bleichenbacher's paper](http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf).

## Access to the oracle
There are situations that an attacker can hgain access to an oracle that enables the attacks - here are some examples:

### Plain encryption without integrity checks

We assume that Alice can generate a message m and send to Bob without any further integrity checks, who will decrypt and send back an error if the message is NOT **PKCS conforming**. Eve, the attacker, can impersonate Alice and check the conformance of her chosen cipher texts.

### Detailed Error 
If there is an error message indicating that the reason for message failure is **PKCS non-conformance**, an attacker can use the message as an orcale.

### Timing attack
If there is a difference in the time required to handle a **PKCS non-conforming** message and a **PKCS conforming** one, an attacker can measure it and use the timing as an oracle.

E.g: For a hardware system, simply check if the message is conforming or NOT before verifying the signature. The time taken to handle a **PKCS non-conforming** cipher text and a **PKCS conforming** one will be different.

# How to use

## Requirement packages
These packages are used in this project
* pythoncrypto for secure RSA keys generation
* pycryptodome for random generators and some other utility functions
* seaborn for graph drawing (used for statistics)

## Installation
Clone this repo. In the root directory, run this command:
> pip install requirements.txt

## Running the code
Run the file main.py: The program will prompt three options for 3 use cases.

### Performing a normal attack
* User will be prompted to enter a plain text, and the program will encode it using PKCS1# standard, then encrypt it. Afterward, it will attempt to retrive the plain text from the cipher text.

### Performing an attack optimized by parrallel computing
* Same as the first use case, except the attack is optimized by parallelizing the oracle queries.
* Note: half of the CPU cores available will be used.

### Performing multiple attacks to perform statistics
* This option is to show statistics information by running multiple attacks on random **PKCS conforming** messages.
* The statistics include numbers of oracle queries and running time of each attack.
* The program will use the optimized version of the attack.
