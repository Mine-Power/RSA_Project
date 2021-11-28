# Bielencheier attack on PKC#1 V1.5
## Motivation
We want to highlight that although strong RSA is secure, the weak implemenation can result in security issue.

We choose the Bielencheier attack on PKCS1 V1.5 because this highlighted the weak use case of RSA protocol on a popular standard and lead to the improvement in the ways RSA is used.

## PKCS1 V1.5 RSA block type 2

The standard defined 3 block types and the attack focus on the **blocktype 2** for message encryption:

* 00 | 02 | padding string || 00 || data blocks
* The padding string length is at least 8 blocks

## The attack
In the Bleichenbacher attacks define that an **encryption block EB** is **PKCS conforming** if it can be parsed in the block 2 format above, i.e it is in this form

> EB = EB1 || EB2 || ... || EBk
* EB1 = 00
* EB2 = 02
* EB3 to EB10 are non-zero
* At least one of the bytes from EB11 through EBk is 00

And the **cipher text c** of a PKCS conforming encryption block EB is **PKCS conforming**

With an **orcale** that allow attacker know **whether** a **cipher text** is **PKCS conforming** or not, he can do an **adaptive chosen cipher text attacks** to figure out the cipher text.

The number of **choosen cipher text** required is about **2^20**. The detailed proof is stated in the [Bleichenbacher's paper](http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf)

## Access to the oracle
There are situations that attacker can access to an oracle that enable the attacks, and here are some examples:

### Plain encryption without integrity checks

Assume if Alice can generate a message m and send to Bob with out any further integrity check, who will decrypt and send error if the message is NOT PKCS confroming. Eve can impersonate Alice and check the conformance

### Detailed Error 
If the error message that stat if the message failure reason is PKCS conforming (e.g the error state that the message is not PKCS conforming or verification is failed), attacker can use the message as an orcale.

### Timing attack:
If there is differece in the time required to handle a NOT PKCS conforming and a PKCS conforming once, attacker can measure it and use as an oracle.

E.g: for system simply check if the message is conforming or NOT before verify the signature, the time to handle a NOT PKCS conforming and a PKCS conforming cipher text will be different 

# How to use
## Requirement package
These packages are used in this project
* pythoncrypto for secure RSA keys generation
* pycryptodome for random generators and some other utilities functions
* seaborn for graph drawing
## Install
Clone this repo. In the root directory, run this command:
> pip install requirements.txt

## Run the code
Run the file main.py: The program will prompt three options for 3 use case.

1 Perform a normal attacks
* User will be promt to enter a plain text, and the program will encode it using PKCS1# standard, then encrypt it and try to retrive the plain text from the cipher text.

2 Perform a attacks optimized by parrallel computing
* Same as 1 except the attack is oprimized parrallel the oracle queries.
* Note: half of the cores of the CPUS will be used.

3 Run multiple attacks to perform statistics
* This options is to show statistics information by running multiple attack on random PKCS conformation message.
* The statistics information including number of oracle queries, running time of each attacks.
* The program will use the optimzed attacks.
