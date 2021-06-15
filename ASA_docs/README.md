# Toward the Detection of Algorithm Substitution Attacks in Post Quantum Cryptography

### Installation

Clone this repository:
```
git clone --single-branch --branch falcon_asa_attack https://github.com/DuniaMarchiori/liboqs.git
```
Clone submodule CECIES:
```
git submodule update --init --recursive
```
Compile Liboqs following their README


### Third Party Repositories

In our Falcon attack we use the Elliptic Curve Integrated Encryption Scheme (ECIES) to establish a shared symmetric key from the attacker public key and an ephemeral key pair, both are ECDH keys.

To implement this scheme, we rely on the fork of a third party library, CECIES. 

The fork made by us can be found [here](...) and the library [here](https://github.com/GlitchedPolygons/cecies).


### Testing

The test scripts are located in `build/tests`.

To execute a test, from the build directory run:
```
./tests/<test_name>
```

There are tests provided by liboqs and tests specifically for our ASA attacks, which are the following:
- test_parse_falcon
- test_attack_falcon
- test_attack_falcon1024


#### Test: test_parse_falcon

Since the falcon attack require at least 2 signatures to leak secret data, the attacker needs to know how to recognize if the signature he is capturing is the first one or the second one.

To do this we set 2 fixed bits in the AES Initiliazation Vector, such that the first signature has the first bit equal to zero, and the second signature has the first bit equal to 1.

In this script we demonstrate the attacker recognizing this pattern and acting as a state machine, described in `state_machine_falcon_attacker.png`.

The user will be prompted the following:
- Generate a new key pair
- Sign without the attacker capturing
- Sign with the attacker capturing

With these actions, the user can interact with the attacker state machine.

#### Test: test_attack_falcon

This script simply performs the algorithm substitution attack on Falcon 512.
It is performed:
- Victim generated a keypair
- Victim signs 2 times
- Attacker capture both signatures
- Attacker parse ciphertext from the signature
- Attacker decrypt ciphertext 
- Attacker recover victim private key

#### Test: test_attack_falcon1024

Same as `test_attack_falcon`, but with the Falcon 1024 version.

### Source code modifications

The modifications done to implement the attack can be found in the file [FALCON_ATTACK.md](...) and [KYBER_ATTACK.md](...).

