# yAcademy - Spartan ECDSA <!-- omit in toc -->

**Review Resources:**

- [Spartan ECDSA](https://github.com/personaelabs/spartan-ecdsa)

**Auditors:**

 - [nullity](https://github.com/nullity00)

## Table of Contents <!-- omit in toc -->

- [Review Summary](#review-summary)
- [Scope](#scope)
- [Findings Explanation](#findings-explanation)
- [Critical Findings](#critical-findings)
- [High Findings](#high-findings)
- [Medium Findings](#medium-findings)
- [Low Findings](#low-findings)
- [Informational Findings](#informational-findings)

## Review Summary

**Spartan ECDSA**

Spartan-ecdsa (which to our knowledge) is the fastest open-source method to verify ECDSA (secp256k1) signatures in zero-knowledge. [Spartan](https://github.com/microsoft/Spartan) is a high-speed zero-knowledge proof system which does not require trusted setup. Spartan uses [curve25519-dalek](https://docs.rs/curve25519-dalek) for arithmetic over ristretto255 whereas ``spartan-ecdsa`` uses the secp256k1 curve with the following params. Ref [[1](https://neuromancer.sk/std/secg/secp256k1#)] [[2](https://www.secg.org/sec2-v2.pdf)]
```
p (base field) = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
q (generator order) = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
```

The code was reviewed over 17 days. The code review was performed between 19th June and 5th July, 2023. The repository was under active development during the review, but the review was limited to the latest commit at the start of the review. This was commit [3386b30d9b](https://github.com/personaelabs/spartan-ecdsa/tree/3386b30d9b5b62d8a60735cbeab42bfe42e80429) for the circom-rln repo.

## Scope

The following circom files are in scope!
```
eff_ecdsa.circom
tree.circom
add.circom
double.circom
mul.circom
poseidon.circom
pubkey_membership.circom
```

The findings were presented to Personae Labs team.

This review is a code review to identify potential vulnerabilities in the code. The reviewers did not investigate security practices or operational security and assumed that privileged accounts could be trusted. The reviewers did not evaluate the security of the code relative to a standard or specification. The review may not have identified all potential attack vectors or areas of vulnerability.

yAcademy and the auditors make no warranties regarding the security of the code and do not warrant that the code is free from defects. yAcademy and the auditors do not represent nor imply to third parties that the code has been audited nor that the code is free from defects. By deploying or using the code, Personae Labs and users of the contracts agree to use the code at their own risk.

Code Breakdown Matrix
---

| Section                 | Mark    | Description |
| ------------------------ | ------- | ----------- |
| benchmark                | Good    | Typescript files to prove public key membership & address membership in web browser & local environment |
| circuit_reader           | Good    | Circom Circuit reader written in Rust to read r1cs files, constraint vectors etc. |
| circuits                 | Good    | Consists an implementation of Poseidon hash function, ecdsa membership, address & public key verification & addition, multiplication, doubling of secp256k1 curve points as specified in [Halo2 book](https://zcash.github.io/halo2/design/gadgets/ecc.html) in circom |
| lib                      | Good    | Membership Prover & Verifier Classes written in typescript |
| poseidon                 | Good    | Rust implementation of Poseidon over the base field of secp256k1 & contains sagemath files to produce parameters |
| secq256k1                | Good    | Rust implementation of secp256k1 curve for big int & 256 bit numbers |
| spartan_wasm             | Good    | Wasm Module in Rust to generate proof & verify using Spartan |
| Spartan-secq             | Good    | Modified version of the original spartan with curve secp256k1 |

Code Evaluation Matrix
---

| Category                 | Mark    | Description |
| ------------------------ | ------- | ----------- |
| Cryptography             | Good    | To hash the secret values, Poseidon hash function has been used. This uses fewer constraints per bit compared to other functions lowering down the time consumed |
| Libraries                | Good    | The circuits use the defacto circomlib |
| Circuit Dependence Graph | Good    | The signals in the circuit are properly constrained with a well formed CDG |
| Documentation            | Good     | The documentation is clear & concise |
| Proof Systems            | Good    | Proof generation is done using Spartan-secq using a secp256k1 curve, which has security level of 128 bits|



## Findings Explanation

Findings are broken down into sections by their respective impact:
 - Critical, High, Medium, Low impact
     - These are findings that range from attacks that may cause loss of funds, impact control/ownership of the contracts, or cause any unintended consequences/actions that are outside the scope of the requirements
 - Informational
     - Findings including recommendations and best practices

---

## Critical Findings
None.

## High Findings

 - Under constrained circuits compromising the soundness of the system


``File`` : [packages/circuits/eff_ecdsa_membership/secp256k1/mul.circom](https://github.com/personaelabs/spartan-ecdsa/blob/3386b30d9b5b62d8a60735cbeab42bfe42e80429/packages/circuits/eff_ecdsa_membership/secp256k1/mul.circom#L123)

```
    signal slo <-- s & (2 ** (128) - 1);
    signal shi <-- s >> 128;
```

The signals slo & shi are underconstrained.

**Recommended Solution**

```
template bitwiseAND(n){
  signal input a;
  signal input b;
  signal output out;
  component n2ba = Num2Bits(n);
  n2ba.in <== a;
  component n2bb = Num2Bits(n);
  n2bb.in <== b;
  signal bits[n];
  for (var i = 0; i < n; i++) {
    bits[i] <== n2ba.out[i] * n2bb.out[i];
  }
  component b2n = Bits2Num(n);
  b2n.in <== bits;
  out <== b2n.out;
}

template RightShift(b, shift) {
  assert(shift < b);
  signal input x;
  signal output y;
  component x_bits = Num2Bits(b);
  x_bits.in <== x;
  signal y_bits[ b - shift ];
  for (var i = 0; i < b - shift; i++) {
    y_bits[i] <== x_bits.out[i + shift];
  }
  component y_num = Bits2Num(b - shift);
  y_num.in <== y_bits;
  y <== y_num.out;
}

template K() {
    ....
    signal temp <== (2 ** (128) - 1);
    component and = bitwiseAND(256);
    and.a <== temp;
    and.b <== s;
    signal slo <== and.out;
    component shright = RightShift(256, 128);
    shright.x <== s;
    signal shi <== shright.y;
    ...
```

## Medium Findings
None.

## Low Findings
None.

## Informational Findings

**1. Over allocation of components**

``File`` : [circuits/eff_ecdsa_membership/secp256k1/mul.circom](https://github.com/personaelabs/spartan-ecdsa/blob/3386b30d9b5b62d8a60735cbeab42bfe42e80429/packages/circuits/eff_ecdsa_membership/secp256k1/mul.circom#L66)
```
    var bits = 256;
    component PComplete[bits-3]; 
    component accComplete[3];

    for (var i = 0; i < 3; i++) {
        PComplete[i] = Secp256k1AddComplete(); // (Acc + P)
```
**Recommended Solution**
```
component PComplete[3]
```

**2. Over allocation of components**

File : [circuits/eff_ecdsa_membership/secp256k1/mul.circom](https://github.com/personaelabs/spartan-ecdsa/blob/3386b30d9b5b62d8a60735cbeab42bfe42e80429/packages/circuits/eff_ecdsa_membership/secp256k1/mul.circom#L35)
```
    component PIncomplete[bits-3]; 
    component accIncomplete[bits];

    for (var i = 0; i < bits-3; i++) {
        if (i == 0) {
            PIncomplete[i] = Secp256k1AddIncomplete(); // (Acc + P)
            ...
            accIncomplete[i] = Secp256k1AddIncomplete(); // (Acc + P) + Acc
```
Since the loop runs for ``bits-3`` times, ``component accIncomplete[bits-3]`` would be the correct declaration of components.








