# yAcademy - Rate Limiting Nullifier  Review <!-- omit in toc -->

**Review Resources:**

- [Circom-rln](https://github.com/Rate-Limiting-Nullifier/circom-rln)

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
- [Final remarks](#final-remarks)

## Review Summary

**Rate Limiting Nullifier**

RLN (Rate-Limiting Nullifier) is a zk-gadget/protocol that enables spam prevention mechanism for anonymous environments.

The circuits of [RLN](https://github.com/Rate-Limiting-Nullifier/circom-rln) were reviewed over 15 days. The code review was performed between 31st May and 14th June, 2023. The repository was under active development during the review, but the review was limited to the latest commit at the start of the review. This was commit [37073131b9](https://github.com/Rate-Limiting-Nullifier/circom-rln/tree/37073131b9c5910228ad6bdf0fc50080e507166a) for the circom-rln repo.

## Scope

The scope of the review consisted of the following circuits at the specific commit:

- rln.circom
- utils.circom
- withdraw.circom

After the findings were presented to the RLN team, fixes were made and included in several PRs.

This review is a code review to identify potential vulnerabilities in the code. The reviewers did not investigate security practices or operational security and assumed that privileged accounts could be trusted. The reviewers did not evaluate the security of the code relative to a standard or specification. The review may not have identified all potential attack vectors or areas of vulnerability.

yAcademy and the auditors make no warranties regarding the security of the code and do not warrant that the code is free from defects. yAcademy and the auditors do not represent nor imply to third parties that the code has been audited nor that the code is free from defects. By deploying or using the code, RLN and users of the contracts agree to use the code at their own risk.


Code Evaluation Matrix
---

| Category                 | Mark    | Description |
| ------------------------ | ------- | ----------- |
| Cryptography             | Good    | To hash the secret values, Poseidon hash function has been used. This uses fewer constraints per bit compared to other functions lowering down the time consumed |
| Libraries                | Good    | The circuits use the defacto circomlib which has been audited multiple times |
| Circuit Dependence Graph | Good    | The signals in the circuit are properly constrained with a well formed CDG |
| Documentation            | Low     | The documentation is outdated and needs refactoring |
| Proof Systems            | Good    | The docs recommend generating proofs using Groth16 using a BN254 curve, which has security level of 128 bits|

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

None

## Medium Findings

None.

## Low Findings

### 1. Low - Under constrained userMessageLimit

In [utils.circom](https://github.com/Rate-Limiting-Nullifier/circom-rln/blob/37073131b9c5910228ad6bdf0fc50080e507166a/circuits/utils.circom#LL40C1-L40C64), the signal ``limit`` is under constrained.

**Suggested Solution**
```
template RangeCheck(LIMIT_BIT_SIZE) {
    assert(LIMIT_BIT_SIZE < 253);

    signal input messageId;
    signal input limit;

    signal bitCheck[LIMIT_BIT_SIZE] <== Num2Bits(LIMIT_BIT_SIZE)(messageId);
    signal limitCheck[LIMIT_BIT_SIZE] <== Num2Bits(LIMIT_BIT_SIZE)(limit);
    signal rangeCheck <== LessThan(LIMIT_BIT_SIZE)([messageId, limit]);
    rangeCheck === 1;
}
```

### **2. Low - Incosistency between contract and the circuit on the number of bits for userMessageLimit**

**RLN.sol**
```
uint256 messageLimit = amount / MINIMAL_DEPOSIT;
```
**rln.circom**
```
template RLN(DEPTH, LIMIT_BIT_SIZE) {
...
    // messageId range check
    RangeCheck(LIMIT_BIT_SIZE)(messageId, userMessageLimit);
...
}
component main { public [x, externalNullifier] } = RLN(20, 16);
```
In [RLN.sol](https://github.com/Rate-Limiting-Nullifier/rln-contracts/blob/465579c872edbc03f8044f17926180d82f5abd56/src/RLN.sol#L121), the ``messageLimit`` can take upto ``2**256 - 1`` values whereas ``messageId`` & ``userMessageLimit`` values in [circuits](https://github.com/Rate-Limiting-Nullifier/circom-rln/blob/37073131b9c5910228ad6bdf0fc50080e507166a/circuits/rln.circom) is restricted to ``2**16 - 1`` .

**Recommended solution**

- RLN.sol
```
function register(uint256 identityCommitment, uint256 amount) external {
        ...
        uint256 messageLimit = amount / MINIMAL_DEPOSIT;
        require( messageLimit <= type(uint16).max , "Max amount of message limit is 65535");
        token.safeTransferFrom(msg.sender, address(this), amount);
        ...
    }
```

### Informational findings

- Missing range checks for `x` & `externalNullifier`
- Restoring the polynomial for Shamir's Secret Sharing Scheme gives ``f(x) = 0`` for same messages sent more than once . As in this case ``x1 = x2 = x3 ...``. The protocol does fall short of preventing spam here but would be a perfect fit for low-limit messaging platforms `eg. voting`.
- The prime field in circom is ~ 2**254 whereas solidity supports 256-bit integers. There is a possibility of users registering using the ``identityCommitment`` & another hash ``A`` such that ``A mod p = identityCommitment`` where p is the prime field of circom. Here, the user registers twice using the same ``identitySecret``. 

