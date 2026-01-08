---
title: "Public Commitments to UpdatePath Path Secrets in Messaging Layer Security (MLS)"
abbrev: "MLS UpdatePath Commitments"
category: info

docname: draft-mahy-mls-updatepath-commitment-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Messaging Layer Security"
keyword:
 - UpdatePath
 - path_secret
 - node_secret
 - node_pub
 - node_priv
 - forked commit
 - malicious commit
venue:
  group: "Messaging Layer Security"
  type: "Working Group"
  mail: "mls@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/mls/"
  github: "rohanmahy/mls-updatepath-commitment"
  latest: "https://rohanmahy.github.io/mls-updatepath-commitment/draft-mahy-mls-updatepath-commitment.html"

author:
 -
    fullname: Rohan Mahy
    email: rohan.ietf@gmail.com

normative:

informative:

...

--- abstract

TODO Abstract


--- middle

# Introduction

TODO Introduction

For a group of n members, the additional cost of using the extension is log(n) hashes and one signature operation per commit to send and verify.


# Conventions and Definitions

{::boilerplate bcp14-tagged}

# UpdatePath Commitments

An UpdatePath Commitment is sent as an AAD component in any Commit messages with an UpdatePath.
It contains a hash of each path_secret, and the Committer's signature over the commitment.

## Including an UpdatePath Commitment

`committer_signature_public_key` is the Committer's `LeafNode.signature_key`.
`committer_signature_private_key` is the private key corresponding to that public key.

The Committer calculates the `path_secret` hash and a hash of its own signature public key as follows:
~~~
path_secret_hash[n] = RefHash("MLS 1.0 path secret hash",
                              path_secret[n])

committer_signature_key_hash = Hash(committer_signature_public_key)
~~~

Then the Committer:

- fills in the PathSecretCommitmentTBS data structure, and the PathSecretCommitment except its signature;
- generates the signature in the PathSecretCommitment data structure;
- and includes the PathSecretCommitment in an AAD component of the Commit.

~~~ tls
struct {
  HashReference path_secret_hashes<V>;
  HashReference committer_signature_key_hash;
  /* SignWithLabel(committer_signature_private_key,               */
  /*  "PathSecretCommitmentTBS", PathSecretCommitmentTBS) */
  opaque signature<V>;
} PathSecretCommitment;

struct {
  Ciphersuite ciphersuite;
  opaque group_id<V>;
  uint64 epoch;
  opaque confirmed_transcript_hash<V>;
  Hash path_secret_hashes<V>;
  Hash signature_key_hash;
  uint32 sender_leaf_node;
} PathSecretCommitmentTBS;
~~~


## Verification of PathSecretCommitment

After validating an incoming Commit, each member checks the `PathSecretCommitment.signature`.

~~~
VerifyWithLabel(committer_signature_public_key,
  "PathSecretCommitmentTBS", PathSecretCommitmentTBS,
   PathSecretCommitment.signature)
~~~

Next each member checks the hash of each path_secret decrypted from the UpdatePath.
If the path_secret[i] is encrypted to the receiving member, it decrypts the path_secret using the private key for the node as usual.
If the path_secret_hash[i] is equal to RefHash("MLS 1.0 path secret hash", path_secret[i]), then the member confirms that the commitment is consistent for that member.

If a member discovers that its path_secret does NOT match the hash provided, it has strong evidence that the Committer acted maliciously and can prove it.

## Generating a Proof of a Malicious UpdatePath

To generate a proof, a member whose hashes did not match the relevant commitments provides the Commit message, and any path_secret that didn't match the commit hash, to the DS and/or the other members so the remaining honest parties can automatically recover.

The prover constructs the following structures as evidence.

~~~ tls
struct {
  uint32 receiver_leaf_index;
  MLSMessage private_commit_message;
  MaliciousPathSecret malicious_path_secrets<V>;
  /* SignWithLabel(receiver_private_signature_key, */
  /*   "MaliciousUpdatePathProofTBS", MaliciousUpdatePathProofTBS) */
  opaque receiver_signature<V>;
} MaliciousUpdatePathProof

struct {
  uint32 receiver_leaf_index;
  MLSMessage commit_message;
  MaliciousPathSecret malicious_path_secrets<V>;
} MaliciousUpdatePathProofTBS;

struct {
  uint8 n;
  opaque presented_secret<V>;
} MaliciousPathSecret
~~~

## Validating the Proof

The receiver of such a proof, validates the proof with the following steps.

- First it verifies the committer's signature on the `MaliciousUpdatePathProof.private_commit_message`.
- It locates the UpdatePath and finds the `receiver_leaf_index` in the path.
- Then it extracts the `PathSecretCommitment` from the Commit message's AAD.
- For each of the `MaliciousUpdatePathProof.malicious_path_secrets`, at level `n`:
  - verifies that the `receiver_leaf_index` should be privy to level `n`
  - checks that `RefHash("MLS 1.0 path secret hash", presented_secret)` is not the same as `PathSecretCommitment.path_secret_hashes[n]`
  - encrypts `presented_secret` with the previous epoch's public key at level `n` of the resolution covering `receiver_leaf_index`, and verifies that the cipher text matches the cipher text in the appropriate `FramedContent.commit.path.nodes.encrypted_path_secret` of `MaliciousUpdatePathProof.commit_message`.
- It verifies the `MaliciousPathSecret.signature` and that the signature_public_key used to sign the `MaliciousPathSecret.receiver_private_signature_key` corresponds to the `receiver_leaf_index`.


# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
