This repository contains an implementation of important components/papers that are critical to my thesis research including: 
[Aggregate Signatures with Versatile Randomization and Issuer-Hiding Multi-Authority Anonymous Credentials](https://eprint.iacr.org/2023/1016) (ACM CCS 2023),

[Practical Delegatable Anonymous Credentials From Equivalence Class Signatures](https://eprint.iacr.org/2022/680) (PETS 2023),

[Practical Delegatable Anonymous Credentials From Equivalence Class Signatures](https://eprint.iacr.org/2022/680) (PETS 2023),

[Threshold Delegatable Anonymous Credentials with Controlled and Fine-Grained Delegation](https://eprint.iacr.org/2022/680) (IEEE Transactions on Dependable and Secure Computing 2023),

The code provided in this repository has been used to showcase the performance and practicality of the research, and generate results that are discussed in detail in the thesis and accompanying papers.

Including this code in the repository is crucial to ensure transparency and reproducibility of the research conducted. The code plays a significant role in supporting the claims made in the thesis and papers, and is essential for understanding the research conducted.

## Status

**Under Progress**

This repository is currently a work in progress. We are actively working on it, adding new features, fixing issues, and improving documentation. 

# Warning:
This implementation not been audited and is not ready for a production application. The library is provided for research-purpose only and is still not meant to be used in production.

#  Dependencies
Library is built on top of [petlib](https://github.com/gdanezis/petlib) and [bplib ](https://github.com/gdanezis/bplib), make sure to follow these instructions to install all the pre-requisites.

# Getting started
To install the development dependencies run
1. Install nix with the required experimental features from determinate systems

           curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install
    
2. Run: 
            
            nix develop

This will activate the development environment with the required dependencies.

# Run tests with nix

To run the tests in a precisely defined python environment using Nix 
         
         nix develop -c pytest -s -v tests/

# Documentation
The source codes are in core file  and is written in Python. Below, we describe each module:

-   *set_commit.py* : This module provides an implementation of set commitments that takes a set of messages in string format as input and outputs a set commitment and opening information. The module allows users to create a witness to open any subset of messages, and a verifier can use the witness to confirm that the subset is indeed a subset of the original message set.  

         SetCommitment

Additionally, the module implements a cross-set commitment. This feature enables the aggregation of witnesses across multiple commitments into a single witness,enables batching verification, which further enhances the efficiency of the implementation.

      CrossSetCommitment(SetCommitment)

-   *spseq_uc.py* : This module provides an implementation of the SPSQE-UC signature scheme, which is referred to as EQC_Sign class. The scheme is a special signature scheme that can sign vectors of set commitments, which can be extended by additional set commitments. The signatures generated by the scheme also include a user's public key, which can be switched. Also, the module offers the ability to randomize the set commitment and to randomize and adapt the signature to it. This feature enables the creation of signatures and set commitments that are unlinkable and improves the privacy guarantees of the overall system.

-   *util.py* : This module provides all the common requirements for other schemes. It contains a collection of utility functions that are used across multiple modules in the system. 

-   *zkp.py* : This module provides a collection of zero-knowledge proof (ZKP) implementations in Schnorr style. These include:
     1. Schnorr (interactive) proof of the statement ZK(x ; h = g^x). 
            
            ZKP_Schnorr
            
     2. Schnorr proof (non-interactive using Fiat-Shamir heuristic) of the statement ZK(x, m_1, ..., m_n; h = g^x and h_1^m_1...h_n^m_n) and a generalized version.
                  
            ZKP_Schnorr_FS
                  
      3. Damgard's technique that extend interactive proof for obtaining malicious-verifier interactive zero-knowledge proofs of knowledge.
            
            
             Damgard_Transfor(ZKP_Schnorr)  
             

- *dac.py* : This module is provided as a DAC class in Python. It requires the abouve modulars and has the following methods:

     1. setup(self): Generates the public parameters of the DAC scheme, including the signing and set commitment and zero-knowledge proofs. It also creates objects of the underlying schemes.

     2. user_keygen(self, pp_dac): Generates a key pair for a user.

     3. nym_gen(self, pp_dac, usk, upk): Generates a new pseudonym and auxiliary information.

     4. issue_cred(self, pp_dac, attr_vector, sk, nym_u, k_prime, proof_nym_u): Issues a root credential to a user.

     5. proof_cred(self, pp_dac, nym_R, aux_R, cred_R, Attr, D):
    Generates a proof of a credential for a given pseudonym and selective disclosure D.

    6. verify_proof(self, pp_dac, proof, D):  verify proof of a credential

    7. delegator(self, pp_dac, cred_u, A_l, l, sk_u, proof_nym) and delegatee(self, pp_dac, cred, A_l, sk_R, nym_R): Create a delegatable credential form user U to a user R

# Usage

An easy way to see how to use the library can be found on the tests. 

# Acknowledgements
I want to express my sincere thanks to Martin Schwaighofer for his support and assistance in using nix manager to build the library. 

