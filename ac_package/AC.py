"""
This module defines an abstract interface for anonymous credential systems
(interactive between prover and verifier to privately show a credential (cred) and selectively disclose attributes).

Classes:
    AC: An abstract class defining basic methods for anonymous credential systems.

Methods:
    setup(): Abstract method to set up the anonymous credential system and generate public parameters.
    user_keygen(): Default method implementation for user key generation.
    isuser_keygen(): Default method implementation for issuers key generation.
    issue_cred(key: Tuple) -> Tuple: Abstract method to issue a credential for a user.
    proof_cred(cred: Tuple) -> Tuple: Abstract method to generate a proof for a credential.
    verify_proof(proof: Tuple) -> bool: Abstract method to verify the validity of a proof.
"""

from abc import ABC, abstractmethod
from typing import Tuple

class AC(ABC):
    @abstractmethod
    def setup(self) -> Tuple:
        """Abstract method to set up the anonymous credential system."""
        pass

    def user_keygen(self, pp):
        """Default method implementation for user key generation."""
        print("default method implementations")

    def isuser_keygen(self, pp):
        """Default method implementation for issuers keys."""
        print("default method implementations")

    @abstractmethod
    def issue_cred(self, key: Tuple) -> Tuple:
        """Abstract method to issue a credential for a user.

        Args:
            key (Tuple): A tuple containing the user's keypair and some additional information depend on AC system.

        Returns:
            Tuple: A tuple containing the user's credential and some additional information depend on AC system.
        """
        pass

    @abstractmethod
    def proof_cred(self, cred: Tuple) -> Tuple:
        """Abstract method to generate a proof for a credential.
        Args:
            cred (Tuple): A tuple containing the user's credential and some additional information depend on AC system.

        Returns:
            Tuple: A tuple containing the proof.
        """
        pass

    @abstractmethod
    def verify_proof(self, proof: Tuple) -> bool:
        """Abstract method to verify the validity of a proof.

        Args:
            proof (Tuple): A tuple containing the proof to be verified.

        Returns:
            bool: True if the proof is valid, False otherwise.
        """
        pass
