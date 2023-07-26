"""
This is implementation of multi authoritycredential using aggregate signatures.
See the following for the details
- (Submitted) Aggregate Signatures with Versatile Randomization: Issuer-Hiding Multi-Authority Anonymous Credentials, by Mir et al.,
@Author: Omid Mir
"""

from bplib.bp import BpGroup, G2Elem
from ac_package.AC import AC
from ac_package.primitives.atosa import AtoSa
from ac_package.util import pedersen_dec, pedersen_setup
from ac_package.zkp import ZKP_Schnorr_FS, ZKP_Schnorr, ZKP_Tag
from ac_package.primitives.spseq_signs import FHS_Sign

class A2C_AtoSa(AC):
    def __init__(self):
        self.group = BpGroup()
        self.atosa = AtoSa()
        self.spseq = FHS_Sign()
        self.zkp_tag = ZKP_Tag(self.group)

    def setup(self):
        """
        :return: public parameters
        """
        pp_sig = self.atosa.setup()
        pp_spseq = self.spseq.setup()
        pp_zkp = self.zkp_tag.setup()
        pp = (pp_sig, pp_spseq, pp_zkp)
        return pp

    def isuser_keygen(self, pp):
        """
        :param pp: public parameters
        :return: key pair for issuers
        """
        (pp_sign, pp_spseq, pp_nizk) = pp
        (isk, ipk) = self.atosa.keygen(pp_sign)
        return (isk, ipk)

    def user_keygen(self, pp, message_vk_vector):
        """
        :param pp: public parameters
        :param m_vector: total messages
        :return: key pair for users, tag , index
        """
        (pp_sign, pp_spseq, pp_zkp) = pp
        (group, g, g2, o) = pp_zkp
        (tag, aux, commitment_pair_list) = self.atosa.gen_tag_aux(pp_sign, message_vk_vector)
        (tau, T_vec)= tag
        usk = tau
        upk = T_vec
        h = group.hashG1(aux.export())
        return (usk, upk, aux, h, commitment_pair_list)

    def nym_gen(self, pp, h, tag):
        """
        :param pp:  public parameters
        :param upk: user public key ( or pseudonym)
        :return: a new pseudonym and auxiliary information
        """
        (pp_sign, pp_spseq, pp_zkp) = pp
        (group, g, g2, o) = pp_zkp
        upsilon = o.random()

        (tau_prime, T_prime) = self.atosa.convert_tag(tag, upsilon)
        nym = T_prime
        secret_nym = tau_prime

        (announce_public, announce_randomnes) = self.zkp_tag.announce(pp_zkp, h)
        state = ['schnorr', g, h, announce_public.__hash__()]
        challenge = self.zkp_tag.challenge(state)
        response = self.zkp_tag.response(pp_zkp, challenge, announce_randomnes, h, stm=nym, secret_wit=secret_nym)
        proof_nym_u = (challenge, announce_public, nym, response)

        assert self.zkp_tag.verify(pp_zkp, challenge, announce_public, h, stm=nym, response=response)
        return (nym, secret_nym, proof_nym_u)

    def issue_cred(self, pp, isk, attr, upk, aux, proof_upk, comit_list = None):
        """
        :param pp: public parameters
        :param isk:  issuer secert key
        :param attr:  attribute
        :param tag: tag
        :param index_pair: index
        :return: credential for attribute based on tag and index
        """
        (pp_sig, pp_spseq, pp_zkp) = pp
        (group, order, g1, g2, e, pp_pedersen) = pp_sig
        (challenge, announce_public, nym, response) = proof_upk
        h = group.hashG1(aux.export())
        assert self.zkp_tag.verify(pp_zkp, challenge, announce_public, h, stm=nym, response=response)

        # if a commitemnt of message is provided, then check it's correct
        if comit_list is not None:
            (commitment_message, opening_message) = comit_list
            (randomness, m) = opening_message
            assert attr == m and pedersen_dec(pp_pedersen, opening_message,
                                                 commitment_message), 'the message and commitment values do not match'

        signature = self.atosa.sign_intract(pp_sig, isk, upk, aux, attr)
        cred = signature
        return cred

    def gen_policies(self, pp, ivk_vector):
        """
        :param pp: public parameters
        :param messages_vks: issuer verification keys act as messagses need to be signied in polices
        :return: policies (sign on issuer verification key) shows which issuers are accepted by verifier
        """
        (pp_sig, pp_spseq, pp_zkp) = pp
        signatures_list = []
        (vsk, vpk) = self.spseq.keygen(pp_spseq, 3, type = G2Elem)
        for ivk in ivk_vector:
            signature  = self.spseq.sign(pp_spseq, vsk, ivk)
            signatures_list.append(signature)
        policies = (signatures_list, ivk_vector, (vsk, vpk))
        return policies

    def proof_cred(self, pp, tag, pk_vector, cred, h, attr_vector, policies = None):
        """
        :param pp: public parameters
        :param tag: tag
        :param pk_vector:  issuer verification keys
        :param cred: credential
        :param attr_vector: attributes needed to disclose
        :param policies: if set it means we are going to run proof with issuer hiding
        :return: proof over attributes
        """
        (pp_sig, pp_spseq, pp_zkp) = pp
        (group, order, g1, g2, e, pp_pedersen) = pp_sig
        (group, g, g2, o) = pp_zkp

        if type(cred) is list:
            filter_signs = [cred[i] for i in range(len(attr_vector)) if cred[i] is not None]
            aggre_sign = self.atosa.aggr_sign(filter_signs)
        else: aggre_sign = cred

        ### some commen computation can be moved outer of if else
        upsilon = order.random()
        if policies is None:
            ## randomizing signatures
            randomize_sig, randomize_tag = self.atosa.rand_sign(aggre_sign, tag, upsilon)

            (rho_new, rho_hat_new) = randomize_tag
            nym = rho_hat_new
            cred_new = randomize_sig
            ## ccreate a proof for tag
            (announce_public, announce_randomnes) = self.zkp_tag.announce(pp_zkp, h)
            state = ['schnorr', g, h, announce_public.__hash__()]
            challenge = self.zkp_tag.challenge(state)

            response = self.zkp_tag.response(pp_zkp, challenge, announce_randomnes, h, stm=nym, secret_wit=rho_new)
            proof_nym_u = (challenge, announce_public, nym, response)
            return (cred_new, nym, proof_nym_u, h)
        else:
            ## convert signature
            (signatures_list, ivk_vector, (vsk, vpk)) = policies
            omega = order.random()
            upsilon = order.random()
            convert_cred = self.atosa.convert_sig(aggre_sign, omega) #pk_vector_new = sign_scheme.convert_vk(pk_vector, mu)
            ivk_vector_new = self.atosa.convert_vk(ivk_vector, omega)

            ## randomizing signatures (credential)
            randomize_sig, randomize_tag = self.atosa.rand_sign(convert_cred, tag, upsilon)
            (rho_new, rho_hat_new) = randomize_tag
            nym = rho_hat_new
            cred_new = randomize_sig

            ## ccreate a proof for tag
            (announce_public, announce_randomnes) = self.zkp_tag.announce(pp_zkp, h)
            state = ['schnorr', g, h, announce_public.__hash__()]
            challenge = self.zkp_tag.challenge(state)
            response = self.zkp_tag.response(pp_zkp, challenge, announce_randomnes, h, stm=nym, secret_wit=rho_new)
            proof_nym_u = (challenge, announce_public, nym, response)

            ## changerep policies
            signatures_list_rnd = []
            ivk_vector_rnd = []

            for i in range(len(signatures_list)):
                randomized_signature, ivk_rnd = self.spseq.changerep(pp_spseq, ivk_vector[i], signatures_list[i], omega, upsilon)
                signatures_list_rnd.append(randomized_signature)
                ivk_vector_rnd.append(ivk_rnd)
            policies_rnd = (signatures_list_rnd, ivk_vector_new, (vsk, vpk))

            return (cred_new, nym, proof_nym_u, policies_rnd, h)

    def verify_proof(self, pp, pk_vector, proof, D, policy  = None):
        """
        :param pp: public parameters
        :param pk_vector: issuer vk
        :param proof: proof for D
        :param D: subset attributes to disclose
        :param policy: if set meaning check proof with respective issue hiding property
        :return: 0 or 1
        """
        (pp_sig, pp_spseq, pp_zkp) = pp
        if policy is None:
            (cred_new, nym, proof_tag , h) = proof
            (challenge, announce_public, nym, response) =proof_tag
            if type(D) is list:
               return self.atosa.aggr_verify(pp_sig, pk_vector, nym, D, cred_new) and \
               self.zkp_tag.verify(pp_zkp, challenge, announce_public, h, stm=nym, response=response)
            else: return self.atosa.verify(pp_sig, pk_vector, nym, D, cred_new) and \
                  self.zkp_tag.verify(pp_zkp, challenge, announce_public, h, stm=nym, response=response)
        else:
            (cred_new, nym, proof_tag, randomized_policies, h) = proof
            (signatures_list_rnd, ivk_vector_rnd, (vsk, vpk)) = randomized_policies
            (challenge, announce_public, nym, response) =proof_tag

            for i in range(len(ivk_vector_rnd)):
                 print(self.spseq.verify(pp_spseq, vpk, ivk_vector_rnd[i], signatures_list_rnd[i], types = G2Elem))

            return self.atosa.aggr_verify(pp_sig, ivk_vector_rnd, nym, D, cred_new) and \
                self.zkp_tag.verify(pp_zkp, challenge, announce_public, h, stm=nym, response=response)
