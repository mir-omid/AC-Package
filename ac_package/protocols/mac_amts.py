"""
Multi_AC using Aggregate Mercurial and Index-SetCommitment
"""

from bplib.bp import BpGroup, G2Elem
from ac_package.AC import AC
from ac_package.primitives.amts import AggrMercurial
from ac_package.primitives.set_commit import  IndexSetCommitment
from ac_package.primitives.spseq_signs import SingleAggr_FHS, FHS_Sign
from ac_package.util import pedersen_dec, convert_mess_to_bn
from ac_package.zkp import ZKP_Tag


class Multi_AC_Mercurial(AC):
    def __init__(self, max_cardinal):
        """
        :param max_cardinal: max cardinality for set commitment
        """
        self.group = BpGroup()
        self.mercurial = AggrMercurial()
        self.sc_commit = IndexSetCommitment(self.group, max_cardinal)
        self.spseq = FHS_Sign()
        self.zkp_tag = ZKP_Tag(self.group)

    def setup(self):
        """
        :return: pp
        """
        pp_sig = self.mercurial.setup()
        pp_spseq =  self.spseq.setup()
        pp_sc, alpha_trapdoor = self.sc_commit.setup_create_pp()
        pp_zkp = self.zkp_tag.setup()
        pp = (pp_sig, pp_spseq, pp_sc, pp_zkp)
        return pp, alpha_trapdoor

    def isuser_keygen(self, pp):
        """
        :param pp: public parameters
        :return: key pair for issuers
        """
        (pp_sig, pp_spseq, pp_sc, pp_zkp) = pp
        (isk, ipk) = self.mercurial.keygen(pp_sig)
        return (isk, ipk)

    def user_keygen(self, pp, alpha_trapdoor, message_vk_vector):
        """
        :param pp: public parameters
        :return: key pair for users
        """
        (pp_sig, pp_spseq, pp_sc, pp_zkp)= pp
        (tag, aux, pedersen_commitments_pair)= self.mercurial.gen_tag_aux(pp_sig, message_vk_vector, mac_amts= True)
        set_commitment_vector, open_info, h = self.sc_commit.commit_set(pp_sc, alpha_trapdoor, message_vk_vector, tag, aux)

        (tau, T_hat_vec) = tag
        uvk = T_hat_vec
        usk = tau
        return (usk, uvk, tag, aux, pedersen_commitments_pair, set_commitment_vector, open_info, h)

    def nym_gen(self, pp, h, tag):
        """
        :param pp:  public parameters
        :param upk: user public key ( or pseudonym)
        :return: a new pseudonym and auxiliary information
        """
        (pp_sig, pp_spseq, pp_sc, pp_zkp)= pp
        (group, g, g2, o) = pp_zkp
        upsilon = o.random()

        (tau_prime, T_prime) = self.mercurial.convert_tag(tag, upsilon)
        nym = T_prime
        secret_nym = tau_prime

        (announce_public, announce_randomnes) = self.zkp_tag.announce(pp_zkp, h)
        state = ['schnorr', g, h, announce_public.__hash__()]
        challenge = self.zkp_tag.challenge(state)
        response = self.zkp_tag.response(pp_zkp, challenge, announce_randomnes, h, stm=nym, secret_wit=secret_nym)
        proof_nym_u = (challenge, announce_public, nym, response)
        assert self.zkp_tag.verify(pp_zkp, challenge, announce_public, h, stm=nym, response=response)
        return (nym, secret_nym, proof_nym_u)


    # def gen_encode(self, pp, alpha_trapdoor, message_keys_set, tag, deactive_aggre_mercurial = None):
    #     """
    #     :param pp: public parameters
    #     :param alpha_trapdoor: trapdoor
    #     :param h: base
    #     :param tag: tag
    #     :param attr_set: attribute-set
    #     :return: vonvert attributes into DH based set commitment
    #     """
    #     (pp_sig, pp_spseq, pp_sc, pp_nizk) = pp
    #     ## create aux first then run encod
    #     set_commitment_vector, open_info = self.sc_commit.commit_set(pp_sc, alpha_trapdoor, message_keys_set, tag, aux)
    #     return set_commitment_vector, open_info


    # def gen_encode(self, pp, alpha_trapdoor, message_vk_vector, tag, attr_vector):
    #     """
    #     :param pp: public parameters
    #     :param alpha_trapdoor: trapdoor
    #     :param h: base
    #     :param tag: tag
    #     :param attr_set: attribute-set
    #     :return: vonvert attributes into DH based set commitment
    #     """
    #     (pp_sig, pp_spseq, pp_sc, pp_nizk) = pp
    #     (group, order, g1, g2, e) = pp_sig
    #     (usk, upk) = tag
    #     ## create aux first then run encod
    #
    #     aux = self.mercurial.gen_aux(pp_sig, message_vk_vector, upk)
    #     h = group.hashG1(aux.export())
    #
    #
    #     ## create set commitments
    #     set_commitment_vector = []
    #     open_info_vector = []
    #     if attr_vector[0][0] == list:
    #         for attr_item in attr_vector:
    #             commitment, open_info = self.sc_commit.commit_set(pp_sc, alpha_trapdoor, h, tag, attr_item)
    #             set_commitment_vector.append(commitment)
    #             open_info_vector.append(open_info)
    #         return set_commitment_vector, open_info_vector, aux, h
    #     else:
    #         commitment, open_info = self.sc_commit.commit_set(pp_sc, alpha_trapdoor, h, tag, attr_vector)
    #         return commitment, open_info, aux, h

    def issue_cred(self, pp, isk, set_commitment, aux, tag, attr_set, pedersen_commitment, proof_upk):
        """
        :param pp:  public parameters
        :param isk: issuer secert key
        :param set_commitment: messages vector for AMTS
        :param tag: tag
        :return: credential
        """
        ##---- this part can be completed like atosa protocol, for interactive singing----##
        (pp_sig, pp_spseq, pp_sc, pp_zkp)= pp
        (group, order, g1, g2, e, pp_pedersen) = pp_sig
        (challenge, announce_public, nym, response) = proof_upk
        h = group.hashG1(aux.export())
        assert self.zkp_tag.verify(pp_zkp, challenge, announce_public, h, stm=nym, response=response)

        if type(attr_set[0]) == str:
            attr_set_new = convert_mess_to_bn(attr_set)

        # if a commitemnt of message is provided, then check it's correct
        for i in range(len(attr_set_new)):
            (commitment_message, opening_message) = pedersen_commitment[i]
            (randomness, m) = opening_message
            assert pedersen_dec(pp_pedersen, opening_message, commitment_message), 'the message and commitment values do not match'
            #assert attr_set_new[i] == m and pedersen_dec(pp_pedersen, opening_message, commitment_message), 'the message and commitment values do not match'

        # for set_commitment_item in set_commitment_vector:
        #     if set_commitment == set_commitment_item:
        #         assert self.sc_commit.verify_subset(pp_sc, set_commitment, h, T_hat_vec[0], attr_set, witness)
        # else:
        #     print("set_commitment is not in vector of set_commitments.")

        signature = self.mercurial.sign(pp_sig, isk, tag, aux, set_commitment)
        cred = signature
        return cred

    def gen_policies(self, pp, messages_vks):
        """
        :param pp: public parameters
        :param messages_vks: issuer verification keys
        :return: policies (sign on issuer verification key) shows which issuers are accepted by verifier
        """
        (pp_sig, pp_spseq, pp_sc, pp_zkp)= pp

        signatures_list = []
        (vsk, vpk) = self.spseq.keygen(pp_spseq, len(messages_vks[0]), type=G2Elem)
        for ivk in messages_vks:
            signature = self.spseq.sign(pp_spseq, vsk, ivk)
            signatures_list.append(signature)
        policies = (signatures_list, messages_vks, (vsk, vpk))
        return policies

        # (pp_sig, pp_spseq, pp_sc, pp_zkp)= pp
        # (group, order, g1, g2, e, pp_pedersen) = pp_sig
        # signatures_list = []
        # prf = order.random()
        # verifier_keys = []
        #
        # for messagses in messages_vks:
        #     (verifier_sk, verifier_pk) = self.spseq.keygen_g1(pp_spseq, len(messagses))
        #     verifier_keys.append(verifier_pk)
        #     signature = self.spseq.sign(pp_spseq, verifier_sk, prf, messagses)
        #     signatures_list.append(signature)
        #
        # policies = (signatures_list, verifier_keys)
        # ### check policy are correct?
        # assert self.spseq.aggre_verify(pp_spseq, verifier_keys, messages_vks,
        #                                     self.spseq.aggr_sign(signatures_list),types=G2Elem)
        # return policies

    def proof_cred(self, pp, tag, vk_vector, cred, h, set_commitment_vector, attr_vector, D, policies=None):
        """
        :param pp: public parameters
        :param tag: tag
        :param vk_vector: issuer verification keys
        :param cred: credential
        :param commitment_vector: set commitment vector
        :param attr_vector: total attributes
        :param D: subset attributes to disclose
        :param policies: if set it means we are going to run proof with issuer hiding
        :return: proof over D
        """
        (pp_sig, pp_spseq, pp_sc, pp_zkp) = pp
        (group, order, g1, g2, e, pp_pedersen) = pp_sig

        if type(cred) is list:
            filter_signs = [cred[i] for i in range(len(attr_vector)) if cred[i] is not None]
            aggre_sign = self.mercurial.aggr_sign(filter_signs)
        else: aggre_sign = cred
        mu, opsilon, omega, chi = order.random(), order.random(), order.random(), order.random()

        if policies is None:
            ## randomizing signatures
            randomized_commitment_vector, randomize_sig, randomize_tag = self.mercurial.chang_rep(aggre_sign, set_commitment_vector, tag, mu, opsilon)
            (tau_new, T_hat_new) = randomize_tag
            nym = T_hat_new
            [rho_1_new, rho_2_new] = tau_new
            cred_new = randomize_sig

            ## ccreate a proof for tag
            (announce_public, announce_randomnes) = self.zkp_tag.announce(pp_zkp, h)
            state = ['schnorr', g1, h, announce_public.__hash__()]
            challenge = self.zkp_tag.challenge(state)
            response = self.zkp_tag.response(pp_zkp, challenge, announce_randomnes, h, stm=nym, secret_wit=tau_new)
            proof_nym_u = (challenge, announce_public, nym, response, h)
            if type(D[0]) ==list:
                 witness = [self.sc_commit.open_subset(pp_sc, attr_vector[i], opsilon, D[i]) for i in range(len(D))]
            else: witness = self.sc_commit.open_subset(pp_sc, attr_vector, opsilon, D)
            return (cred_new, nym, proof_nym_u, vk_vector, randomized_commitment_vector, witness)
        else:
            ### convert signature
            (signatures_list, ivk_vector, (vsk, vpk)) = policies
            convert_cred = self.mercurial.convert_sig(pp_sig, aggre_sign, omega)  # pk_vector_new = sign_scheme.convert_vk(pk_vector, mu)

            ### randomizing signature
            randomize_commitment_vector, randomize_sig, randomize_tag = self.mercurial.chang_rep(convert_cred, set_commitment_vector, tag, mu, opsilon)
            (tau_new, T_hat_new) = randomize_tag
            nym = T_hat_new
            cred_new = randomize_sig

            ## ccreate a proof for tag
            (announce_public, announce_randomnes) = self.zkp_tag.announce(pp_zkp, h)
            state = ['schnorr', g1, h, announce_public.__hash__()]
            challenge = self.zkp_tag.challenge(state)
            response = self.zkp_tag.response(pp_zkp, challenge, announce_randomnes, h, stm=nym, secret_wit=tau_new)
            proof_nym_u = (challenge, announce_public, nym, response, h)

            ### aggregate and changerep policies
            # (signatures_list, verifier_keys) = policies
            # aggreSign_in_policies = self.spseq.aggr_sign(signatures_list)
            # randomized_policies, message_vks_representive = self.spseq.changerep(pp_spseq, messages_vector = vk_vector,
            #                                                                  sign = aggreSign_in_policies, mu = omega, chi = chi)
            ## changerep policies

            signatures_list_rnd = []
            ivk_vector_rnd = []
            for i in range(len(signatures_list)):
                randomized_signature, ivk_rnd = self.spseq.changerep(pp_spseq, ivk_vector[i], signatures_list[i], omega, chi)
                signatures_list_rnd.append(randomized_signature)
                ivk_vector_rnd.append(ivk_rnd)
            policies_rnd = (signatures_list_rnd, ivk_vector_rnd, (vsk, vpk))

            if type(D[0]) == list:
                witness = [self.sc_commit.open_subset(pp_sc, attr_vector[i], opsilon, D[i]) for i in range(len(D))]
            else:
                witness = self.sc_commit.open_subset(pp_sc, attr_vector[0], opsilon, D)
            return (cred_new, nym, proof_nym_u, policies_rnd, ivk_vector_rnd, randomize_commitment_vector, witness)

    def verify_proof(self, pp, proof, D, aggregate_active = None, policies=None):
        """
        :param pp: public parameters
        :param proof: proof for D
        :param D: subset attributes to disclose
        :param policy: if set meaning check proof with respective issue hiding property
        :return: 0 or 1
        """
        (pp_sig, pp_spseq, pp_sc, pp_zkp) = pp

        if policies is None:
            (cred_new, nym, proof_nym_u, vk_vector, randomized_commitment_vector, witness) = proof
            (challenge, announce_public, nym, response, h_base) =proof_nym_u
            assert self.zkp_tag.verify(pp_zkp, challenge, announce_public, h_base, stm=nym, response=response)

            (h, b, s) = cred_new
            if type(D[0]) == list:
                for i in range(len(D)):
                    assert self.sc_commit.verify_subset(pp_sc, randomized_commitment_vector[i], nym[0], D[i], witness[i])
            else:
                assert self.sc_commit.verify_subset(pp_sc, randomized_commitment_vector, nym[0], D, witness)

            if aggregate_active is not None:
                return self.mercurial.aggre_verify(pp_sig, vk_vector, nym, randomized_commitment_vector, cred_new)
            else:
                return self.mercurial.verify(pp_sig, vk_vector, nym, randomized_commitment_vector, cred_new)
        else:
            (cred_new, nym, proof_nym_u, policies_rnd, ivk_vector_rnd, randomize_commitment_vector, witness) = proof
            (signatures_list_rnd, ivk_vector_rnd, (vsk, vpk)) = policies_rnd

            (challenge, announce_public, nym, response, h_base) = proof_nym_u
            assert self.zkp_tag.verify(pp_zkp, challenge, announce_public, h_base, stm=nym, response=response)
            if type(D[0]) == list:
                for i in range(len(D)):
                    assert self.sc_commit.verify_subset(pp_sc, randomize_commitment_vector[i], nym[0], D[i],witness[i])

            for i in range(len(ivk_vector_rnd)):
                assert self.spseq.verify(pp_spseq, vpk, ivk_vector_rnd[i], signatures_list_rnd[i], types = G2Elem)

            return self.mercurial.aggre_verify(pp_sig, ivk_vector_rnd, nym, randomize_commitment_vector, cred_new)