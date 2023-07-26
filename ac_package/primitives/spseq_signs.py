"""
This implementation of SPSQE signatures (FHS, Mercurial, single aggre FHS). See  the following for the details
- Structure-Preserving Signatures on Equivalence Classes and Constant-Size Anonymous Credentials" by Fuchsbauer1 et al.,
@Author: Omid
"""
from ac_package.util import *

class FHS_Sign:

    def __init__(self):
        global group
        group = BpGroup()
    @staticmethod
    def setup():
        """
        :return:  generate and return public parameters
        """
        g1, g2 = group.gen1(), group.gen2()
        e, order = group.pair, group.order()
        return (group, order, g1, g2, e)

    def keygen(self, pp_sign, l_message, type = None):
        """
        :param pp_sign: params: get public parameters
        :param l_message: length of keys and messages to be signed
        :return: keys pair sk, vk
        """
        (group, order, g1, g2, e) = pp_sign
        sk = [order.random() for _ in range(0, l_message)]
        if type is None:
            vk = [sk[i] * g2 for i in range(len(sk))]
        else:
            vk = [sk[i] * g1 for i in range(len(sk))]
        return (sk, vk)

    def sign(self, pp_sign, sk, messages_vector):
        """
        :param pp_sign: get public parameters
        :param sk: secret keys for signing
        :param messages_vector:  messages_vector
        :return: FHS signature as sign
        """
        assert isinstance(messages_vector, list)
        if type(messages_vector[0]) == str:
            messages_vector = convert_mess_to_groups(messages_vector)

        (group, order, g1, g2, e) = pp_sign
        y = order.random()
        list_z = [sk[i] * messages_vector[i] for i in range(len(messages_vector))]
        z_point = ec_sum(list_z)
        Z = y.mod_inverse(order) * z_point
        Y = y * g1
        Y_hat = y * g2
        sign = (Z, Y, Y_hat)
        return sign

    def changerep(self, pp_sign, messages_vector, sign, mu, chi):
        """
        :param pp_sign: get public parameters
        :param messages_vector: messages_vector
        :param sign: signature
        :param mu: randomness
        :param chi: randomness
        :return: randomized signature
        """
        (group, order, g1, g2, e) = pp_sign
        assert isinstance(messages_vector, list)
        # randomize messages_vector
        if type(messages_vector[0]) == str:
            messages_vector = convert_mess_to_groups(messages_vector)
            randomized_messages = eq_relation(messages_vector, mu)
        else:
            randomized_messages = eq_relation(messages_vector, mu)

        ## adapt the signiture for the randomized messages_vector
        (Z, Y, Y_hat) = sign
        Z_prime = (mu * chi.mod_inverse(order)) * Z
        Y_prime =  chi * Y
        Y_hat_prime = chi * Y_hat
        sigma_prime = (Z_prime, Y_prime, Y_hat_prime)
        return sigma_prime, randomized_messages

    def verify(self, pp_sign, vk, messages_vector, sign, types = None):
        """
        :param pp_sign: public parameters
        :param vk: verification key
        :param messages_vector: signed messages_vector
        :param sign: signature
        :return: 0,1 (1 if it is correct, 0 otherwise)
        """
        assert isinstance(messages_vector, list)
        if type(messages_vector[0]) == str:
            messages_vector = convert_mess_to_groups(messages_vector)

        (group, order, g1, g2, e) = pp_sign
        (Z, Y, Y_hat) = sign
        if types is None:
            # statment 1
            right_side = group.pair(Z, Y_hat)
            pairing_op = [group.pair(messages_vector[j], vk[j]) for j in range(len(messages_vector))]
            left_side = product_GT(pairing_op)
            return (group.pair(Y, g2) == group.pair(g1, Y_hat)) and right_side == left_side
        else:
            # statment 1
            right_side = group.pair(Y, Z)
            pairing_op = [group.pair(vk[j], messages_vector[j]) for j in range(len(messages_vector))]
            left_side = product_GT(pairing_op)
            return (group.pair(Y, g2) == group.pair(g1, Y_hat)) and right_side == left_side



class Mercurial_Sign(FHS_Sign):

    def convert_sk(self, sk, rho):
        """
        :param sk: secret keys
        :param rho: randomness
        :return: randomized sk
        """
        sk_prime = [rho * sk[i] for i in range(len(sk))]
        return sk_prime

    def convert_vk(self, vk, rho):
        """
        :param vk: verification key
        :param rho: randomness
        :return: randomized vk
        """
        vk_prime = [rho * vk[i] for i in range(len(vk))]
        return vk_prime

    def convert_sig(self, pp_sign, sign, rho):
        """
        :param sign: signature
        :param rho: randomness
        :return: adatpted sig for randomized vk/sk
        """
        (group, order, g1, g2, e) = pp_sign
        (Z, Y, Y_hat) = sign
        chi = order.random()
        Z_prime = (rho * chi.mod_inverse(order)) * Z
        Y_prime = chi * Y
        Y_hat_prime = chi * Y_hat
        converted_sign = (Z_prime, Y_prime, Y_hat_prime)
        return converted_sign




"""
This is a type of FHS signature where a signer can sign many messages independently with a single prf.
later one can aggregate them. This allows for signing G1 and G2 messages and used in multi authority AC protocol
Not work yet
"""

class SingleAggr_FHS(FHS_Sign):

    # def __init__(self):
    #     super().__init__()

    def sign(self, pp_sign, sk, prf, messages_vector):
        """
        :param pp_sign: public parameters
        :param sk: secret keys
        :param prf: a prf <- H(tag, k)
        :param messages_vector:
        :return: sign as a signature
        """
        assert isinstance(messages_vector, list)
        if type(messages_vector[0]) == str:
            messages_vector = convert_mess_to_groups(messages_vector)

        (group, order, g1, g2, e) = pp_sign
        list_z = [sk[i] * messages_vector[i] for i in range(len(messages_vector))]
        z_point = ec_sum(list_z)
        Z = prf.mod_inverse(order) * z_point
        Y = prf * g1
        Y_hat = prf * g2
        sign = (Z, Y, Y_hat)
        return sign

    def keygen_g1(self, pp_sig, l_message):
        """
        :param pp_sign: public parameters
        :param l_message: l_message: length of keys and messages to be signed
        :return: vk and sk in G1 that allow signing messages in G2
        """
        (group, order, g1, g2, e) = pp_sig
        sk = [order.random() for _ in range(0, l_message)]
        vk = [sk[i] * g1 for i in range(len(sk))]
        return (sk, vk)

    def aggr_sign(self, sign_list):
        """
        :param sign_list: list of signatures
        :return: an aggregate signature
        """
        Z_vector = []
        for i in range(len(sign_list)):
            (Z, Y, Y_tag) = sign_list[i]
            Z_vector.append(Z)
        aggre_z = ec_sum(Z_vector)
        (Z_0, Y_0, Y_tag_0)  = sign_list[0]
        aggre_sign = (aggre_z, Y_0, Y_tag_0)
        return aggre_sign

    def aggre_verify(self, params, vk_vector, m_vector, agg_sig, types = None):
        """
        :param params: public parameters
        :param vk_vector: vector of verification key
        :param m_vector: vector of message's vector
        :param agg_sig: aggegate signature
        :param types: this show which type of messages should be verifiedG1 or G2
        :return: 0,1 (1 if it is correct, 0 otherwise)
        """
        (group, order, g1, g2, e) = params
        (Z, Y, Y_hat) = agg_sig

        if type(m_vector[0][0]) == str:
            m_vector = [convert_mess_to_groups(item) for item in m_vector]

        if types is None:
            pairing_op = [group.pair(m_vector[i][j], vk_vector[i][j]) for i in range(len(m_vector)) for j in range(len(m_vector[i]))]
            right_side = group.pair(Z, Y_hat)
            # pairing_op = [group.pair(m_vector[j][i], vk_vector[j][i]) for j, i in range(len(m_vector))]
            left_side = product_GT(pairing_op)
            return (group.pair(Y, g2) == group.pair(g1, Y_hat)) and right_side == left_side
        else:
            pairing_op = [group.pair(vk_vector[i][j], m_vector[i][j]) for i in range(len(m_vector)) for j in
                          range(len(m_vector[i]))]
            right_side = group.pair(Y, Z)
            # pairing_op = [group.pair(m_vector[j][i], vk_vector[j][i]) for j, i in range(len(m_vector))]
            left_side = product_GT(pairing_op)
            return (group.pair(Y, g2) == group.pair(g1, Y_hat)) and right_side == left_side



