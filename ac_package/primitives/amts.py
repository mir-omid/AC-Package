""" An implementation of the Aggregate Mercurial  Signatures scheme with the randomization of keys/tag/messagges/signatures
@Author: Omid Mir
"""

from bplib.bp import BpGroup
from ac_package.util import tag_dh_message, eq_dh_relation, product_GT, ec_sum, eq_relation, convert_mess_to_bn, \
    pedersen_committ, pedersen_setup


class AggrMercurial:
    def __init__(self):
        global group
        group = BpGroup()
    @staticmethod
    def setup():
        """
        :return: public parameters
        """
        (pp_pedersen, trapdoor) = pedersen_setup(group)
        g1, g2 = group.gen1(), group.gen2()
        e, order = group.pair, group.order()
        return (group, order, g1, g2, e, pp_pedersen)

    def keygen(self, params):
        """
        :param params: public parameters
        :return: secret and verification keys
        """
        (group, order, g1, g2, e, pp_pedersen) = params
        (x, y_1, y_2, z_1, z_2) = order.random(), order.random(), order.random(), order.random(), order.random()
        sk = (x, y_1, y_2, z_1, z_2)
        vk = [x * g2, y_1 * g2, y_2 * g2,  z_1 * g2, z_2 * g2]
        return (sk, vk)

    # def gen_aux(self, params, message_vk_vector, T_vec):
    #     """
    #     :param rho_hat: the public part of tag
    #     :param messages_vector: message vector
    #     :return: tag based dh messages type
    #     """
    #     (group, order, g1, g2, e) = params
    #     [T_1, T_2] = T_vec
    #     [message_vector, vk_vector] = message_vk_vector
    #
    #     if type(message_vector[0][0]) is str:
    #         assert len(message_vector) == 2
    #         message_vector = [convert_mess_to_bn(message_vector[i]) for i in range(len(message_vector))]
    #     list_N = [item[i] * g2 for item in message_vector for i in range(len(item))]
    #     aux = T_1 + T_2 + ec_sum(list_N)
    #     return aux

    def encode(self, params, T_vec, messages_vector):
        """
        :param rho_hat: the public part of tag
        :param messages_vector: message vector
        :return: tag based dh messages type
        """
        # first check if all message are string, also if it is a vector of length two (this is needed in the paper)
        assert type(messages_vector) == list and len(messages_vector) <= 2 and all(
            isinstance(x, str) for x in messages_vector)
        tag_dh_messages = tag_dh_message(params, T_vec, messages_vector)
        return tag_dh_messages

    def gen_tag_aux(self, params, message_vk_vector, mac_amts = None):
        """
        :param params:
        :param message_vk_vector:
        :return:
        """
        (group, order, g1, g2, e, pp_pedersen) = params
        ## pick two randoms as tag secret
        rho_1, rho_2 = order.random(), order.random()

        ## create aux using tag secret and the set
        commit_list = []
        commitment_temp = []
        commitment_pair_list = []
        [message_vector, vk_vector] = message_vk_vector

        # if all(isinstance(element, str) for element in message_vector):
        #     set_m = convert_mess_to_bn(message_vector)
        # else:
        #     print("Please insert messages of the same data type")
        message_vector_new = []
        if mac_amts is None:
            assert len(message_vector) == 2
            message_vector_new = [convert_mess_to_bn(message_vector[i]) for i in range(len(message_vector))]
            for m_set in message_vector_new:
                for item in m_set:
                    (pedersen_commit, pedersen_open) = pedersen_committ(pp_pedersen, item)
                    commit_list.append(pedersen_commit)
                    commitment_pair_list.append((pedersen_commit, pedersen_open))
        else:
            for item in message_vector:
                vector = [convert_mess_to_bn(item[i]) for i in range(len(item))]
                message_vector_new.append(vector)
                for m_vector in message_vector_new:
                    for m_set in m_vector:
                        for item in m_set:
                            (pedersen_commit, pedersen_open) = pedersen_committ(pp_pedersen, item)
                            commit_list.append(pedersen_commit)
                            commitment_temp.append((pedersen_commit, pedersen_open))
                            commitment_pair_list.append(commitment_temp)

        #list_N = [item[i] * g2 for item in message_vector for i in range(len(item))]
        ## for now, we do not consider vk in the aux for now?, we should concatenat them in aux

        aux = (rho_1 * g1) + (rho_2 * g1) + ec_sum(commit_list)
        h = group.hashG1(aux.export())
        T_vec = [rho_1 * h, rho_2 * h]
        tau = [rho_1, rho_2]
        tag = (tau, T_vec)
        return (tag, aux, commitment_pair_list)

    def sign(self, params, sk, tag, aux, messages_vector, commitment_pair= None):
        """
        :param params: public parameters
        :param sk:  secret keys for signing
        :param tag: a tag that is pair of secret and public parts
        :param messages_vector: messages
        :return: signature
        """
        (group, order, g1, g2, e, pp_pedersen) = params
        (x, y_1, y_2, z_1, z_2) = sk
        (tau, T_hat_vec) = tag
        (rho_1, rho_2) = tau

        # check if message are string, then convert to tag dh type
        if type(messages_vector[0]) is str:
            assert len(messages_vector) == 2
            messages_vector = tag_dh_message(T_hat_vec, messages_vector)


        # if commitment_pair is not None:
        #     (commitment_message, opening_message) = commitment_pair
        #     (randomness, m) = opening_message
        #     assert m == message and pedersen_dec(pp_pedersen, opening_message,
        #                                          commitment_message), 'the message and commitment values do not match'

        # generate sig for a vector of size two, this is in the paper construction
        (M_1, N_1) = messages_vector[0]
        (M_2, N_2) = messages_vector[1]
        h = group.hashG1(aux.export())
        b = (rho_1 * z_1 + rho_2 * z_2) * h
        s = x * h + y_1 * M_1 + y_2 * M_2
        signature  = (h, b, s)
        return signature

    def sign_intract(self, params, sk, aux, T_vec, messages_vector, proof):
        """
        :param params: public parameters
        :param sk:  secret keys for signing
        :param tag: a tag that is pair of secret and public parts
        :param messages_vector: messages
        :return: signature
        """
        (group, order, g1, g2, e, pp_pedersen) = params
        (x, y_1, y_2, z_1, z_2) = sk
        [T_1, T_2] = T_vec

        ## generate sig for a vector of size two, this is in the paper construction
        # check proofs
        (M_1, N_1) = messages_vector[0]
        (M_2, N_2) = messages_vector[1]

        h = group.hashG1(aux.export())
        b = z_1 * T_1 + z_2 * T_2
        s = (x * h + y_1 * M_1 + y_2 * M_2)
        signature  = (h, b, s)
        return signature

    def verify(self, params, vk, T_vec, messages_vector, signature):
        """
        :param params:  public parameters
        :param vk: verification key
        :param rho_hat: the  public part of tag
        :param messages_vector:  a signed messages
        :param signature: sigature
        :return: true,false (true if it is correct, false otherwise)
        """
        (group, order, g1, g2, e, pp_pedersen) = params
        [T_1, T_2] = T_vec

        # check if message is string if yet convert it  or call encode
        if type(messages_vector[0]) is str:
             messages_vector = tag_dh_message(T_vec, messages_vector)

        # it works only for two messages similar to the paper construction
        [M_1, N_1] = messages_vector[0]
        [M_2, N_2] = messages_vector[1]
        [X, Y_1, Y_2, Z_1, Z_2] = vk
        (h, b, s) = signature
        return e(h, X) * e(M_1, Y_1) * e(M_2, Y_2) == e(s, g2) and e(b, g2) == e(T_1, Z_1) *  e(T_2, Z_2)  \
            and e(T_1, N_1) == e(M_1, g2) and e(T_2, N_2) == e(M_2, g2)

    def chang_rep(self, sig, m_vector, tag, mu, opsilon):
        """
        :param sig: sigature
        :param m_vector:  only accept tag dh based messave vector
        :param tag: tag
        :param mu: randomness
        :param opsilon: randomness
        :return: randomized signature/tga and messave vector
        """
        #assert type(m_vector[0]) == str, print("not correct message format, encode your messages into the tag based dh")
        (h, b, s) = sig
        h_new = (mu * opsilon) * h
        b_new = mu * b
        s_new = (mu * opsilon) * s
        randomize_sig = (h_new, b_new, s_new)
        (tau,T_vec) = tag
        [T_1, T_2] = T_vec
        [rho_1, rho_2] = tau
        (tau_prime, T_prime) = self.convert_tag(tag, mu)
        randomize_tag = (tau_prime, T_prime)

        # randomize (tag) dh message vector that can be vector of some vector
        if type(m_vector[0][0]) is list:
            randomize_dh_message = [eq_dh_relation(item, mu, opsilon) for item in m_vector]
        else: randomize_dh_message = eq_dh_relation(m_vector, mu, opsilon)
        return randomize_dh_message, randomize_sig, randomize_tag

    def convert_tag(self, tag, upsilon):
        (tau, T_vec) = tag
        [T_1, T_2] = T_vec
        [rho_1, rho_2] = tau
        # T_prime = (upsilon * T_1, upsilon * T_2)
        T_prime = eq_relation(T_vec, upsilon)
        tau_prime = eq_relation(tau, upsilon)
        return (tau_prime, T_prime)

    def aggre_verify(self, params, vk_vector, T_vec, messages_set_vector, agg_sig):
        """
        :param params: public parameters
        :param vk_vector: aggregate avk which is a vector of vks
        :param rho_hat: public part of tag
        :param messages_set_vector: vector of messages vector
        :param agg_sig: aggregate signature
        :return:  true, false (true if it is correct, false otherwise)
        """
        (BG, order, g1, g2, e, pp_pedersen) = params
        (h, b, s) = agg_sig
        [T_1, T_2] = T_vec

        if type(messages_set_vector[0][0]) is str:
             messages_set_vector = [tag_dh_message(T_vec, item) for item in messages_set_vector]

        # compute the left side of  first equation
        precompute_s = []
        precompute_b = []
        for i in range(len(vk_vector)):
            [X, Y_1, Y_2, Z_1, Z_2] = vk_vector[i]
            [[M_1, N_1], [M_2, N_2]] = messages_set_vector[i]
            precompute_s.append(e(h, X) * e(M_1, Y_1) * e(M_2, Y_2))
            precompute_b.append(e(T_1, Z_1) *  e(T_2, Z_2))

        # check other second equation, checking messages are correct tag dh message
        for i in range(len(messages_set_vector)):
            [[M_1, N_1], [M_2, N_2]] = messages_set_vector[i]
            assert e(T_1, N_1) == e(M_1, g2) and e(T_2, N_2) == e(M_2, g2)

        left_eq_s = product_GT(precompute_s)
        left_eq_b = product_GT(precompute_b)
        return not h.isinf() and left_eq_s == e(s, g2) and e(b, g2) == left_eq_b

    # def gen_tag(self, params):
    #     """
    #     :param params:
    #     :param message_vk_vector:
    #     :return:
    #     """
    #     (BG, order, g1, g2, e) = params
    #     ## pick two randoms as tag secret
    #     rho_1, rho_2 = order.random(), order.random()
    #     T_hat1 = rho_1 * g2
    #     T_hat2 = rho_2 * g2
    #     T_hat_vec = [T_hat1, T_hat2]
    #     tau = [rho_1, rho_2]
    #     tag = (tau, T_hat_vec)
    #     return tag

    def aggr_sign(self, sig_list):
        """
        :param sig_list:
        :return: aggregate signature
        """
        (h, b, s) = sig_list[0]
        filter_s = [item[2] for item in sig_list]
        filter_b = [item[1] for item in sig_list]
        aggre_b = ec_sum(filter_b)
        aggre_s = ec_sum(filter_s)
        aggre_sign = (h, aggre_b, aggre_s)
        return aggre_sign

    def convert_sk(self, sk, omega):
        """
        :param sk: secret key
        :param omega: randomness
        :return: randomized sk
        """
        (x, y_1, y_2, z_1, z_2) = sk
        sk_prime = (omega * x, omega * y_1, omega * y_2, omega * z_1, omega * z_2)
        return sk_prime

    def convert_vk(self, vk, omega):
        """
        :param vk: verification keys
        :param omega: randomness
        :return: randomized vk
        """
        vk_prime = eq_relation(vk, omega)
        return vk_prime

    def convert_sig(self, params, sig, omega):
        """
        :param sig: signature
        :param omega: randomness
        :return: converted signature for randomized vk/dk
        """
        (h, b, s) = sig
        b_new = omega * b
        s_new = omega * s
        converted_sig = (h, b_new, s_new)
        return converted_sig
