"""
This implementation of Set commitments with additional cross commitment and  aggregation properties .
These commitments can be used to build SPSQE-UC signatures and their application delegatable anonymous credential.
See  the following for the details:
- Structure-Preserving Signatures on Equivalence Classes and Constant-Size Anonymous Credentials" by Fuchsbauer1 et al.,
- (PETS) Practical, Efficient, Delegatable Ano nymous Credentials through SPSEQ-UC, by Mir et al.,
@Author: ...
"""

from binascii import hexlify
from hashlib import sha256
from bplib.bp import BpGroup
from numpy.polynomial.polynomial import polyfromroots
from petlib.bn import Bn
from ac_package.util import convert_mess_to_bn, ec_sum, product_GT, eq_dh_relation


class SetCommitment:
    def __init__(self, BG_obj, max_cardinal = 1):
        """
        :param BG_obj: bilinear pairing groups
        :param max_cardinal: this is the maximum cardinality 𝑡
        """
        global group
        global max_cardinality
        max_cardinality = max_cardinal
        group = BG_obj

    @staticmethod
    def setup_create_pp():
        """
        :return: it is a static method to generate public parameters
        """
        g_1, g_2 = group.gen1(), group.gen2()
        order = group.order()
        alpha_trapdoor = order.random()
        pp_commit_G1 = [g_1.mul(alpha_trapdoor.pow(i)) for i in range(max_cardinality)]
        pp_commit_G2 = [g_2.mul(alpha_trapdoor.pow(i)) for i in range(max_cardinality)]
        param_sc = (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group)
        return param_sc, alpha_trapdoor

    def commit_set(self, param_sc,  mess_set_str):
        """
        :param param_sc: public parameters as P^ai, P_hat^ai, P = g1, P_hat = g2, Order, BG
        :param mess_set_str: a message set
        :return: a set commitment and related opening information
        """
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group) = param_sc

        # convert string to Zp
        mess_set = convert_mess_to_bn(mess_set_str)
        monypol_coeff = polyfromroots(mess_set)
        rho = group.order().random()

        # create group elements using the coefficent and public info
        coef_points = [(pp_commit_G1.__getitem__(i)).mul(monypol_coeff[i])for i in range(len(monypol_coeff))]

        # create a set commitment and opening info
        pre_commit = ec_sum(coef_points)
        commitment = pre_commit.mul(rho)
        open_info = rho
        return (commitment, open_info)


    def open_set(self, param_sc, commitment, open_info, mess_set_str):
        """
        :param param_sc: public parameters
        :param commitment: the set commitment
        :param open_info: the opening info of commitment
        :param mess_set_str: the message set
        :return: true if evolution is correct, false otherwise
        """
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group) = param_sc

        mess_set = convert_mess_to_bn(mess_set_str)
        monypol_coeff = polyfromroots(mess_set)

        #pre compitation to recompute the commitment
        coef_points = [(pp_commit_G1.__getitem__(i)).mul(monypol_coeff[i])for i in range(len(monypol_coeff))]
        pre_commit = ec_sum(coef_points)
        re_commit = pre_commit.mul(open_info)

        #check if the regenerated commitment is match with the orginal commitment
        if re_commit == commitment:
            return True
        else:
            return False

    def open_subset(self, param_sc, mess_set_str, open_info, subset_str):
        """
        :param param_sc: public parameters
        :param mess_set_str: the messagfe set
        :param open_info: opening information
        :param subset_str: a subset of the message set
        :return: a witness for the subset
        """
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group) = param_sc

        # convert the string to BN elements
        mess_set = convert_mess_to_bn(mess_set_str)
        mess_subset_t = convert_mess_to_bn(subset_str)

        # check if sets are subset with each other
        def is_subset(mess_set, mess_subset_t):
            chcker = None
            if len(mess_subset_t) > len(mess_set):
                return False
            else:
                for item in mess_subset_t:
                    if (item in mess_set):
                        chcker = True
                    else:
                        chcker = False
            return chcker

        # comute a witness
        if is_subset(mess_set, mess_subset_t) == True:
            create_witn_elements = [item for item in mess_set if item not in mess_subset_t]
            coeff_witn = polyfromroots(create_witn_elements)
            witn_groups = [(pp_commit_G1.__getitem__(i)).mul(coeff_witn[i]) for i in range(len(coeff_witn))]
            witn_sum = ec_sum(witn_groups)
            witness = witn_sum.mul(open_info)
            return witness
        else:
            print("It is Not a subset")
            return False

    def verify_subset(self, param_sc, commitment, subset_str, witness):
        """
        :param param_sc: set commitment public parameters
        :param commitment: commitment
        :param subset_str: subset message
        :param witness: witness to prove subset message in message set
        :return: 0 or 1
        """
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group) = param_sc

        mess_subset_t = convert_mess_to_bn(subset_str)
        coeff_t = polyfromroots(mess_subset_t)
        subset_group_elements =[(pp_commit_G2.__getitem__(i)).mul(coeff_t[i])for i in range(len(coeff_t))]
        subset_elements_sum = ec_sum(subset_group_elements)

        if group.pair(witness, subset_elements_sum) == group.pair(commitment, g_2):
            return True
        else:
            return False

    # def Open(self, param_sc, commitment, open_info, set_str):
    #     pass

class CrossSetCommitment(SetCommitment):

    def __init__(self, BG_p, max_cardinal):
        SetCommitment.__init__(self, BG_p, max_cardinal)

    def aggregate_cross(self, witness_vector, commit_vector):
        """
        :param witness_vector: a vector of witnessess
        :param commit_vector: the commitment vector
        :return: a proof which is a aggregate of witnesses and shows all subsets are valid for respective sets
        """
        # if type(commit_vector[0]) is tuple:
        #     commit_vector = [item[0] for item in commit_vector]

        witnessness_group_elements = list()
        for i in range(len(witness_vector)):
            """ generates a Bn challenge t_i by hashing a number of EC points """
            Cstring = b",".join([hexlify(commit_vector[i].export())])
            chash = sha256(Cstring).digest()
            hash_i = Bn.from_binary(chash)
            witnessness_group_elements.append(witness_vector[i].mul(hash_i))
            # pi = (list_W[i+1] ** t_i).add(pi)
            # comute pi as each element of list power to t_i
        proof = ec_sum(witnessness_group_elements)
        return proof

    def verify_cross(self, param_sc, commit_vector, subsets_vector_str, proof):
        """
        :param param_sc: public parameters
        :param commit_vector: the set commitment vector
        :param subsets_vector_str: the message sets vector
        :param proof: a proof which is a aggregate of witnesses
        :return: 1 or 0
        """
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group) = param_sc

        # create a union of sets
        def union(subsets_vector):
            set_s = subsets_vector[0]
            for i in range(1, len(subsets_vector)):
                set_s = set_s + subsets_vector[i]
            return set_s

        # create a set that is not intersection
        def not_intersection(list_S, list_T):
            set_s_not_t = [value for value in list_S if value not in list_T]
            return set_s_not_t

        ## convert message str into the BN
        subsets_vector = [convert_mess_to_bn(item) for item in subsets_vector_str]
        set_s = union(subsets_vector)
        coeff_set_s = polyfromroots(set_s)

        # compute right side of veriication
        set_s_group_elements = [(pp_commit_G2.__getitem__(i)).mul(coeff_set_s[i])for i in range(len(coeff_set_s))]
        set_s_elements_sum = ec_sum(set_s_group_elements)
        right_side = group.pair(proof, set_s_elements_sum)

        set_s_not_t = [not_intersection(set_s, subsets_vector[i]) for i in range(len(subsets_vector))]
        vector_GT = list()
        for j in range(len(commit_vector)):
            coeff_s_not_t = polyfromroots(set_s_not_t[j])
            listpoints_s_not_t = [(pp_commit_G2.__getitem__(i)).mul(coeff_s_not_t[i]) for i in
                                  range(len(coeff_s_not_t))]
            temp_sum = ec_sum(listpoints_s_not_t)
            Cstring = b",".join([hexlify(commit_vector[j].export())])
            chash = sha256(Cstring).digest()
            hash_i = Bn.from_binary(chash)
            GT_element = group.pair(commit_vector[j], hash_i * temp_sum)
            vector_GT.append(GT_element)

        left_side = product_GT(vector_GT)
        if right_side.eq(left_side):
            return True
        else:
            return False



"""
Index (tag) based SetCommitment is propossed here 
"""

class IndexSetCommitment:
    def __init__(self, BG_obj, max_cardinal=1):
        """
        :param BG_obj: bilinear pairing groups
        :param max_cardinal: this is the maximum cardinality 𝑡
        """
        global group
        global max_cardinality
        max_cardinality = max_cardinal
        group = BG_obj

    @staticmethod
    def setup_create_pp():
        """
        :return: it is a static method to generate public parameters
        """
        g_1, g_2 = group.gen1(), group.gen2()
        order = group.order()
        alpha_trapdoor = order.random()
        pp_commit_G1 = [g_1.mul(alpha_trapdoor.pow(i)) for i in range(max_cardinality)]
        pp_commit_G2 = [g_2.mul(alpha_trapdoor.pow(i)) for i in range(max_cardinality)]
        param_sc = (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group)
        return param_sc, alpha_trapdoor

    """ this code is not yet efficent but it works"""
    def commit_set(self, param_sc, alpha_trapdoor, message_keys_set, tag, aux, deactive_aggre_mercurial = None):
        """
        :param param_sc: get public parameters
        :param alpha_trapdoor: get alpha_trapdoor to create commitment when base (h) is unknow to commiter
        :param h: base (hash of tag) regarding to tag to create a commitment in G1 related to tag based message space
        :param tag: get a tag (open information) and cehck if h is computed correctly
        :param mess_set_str: messages set
        :param active_aggre_mercurial: a boolean if a commitment needs to be appropriate for aggre mercurial signature (two vectors)
        :return: commitment based on tag dh message space
        """
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group) = param_sc
        (tau, T_vec) = tag
        [T_1 , T_2] = T_vec
        [rho_1, rho_2] = tau
        [message_vector, vks_vector] = message_keys_set
        set_commitment_vector = []
        open_info = tau
        h = group.hashG1(aux.export())
        #pp_commit_h = [h.mul(alpha_trapdoor.pow(i)) for i in range(max_cardinality)]


        ###--- we should also add the case that only message_vector is only  [attributes, dummy_set] (deasctive aggregate)--------###
        if deactive_aggre_mercurial is None:
            ## creating the C1, C2 with the element h and hat C1, hat C2
            for itme in message_vector:
                [attributes, dummy_set] = itme
                # convert string to Zp
                mess_set1 = convert_mess_to_bn(attributes)
                mess_set2 = convert_mess_to_bn(dummy_set)

                # create group elements using the coefficent and public info
                monypol_coeff1 = polyfromroots(mess_set1)
                coef_points1 = [(pp_commit_G2.__getitem__(i)).mul(monypol_coeff1[i]) for i in
                                range(len(monypol_coeff1))]
                pre_commit1 = ec_sum(coef_points1)
                commitment_G2_set1 = 1 * pre_commit1
                coef_pointsh =  [h.mul(alpha_trapdoor.pow(i) * monypol_coeff1[i]) for i in range(len(monypol_coeff1))]
                pre_commit1_g1 = ec_sum(coef_pointsh)
                commitment_G1_set1 = rho_1 * pre_commit1_g1


                # create group elements using the coefficent and public info
                monypol_coeff2 = polyfromroots(mess_set2)
                coef_points2 = [(pp_commit_G2.__getitem__(i)).mul(monypol_coeff2[i]) for i in
                                range(len(monypol_coeff2))]
                pre_commit2 = ec_sum(coef_points2)
                commitment_G2_set2 = pre_commit2.mul(1)

                pre_commit2_g = ec_sum([h.mul(alpha_trapdoor.pow(i) * monypol_coeff2[i]) for i in range(len(monypol_coeff2))])
                commitment_G1_set2 = pre_commit2_g.mul(rho_2)

                set_commitment = [[commitment_G1_set1, commitment_G2_set1], [commitment_G1_set2, commitment_G2_set2]]
                set_commitment_vector.append(set_commitment)
                #assert group.pair(commitment_G1_set1, g_2) == group.pair(T_1, commitment_G2_set1)
                assert group.pair(commitment_G1_set1, g_2) == group.pair(T_1, commitment_G2_set1)

            return set_commitment_vector, open_info, h
        else:
            for item in message_vector:
                # convert string to Zp
                mess_set1 = convert_mess_to_bn(item)
                # create group elements using the coefficent and public info
                monypol_coeff1 = polyfromroots(mess_set1)
                coef_points1 = [(pp_commit_G2.__getitem__(i)).mul(monypol_coeff1[i]) for i in
                                range(len(monypol_coeff1))]
                pre_commit1 = ec_sum(coef_points1)
                commitment_G2_set1 = pre_commit1.mul(rho_1)

                # create group elements using the coefficent and public info
                commitment_G1_set1 = ec_sum(
                    [h.mul(alpha_trapdoor.pow(i) * monypol_coeff1[i]) for i in range(len(monypol_coeff1))])
                set_commitment = [commitment_G1_set1, commitment_G2_set1]
                set_commitment_vector.append(set_commitment)
            return set_commitment_vector, open_info, h

    # def commit_set(self, param_sc, alpha_trapdoor, message_keys_set, tag, attr_set, active_aggre_mercurial = None):
    #     """
    #     :param param_sc: get public parameters
    #     :param alpha_trapdoor: get alpha_trapdoor to create commitment when base (h) is unknow to commiter
    #     :param h: base (hash of tag) regarding to tag to create a commitment in G1 related to tag based message space
    #     :param tag: get a tag (open information) and cehck if h is computed correctly
    #     :param mess_set_str: messages set
    #     :param active_aggre_mercurial: a boolean if a commitment needs to be appropriate for aggre mercurial signature (two vectors)
    #     :return: commitment based on tag dh message space
    #     """
    #     (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group) = param_sc
    #     (tau, T_hat_vec) = tag
    #     [rho_1, rho_2] = tau
    #     [[ivk_1, ivk_2], [set_str1, set_str2]] = message_keys_set
    #     set_commitment_vector = []
    #
    #     if active_aggre_mercurial is None:
    #         [attr_set, dummy_set] = attr_vector
    #
    #         # convert string to Zp
    #         mess_set1 = convert_mess_to_bn(attr_set)
    #         mess_set2 = convert_mess_to_bn(dummy_set)
    #
    #         # create group elements using the coefficent and public info
    #         monypol_coeff1 = polyfromroots(mess_set1)
    #         coef_points1 = [(pp_commit_G2.__getitem__(i)).mul(monypol_coeff1[i]) for i in range(len(monypol_coeff1))]
    #         # create a set commitment and opening info
    #         pre_commit1 = ec_sum(coef_points1)
    #         commitment_G2_set1 = pre_commit1.mul(rho_1)
    #         commitment_G1_set1 = ec_sum([h.mul(alpha_trapdoor.pow(i) * monypol_coeff1[i]) for i in range(len(monypol_coeff1))])
    #
    #         # create group elements using the coefficent and public info
    #         monypol_coeff2 = polyfromroots(mess_set2)
    #         coef_points2 = [(pp_commit_G2.__getitem__(i)).mul(monypol_coeff2[i]) for i in range(len(monypol_coeff2))]
    #         # create a set commitment and opening info
    #         pre_commit2 = ec_sum(coef_points2)
    #         commitment_G2_set2 = pre_commit2.mul(rho_2)
    #         commitment_G1_set2 = ec_sum(
    #             [h.mul(alpha_trapdoor.pow(i) * monypol_coeff2[i]) for i in range(len(monypol_coeff2))])
    #
    #         commitment = [[commitment_G1_set1, commitment_G2_set1], [commitment_G1_set2, commitment_G2_set2]]
    #         open_info = tau
    #
    #         list_CN = [commitment_G2_set1, commitment_G2_set2]
    #         aux = T_hat1 + T_hat2 + ec_sum(list_CN)
    #         h = group.hashG1(aux.export())
    #         return commitment, open_info, aux, h
    #
    #     else:
    #         # convert string to Zp
    #         mess_set1 = convert_mess_to_bn(mess_set_str)
    #         # create group elements using the coefficent and public info
    #         monypol_coeff1 = polyfromroots(mess_set1)
    #         coef_points1 = [(pp_commit_G2.__getitem__(i)).mul(monypol_coeff1[i]) for i in range(len(monypol_coeff1))]
    #         # create a set commitment and opening info
    #         pre_commit1 = ec_sum(coef_points1)
    #         commitment_G2_set1 = pre_commit1.mul(rho_1)
    #         commitment_G1_set1 = ec_sum(
    #             [h.mul(alpha_trapdoor.pow(i) * monypol_coeff1[i]) for i in range(len(monypol_coeff1))])
    #
    #         commitment = [[commitment_G1_set1, commitment_G2_set1], [commitment_G1_set1, commitment_G2_set1]]
    #         open_info = rho_1
    #         return commitment, open_info

    def open_set(self, param_sc, alpha_trapdoor, commitment, T_hat, h, open_info, mess_set_str):
        """
        :param param_sc: public parameters
        :param commitment: the set commitment
        :param open_info: the opening info of commitment
        :param mess_set_str: the message set
        :return: true if evolution is correct, false otherwise
        """
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group) = param_sc
        [[commitment_G1_set1, commitment_G2_set1], [commitment_G1_set2, commitment_G2_set2]] = commitment
        [set_str, set_str2] = mess_set_str
        [rho_1, rho_2] = open_info

        # recompute the commitments
        mess_set1 = convert_mess_to_bn(set_str)
        mess_set2 = convert_mess_to_bn(set_str2)
        # create group elements using the coefficent and public info
        monypol_coeff1 = polyfromroots(mess_set1)
        coef_points1 = [(pp_commit_G2.__getitem__(i)).mul(monypol_coeff1[i]) for i in range(len(monypol_coeff1))]
        # create a set commitment and opening info
        pre_commit1 = ec_sum(coef_points1)
        commitment_G2_set1_new = pre_commit1.mul(rho_1)
        commitment_G1_set1_new = ec_sum([h.mul(alpha_trapdoor.pow(i) * monypol_coeff1[i]) for i in range(len(monypol_coeff1))])

        # create group elements using the coefficent and public info
        monypol_coeff2 = polyfromroots(mess_set2)
        coef_points2 = [(pp_commit_G2.__getitem__(i)).mul(monypol_coeff2[i]) for i in range(len(monypol_coeff2))]
        # create a set commitment and opening info
        pre_commit2 = ec_sum(coef_points2)
        commitment_G2_set2_new = pre_commit2.mul(rho_2)
        commitment_G1_set2_new = ec_sum([h.mul(alpha_trapdoor.pow(i) * monypol_coeff2[i]) for i in range(len(monypol_coeff2))])

        # check if the regenerated commitment is match with the orginal commitment
        return commitment_G1_set2_new == commitment_G1_set2 and commitment_G2_set2_new == commitment_G2_set2 and commitment_G2_set1_new == commitment_G2_set1 and commitment_G1_set1_new == commitment_G1_set1 \
            and group.pair(h, commitment_G2_set1_new) == group.pair(commitment_G1_set1_new, T_hat[0]) \
            and group.pair(h, commitment_G2_set2_new) == group.pair(commitment_G1_set2_new, T_hat[1])

    def open_subset(self, param_sc, mess_set_str, open_info, subset_str) -> object:
        """
        :param param_sc: public parameters
        :param mess_set_str: the messagfe set
        :param open_info: opening information
        :param subset_str: a subset of the message set
        :return: a witness for the subset
        """
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group) = param_sc

        # convert the string to BN elements
        mess_set = convert_mess_to_bn(mess_set_str)
        mess_subset_t = convert_mess_to_bn(subset_str)

        # check if sets are subset with each other
        def is_subset(mess_set, mess_subset_t):
            chcker = None
            if len(mess_subset_t) > len(mess_set):
                return False
            else:
                for item in mess_subset_t:
                    if (item in mess_set):
                        chcker = True
                    else:
                        chcker = False
            return chcker

        # comute a witness
        if is_subset(mess_set, mess_subset_t) == True and mess_set != mess_subset_t:
            create_witn_elements = [item for item in mess_set if item not in mess_subset_t]
            coeff_witn = polyfromroots(create_witn_elements)
            witn_groups = [(pp_commit_G1.__getitem__(i)).mul(coeff_witn[i]) for i in range(len(coeff_witn))]
            witn_sum = ec_sum(witn_groups)
            witness = witn_sum.mul(open_info)
            return witness
        elif mess_set == mess_subset_t:
            witness = open_info
            return witness * g_1
        else:
            print("It is Not a subset")
            return False


    # def rnadomize(self, commitment_vector, tag, mu, opsilon):
    #     randomized_commitment_vector = [eq_dh_relation(item, mu, opsilon) for item in commitment_vector]
    #     (rho, rho_hat) = tag
    #     opening_info = (opsilon* rho, opsilon *rho_hat)
    #     return randomized_commitment_vector, opening_info

    def verify_subset(self, param_sc, set_commitment, T_1, subset_str, witness):
        """
        :param param_sc: set commitment public parameters
        :param commitment: commitment
        :param subset_str: subset message
        :param witness: witness to prove subset message in message set
        :return: 0 or 1
        """
        (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group) = param_sc
        [[commitment_G1_set1, commitment_G2_set1], [commitment_G1_dummy, commitment_G2_dummy]] = set_commitment

        mess_subset_t = convert_mess_to_bn(subset_str)
        coeff_t = polyfromroots(mess_subset_t)

        subset_group_elements = [(pp_commit_G2.__getitem__(i)).mul(coeff_t[i]) for i in range(len(coeff_t))]
        subset_elements_sum = ec_sum(subset_group_elements)
        return group.pair(witness, subset_elements_sum) == group.pair(g_1, commitment_G2_set1)
        #return group.pair(witness, subset_elements_sum) == group.pair(g_1, commitment_G2_set1)


    # def aggregate_cross(self, witness_vector, commit_vector):
    #     """
    #     :param witness_vector: a vector of witnessess
    #     :param commit_vector: the commitment vector
    #     :return: a proof which is a aggregate of witnesses and shows all subsets are valid for respective sets
    #     """
    #     if type(commit_vector[0]) is tuple:
    #         commit_vector = [item[0] for item in commit_vector]
    #
    #     witnessness_group_elements = list()
    #     for i in range(len(witness_vector)):
    #         """ generates a Bn challenge t_i by hashing a number of EC points """
    #         Cstring = b",".join([hexlify(commit_vector[i].export())])
    #         chash = sha256(Cstring).digest()
    #         hash_i = Bn.from_binary(chash)
    #         witnessness_group_elements.append(witness_vector[i].mul(hash_i))
    #         # pi = (list_W[i+1] ** t_i).add(pi)
    #         # comute pi as each element of list power to t_i
    #     proof = ec_sum(witnessness_group_elements)
    #     return proof
    #
    # def verify_cross(self, param_sc, commit_vector, subsets_vector_str, proof):
    #     """
    #     :param param_sc: public parameters
    #     :param commit_vector: the set commitment vector
    #     :param subsets_vector_str: the message sets vector
    #     :param proof: a proof which is a aggregate of witnesses
    #     :return: 1 or 0
    #     """
    #     (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group) = param_sc
    #
    #     # create a union of sets
    #     def union(subsets_vector):
    #         set_s = subsets_vector[0]
    #         for i in range(1, len(subsets_vector)):
    #             set_s = set_s + subsets_vector[i]
    #         return set_s
    #
    #     # create a set that is not intersection
    #     def not_intersection(list_S, list_T):
    #         set_s_not_t = [value for value in list_S if value not in list_T]
    #         return set_s_not_t
    #
    #     ## convert message str into the BN
    #     subsets_vector = [convert_mess_to_bn(item) for item in subsets_vector_str]
    #     set_s = union(subsets_vector)
    #     coeff_set_s = polyfromroots(set_s)
    #
    #     # compute right side of veriication
    #     set_s_group_elements = [(pp_commit_G2.__getitem__(i)).mul(coeff_set_s[i])for i in range(len(coeff_set_s))]
    #     set_s_elements_sum = ec_sum(set_s_group_elements)
    #     right_side = group.pair(proof, set_s_elements_sum)
    #
    #     set_s_not_t = [not_intersection(set_s, subsets_vector[i]) for i in range(len(subsets_vector))]
    #     vector_GT = list()
    #     for j in range(len(commit_vector)):
    #         coeff_s_not_t = polyfromroots(set_s_not_t[j])
    #         listpoints_s_not_t = [(pp_commit_G2.__getitem__(i)).mul(coeff_s_not_t[i]) for i in
    #                               range(len(coeff_s_not_t))]
    #         temp_sum = ec_sum(listpoints_s_not_t)
    #         Cstring = b",".join([hexlify(commit_vector[j].export())])
    #         chash = sha256(Cstring).digest()
    #         hash_i = Bn.from_binary(chash)
    #         GT_element = group.pair(commit_vector[j], hash_i * temp_sum)
    #         vector_GT.append(GT_element)
    #
    #     left_side = product_GT(vector_GT)
    #     if right_side.eq(left_side):
    #         return True
    #     else:
    #         return False




