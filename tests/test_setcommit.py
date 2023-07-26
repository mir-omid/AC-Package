from bplib.bp import BpGroup

from ac_package.primitives.amts import AggrMercurial
from ac_package.primitives.set_commit import SetCommitment, CrossSetCommitment, IndexSetCommitment
from ac_package.protocols.mac_amts import Multi_AC_Mercurial

dummy_set = ["..", ".."]
set_str1 = ["age = 30", "name = Alice ", "driver license = 12"]
set_str2 = ["Gender = male", "componey = XX ", "driver license type = B"]

subset_str_1 = ["age = 30", "name = Alice "]
subset_str_2 = ["Gender = male", "componey = XX "]

def setup_module(module):
    print("__________Setup__test set commitments___________")
    global sc_obj, Indexscheme
    global pp, ivk_1,ivk_2,ivk_3, aux, tag
    global pp_indexsc, alpha_trapdoor
    global cssc_obj
    BG = BpGroup()
    sc_obj = SetCommitment(BG, 5)
    cssc_obj = CrossSetCommitment(BG, 5)
    pp, alpha = sc_obj.setup_create_pp()
    Indexscheme = IndexSetCommitment(BG, 5)
    pp_indexsc, alpha_trapdoor = Indexscheme.setup_create_pp()
    ## generate some keys for mac atm
    merc  = AggrMercurial()
    mac_merc = Multi_AC_Mercurial(5)
    pp_atm, alpha_trapdoor2 = mac_merc.setup()

    (isk_1, ivk_1) = mac_merc.isuser_keygen(pp_atm)
    (isk_2, ivk_2) = mac_merc.isuser_keygen(pp_atm)
    (isk_3, ivk_3) = mac_merc.isuser_keygen(pp_atm)

    set1 = [set_str1, dummy_set]
    set2 = [set_str2, dummy_set]
    message_keys_set = [[set1, set2], [ivk_1, ivk_2]]
    pp_merc = merc.setup()
    (tag, aux, commitment_pair_list) = merc.gen_tag_aux(pp_merc, message_keys_set, mac_amts = True)

def test_commit_and_open():
    (Commitment, O) = sc_obj.commit_set(param_sc=pp, mess_set_str=set_str1)
    assert(sc_obj.open_set(pp, Commitment, O, set_str1)), ValueError("set is not match with commit and opening info")

def test_open_verify_subset():
    (Commitment, O) = sc_obj.commit_set(param_sc=pp, mess_set_str=set_str1)
    witness = sc_obj.open_subset(pp, set_str1, O, subset_str_1)
    assert sc_obj.verify_subset(pp, Commitment, subset_str_1, witness), "subset is not match with witness"

def test_aggregate_verify_cross():
    C1, O1 = cssc_obj.commit_set(pp, set_str1)
    C2, O2 = cssc_obj.commit_set(pp, set_str2)

    ## create a witness for a subset -> W
    W1 = cssc_obj.open_subset(pp, set_str1, O1, subset_str_1)
    W2 = cssc_obj.open_subset(pp, set_str2, O2, subset_str_2)

    ## aggegate all witness for a subset is correct-> proof
    proof = cssc_obj.aggregate_cross(witness_vector=[W1, W2], commit_vector=[C1, C2])

    ## verification aggegated witneesees
    assert(cssc_obj.verify_cross(pp, commit_vector=[C1, C2],
                                  subsets_vector_str=[subset_str_1, subset_str_2], proof=proof)), ValueError("verification aggegated witneesees fails")


"""
Index (tag) based set-commitment, cresting commitments is only possible with alpha, and used in Multi AC based Mercurial
"""
# def test_IndexSC_commit_open():
#     (pp_commit_G2, pp_commit_G1, g_1, g_2, order, group) = pp_indexsc
#     ## create a tag
#     rho_1, rho_2 = order.random(), order.random()
#     T_hat = [rho_1 * g_2, rho_2 * g_2]
#     tag = ([rho_1, rho_2], T_hat)
#
#     ## the message_key set S in the paper and also two attribute (messages) sets
#     set1 = [set_str1, dummy_set]
#     message_keys_set = [[ivk_1, ivk_2], set1]
#     ## create aux, h, create two sets for two creds, like set1 is for cred1 and set2 for cred2
#     set_commitment, open_info, aux, h = Indexscheme.commit_set(pp_indexsc, alpha_trapdoor, message_keys_set, tag, deactive_aggre_mercurial=True)
#
#     # generate a witness for a subset messages
#     witness = Indexscheme.open_subset(pp_indexsc, set_str1, rho_1, subset_str_1)
#     assert Indexscheme.verify_subset(pp_indexsc, set_commitment, h, T_hat[0], subset_str_1, witness), "verfification subset is "

def test_IndexSC_subset_open():
    ## create a tag
    (tau, T_vec) = tag
    [rho_1, rho_2] = tau

    ## the message_key set S in the paper and also two attribute (messages) sets
    set1 = [set_str1, dummy_set]
    set2 = [set_str2, dummy_set]
    message_keys_set = [[set1, set2], [ivk_1, ivk_2]]

    ## create aux, h, create two sets for two creds, like set1 is for cred1 and set2 for cred2
    set_commitment_vector, open_info, h = Indexscheme.commit_set(pp_indexsc, alpha_trapdoor, message_keys_set, tag, aux)
    ## Each set commitment in tag based message space then like (C1, hatC1), (C2, hat C2)
    [set_commitment1, set_commitment2] = set_commitment_vector

    # generate a witness for a subset messages
    open_info = 1
    witness1 = Indexscheme.open_subset(pp_indexsc, set_str1, open_info, set_str1)
    witness2 = Indexscheme.open_subset(pp_indexsc, set_str2, open_info, subset_str_2)

    assert Indexscheme.verify_subset(pp_indexsc, set_commitment1, T_vec[0], set_str1, witness1), "verfification subset is "
    assert Indexscheme.verify_subset(pp_indexsc, set_commitment2, T_vec[0], subset_str_2, witness2), "verfification subset is "
