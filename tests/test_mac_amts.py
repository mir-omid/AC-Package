from bplib.bp import BpGroup

from ac_package.primitives.set_commit import IndexSetCommitment
from ac_package.protocols.mac_amts import Multi_AC_Mercurial

dummy_set = ["..", ".."]
attr_set1 = ["10", "20", "50"]
attr_set2 = ["30", "40", "60"]
subset1 = ["10", "50"]
subset2 = ["30", "40"]

def setup_module(module):
    print("__________Setup___Test Multi-Authority AC ________")
    global mac_merc, pp_indexsc, Indexscheme
    global pp, isk_1, ivk_1, isk_2, ivk_2, isk_3, ivk_3, alpha_trapdoor
    mac_merc = Multi_AC_Mercurial(5)
    BG = BpGroup()
    pp, alpha_trapdoor = mac_merc.setup()
    (isk_1, ivk_1) = mac_merc.isuser_keygen(pp)
    (isk_2, ivk_2) = mac_merc.isuser_keygen(pp)
    (isk_3, ivk_3) = mac_merc.isuser_keygen(pp)
    Indexscheme = IndexSetCommitment(BG, 5)

def test_Issuecred_merc():

    set1 = [attr_set1, dummy_set]
    set2 = [attr_set2, dummy_set]
    message_vk_vector = [[set1, set2],[ivk_1, ivk_2]]
    (usk, uvk, tag, aux, pedersen_commitment_pairs, set_commitment_vector, open_info, h) = mac_merc.user_keygen(pp, alpha_trapdoor, message_vk_vector)
    (nym_u, secret_nym_u, proof_nym_u) = mac_merc.nym_gen(pp, h, tag)

    ## get cred for set_commitment1 -> implies set1 or attr_set1
    pedersen_commitment = pedersen_commitment_pairs[0]

    #witness1 = Indexscheme.open_subset(pp_sc, attr_vector, usk[0], attr_vector)
    cred = mac_merc.issue_cred(pp, isk_1, set_commitment_vector[0], aux, tag, attr_set1, pedersen_commitment, proof_nym_u)
    proof = mac_merc.proof_cred(pp, tag, ivk_1, cred, h, set_commitment_vector[0], attr_set1, subset1)
    assert mac_merc.verify_proof(pp, proof, subset1)

def test_proofcred_merc():
    set1 = [attr_set1, dummy_set]
    set2 = [attr_set2, dummy_set]
    message_vk_vector = [[set1, set2], [ivk_1, ivk_2]]
    (usk, uvk, tag, aux, pedersen_commitment_pairs, set_commitment_vector, open_info, h) = mac_merc.user_keygen(pp, alpha_trapdoor, message_vk_vector)
    (nym_u, secret_nym_u, proof_nym_u) = mac_merc.nym_gen(pp, h, tag)
    attr_vector = [attr_set1, attr_set2]

    ## get cred for set_commitment1 -> implies set1 or attr_set1
    cred1 = mac_merc.issue_cred(pp, isk_1, set_commitment_vector[0], aux, tag, attr_set1, pedersen_commitment_pairs[0], proof_nym_u)
    cred2 = mac_merc.issue_cred(pp, isk_2, set_commitment_vector[1],aux, tag,  attr_set2,  pedersen_commitment_pairs[1], proof_nym_u)
    cred_p = [cred1, cred2]
    vk_vector = [ivk_1, ivk_2]
    #attr_vector = [attr_set, attr_set2]
    D = [subset1, subset2]
    proof = mac_merc.proof_cred(pp, tag, vk_vector, cred_p, h, set_commitment_vector, attr_vector, D)
    assert mac_merc.verify_proof(pp, proof, D, aggregate_active = True)

def test_proofcred_Ih_merc():
    set1 = [attr_set1, dummy_set]
    set2 = [attr_set2, dummy_set]
    message_vk_vector = [[set1, set2], [ivk_1, ivk_2]]
    (usk, uvk, tag, aux, pedersen_commitment_pairs, set_commitment_vector, open_info, h) = mac_merc.user_keygen(pp, alpha_trapdoor, message_vk_vector)
    (nym_u, secret_nym_u, proof_nym_u) = mac_merc.nym_gen(pp, h, tag)
    attr_vector = [attr_set1, attr_set2]

    ## get cred for set_commitment1 -> implies set1 or attr_set1
    cred1 = mac_merc.issue_cred(pp, isk_1, set_commitment_vector[0],aux, tag, attr_set1, pedersen_commitment_pairs[0], proof_nym_u)
    cred2 = mac_merc.issue_cred(pp, isk_2, set_commitment_vector[1],aux, tag,  attr_set2,  pedersen_commitment_pairs[1], proof_nym_u)
    cred_p = [cred1, cred2]
    vk_vector = [ivk_1, ivk_2]
    #attr_vector = [attr_set, attr_set2]
    D = [subset1, subset2]
    policies = mac_merc.gen_policies(pp, vk_vector)
    proof = mac_merc.proof_cred(pp, tag, vk_vector, cred_p, h, set_commitment_vector, attr_vector, D, policies=policies)
    assert mac_merc.verify_proof(pp, proof, D, aggregate_active = True, policies=policies)
