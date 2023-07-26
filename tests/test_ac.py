from bplib.bp import BpGroup

from ac_package.primitives.set_commit import IndexSetCommitment
from ac_package.protocols.dac import DAC
from ac_package.protocols.mac_amts import Multi_AC_Mercurial
from ac_package.protocols.mac_atosa import A2C_AtoSa
from ac_package.protocols.tdac import TDAC

attribute_set1 = ["age = 30", "name = Alice ", "driver license = 12"]
attribute_set2 = ["genther = male", "componey = XX ", "driver license type = B"]
attribute_vector=[attribute_set1, attribute_set2]
attribute_subset1 = ["age = 30", "name = Alice "]
attribute_subset2 = ["genther = male", "componey = XX "]

def setup_module(module):
    print()
    print("__________Setup___Test AC interface________")
    global pp, ac_atosa, ac_dac, ac_tdac, ac_merc, BG
    ## create objects for all ac schemes
    BG = BpGroup()
    ac_atosa = A2C_AtoSa()
    ac_dac = DAC(5, 10)
    ac_tdac = TDAC(t=2, n=5)
    ac_merc = Multi_AC_Mercurial(5)

def test_issue_cred():
    """test issuing credentials using dac """
    (pp_dac, proof_vk, vk_stm, sk_ca, proof_alpha, alpha_stm, zkp, spseq_uc) = ac_dac.setup()
    (pp_sign, pp_zkp, pp_nizkp, vk_ca) = pp_dac
    (usk_u, upk_u) = ac_dac.user_keygen(pp_dac)
    ## create a proof of nym_u and root credential
    (nym_u, secret_nym_u, proof_nym_u) = ac_dac.nym_gen(pp_dac, usk_u, upk_u)
    ## create a root cred for user  u
    cred = ac_dac.issue_cred(pp_dac, attr_vector=[attribute_set1, attribute_set2], sk=sk_ca, nym_u=nym_u, k_prime=3, proof_nym_u=proof_nym_u)
    ## issuing/delegating a credential of user U to a user R ------------------------------------------------
    sub_mess_str = ["Insurance = 2 ", "Car type = BMW"]
    attribute_vector.append(sub_mess_str)
    ## generate key pair of user R
    (usk_R, upk_R) = ac_dac.user_keygen(pp_dac)
    ## generate a nym for the upk_R with corresoing secret key of nym + proof of nym
    (nym_R, secret_nym_R, proof_nym_R) = ac_dac.nym_gen(pp_dac, usk_R, upk_R)
    ## create a credential for new nym_R: delegateor P -> delegatee R
    cred_R_U = ac_dac.delegator(pp_dac, cred, sub_mess_str, l=3, sk_u=secret_nym_u, proof_nym=proof_nym_R)
    (sigma_prime, rndmz_commitment_vector, rndmz_opening_vector, nym_P, chi) = ac_dac.delegatee(pp_dac, cred_R_U, sub_mess_str, secret_nym_R, nym_R)
    ## check the correctness of root credential
    print()
    print("Creating a dac credential, and checking if the credential is correct")
    assert(spseq_uc.verify(pp_sign, vk_ca, nym_P, rndmz_commitment_vector, sigma_prime)), ValueError("signature/credential is not correct")
###-------------------------------------------------------------------------------------------------------------------------
    """test issuing credentials using ac_atosa"""
    attr_1 = attribute_set1[0]
    full_attrs = attribute_set1

    pp = ac_atosa.setup()
    (isk, ivk) = ac_atosa.isuser_keygen(pp)
    (isk_2, ivk_2) = ac_atosa.isuser_keygen(pp)
    (usk, upk, aux, h, commitment_pair_list) = ac_atosa.user_keygen(pp, [full_attrs, [isk, isk_2]])
    # create a nym
    tag = (usk, upk)
    (nym_u, secret_nym_u, proof_nym_u) = ac_atosa.nym_gen(pp, h, tag)
    cred = ac_atosa.issue_cred(pp, isk, attr_1, upk, aux, proof_nym_u)
    # gamma, beta = order.random(), order.random()
    proof = ac_atosa.proof_cred(pp, tag, ivk, cred, h, attr_1)
    assert ac_atosa.verify_proof(pp, ivk, proof, attr_1)
    print()
    print("Creating a atosa credential, and checking if the credential is correct")
###-------------------------------------------------------------------------------------------------------------------------
    """test issuing credentials using ac_amts"""
    pp, alpha_trapdoor = ac_merc.setup()
    (isk_1, ivk_1) = ac_merc.isuser_keygen(pp)
    (isk_2, ivk_2) = ac_merc.isuser_keygen(pp)
    dummy_set = ["..", ".."]
    set1 = [attribute_set1, dummy_set]
    set2 = [attribute_set2, dummy_set]
    message_vk_vector = [[set1, set2],[ivk_1, ivk_2]]
    (usk, uvk, tag, aux, pedersen_commitment_pairs, set_commitment_vector, open_info, h) = ac_merc.user_keygen(pp, alpha_trapdoor, message_vk_vector)
    (nym_u, secret_nym_u, proof_nym_u) = ac_merc.nym_gen(pp, h, tag)
    ## get cred for set_commitment1 -> implies set1 or attr_set1
    pedersen_commitment = pedersen_commitment_pairs[0]
    #witness1 = Indexscheme.open_subset(pp_sc, attr_vector, usk[0], attr_vector)
    cred = ac_merc.issue_cred(pp, isk_1, set_commitment_vector[0], aux, tag, attribute_set1, pedersen_commitment, proof_nym_u)
    proof = ac_merc.proof_cred(pp, tag, ivk_1, cred, h, set_commitment_vector[0], attribute_set1, attribute_subset1)
    assert ac_merc.verify_proof(pp, proof, attribute_subset1)
    print()
    print("Creating a atms credential, and checking if the credential is correct")

###-------------------------------------------------------------------------------------------------------------------------
    """test issuing credentials using ac_tdac"""
    ##  the first set of attributes A
    attr = [("theta%s" % i).encode("utf8") for i in range(3)]
    ##  the set of delegate attributes A^prime
    attr_prime = [("gamma%s" % i).encode("utf8") for i in range(3)]
    pp_tdac, sk_shares, pk = ac_tdac.setup()
    (cred_list, mk_list) = ac_tdac.issue_cred(pp_tdac, sk_shares, attr, attr_prime)
    cred, mk = ac_tdac.agg_cred(cred_list, mk_list)
    ##  the set of attributes that intigerate to A as  A''
    attr_prime_prime = [attr_prime[0], attr_prime[2]]
    cred_new, delegate_key = ac_tdac.delegate(cred, mk, attr_prime, attr_prime_prime)
    # encryption for this new key
    attr.append(attr_prime[0])
    attr.append(attr_prime[2])
    L = len(attr_prime_prime) + 1  ## privious level was 1
    r = BG.order().random()
    # get the random r^prime from prover
    r_prime = BG.order().random()
    # create a message, group element version
    gt = BG.pair(BG.gen1(), BG.gen2())
    m = gt ** (r + r_prime)
    # create a challenge
    (ct, commit_r, open_r) = ac_tdac.verifier_challenge(pp_tdac, pk, m, attr, r, L)
    ##prover starts protocol by creating response -----------------------
    proof = ac_tdac.proof_cred(pp_tdac, cred_new, attr, L, ct, commit_r, open_r)
    ##verifier check proof ----------------------- """
    assert (ac_tdac.verify_proof(pp_tdac, pk, attr, m, proof)), ValueError("credential is not correct")
    print()
    print("Creating a tdac credential, and checking if the credential is correct")


def test_proof_and_verify_cred():
    (pp_dac, proof_vk, vk_stm, sk_ca, proof_alpha, alpha_stm, zkp, spseq_uc) = ac_dac.setup()
    (usk, upk) = ac_dac.user_keygen(pp_dac)
    (nym_P, secret_nym_P, proof_nym_P) = ac_dac.nym_gen(pp_dac, usk, upk)
    # generate a credential
    cred = ac_dac.issue_cred(pp_dac, attr_vector=attribute_vector, sk=sk_ca, nym_u=nym_P, k_prime=None, proof_nym_u=proof_nym_P)
    # prepare a proof
    D = [attribute_subset1, attribute_subset2]
    proof = ac_dac.proof_cred(pp_dac, nym_R=nym_P, aux_R=secret_nym_P, cred_R=cred, Attr=attribute_vector, D=D)
    # check a proof
    assert (ac_dac.verify_proof(pp_dac, proof, D))
    print()
    print("proving  a dac proof to verifiers, and checking if the proof is correct")

###-----------------------------------------------------------------------------------------------------------------------------
    """test proof credentials using ac_atosa"""
    attr_1 = attribute_set1[0]
    attr_2 = attribute_set1[1]
    attr_3 = attribute_set1[2]
    full_attrs = attribute_set1
    pp = ac_atosa.setup()
    (isk, ivk) = ac_atosa.isuser_keygen(pp)
    (isk_2, ivk_2) = ac_atosa.isuser_keygen(pp)
    (isk_3, ivk_3) = ac_atosa.isuser_keygen(pp)
    (usk, upk, aux, h, commitment_pair_list) = ac_atosa.user_keygen(pp, [full_attrs, [isk, isk_2]])
    # create a nym
    tag = (usk, upk)
    (nym_u, secret_nym_u, proof_nym_u) = ac_atosa.nym_gen(pp, h, tag)
    cred1 = ac_atosa.issue_cred(pp, isk, attr_1, upk, aux, proof_nym_u)
    cred2 = ac_atosa.issue_cred(pp, isk_2, attr_2, upk, aux, proof_nym_u)
    cred3 = ac_atosa.issue_cred(pp, isk_3, attr_3, upk, aux, proof_nym_u)
    cred_p = [cred1, cred3]
    attr_vector = [attr_1, attr_3]
    pk_vector = [ivk, ivk_3]
    policies =  ac_atosa.gen_policies(pp, pk_vector)
    proof = ac_atosa.proof_cred(pp, tag, pk_vector, cred_p, h, attr_vector, policies)
    print()
    print("proving  a ac_atosa proof to verifiers, and checking if the proof is correct")
    assert ac_atosa.verify_proof(pp, pk_vector, proof, attr_vector, policies)

###-----------------------------------------------------------------------------------------------------------------------------
    """test proof credentials using ac_atms"""
    pp, alpha_trapdoor = ac_merc.setup()
    (isk_1, ivk_1) = ac_merc.isuser_keygen(pp)
    (isk_2, ivk_2) = ac_merc.isuser_keygen(pp)
    dummy_set = ["..", ".."]
    set1 = [attribute_set1, dummy_set]
    set2 = [attribute_set2, dummy_set]
    message_vk_vector = [[set1, set2], [ivk_1, ivk_2]]
    (usk, uvk, tag, aux, pedersen_commitment_pairs, set_commitment_vector, open_info, h) = ac_merc.user_keygen(pp,
                                                                                                                alpha_trapdoor,
                                                                                                                message_vk_vector)
    (nym_u, secret_nym_u, proof_nym_u) = ac_merc.nym_gen(pp, h, tag)
    attr_vector = [attribute_set1, attribute_set2]

    ## get cred for set_commitment1 -> implies set1 or attr_set1
    cred1 = ac_merc.issue_cred(pp, isk_1, set_commitment_vector[0], aux, tag, attribute_set1, pedersen_commitment_pairs[0],
                                proof_nym_u)
    cred2 = ac_merc.issue_cred(pp, isk_2, set_commitment_vector[1], aux, tag, attribute_set2, pedersen_commitment_pairs[1],
                                proof_nym_u)
    cred_p = [cred1, cred2]
    vk_vector = [ivk_1, ivk_2]
    # attr_vector = [attr_set, attr_set2]
    D = [attribute_subset1, attribute_subset2]
    policies = ac_merc.gen_policies(pp, vk_vector)
    proof = ac_merc.proof_cred(pp, tag, vk_vector, cred_p, h, set_commitment_vector, attr_vector, D, policies=policies)
    assert ac_merc.verify_proof(pp, proof, D, aggregate_active=True, policies=policies)
    print()
    print("proving  a ac_atms proof to verifiers, and checking if the proof is correct")

###-----------------------------------------------------------------------------------------------------------------------------
    """test proof credentials using ac_tdac"""
    ##  the first set of attributes A
    attr = [("theta%s" % i).encode("utf8") for i in range(3)]
    ##  the set of delegate attributes A^prime
    attr_prime = [("gamma%s" % i).encode("utf8") for i in range(3)]
    pp_tdac, sk_shares, pk = ac_tdac.setup()
    (cred_list, mk_list) = ac_tdac.issue_cred(pp_tdac, sk_shares, attr, attr_prime)
    cred, mk = ac_tdac.agg_cred(cred_list, mk_list)
    """ verifier starts protocol by creating challenge ----------------------- """
    L = 1
    # verifier picks the random r
    r = BG.order().random()
    # get the random r^prime from prover
    r_prime = BG.order().random()
    # create a message, group element version
    gt = BG.pair(BG.gen1(), BG.gen2())
    m = gt ** (r + r_prime)
    # create a challenge
    (ct, commit_r, open_r) = ac_tdac.verifier_challenge(pp_tdac, pk, m, attr, r, L)
    ##prover starts protocol by creating response ----------------------- """
    proof = ac_tdac.proof_cred(pp_tdac, cred, attr, L, ct, commit_r, open_r)
    ##verifier check proof ----------------------- """
    assert(ac_tdac.verify_proof(pp_tdac, pk, attr, m, proof)), ValueError("credential is not correct")
    print()
    print("proving  a ac tdac proof to verifiers, and checking if the proof is correct")

