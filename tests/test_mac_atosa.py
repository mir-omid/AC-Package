from ac_package.protocols.mac_atosa import A2C_AtoSa

attr_1 = "10"
attr_2 = "20"
attr_3 = "30"
full_attrs = [attr_1, attr_2, attr_3]

def setup_module(module):
    print("__________Setup___Test Multi-Authority AC based AtoSa ________")
    global mac_ps, mac_merc
    global pp, isk, ivk, isk_2, ivk_2, isk_3, ivk_3, pp_merc, alpha_trapdoor
    mac_ps = A2C_AtoSa()
    pp = mac_ps.setup()
    (isk, ivk) = mac_ps.isuser_keygen(pp)
    (isk_2, ivk_2) = mac_ps.isuser_keygen(pp)
    (isk_3, ivk_3) = mac_ps.isuser_keygen(pp)

def test_Issuecred_atosa():
    "issuer one single credential on a single message and verify it"
    (usk, upk, aux, h, commitment_pair_list) = mac_ps.user_keygen(pp, [full_attrs, [isk, isk_2]])
    # create a nym
    tag = (usk, upk)
    (nym_u, secret_nym_u, proof_nym_u) = mac_ps.nym_gen(pp, h, tag)
    cred = mac_ps.issue_cred(pp, isk, attr_1, upk, aux, proof_nym_u)
    #gamma, beta = order.random(), order.random()
    proof = mac_ps.proof_cred(pp, tag, ivk, cred, h, attr_1)
    assert mac_ps.verify_proof(pp, ivk, proof, attr_1)

def test_proofcred_atosa():
    "issuer three credentials  and verify twp of them"
    (usk, upk, aux, h, commitment_pair_list) = mac_ps.user_keygen(pp, [full_attrs, [isk, isk_2]])
    ## create a nym + proof of nym
    tag = (usk, upk)
    (nym_u, secret_nym_u, proof_nym_u) = mac_ps.nym_gen(pp, h, tag)

    ## send the nym and get three credentials  for three attributes
    cred1 = mac_ps.issue_cred(pp, isk, attr_1, upk, aux, proof_nym_u)
    cred2 = mac_ps.issue_cred(pp, isk_2, attr_2, upk, aux, proof_nym_u)
    cred3 = mac_ps.issue_cred(pp, isk_3, attr_3, upk, aux, proof_nym_u)

    ## select two of them
    cred_p = [cred1, cred3]
    attr_vector = [attr_1, attr_3]
    pk_vector = [ivk, ivk_3]

    ## create a proof for these two cred
    proof = mac_ps.proof_cred(pp, tag, pk_vector, cred_p, h, attr_vector)

    ## verify the proof for these two creds
    assert mac_ps.verify_proof(pp, pk_vector, proof, attr_vector)


def test_proofcred_Ih_atosa():
    "issuer three credentials  and verify twp of them"
    (usk, upk, aux, h, commitment_pair_list) = mac_ps.user_keygen(pp, [full_attrs, [isk, isk_2]])

    # create a nym
    tag = (usk, upk)
    (nym_u, secret_nym_u, proof_nym_u) = mac_ps.nym_gen(pp, h, tag)

    cred1 = mac_ps.issue_cred(pp, isk, attr_1, upk, aux, proof_nym_u)
    cred2 = mac_ps.issue_cred(pp, isk_2, attr_2, upk, aux, proof_nym_u)
    cred3 = mac_ps.issue_cred(pp, isk_3, attr_3, upk, aux, proof_nym_u)
    cred_p = [cred1, cred3]

    attr_vector = [attr_1, attr_3]
    pk_vector = [ivk, ivk_3]

    policies =  mac_ps.gen_policies(pp, pk_vector)
    proof = mac_ps.proof_cred(pp, tag, pk_vector, cred_p, h, attr_vector, policies)

    assert mac_ps.verify_proof(pp, pk_vector, proof, attr_vector, policies)

