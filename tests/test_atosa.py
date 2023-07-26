from ac_package.primitives.atosa import AtoSa

m_1 = "Omid"
m_2 = "mir"
m_3 = "age"
set_str = [m_1, m_2, m_3]
mesage_vector = [m_1, m_2]

def setup_module(module):
    print()
    print("__________Setup___Test Aggre PS Signature________")
    global sign_scheme
    global pp
    global tag
    global sk_1, sk_2
    global vk_1, vk_2
    global aux, commitment_pair_list
    sign_scheme = AtoSa()
    pp = sign_scheme.setup()
    # generate secret and verification keys (example for two signatures)
    (sk_1, vk_1) = sign_scheme.keygen(pp)
    (sk_2, vk_2) = sign_scheme.keygen(pp)
    # create a tag and prepare index and commitments for all messages
    message_vk_vector = [set_str, [vk_1, vk_2]]
    (tag, aux, commitment_pair_list) = sign_scheme.gen_tag_aux(pp, message_vk_vector)

def test_sign():
    (rho, T_vec) = tag
    # select which message should be signed
    (commitment_message1, opening_message1) = commitment_pair_list[0]
    signature_1 = sign_scheme.sign(pp, sk_1, tag, aux,  m_1)
    assert(sign_scheme.verify(pp, vk_1, T_vec, m_1, signature_1)), ValueError("signiture is not correct")

def test_rand_sign():
    # pick two randomness
    (BG, order, g1, g2, e, pp_pedersen) = pp
    upsilon, beta = order.random(), order.random()
    # select which message should be signed
    (commitment_message1, opening_message1) = commitment_pair_list[0]
    signature_1 = sign_scheme.sign(pp, sk_1, tag, aux,  m_1, (commitment_message1, opening_message1))
    # randomize signature and tag
    randomize_sig, randomize_tag = sign_scheme.rand_sign(signature_1, tag, upsilon)
    (rho_new, rho_hat_new) = randomize_tag
    # check if randomized signature/tga is correct
    assert(sign_scheme.verify(pp, vk_1, rho_hat_new, m_1, randomize_sig)), ValueError("verification of randomized signature is not correct")

def test_convert_sign():
    (rho, rho_hat) = tag
    # pick two randomness
    (BG, order, g1, g2, e, pp_pedersen) = pp
    omega = order.random()
    # select which message should be signed
    (commitment_message1, opening_message1) = commitment_pair_list[0]
    signature_1 = sign_scheme.sign(pp, sk_1, tag, aux, m_1, (commitment_message1, opening_message1))
    # randomize sk and vk
    sk_new = sign_scheme.convert_sk(sk_1, omega)
    vk_new = sign_scheme.convert_vk(vk_1, omega)
    sig_new = sign_scheme.convert_sig(signature_1, omega)
    assert(sign_scheme.verify(pp, vk_new, rho_hat, m_1, sig_new)), ValueError("Convert verification is not correct")


def test_aggr_sign():
    (rho, rho_hat) = tag
    # generate two signatures
    (commitment_message1, opening_message1) = commitment_pair_list[0]
    (commitment_message2, opening_message2) = commitment_pair_list[1]
    signature_1 = sign_scheme.sign(pp, sk_1, tag, aux, m_1, (commitment_message1, opening_message1))
    signature_2 = sign_scheme.sign(pp, sk_2, tag, aux, m_2, (commitment_message2, opening_message2))
    # aggregate signatures and vks
    aggre_sign = sign_scheme.aggr_sign([signature_1, signature_2])
    vk_vector = [vk_1, vk_2]
    # check the aggregate signature
    assert(sign_scheme.aggr_verify(pp, vk_vector, rho_hat, mesage_vector, aggre_sign)), ValueError("aggregation verification is not correct")

def test_convert_aggrsign():
    # pick randomness
    (BG, order, g1, g2, e, pp_pedersen) = pp
    omega , upsilon = order.random(), order.random()
    (rho, rho_hat) = tag

    # generate two signatures
    (commitment_message1, opening_message1) = commitment_pair_list[0]
    (commitment_message2, opening_message2) = commitment_pair_list[1]
    signature_1 = sign_scheme.sign(pp, sk_1, tag, aux, m_1, (commitment_message1, opening_message1))
    signature_2 = sign_scheme.sign(pp, sk_2, tag, aux, m_2, (commitment_message2, opening_message2))

    # aggregate signatures and vks
    aggre_sign = sign_scheme.aggr_sign([signature_1, signature_2])
    vk_vector = [vk_1, vk_2]

    # change keys of aggregate signature
    vk_vector_new = sign_scheme.convert_vk(vk_vector, omega)
    aggre_sig_new = sign_scheme.convert_sig(aggre_sign, omega)
    assert(sign_scheme.aggr_verify(pp, vk_vector_new, rho_hat, mesage_vector, aggre_sig_new)), ValueError("Convert verification of aggregation signature is not correct")
    # randomize aggregate signature
    randomize_aggrsig, randomize_tag = sign_scheme.rand_sign(aggre_sign, tag, upsilon)
    (rho_new, rho_hat_new) = randomize_tag
    # check if randomized signature/tga is correct
    assert (sign_scheme.aggr_verify(pp, vk_vector, rho_hat_new, mesage_vector, randomize_aggrsig)), ValueError(
        "verification of randomized signature is not correct")
