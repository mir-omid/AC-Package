from ac_package.primitives.amts import AggrMercurial

m_vector = ["10", "20"]
m_vector2 = ["40", "30"]


def setup_module(module):
    print()
    print("__________Setup___Test Aggre Mercurial Signature________")
    global sign_scheme
    global params, tag_dh_message1, tag_dh_message2
    global tag, aux
    global sk_1, sk_2
    global vk_1, vk_2
    sign_scheme = AggrMercurial()
    params = sign_scheme.setup()
    # generate secret and verification keys (example for two signatures)
    (sk_1, vk_1) = sign_scheme.keygen(params)
    (sk_2, vk_2) = sign_scheme.keygen(params)
    # create a tag
    # #tag = sign_scheme.gen_tag_aux(params, message_vk_vector)
    message_vk_vector = [[m_vector, m_vector2], [vk_1, vk_2]]
    (tag, aux, commitment_pair_list) = sign_scheme.gen_tag_aux(params, message_vk_vector)
    (rho, T_vec) = tag
    # converting message to tag based dh message that signature can work
    tag_dh_message1 = sign_scheme.encode(params, T_vec, m_vector)
    tag_dh_message2 = sign_scheme.encode(params, T_vec, m_vector2)

def test_sign():
    "signing algorithm"
    (tau, T_hat_vec) = tag
    # select which message should be signed
    signature_1 = sign_scheme.sign(params, sk_1, tag, aux, tag_dh_message1)
    assert(sign_scheme.verify(params, vk_1, T_hat_vec,  tag_dh_message1, signature_1)), ValueError("signiture is not correct")
#
def test_changerep():
    "randomization of a signature"
    # pick two randomness
    (group, order, g1, g2, e, pp_pedersen) = params
    mu, opsilon = order.random(), order.random()
    signature_1 = sign_scheme.sign(params, sk_1, tag, aux, tag_dh_message1)
    # randomize signature and tag
    randomized_commitment1, randomize_sig, randomize_tag = sign_scheme.chang_rep(signature_1, tag_dh_message1, tag, mu,opsilon)
    (randomize_rho, randomize_rho_hat) = randomize_tag
    # check if randomized signature/tga is correct
    assert(sign_scheme.verify(params, vk_1, randomize_rho_hat, randomized_commitment1, randomize_sig)), \
        ValueError("verification of randomized signature is not correct")

def test_convert_sign():
    "randomization of vk and convert signature"
    (rho, rho_hat) = tag
    # pick randomness
    (group, order, g1, g2, e, pp_pedersen) = params

    omega = order.random()
    # create a sing
    signature_1 = sign_scheme.sign(params, sk_1, tag, aux, tag_dh_message1)
    # randomize keys
    sk_new = sign_scheme.convert_sk(sk_1, omega)
    pk_new = sign_scheme.convert_vk(vk_1, omega)
    # convert sign
    sig_new = sign_scheme.convert_sig(params, signature_1, omega)
    # check converted sign
    assert(sign_scheme.verify(params, pk_new, rho_hat, tag_dh_message1, sig_new)), \
        ValueError("Convert verification is not correct")

def test_aggr_sign():
    "aggregation of two signatures"
    (rho, rho_hat) = tag
    # generate two signatures
    signature_1 = sign_scheme.sign(params, sk_1, tag, aux,  tag_dh_message1)
    signature_2 = sign_scheme.sign(params, sk_2, tag, aux , tag_dh_message2)
    print()
    print("signature_1", signature_1)
    print("signature_2", signature_2)

    # aggregate signatures and vks
    aggre_sign = sign_scheme.aggr_sign([signature_1, signature_2])
    vk_vector = [vk_1, vk_2]
    m_vector_vector = [tag_dh_message1, tag_dh_message2]
    # check the aggregate signature
    assert(sign_scheme.aggre_verify(params, vk_vector, rho_hat,  m_vector_vector, aggre_sign)), \
        ValueError("aggregation verification is not correct")

def test_aggr_changrepsign():
    "aggregation of two randomized signatures"
    (group, order, g1, g2, e, pp_pedersen) = params
    mu, opsilon = order.random(), order.random()
    (tau, T_hat_vec) = tag
    # generate two signatures
    signature_1 = sign_scheme.sign(params, sk_1, tag, aux, tag_dh_message1)
    signature_2 = sign_scheme.sign(params, sk_2, tag, aux, tag_dh_message2)

    # randomize signature and tag
    randomized_commitment1, randomize_sig1, randomize_tag1 = sign_scheme.chang_rep(signature_1, tag_dh_message1, tag, mu, opsilon)
    (randomize_rho, randomize_rho_hat) = randomize_tag1
    randomized_commitment2, randomize_sig2, randomize_tag2 = sign_scheme.chang_rep(signature_2, tag_dh_message2, tag, mu, opsilon)

    sig_list2 = [randomize_sig1, randomize_sig2]
    aggre_sign = sign_scheme.aggr_sign(sig_list2)
    vk_vec = [vk_1, vk_2]
    m_vector_vector2 = [randomized_commitment1, randomized_commitment2]
    assert(sign_scheme.aggre_verify(params, vk_vec, randomize_rho_hat, m_vector_vector2, aggre_sign)), \
        ValueError("Aggregate of two randomized signatures is not correct")

def test_changrep_aggrsign():
    "changerep of the aggregated signature (randomize aggregate signature)"
    (rho, rho_hat) = tag
    (group, order, g1, g2, e, pp_pedersen) = params
    mu, opsilon = order.random(), order.random()
    # generate two signatures
    signature_1 = sign_scheme.sign(params, sk_1, tag, aux, tag_dh_message1)
    signature_2 = sign_scheme.sign(params, sk_2, tag, aux, tag_dh_message2)
    # aggregate signatures and vks
    aggre_sign = sign_scheme.aggr_sign([signature_1, signature_2])
    vk_vector = [vk_1, vk_2]
    m_vector_vector = [tag_dh_message1, tag_dh_message2]
    # randomize aggreg sign
    randomize_dh_message, randomize_sig, randomize_tag = sign_scheme.chang_rep(aggre_sign, m_vector_vector, tag, mu, opsilon)
    (randomize_rho, randomize_rho_hat) = randomize_tag
    assert( sign_scheme.aggre_verify(params, vk_vector, randomize_rho_hat,  randomize_dh_message, randomize_sig)), \
        ValueError("randomized aggregate sign verification is not correct")
