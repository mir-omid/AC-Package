from bplib.bp import G2Elem

from ac_package.primitives.spseq_signs import Mercurial_Sign, FHS_Sign, SingleAggr_FHS
from ac_package.protocols.mac_atosa import A2C_AtoSa

messages_vector = ["omid","mir"]
messages_vector2 = ["age","address"]

def setup_module(module):
    print()
    print("__________Setup___Test SPSEQ Signatures (FHS and Mercurial)________")
    global mercu_sign, fhs_sign, aggrefhs_sign, pp
    global sk, vk, sk_2, vk_2, isk, ivk, isk_2, ivk_2
    mercu_sign = Mercurial_Sign()
    fhs_sign = FHS_Sign()
    pp = fhs_sign.setup()
    (sk, vk) = fhs_sign.keygen(pp_sign=pp, l_message=2)

"""
all tests for FHS and Mercurial signatures (they are type of SPSEQ)
"""

def test_fhs_sign():
    "fhs signing verification"
    signature = fhs_sign.sign(pp, sk, messages_vector)
    assert(fhs_sign.verify(pp, vk, messages_vector, signature)), ValueError("signiture is not correct")
    #assert(fhs_sign.verify(pp, vk, messages_vector, signature, types=G2Elem)), ValueError("signiture is not correct")

def test_fhs_sign_G2():
    "fhs signing verification"
    (sk, vk) = fhs_sign.keygen(pp_sign=pp, l_message=3, type=G2Elem)
    mac_ps = A2C_AtoSa()
    pp_macps = mac_ps.setup()
    (isk, ivk) = mac_ps.isuser_keygen(pp_macps)
    print("ivk ", ivk)
    signature = fhs_sign.sign(pp, sk, ivk)
    assert(fhs_sign.verify(pp, vk, ivk, signature, types=G2Elem)), ValueError("signiture is not correct")

def test_fhs_changerep():
    "fhs randomization of signature"
    (group, order, g1, g2, e) = pp
    # pick randomness
    mu, chi = order.random(), order.random()
    # generate signature
    signature = fhs_sign.sign(pp, sk, messages_vector)
    sigma_prime, randomized_messages = fhs_sign.changerep(pp, messages_vector, signature, mu, chi)
    # verification
    assert (fhs_sign.verify(pp, vk, randomized_messages, sigma_prime)), ValueError("randomized signiture is not correct")

def test_fhs_changerepG2():
    "fhs randomization of signature"
    (group, order, g1, g2, e) = pp
    # pick randomness
    mu, chi = order.random(), order.random()
    # generate signature
    (sk, vk) = fhs_sign.keygen(pp_sign=pp, l_message=3, type=G2Elem)
    mac_ps = A2C_AtoSa()
    pp_macps = mac_ps.setup()
    (isk, ivk) = mac_ps.isuser_keygen(pp_macps)

    signature = fhs_sign.sign(pp, sk, ivk)
    sigma_prime, randomized_messages = fhs_sign.changerep(pp, ivk, signature, mu, chi)
    # verification
    assert (fhs_sign.verify(pp, vk, randomized_messages, sigma_prime, types=G2Elem)), ValueError("randomized signiture is not correct")

def test_mercurial_convert():
    "mercurial signing and randomization of vk/sk"
    (group, order, g1, g2, e) = pp
    # pick randomness
    rho = order.random()
    # gen signature
    signature = mercu_sign.sign(pp, sk, messages_vector)
    # randomize vk/sk
    sk_prime = mercu_sign.convert_sk(sk, rho)
    vk_prime = mercu_sign.convert_vk(vk, rho)
    # convert signature for randomized vk/sk
    converted_sign = mercu_sign.convert_sig(pp, signature, rho)
    # verification of converted signature
    assert(mercu_sign.verify(pp, vk_prime, messages_vector, converted_sign)), ValueError("converted signature is ")


# """
# all tests for Single Singer Aggr FHS ( called SAFHS they are also type of SPSEQ)
# """
# def test_safhs_sign():
#     "Sigle singer Aggre FHS (SAFHS) signature"
#     (group, order, g1, g2, e) = pp
#     prf = order.random()
#     signature1 = aggrefhs_sign.sign(pp, sk, prf, messages_vector)
#     assert(aggrefhs_sign.verify(pp, vk, messages_vector, signature1)), ValueError("verification signature is ")
#
# def test_safhs_aggresign():
#     "SAFHS aggregte two signatures"
#     (group, order, g1, g2, e) = pp
#     # create a prf, here we only pick a randomness for simplicity
#     prf = order.random()
#     # genreate signatures
#     signature1 = aggrefhs_sign.sign(pp, sk, prf, messages_vector)
#     signature2 = aggrefhs_sign.sign(pp, sk_2, prf, messages_vector2)
#     # aggregate signatures
#     aggreSign = aggrefhs_sign.aggr_sign([signature1, signature2])
#     vk_vector = [vk, vk_2]
#     messages_vector_v = [messages_vector, messages_vector2]
#     assert(aggrefhs_sign.aggre_verify(pp, vk_vector, messages_vector_v, aggreSign)), ValueError("aggregate signature verification is  ")
#
# def test_safhs_changerep():
#     "SAFHS: randomize a signature"
#     (group, order, g1, g2, e) = pp
#     prf = order.random()
#     mu = order.random()
#     chi = order.random()
#     signature = aggrefhs_sign.sign(pp, sk, prf, messages_vector)
#     sigma_prime, message_representive = aggrefhs_sign.changerep(pp, messages_vector, signature, mu, chi)
#     assert(aggrefhs_sign.verify(pp, vk, message_representive, sigma_prime)), ValueError("chagerep signature verification is  ")
#
#
# def test_safhs_aggrechangerep():
#     "SAFHS: aggregate two randomized signatures"
#     (group, order, g1, g2, e) = pp
#     # gen randomness and prf
#     prf = order.random()
#     mu = order.random()
#     chi = order.random()
#     # gen signatures
#     signature1 = aggrefhs_sign.sign(pp, sk, prf, messages_vector)
#     signature2 = aggrefhs_sign.sign(pp, sk_2, prf, messages_vector2)
#     # randomize signatures
#     sigma_prime, message_representive = aggrefhs_sign.changerep(pp, messages_vector, signature1, mu, chi)
#     sigma_prime2, message_representive2 = aggrefhs_sign.changerep(pp, messages_vector2, signature2, mu, chi)
#     # aggregate randomized signatures
#     aggreSign2 = aggrefhs_sign.aggr_sign([sigma_prime, sigma_prime2])
#     messages_vector_v2 = [message_representive, message_representive2]
#     vk_vector = [vk, vk_2]
#     # verification of aggregate sign
#     assert(aggrefhs_sign.aggre_verify(pp, vk_vector, messages_vector_v2, aggreSign2)), ValueError("aggregate chagerep signatures  verification is  ")

# def test_safhs_changerepAggreSign():
#     "randomized the aggregate signature"
#     (group, order, g1, g2, e) = pp
#     prf = order.random()
#     mu = order.random()
#     chi = order.random()
#     # create two signatures
#     signature1 = aggrefhs_sign.sign(pp, sk, prf, messages_vector)
#     signature2 = aggrefhs_sign.sign(pp, sk_2, prf, messages_vector2)
#     # aggregate  two signatures
#     aggreSign = aggrefhs_sign.aggr_sign([signature1, signature2])
#     vk_vector = [vk, vk_2]
#     messages_vector_v = [messages_vector, messages_vector2]
#     # randomize the aggregate signature
#     sigma_prime, message_representive = aggrefhs_sign.changerep(pp, messages_vector_v, aggreSign, mu, chi)
#     assert (aggrefhs_sign.aggre_verify(pp, vk_vector, message_representive, sigma_prime)), ValueError(
#         "randomized the aggregate signature is  ")



