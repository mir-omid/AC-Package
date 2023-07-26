# from ac_package.primitives.amts import Aggr_Mercurial
# import statistics
# import time
# import random
# import string
#
# run_num = 1 # the number of running time
# n = 2 # the number of messages in the set
# m_vector = ["10", "20"]
# m_vector2 = ["40", "30"]
# message_str_set = []
# for i in range(n):
#     message_str = [''.join(random.choices(string.ascii_letters + string.digits, k=5)) for _ in range(2)]
#     message_str_set.append(message_str)
#
#
# def setup_module(module):
#     print()
#     print("__________Setup___ Times Aggre Mercurial Signature________")
#     global sign_scheme,sk_list, vk_list
#     global params, tag_dh_message1, tag
#     global sk_1, sk_2, vk_1, vk_2
#     sign_scheme = Aggr_Mercurial()
#     params = sign_scheme.setup()
#     # generate secret and verification keys (example for two signatures)
#     (sk_1, vk_1) = sign_scheme.keygen(params)
#     (sk_2, vk_2) = sign_scheme.keygen(params)
#     keys = [sign_scheme.keygen(params) for _ in range(n)]
#     sk_list = [item[0] for item in keys]
#     vk_list = [item[1] for item in keys]
#
#     # create a tag
#     tag = sign_scheme.gen_tag(params)
#     # converting message to tag based dh message that signature can work
#     (rho, rho_hat) = tag
#     tag_dh_message1 = sign_scheme.encode(rho_hat, m_vector)
#
#
# def test_sign():
#     "signing algorithm"
#     # create a tag
#     times_tag = []
#     for i in range(run_num):
#         start_time = time.perf_counter()
#
#         tag = sign_scheme.gen_tag(params)
#         (rho, rho_hat) = tag
#         # converting message to tag based dh message that signature can work
#         tag_dh_message1 = sign_scheme.encode(rho_hat, m_vector)
#
#         end_time = time.perf_counter()
#         x = end_time - start_time
#         times_tag.append(x)
#     print()
#     print("average mean time for precomputation ", statistics.mean(times_tag))
#
#     times= []
#     for i in range(run_num):
#         start_time2 = time.perf_counter()
#
#         signature_1 = sign_scheme.sign(params, sk_1, tag, tag_dh_message1)
#
#         end_time2 = time.perf_counter()
#         x = end_time2 - start_time2
#         times.append(x)
#     print()
#     print("average mean time for signing ", statistics.mean(times))
#
#     times_verify = []
#     for i in range(run_num):
#         start_times_verify = time.perf_counter()
#
#         assert (sign_scheme.verify(params, vk_1, rho_hat, tag_dh_message1, signature_1)), ValueError(
#             "signiture is not correct")
#
#         end_times_verify = time.perf_counter()
#         x_times_verify = end_times_verify - start_times_verify
#         times_verify.append(x_times_verify)
#     print()
#     print("average mean time for verifing sign ", statistics.mean(times_verify))
#
#
# def test_changerep():
#     "randomization of a signature"
#     # pick two randomness
#     (BG, order, g1, g2, e)  = params
#     mu, opsilon = order.random(), order.random()
#     signature_1 = sign_scheme.sign(params, sk_1, tag, tag_dh_message1)
#
#     times_random = []
#     for i in range(run_num):
#         start_times = time.perf_counter()
#
#         # randomize signature and tag
#         randomized_commitment1, randomize_sig, randomize_tag = sign_scheme.chang_rep(signature_1, tag_dh_message1, tag,
#                                                                                      mu, opsilon)
#         end_times = time.perf_counter()
#         x_times_random = end_times - start_times
#         times_random.append(x_times_random)
#     print()
#     print("average mean time for randomizing sign ", statistics.mean(times_random))
#
#     (randomize_rho, randomize_rho_hat) = randomize_tag
#     # check if randomized signature/tga is correct
#     assert(sign_scheme.verify(params, vk_1, randomize_rho_hat, randomized_commitment1, randomize_sig)), \
#         ValueError("verification of randomized signature is not correct")
#
# def test_convert_sign():
#     "randomization of vk and convert signature"
#     (rho, rho_hat) = tag
#     # pick randomness
#     (BG, order, g1, g2, e)  = params
#     omega = order.random()
#     # create a sing
#     signature_1 = sign_scheme.sign(params, sk_1, tag, tag_dh_message1)
#
#     times_convert= []
#     for i in range(run_num):
#         start_times = time.perf_counter()
#
#         # randomize keys
#         sk_new = sign_scheme.convert_sk(sk_1, omega)
#         pk_new = sign_scheme.convert_vk(vk_1, omega)
#         # convert sign
#         sig_new = sign_scheme.convert_sig(signature_1, omega)
#
#         end_times = time.perf_counter()
#         x_times = end_times - start_times
#         times_convert.append(x_times)
#     print()
#     print("average mean time for convert sign/keys ", statistics.mean(times_convert))
#
#     # check converted sign
#     assert(sign_scheme.verify(params, pk_new, rho_hat, tag_dh_message1, sig_new)), \
#         ValueError("Convert verification is not correct")
#
# #
# def test_aggr_sign():
#     "aggregation of two signatures"
#     (rho, rho_hat) = tag
#
#     # generate two signatures
#     sign_list = []
#     for i in range(n):
#         signature =  sign_scheme.sign(params, sk_list[i], tag, message_str_set[i])
#         sign_list.append(signature)
#
#
#     # aggregate signatures and vks
#     times_aggre = []
#     for i in range(run_num):
#         start_times = time.perf_counter()
#
#         aggre_sign = sign_scheme.aggr_sign(sign_list)
#
#         end_times = time.perf_counter()
#         x_times = end_times - start_times
#         times_aggre.append(x_times)
#     print()
#     print("average mean time for aggregate signs ", statistics.mean(times_aggre))
#     # check the aggregate signature
#     times_aggre_verify = []
#     for i in range(run_num):
#         start_times2 = time.perf_counter()
#
#         assert (sign_scheme.aggre_verify(params, vk_list, rho_hat, message_str_set, aggre_sign))
#
#         end_times2 = time.perf_counter()
#         x_times2 = end_times2 - start_times2
#         times_aggre_verify.append(x_times2)
#     print()
#     print("average mean time for aggregate verification ", statistics.mean(times_aggre_verify))
