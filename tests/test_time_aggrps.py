#
# '''
# Compute running time of Aggregate PS
# '''
# import string
# from ac_package.primitives.atosa import AggrSign_PS
# import statistics
# import time
# import random
#
# run_num = 1 # the number of running time
# n = 2 # the number of messages in the set
# m_1 = "Omid"
# m_2 = "mir"
# m_3 = "age"
# set_str = [m_1, m_2, m_3]
# mesage_vector = [m_1, m_2]
# message_str_set = [''.join(random.choices(string.ascii_letters + string.digits, k=5)) for _ in range(n)]
#
#
# def setup_module(module):
#     print()
#     print("__________Setup___ Times for Aggre PS Signature________")
#     global sign_scheme
#     global pp, vk_list, sk_list
#     global tag
#     global sk_1, sk_2
#     global vk_1, vk_2
#     global index, commitment_pair_list
#     sign_scheme = AggrSign_PS()
#     pp = sign_scheme.setup()
#     # generate secret and verification keys (example for two signatures)
#     (sk_1, vk_1) = sign_scheme.keygen(pp)
#     (sk_2, vk_2) = sign_scheme.keygen(pp)
#     keys = [sign_scheme.keygen(pp) for _ in range(n)]
#     sk_list = [item[0] for item in keys]
#     vk_list = [item[1] for item in keys]
#
# def test_sign():
#     times = []
#     times_tag = []
#     times_verify = []
#     # create a tag
#     for i in range(run_num):
#         start_time = time.perf_counter()
#         # select which message should be signed
#         tag = sign_scheme.gen_tag(pp)
#         (rho, rho_hat) = tag
#         # prepare index and commitments for all messages
#         index, commitment_pair_list = sign_scheme.gen_index(pp, tag, set_str)
#         end_time = time.perf_counter()
#         x = end_time - start_time
#         times_tag.append(x)
#     print()
#     print("average mean time for precomputation ", statistics.mean(times_tag))
#
#     for i in range(run_num):
#         start_time2 = time.perf_counter()
#         # select which message should be signed
#         (commitment_message1, opening_message1) = commitment_pair_list[0]
#         signature_1 = sign_scheme.sign(pp, sk_1, tag, index,  m_1, (commitment_message1, opening_message1))
#         end_time2 = time.perf_counter()
#         x2 = end_time2 - start_time2
#         times.append(x2)
#     print()
#     print("average mean time for signing ", statistics.mean(times))
#     for i in range(run_num):
#         start_times_verify = time.perf_counter()
#         assert (sign_scheme.verify(pp, vk_1, rho_hat, m_1, signature_1)), ValueError("signiture is not correct")
#         end_times_verify = time.perf_counter()
#         x_times_verify = end_times_verify - start_times_verify
#         times_verify.append(x_times_verify)
#     print()
#     print("average mean time for verifing sign ", statistics.mean(times_verify))
#
#
# def test_rand_sign():
#     # create a tag
#     tag = sign_scheme.gen_tag(pp)
#     (rho, rho_hat) = tag
#
#     # prepare index and commitments for all messages
#     index, commitment_pair_list = sign_scheme.gen_index(pp, tag, set_str)
#     # pick two randomness
#     (BG, order, g1, g2, e, pp_pedersen) = pp
#     gamma, beta = order.random(), order.random()
#     # select which message should be signed
#     (commitment_message1, opening_message1) = commitment_pair_list[0]
#     signature_1 = sign_scheme.sign(pp, sk_1, tag, index,  m_1, (commitment_message1, opening_message1))
#     # randomize signature and tag
#     times_random = []
#     for i in range(run_num):
#         start_times_verify = time.perf_counter()
#
#         randomize_sig, randomize_tag = sign_scheme.rand_sign(signature_1, tag, gamma, beta)
#         (rho_new, rho_hat_new) = randomize_tag
#
#         end_times_verify = time.perf_counter()
#         x_times_random = end_times_verify - start_times_verify
#         times_random.append(x_times_random)
#     print()
#     print("average mean time for randomizing sign ", statistics.mean(times_random))
#     # check if randomized signature/tga is correct
#     assert(sign_scheme.verify(pp, vk_1, rho_hat_new, m_1, randomize_sig)), ValueError("verification of randomized signature is not correct")
#
# def test_convert_sign():
#     # create a tag
#     tag = sign_scheme.gen_tag(pp)
#     (rho, rho_hat) = tag
#     # prepare index and commitments for all messages
#     index, commitment_pair_list = sign_scheme.gen_index(pp, tag, set_str)
#     # pick two randomness
#     (BG, order, g1, g2, e, pp_pedersen) = pp
#     omega = order.random()
#     # select which message should be signed
#     (commitment_message1, opening_message1) = commitment_pair_list[0]
#     signature_1 = sign_scheme.sign(pp, sk_1, tag, index, m_1, (commitment_message1, opening_message1))
#     # randomize sk and vk
#     times_convert = []
#     for i in range(run_num):
#         start_times = time.perf_counter()
#
#         sk_new = sign_scheme.convert_sk(sk_1, omega)
#         vk_new = sign_scheme.convert_vk(vk_1, omega)
#         sig_new = sign_scheme.convert_sig(signature_1, omega)
#
#         end_times = time.perf_counter()
#         x_times = end_times - start_times
#         times_convert.append(x_times)
#     print()
#     print("average mean time for convert sign ", statistics.mean(times_convert))
#     assert(sign_scheme.verify(pp, vk_new, rho_hat, m_1, sig_new)), ValueError("Convert verification is not correct")
#
#
# def test_aggr_sign():
#     # create a tag
#     tag = sign_scheme.gen_tag(pp)
#     # prepare index and commitments for all messages
#     index, commitment_pair_list = sign_scheme.gen_index(pp, tag, set_str)
#     (rho, rho_hat) = tag
#     # generate some signatures
#     sign_list = []
#     for i in range(n):
#         signature = sign_scheme.sign(pp, sk_list[i], tag, index, message_str_set[i])
#         sign_list.append(signature)
#
#     # aggregate signatures and vks
#     times_aggre = []
#     for i in range(run_num):
#         start_times = time.perf_counter()
#
#         aggre_sign = sign_scheme.aggr_sign(sign_list)  # check the aggregate signature
#
#         end_times = time.perf_counter()
#         x_times = end_times - start_times
#         times_aggre.append(x_times)
#     print()
#     print("average mean time for aggregate signs ", statistics.mean(times_aggre))
#     times_aggre_verify = []
#     for i in range(run_num):
#         start_times2 = time.perf_counter()
#
#         assert (sign_scheme.aggr_verify(pp, vk_list, rho_hat, message_str_set, aggre_sign)), ValueError(
#             "aggregation verification is not correct")
#
#         end_times2 = time.perf_counter()
#         x_times2 = end_times2 - start_times2
#         times_aggre_verify.append(x_times2)
#     print()
#     print("average mean time for aggregate verification ", statistics.mean(times_aggre_verify))
#
