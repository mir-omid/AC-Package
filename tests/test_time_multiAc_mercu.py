# import statistics
# import time
# import random
# import string
#
# from ac_package.protocols.mac_amts import Multi_AC_Mercurial
#
# run_num = 1 # the number of running time
# n = 10  # the number of issuer
# t = 3 # number of attributes in each commitment that each issuer will provide
# d = 1 # number of disclose attributes in each set
# D = [] # a vector of subset of disclose attributes D = [d_i] for i in issuer set n
# # some default attributes and their subsets
# attr_set = ["10", "20", "50"]
# #attr_set = ["".join(random.choices(string.ascii_letters + string.digits, k=5)) for _ in range(t)]
# attr_set2 = ["30", "40", "60"]
# subset1 = ["10", "50"]
# subset2 = ["30", "40"]
#
# message_str_set = []
# for i in range(n):
#     message_str = [''.join(random.choices(string.ascii_letters + string.digits, k=5)) for _ in range(t)]
#     message_str_set.append(message_str)
#     SubList_str = random.sample(message_str, d)
#     D.append(SubList_str)
#
# def setup_module(module):
#     print("__________Setup___Test Multi-Authority AC ________")
#     global mac_merc
#     global pp, isk, ivk, isk_2, ivk_2, isk_3, ivk_3, alpha_trapdoor, sk_list, vk_list
#     mac_merc = Multi_AC_Mercurial(5)
#     pp, alpha_trapdoor = mac_merc.setup()
#     (isk, ivk) = mac_merc.isuser_keygen(pp)
#     (isk_2, ivk_2) = mac_merc.isuser_keygen(pp)
#     (isk_3, ivk_3) = mac_merc.isuser_keygen(pp)
#
#     keys = [mac_merc.isuser_keygen(pp) for _ in range(n)]
#     sk_list = [item[0] for item in keys]
#     vk_list = [item[1] for item in keys]
#
#
# def test_Issuecred_merc():
#     (pp_sig, pp_spseq, pp_sc, pp_nizk) = pp
#     (group, order, g1, g2, e) = pp_sig
#     times = []
#     for i in range(run_num):
#         start_time = time.perf_counter()
#
#         (usk, uvk, tag) = mac_merc.user_keygen(pp)
#         (rho, rho_hat) = tag
#         h = group.hashG1(rho_hat.export())
#         commitment, open_info = mac_merc.gen_encode(pp, alpha_trapdoor, h, tag, attr_set)
#         cred = mac_merc.issue_cred(pp, isk, commitment, tag)
#
#         end_time = time.perf_counter()
#         x = end_time - start_time
#         times.append(x)
#     print()
#     print("average mean time for issuing cred ", statistics.mean(times))
#
#     proof = mac_merc.proof_cred(pp, tag, ivk, cred, commitment, attr_set, subset1)
#     assert mac_merc.verify_proof(pp, proof, subset1)
#
#
# def test_proofcred_merc():
#     (pp_sig, pp_spseq, pp_sc, pp_nizk) = pp
#     (group, order, g1, g2, e) = pp_sig
#     (usk, uvk, tag) = mac_merc.user_keygen(pp)
#     (rho, rho_hat) = tag
#     h = group.hashG1(rho_hat.export())
#
#     cred_list = []
#     commitment_vector= []
#     for i in range(n):
#         commitment, open_info = mac_merc.gen_encode(pp, alpha_trapdoor, h, tag, message_str_set[i])
#         cred = mac_merc.issue_cred(pp, sk_list[i], commitment, tag)
#         cred_list.append(cred)
#         commitment_vector.append(commitment)
#
#     times_prove = []
#     for i in range(run_num):
#         start_time = time.perf_counter()
#         proof = mac_merc.proof_cred(pp, tag, vk_list, cred_list, commitment_vector, message_str_set, D)
#         end_time = time.perf_counter()
#         x = end_time - start_time
#         times_prove.append(x)
#     print()
#     print("average mean time for proving cred", statistics.mean(times_prove))
#
#     times_verify = []
#     for i in range(run_num):
#         start_time2 = time.perf_counter()
#
#         assert mac_merc.verify_proof(pp, proof, D)
#
#         end_time2 = time.perf_counter()
#         x2 = end_time2 - start_time2
#         times_verify.append(x2)
#     print()
#     print("average mean time for verifying cred ", statistics.mean(times_verify))
#
#
# def test_proofcred_Ih_merc():
#     (pp_sig, pp_spseq, pp_sc, pp_nizk) = pp
#     (group, order, g1, g2, e) = pp_sig
#     (usk, uvk, tag) = mac_merc.user_keygen(pp)
#     (rho, rho_hat) = tag
#     h = group.hashG1(rho_hat.export())
#
#     cred_list = []
#     commitment_vector= []
#     for i in range(n):
#         commitment, open_info = mac_merc.gen_encode(pp, alpha_trapdoor, h, tag, message_str_set[i])
#         cred = mac_merc.issue_cred(pp, sk_list[i], commitment, tag)
#         cred_list.append(cred)
#         commitment_vector.append(commitment)
#
#     times_poly = []
#     for i in range(run_num):
#         start_time = time.perf_counter()
#
#         policies = mac_merc.gen_policies(pp, vk_list)
#
#         end_time = time.perf_counter()
#         x = end_time - start_time
#         times_poly.append(x)
#     print()
#     print("average mean time for generating policies", statistics.mean(times_poly))
#
#     times_prove = []
#     for i in range(run_num):
#         start_time2 = time.perf_counter()
#         proof = mac_merc.proof_cred(pp, tag, vk_list, cred_list, commitment_vector, message_str_set, D, policies=policies)
#         end_time2 = time.perf_counter()
#         x2 = end_time2 - start_time2
#         times_prove.append(x2)
#     print()
#     print("average mean time for proving cred with policies", statistics.mean(times_prove))
#
#     times_verify = []
#     for i in range(run_num):
#         start_time3 = time.perf_counter()
#
#         assert mac_merc.verify_proof(pp, proof, D, policies)
#         end_time3 = time.perf_counter()
#         x3 = end_time3 - start_time3
#         times_verify.append(x3)
#     print()
#     print("average mean time for verifying cred with policies ", statistics.mean(times_verify))