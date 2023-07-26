# import statistics
# import time
# import random
# import string
# from ac_package.protocols.mac_atosa import Multi_AC_PS
#
# run_num = 1 # the number of running time
# n = 2 # the number of messages in the set or we can say number of issuers
#
# attr_1 = "10"
# attr_2 = "20"
# attr_3 = "30"
# full_attr_vector = [attr_1, attr_2, attr_3]
# attr_vector = [''.join(random.choices(string.ascii_letters + string.digits, k=5)) for _ in range(n)]
#
# def setup_module(module):
#     print("__________Setup___  Times Multi-Authority AC based PS ________")
#     global mac_ps, mac_merc, sk_list, vk_list
#     global pp, isk, ivk, isk_2, ivk_2, isk_3, ivk_3, pp_merc, alpha_trapdoor
#     mac_ps = Multi_AC_PS()
#     pp = mac_ps.setup()
#     (isk, ivk) = mac_ps.isuser_keygen(pp)
#     (isk_2, ivk_2) = mac_ps.isuser_keygen(pp)
#     (isk_3, ivk_3) = mac_ps.isuser_keygen(pp)
#
#     keys = [mac_ps.isuser_keygen(pp) for _ in range(n)]
#     sk_list = [item[0] for item in keys]
#     vk_list = [item[1] for item in keys]
#
#     # mac_merc = Multi_AC_Mercurial(5)
#     # pp_merc, alpha_trapdoor = mac_merc.setup()
#
#
# def test_Issuecred_ps():
#     "issuer one single credential on a single message and verify it"
#     times = []
#     for i in range(run_num):
#         start_time = time.perf_counter()
#
#         (usk, uvk, tag, index) = mac_ps.user_keygen(pp, attr_vector)
#         cred = mac_ps.issue_cred(pp, isk, attr_1, tag, index)
#
#         end_time = time.perf_counter()
#         x = end_time - start_time
#         times.append(x)
#     print()
#     print("average mean time for issuing cred ", statistics.mean(times))
#     proof = mac_ps.proof_cred(pp, tag, ivk, cred, attr_1)
#     assert mac_ps.verify_proof(pp, ivk, proof, attr_1)
#
# def test_proofcred_ps():
#     "issuer three credentials  and verify twp of them"
#     (usk, uvk, tag, index) = mac_ps.user_keygen(pp, attr_vector)
#     cred_list = []
#     for i in range(n):
#         cred = mac_ps.issue_cred(pp, sk_list[i], attr_vector[i], tag, index)
#         cred_list.append(cred)
#
#
#     times_prove = []
#     for i in range(run_num):
#         start_time = time.perf_counter()
#         proof = mac_ps.proof_cred(pp, tag, vk_list, cred_list, attr_vector)
#
#         end_time = time.perf_counter()
#         x = end_time - start_time
#         times_prove.append(x)
#     print()
#     print("average mean time for proving cred", statistics.mean(times_prove))
#
#     times_verify = []
#     for i in range(run_num):
#         start_time2 = time.perf_counter()
#         assert(mac_ps.verify_proof(pp, vk_list, proof, attr_vector))
#
#         end_time2 = time.perf_counter()
#         x2 = end_time2 - start_time2
#         times_verify.append(x2)
#     print()
#     print("average mean time for verifying cred ", statistics.mean(times_verify))
#
# def test_proofcred_Ih_ps():
#     "issuer three credentials  and verify twp of them"
#     (usk, uvk, tag, index) = mac_ps.user_keygen(pp, attr_vector)
#     cred_list = []
#     for i in range(n):
#         cred = mac_ps.issue_cred(pp, sk_list[i], attr_vector[i], tag, index)
#         cred_list.append(cred)
#
#     times_poly = []
#     for i in range(run_num):
#         start_time = time.perf_counter()
#
#         policies = mac_ps.gen_policies(pp, vk_list)
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
#
#         proof = mac_ps.proof_cred(pp, tag, vk_list, cred_list, attr_vector, policies)
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
#         assert mac_ps.verify_proof(pp, vk_list, proof, attr_vector, policies)
#
#         end_time3 = time.perf_counter()
#         x3 = end_time3 - start_time3
#         times_verify.append(x3)
#     print()
#     print("average mean time for verifying cred with policies", statistics.mean(times_verify))
