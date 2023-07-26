"""
This is a class implementation of the Aggregate PS  Signatures scheme with the randomization of keys/tag (called ATOSA)
@Author: Omid Mir
"""

from bplib.bp import BpGroup
from ac_package.util import ec_sum, pedersen_setup, pedersen_committ, eq_relation, pedersen_dec, convert_mess_to_bn


class AtoSa:
	def __init__(self):
		global group
		group = BpGroup()

	@staticmethod
	def setup():
		"""
		:return: generate and return public parameters
		"""
		(pp_pedersen, trapdoor) = pedersen_setup(group)
		g1, g2 = group.gen1(), group.gen2()
		e, order = group.pair, group.order()
		return (group, order, g1, g2, e, pp_pedersen)

	def keygen(self, params):
		"""
		:param params: get public parameters
		:return: keys pair sk, vk
		"""
		(group, order, g1, g2, e, pp_pedersen) = params
		## pick randomness
		(x, y_1, y_2) = order.random(), order.random(), order.random()
		## create a key pair
		sk = (x, y_1, y_2)
		vk = [x * g2, y_1 * g2, y_2 * g2]
		return (sk, vk)

	def gen_tag_aux(self, params, message_vk_vector):
		"""
		:param params:
		:param message_vk_vector:
		:return:
		"""
		(group, order, g1, g2, e, pp_pedersen) = params
		## pick two randoms as tag secret
		rho_1, rho_2 = order.random(), order.random()

		## create aux using tag secret and the set
		commit_list = []
		commitment_pair_list = []

		[message_vector, vk_vector] = message_vk_vector
		if all(isinstance(element, str) for element in message_vector):
			set_m = convert_mess_to_bn(message_vector)
		else:
			print("Please insert messages of the same data type")

		## for now, we do not consider vk in the aux for now?, we should concatenat them in aux
		for item in set_m:
			(pedersen_commit, pedersen_open) = pedersen_committ(pp_pedersen, item)
			commit_list.append(pedersen_commit)
			commitment_pair_list.append((pedersen_commit, pedersen_open))

		add_commitments = ec_sum(commit_list)
		aux = (rho_1 * g1) + (rho_2 * g1) + add_commitments
		h = group.hashG1(aux.export())

		T_vec = [rho_1 * h, rho_2 * h]
		tau = [rho_1, rho_2]
		tag = (tau, T_vec)
		return (tag, aux, commitment_pair_list)

	# def gen_index(self, params, tag, message_vector):
	# 	"""
	# 	:param params: public parameters
	# 	:param tag: tag
	# 	:param message_vector: entire if messages
	# 	:return: index that is concatenation of massage commitments and tga
	# 	"""
	# 	(group, order, g1, g2, e, pp_pedersen) = params
	# 	(rho, rho_hat) = tag
	# 	pre_list = []
	# 	commitment_pair_list = []
	# 	if type(message_vector[0]) == str:
	# 		set_m = convert_mess_to_bn(message_vector)
	#
	# 	for item in set_m:
	# 		(pedersen_commit, pedersen_open) = pedersen_committ(pp_pedersen, item)
	# 		pre_list.append(pedersen_commit)
	# 		commitment_pair_list.append((pedersen_commit, pedersen_open))
	#
	# 	commitment_list = ec_sum(pre_list)
	# 	index = (rho * g1) + commitment_list
	# 	return index, commitment_pair_list
	#
	# def gen_tag(self, params):
	# 	"""
	# 	:param params: pp
	# 	:return: a tag
	# 	"""
	# 	(group, order, g1, g2, e, pp_pedersen) = params
	# 	rho = order.random()
	# 	rho_hat = rho * g2
	# 	tag = (rho, rho_hat)
	# 	return tag


#### ------------------this signing alo only is used in AC aopplication---------------
	def sign_intract(self, params, sk, T_vec, aux, message, commitment_pair=None):
		"""
		:param params:
		:param sk:
		:param T_vec:
		:param aux:
		:param message:
		:param commitment_pair:
		:return:
		"""
		(group, order, g1, g2, e, pp_pedersen) = params
		if type(message) == str:
			message = convert_mess_to_bn(message)
		(x, y_1, y_2) = sk
		[T_1, T_2] = T_vec
		# if a commitemnt of message is provided, then check it's correct
		if commitment_pair is not None:
			(commitment_message, opening_message) = commitment_pair
			(randomness, m) = opening_message
			assert m == message and pedersen_dec(pp_pedersen, opening_message,
												 commitment_message), 'the message and commitment values do not match'

		# generate signature h = H(aux), s = (h^{x+y.m})^rho-1
		h_prime = T_1
		s = ((x + y_1 * message) * T_1) + (y_2 * T_2)
		return (h_prime, s)

	def sign(self, params, sk, tag,  aux, message, commitment_pair = None):
		"""
		:param params: public parameters
		:param sk: secret keys for signing
		:param tag: a tag that is pair of secret and public parts
		:param index: index for hashing and get h
		:param message: message
		:param commitment_pair: commitment if message is correct (optional)
		:return: signature
		"""
		(group, order, g1, g2, e, pp_pedersen) = params

		if type(message) == str:
			message = convert_mess_to_bn(message)

		(x, y_1, y_2) = sk
		(tau, T_vec) = tag
		[rho_1, rho_2] = tau
		[T_1, T_2] = T_vec

		# if a commitemnt of message is provided, then check it's correct
		if commitment_pair is not None:
			(commitment_message, opening_message) = commitment_pair
			(randomness, m) = opening_message
			assert m == message and pedersen_dec(pp_pedersen, opening_message, commitment_message), 'the message and commitment values do not match'

		# generate signature h = H(aux), s = (h^{x+y.m})^rho-1
		h = group.hashG1(aux.export())
		h_prime = rho_1 * h
		assert h_prime == T_1
		s = ((x + y_1 * message) * T_1) + ((y_2 * rho_2) * h)
		return (h_prime, s)

	def verify(self, params, vk, T_vec, message, sign):
		"""
		:param params: public parameters
		:param vk: verification key
		:param rho_hat: the  public part of tag
		:param message: a signed message
		:param sig: sigature
		:return: 0,1 (1 if it is correct, 0 otherwise)
		"""
		(group, order, g1, g2, e, pp_pedersen) = params
		if type(message) is str:
			message = convert_mess_to_bn(message)
		[T_1, T_2] = T_vec
		[X, Y_1, Y_2] = vk
		(h_prime, s) = sign
		return T_1 == h_prime and e(h_prime, X + message * Y_1) * e(T_2, Y_2) == e(s, g2)

	def aggr_verify(self, params, vk_vector, T_vec, message_vector, agg_sig):
		"""
		:param params:  public parameters
		:param vk_vector: aggregate avk which is a vector of vks
		:param rho_hat: the  public part of tag
		:param m_vector: vector of messages
		:param agg_sig: aggregate signature
		:return: 0,1 (1 if it is correct, 0 otherwise)
		"""
		# check if messages are inserted as string then convert them to Bn
		if type(message_vector[0]) is str:
			message_vector = convert_mess_to_bn(message_vector)

		(group, order, g1, g2, e, pp_pedersen) = params
		[T_1, T_2] = T_vec
		(h, s) = agg_sig

		precompute_1 = [X + message_vector[i] * Y_1 for [X, Y_1, Y_2] in vk_vector for i in range(len(message_vector)) if [X, Y_1, Y_2] == vk_vector[i]]
		sum_x_y = ec_sum(precompute_1)
		precompute_2 = [Y_2 for [X, Y_1, Y_2] in vk_vector for i in range(len(message_vector)) if [X, Y_1, Y_2] == vk_vector[i]]
		sum_Y2 = ec_sum(precompute_2)

		return  e(h, sum_x_y) * e(T_2, sum_Y2) == e(s, g2) and T_1 == h

	def convert_tag(self, tag, upsilon):
		(tau, T_vec) = tag
		[T_1, T_2] = T_vec
		[rho_1, rho_2] = tau
		#T_prime = (upsilon * T_1, upsilon * T_2)
		T_prime = eq_relation(T_vec, upsilon)
		tau_prime = eq_relation(tau, upsilon)
		return (tau_prime, T_prime)

	def rand_sign(self, sig, tag, upsilon):
		"""
		:param sig: get a signatur
		:param tag: a tag
		:param gamma: randomness
		:param beta: randomness
		:return: randomized signature and tag
		"""
		(h, s) = sig
		(tau_prime, T_prime) = self.convert_tag(tag, upsilon)
		[T_1_prime, T_2_prime] = T_prime
		h_new = upsilon * h
		assert  h_new == T_1_prime
		s_new = upsilon * s

		randomize_sig = (h_new, s_new)
		randomize_tag = (tau_prime, T_prime)
		return randomize_sig, randomize_tag

	def aggr_sign(self, sig_list):
		"""
		:param sig_list: get all signautres
		:return: aggregate signautre
		"""
		(h,s) = sig_list[0]
		filter = [item[1] for item in sig_list]
		aggre_s = ec_sum(filter)
		aggre_sign = (h, aggre_s)
		return aggre_sign

	def convert_sk(self, sk, omega):
		"""
		:param sk: secret key
		:param omega: randomness
		:return: conver/randomize sk
		"""
		(x, y_1, y_2) = sk
		sk_prime = (omega * x, omega * y_1, omega * y_2)
		return sk_prime

	def convert_vk(self, vk, omega):
		"""
		:param vk: verification key
		:param omega: randomness
		:return: conver/randomize vk
		"""
		# randomizing vk is similar to change eq relation
		vk_prime = eq_relation(vk, omega)
		return vk_prime

	def convert_sig(self, sig, omega):
		"""
		:param sig: a signature
		:param omega: randomness
		:return: converted signature for randomized vk/dk
		"""
		(h, s) = sig
		s_new = omega * s
		converted_sig = (h, s_new)
		return converted_sig

