from binascii import hexlify

from bplib.bp import BpGroup
from petlib.bn import Bn
from hashlib import sha256
from ac_package.util import pedersen_setup, pedersen_committ, pedersen_dec, ec_sum


class ZKP_Schnorr_FS:
    """Schnorr proof (non-interactive using FS heuristic) of the statement ZK(x, m_1....m_n; h = g^x and h_1^m_1...h_n^m_n) and generilized version"""

    def __init__(self, group):
        self.G = group
    def setup(self):
        g = self.G.gen2()
        o = self.G.order()
        group = self.G
        params = (group, g, o)
        return params

    def challenge(self, elements):
        """Packages a challenge in a bijective way"""
        elem = [len(elements)] + elements
        elem_str = map(str, elem)
        elem_len = map(lambda x: "%s||%s" % (len(x), x), elem_str)
        state = "|".join(elem_len)
        H = sha256()
        H.update(state.encode("utf8"))
        return Bn.from_binary(H.digest())


    def non_interact_prove(self, params, stm, secret_wit):
        """Schnorr proof (non-interactive using FS heuristic)"""
        (G, g, o) = params
        if isinstance(stm, list) == True:
            w_list = [o.random() for i in range(len(stm))]
            W_list = [w_list[i] * g for i in range(len(w_list))]
            Anoncment = ec_sum(W_list)
            state = ['schnorr', g, stm, Anoncment.__hash__()]
            c = self.challenge(state) % o
            r = [(w_list[i] - c * secret_wit[i]) % o for i in range(len(secret_wit))]
            return (r, c)
        else:
            w = o.random()
            W = w * g
            state = ['schnorr', g, stm, W.__hash__()]
            c = self.challenge(state) % o
            # hash_c = challenge(state)
            # c = Bn.from_binary(hash_c) % o
            r = (w - c * secret_wit) % o
            return (r, c)

    def non_interact_verify(self, params, stm, proof_list):
        """Verify the statement ZK(x ; h = g^x)"""
        (G, g, o) = params
        (r, c) = proof_list

        if isinstance(stm, list) == True:
            W_list = [r[i] * g + c * stm[i] for i in range(len(r))]
            Anoncment = ec_sum(W_list)
            state = ['schnorr', g, stm, Anoncment.__hash__()]
            hash = self.challenge(state) % o
            return c == hash
        else:
            W = (r * g + c * stm)
            state = ['schnorr', g, stm, W.__hash__()]
            c2 = self.challenge(state) % o
            return c == c2


class ZKP_Schnorr:
    """Schnorr (interactive) proof of the statement ZK(x ; h = g^x)"""

    def __init__(self, group):
        self.G = group

    def setup(self):
        g = self.G .gen1()
        o = self.G .order()
        group = self.G
        params = (group, g, o)
        return params

    def challenge(self, elements):
        """Packages a challenge in a bijective way"""

        elem = [len(elements)] + elements
        elem_str = map(str, elem)
        elem_len = map(lambda x: "%s||%s" % (len(x), x), elem_str)
        state = "|".join(elem_len)
        H = sha256()
        H.update(state.encode("utf8"))
        return Bn.from_binary(H.digest())

    def announce(self, params):
        (G, g, o) = params
        w_random = o.random()
        W_element = w_random * g
        return (W_element, w_random)

    def response(self, challenge, announce_randomnes, stm, secret_wit):
        """the statement ZK(x ; h = g^x)"""
        assert secret_wit * self.G.gen1() == stm
        res = (announce_randomnes + challenge * secret_wit) % self.G.order()
        return res

    def verify(self, params, challenge, announce_element, stm, response):
        """Verify the statement ZK(x ; h = g^x)"""
        (G, g, o) = params
        left_side = response * g
        right_side = (announce_element + challenge * stm)
        return left_side == right_side


class ZKP_Tag:
    """Schnorr (interactive) proof of the Tag stetment: ZK( (rh1, rho2): T1 = h^rh1 AND T1 = h^rh2)"""
    def __init__(self, group):
        self.G = group
    def setup(self):
        g = self.G .gen1()
        g2 = self.G .gen2()
        o = self.G .order()
        group = self.G
        params = (group, g, g2, o)
        return params

    def challenge(slef, elements):
        """Packages a challenge in a bijective way"""

        elem = [len(elements)] + elements
        elem_str = map(str, elem)
        elem_len = map(lambda x: "%s||%s" % (len(x), x), elem_str)
        state = "|".join(elem_len)
        H = sha256()
        H.update(state.encode("utf8"))
        return Bn.from_binary(H.digest())

    def announce(self, params, h, AMT = None):
        """
        :param AMT: if the tag is for AMTS signature this paramiters is not none
        :return: create an anoncment for proof
        """
        (group, g, g2, o) = params
        if AMT == None:
            w_1, w_2 = o.random(), o.random()
            W_element1 = w_1 * h
            W_element2 = w_2 * h
            announce_randomnes = (w_1, w_2)
            announce_public = (W_element1, W_element2)
            return (announce_public, announce_randomnes)
        else:
            w_1, w_2 = o.random(), o.random()
            W_element1 = w_1 * g
            W_element2 = w_2 * g
            announce_randomnes = (w_1, w_2)
            announce_public = (W_element1, W_element2)
            return (announce_public, announce_randomnes)

    def response(slef, params, challenge, announce_randomnes, h, stm, secret_wit, AMTS = None):
        (group, g, g2, o) = params
        (w_1, w_2) = announce_randomnes
        (T_1, T_2) = stm
        (rho1, rho2) = secret_wit
        """the statement ZK(x; T1 = h^rho1 and T2 = h^rho2)"""
        if AMTS ==None:
            assert rho1 * h == T_1 and rho2 * h == T_2
            r1 = (w_1 + challenge * rho1) % slef.G.order()
            r2 = (w_2 + challenge * rho2) % slef.G.order()
            return (r1, r2)
        else:
            assert rho1 * g2 == T_1 and rho2 * g2 == T_2
            r1 = (w_1 + challenge * rho1) % slef.G.order()
            r2 = (w_2 + challenge * rho2) % slef.G.order()
            return (r1, r2)

    def verify(self, params, challenge, announce_public, h, stm, response, AMTS = None):
        """Verify the statement ZK(x ; h = g^x)"""
        (group, g, g2, o)  = params
        (W_element1, W_element2) = announce_public
        (r1, r2) = response
        [T_1, T_2] = stm
        if AMTS == None:
            return r1 * h == W_element1 + challenge * T_1 and r2 * h == W_element2 + challenge * T_2
        else:
            return r1 * g2 == W_element1 + challenge * stm[0] and r1 * g2 == W_element1 + challenge * stm[1]


# class Chaum_Pedersen(ZKP_Schnorr):
#
#     def non_interact_prove(slef, params, stm, secret_wit):
#         """Schnorr proof (non-interactive using FS heuristic)"""
#         (G, g, h, o) = params
#         w = o.random()
#         W_1 = w * g
#         W_2 = w * h
#         W = W_1 + W_2
#         # hash_c = challenge(state)
#         state = ['schnorr', g, stm, W.__hash__()]
#         c = slef.challenge(state) % o
#         # response
#         s = (w - c * secret_wit) % o
#         return (s, c)
#
#     def non_interact_verify(slef, params, stm, proof):
#         """Verify the statement ZK(x ; h = g^x)"""
#         (G, g, h, o) = params
#         (s, c) = proof
#         (y_1, y_2) = stm
#         W_1 = (s * g + c * y_1)
#         W_2 = (s * h + c * y_2)
#         W = W_1+ W_2
#         state = ['schnorr', g, stm, W.__hash__()]
#         c2 = slef.challenge(state) % o
#         return c == c2

class Damgard_Transfor(ZKP_Schnorr):
    def __init__(self, group):
        super().__init__(group)
        self.pp_pedersen = self.setup(group)

    @staticmethod
    def setup(group):
        (pp_pedersen, trapdoor) = pedersen_setup(group)
        return pp_pedersen

    def announce(self):
        (G, g, o, h) = self.pp_pedersen
        w_random = o.random()
        W_element = w_random * g
        pedersen_commit, (r,m) = pedersen_committ(self.pp_pedersen, w_random)
        pedersen_open = (r, m, W_element)
        return (pedersen_commit, pedersen_open)

    def verify(self, challenge, pedersen_open, pedersen_commit, stm, response):
        (G, g, o, h) = self.pp_pedersen
        (open_randomness, announce_randomnes, announce_element) = pedersen_open
        pedersen_open = (open_randomness, announce_randomnes)
        left_side = response * g
        right_side = (announce_element + challenge * stm)
        return left_side == right_side and pedersen_dec(self.pp_pedersen, pedersen_open, pedersen_commit)



