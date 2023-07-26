"""
we implement SPE encryption and threshold delegation credential (TDAC) in the TDAC paper
use coconuit for threshold and reconstruction keys methods
"""

from coconut.utils import *
from bplib.bp import BpGroup

class SPE:
    def __init__(self, threshold, n):
        global group
        group = BpGroup()
        self.t = threshold
        self.n = n

    def setup(self):
        """
        :return: public parameters
        """
        BG = BpGroup()
        g1, g2 = BG.gen1(), BG.gen2()
        order = BG.order()
        param_spe = (g1, g2, order, BG, self.t)
        ## generate polynomials
        v = [order.random() for _ in range(0, self.t)]
        ## the single secret key is
        x = v[0]

        # generate shares (set shares keys)
        sk_shares = [poly_eval(v, i) % order for i in range(1, self.n + 1)]
        pk_shares = [sk_shares[i] * g2 for i in range(len(sk_shares))]
        return (param_spe, sk_shares, pk_shares)

    def agg_keys(self, param_spe, pk_shares):
        (g1, g2, order, BG, t) = param_spe
        # filter missing keys (in the threshold setting)
        filter = [pk_shares[i] for i in range(len(pk_shares)) if pk_shares[i] is not None]
        indexes = [i + 1 for i in range(len(pk_shares)) if pk_shares[i] is not None]
        # evaluate all lagrange basis polynomials
        l = lagrange_basis(indexes, order)
        # aggregate keys
        aggr_pk = ec_sum([l[i] * filter[i] for i in range(len(filter))])
        return aggr_pk

    def share_KeyGen(self, param_spe, sk_shares, theta, gamma):
        (g1, g2, order, BG, t) = param_spe
        ##check if the thresholds number of authorities are involved to create key shares
        assert len(sk_shares) >= t

        ## create a lagrange interpolant
        filter = [sk_shares[i] for i in range(len(sk_shares)) if sk_shares[i] is not None]
        indexes = [i + 1 for i in range(len(sk_shares))]
        l = lagrange_basis(indexes, order)

        ## pre computation for generating k_i, h_i
        pre_k_i = [l[i] * (filter[i] * g1) for i in range(len(filter))]
        k_shares = []
        r_list = []
        h_shares = []
        mk_list = []
        hash_Y_theta = [BG.hashG1(item) for item in theta]
        product_Y_theta = ec_sum(hash_Y_theta)
        hash_Y_gamma = [BG.hashG1(item) for item in gamma]

        ## generate k_i, h_i for dk
        for item in pre_k_i:
            r_i = order.random()
            r_list.append(r_i)
            k_shares.append(item + (r_i * product_Y_theta))
            h_shares.append(r_i * g2)

        ## set a decryption key dk and delegation key mk
        dk_list = (h_shares, k_shares)
        for Y in hash_Y_gamma:
            mk_shares = [pre_k_i[i] + (r_list[i] * Y) for i in range(len(pre_k_i))]
            mk_list.append(mk_shares)
        return (dk_list, mk_list)

    def keyGen_comb(self, dk_list, mk_list):
        """
        main problem is how we make two vector merge together
        """
        # aggregates dk keys
        (h_shares, k_shares) = dk_list
        aggr_k = ec_sum(k_shares)
        aggr_h = ec_sum(h_shares)
        aggr_dk = (aggr_h, aggr_k)

        # aggregates dk keys
        aggr_mk = [ec_sum(item) for item in mk_list]
        # aggr_mk = ec_sum(mk_list[0])
        return (aggr_dk, aggr_mk)


    def enccrypt(self, param_spe, aggre_pk, M, f, L=1):
        (g1, g2, Order, BG, t) = param_spe
        # random value
        r = BG.order().random()
        list = [aggre_pk for _ in range(0, L)]
        product_X = ec_sum(list)

        c_0 = M * BG.pair(g1, product_X).exp(r)
        c_1 = r * g2
        c_2 = [BG.hashG1(item).mul(r) for item in f if item is not None]
        ct = (c_0, c_1, c_2)
        return ct

    def decrypt(self, param_spe, dk, ct):
        (g1, g2, order, BG, t) = param_spe
        (h, k) = dk
        (C_0, C_1, C_2) = ct
        product_C = ec_sum(C_2)
        pre_compute = C_0 * BG.pair(product_C, h)
        M = pre_compute.mul(BG.pair(k, C_1).inv())
        return M

    def delegtae(self, dk, mk, theta_hat, gamma):
        assert type(theta_hat) is list
        (h, k) = dk

        if len(theta_hat) == 1:
            k_new = k + mk[0]
        else:
            indexes = [gamma.index(item) for item in theta_hat if item in gamma]
            mk_filter = [mk.__getitem__(index) for index in indexes]
            mk_filter = [mk_filter[i] for i in range(len(theta_hat))]
            temp = k + mk_filter[0]
            for i in range(1, len(mk_filter)):
                k_new = temp + mk_filter[i]
        dk_new = (h, k_new)
        #gamm_hat =  even_nums = list(filter(is_there, gamma))
        delegate_key = [item for item in mk if item not in mk_filter]
        return dk_new, delegate_key

"""
delegate is not yet flexible, it needs work with different situation
"""