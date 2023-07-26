"""
This is implementation of threshold delegatable anonymous credential using TDSPE encryption
and commitment See  the following for the details
- (Submitted) Threshold Delegatable Anonymous Credentials with Controlled and Fine-Grained Delegation,
@Author: Omid Mir
"""

from bplib.bp import BpGroup
from petlib.bn import Bn
from ac_package.AC import AC
from ac_package.primitives.spe_enc import SPE
from ac_package.util import pedersen_setup, pedersen_committ, pedersen_dec


class TDAC(AC):
    def __init__(self, t, n):
        """
        :param t: threshold number of issuers
        :param n: all issuers
        """
        self.group = BpGroup()
        self.spe = SPE(t, n)

    def setup(self):
        """
        :return: public parameters
        """
        (param_spe, sk_shares, pk_shares) = self.spe.setup()
        (pp_commit, trapdoor) = pedersen_setup(self.group)
        pk = self.spe.agg_keys(param_spe, pk_shares)
        pp_tdac = (param_spe, pp_commit, pk)
        return (pp_tdac, sk_shares, pk)

    def issue_cred(self, pp_tdac, sk_shares, attr, delegate_attr):
        """
        :param pp_tdac:
        :param sk_shares:
        :param attr:
        :param delegate_attr:
        :return:
        """
        (param_spe, pp_commit, pk) = pp_tdac
        (cred_list, mk_list) = self.spe.share_KeyGen(param_spe, sk_shares, attr, delegate_attr)
        return (cred_list, mk_list)

    def agg_cred(self, cred_list, mk_list):
        """
        :param cred_list:
        :param mk_list:
        :return:
        """
        (cred, mk) = self.spe.keyGen_comb(cred_list, mk_list)
        return (cred, mk)

    def verifier_challenge(self, pp_tdac, pk, m, attr, r, L=1):
        """
        :param pp_tdac:
        :param pk:
        :param m:
        :param attr:
        :param r:
        :param L:
        :return:
        """
        (param_spe, pp_commit, pk) = pp_tdac
        ## create a commit for a random r
        (commit_r, open_r) = pedersen_committ(pp_commit, r)
        ## create enc for f
        ct = self.spe.enccrypt(param_spe, pk, m, attr, L)
        return (ct, commit_r, open_r)

    def proof_cred(self, pp_tdac, cred, attr, L, ct, commit_r, open_r):
        """
        :param pp_tdac:
        :param cred:
        :param attr:
        :param L:
        :param ct:
        :param commit_r:
        :param open_r:
        :return:
        """
        (param_spe, pp_commit, pk) = pp_tdac
        ## check of commit_ r is correct
        assert  pedersen_dec(pp_commit, open_r, commit_r)
        ## decrypt m
        m = self.spe.decrypt(param_spe, cred, ct)

        #assert ct == self.spe.enccrypt(param_spe, pk, m, attr, L)

        ## commit to M  first need to conver it to zp
        m_zp = Bn.from_binary(m.export())
        (commit_m, open_m) = pedersen_committ(pp_commit, m_zp)
        proof = (commit_m, open_m)
        return proof

    def verify_proof(self, pp_tdac, PK, f, message, proof):
        (param_spe, pp_commit, pk) = pp_tdac
        ## check if message is decrypted correctly
        (commit_m, open_m) = proof
        (r, m) = open_m
        assert pedersen_dec(pp_commit, open_m, commit_m)
        message_zp = Bn.from_binary(message.export())
        return (m == message_zp)

    def delegate(self, dk, mk, delegate_attr, theta_hat):
        # create new key in delegate
        dk_new, delegate_key = self.spe.delegtae(dk, mk, theta_hat, delegate_attr)
        return (dk_new, delegate_key)
