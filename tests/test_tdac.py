"""
test and example of tdac paper
"""
from bplib.bp import BpGroup
from ac_package.protocols.tdac import TDAC

##  the first set of attributes A
attr = [("theta%s" % i).encode("utf8") for i in range(3)]
##  the set of delegate attributes A^prime
attr_prime = [("gamma%s" % i).encode("utf8") for i in range(3)]


def setup_module(module):
    print("__________Setup___Test TDAC ________")
    global pp_tdac, sk_shares, pk, tdac, BG
    BG = BpGroup()
    tdac = TDAC(t=2, n=5)
    pp_tdac, sk_shares, pk = tdac.setup()

def test_issuing():
    """ issuing the level first credential ----------------------- """
    (cred_list, mk_list) = tdac.issue_cred(pp_tdac, sk_shares, attr, attr_prime)
    cred, mk = tdac.agg_cred(cred_list, mk_list)
    """ deleting the first credential and creating the second level credential ----------------------- """
    ##  the set of attributes that intigerate to A as  A''
    attr_prime_prime = [attr_prime[0], attr_prime[2]]
    cred_new, delegate_key = tdac.delegate(cred, mk, attr_prime, attr_prime_prime)

    # encryption for this new key
    attr.append(attr_prime[0])
    attr.append(attr_prime[2])

    L = len(attr_prime_prime) + 1  ## privious level was 1
    r = BG.order().random()
    # get the random r^prime from prover
    r_prime = BG.order().random()
    # create a message, group element version
    gt = BG.pair(BG.gen1(), BG.gen2())
    m = gt ** (r + r_prime)
    # create a challenge
    (ct, commit_r, open_r) = tdac.verifier_challenge(pp_tdac, pk, m, attr, r, L)
    """ prover starts protocol by creating response ----------------------- """
    proof = tdac.proof_cred(pp_tdac, cred_new, attr, L, ct, commit_r, open_r)
    """ verifier check proof ----------------------- """
    assert (tdac.verify_proof(pp_tdac, pk, attr, m, proof)), ValueError("credential is not correct")


def test_proof_cred():
    """ issuing credentials ----------------------- """
    (cred_list, mk_list) = tdac.issue_cred(pp_tdac, sk_shares, attr, attr_prime)
    cred, mk = tdac.agg_cred(cred_list, mk_list)
    """ verifier starts protocol by creating challenge ----------------------- """
    L = 1
    # verifier picks the random r
    r = BG.order().random()
    # get the random r^prime from prover
    r_prime = BG.order().random()
    # create a message, group element version
    gt = BG.pair(BG.gen1(), BG.gen2())
    m = gt ** (r + r_prime)
    # create a challenge
    (ct, commit_r, open_r) = tdac.verifier_challenge(pp_tdac, pk, m, attr, r, L)
    """ prover starts protocol by creating response ----------------------- """
    proof = tdac.proof_cred(pp_tdac, cred, attr, L, ct, commit_r, open_r)
    """ verifier check proof ----------------------- """
    assert(tdac.verify_proof(pp_tdac, pk, attr, m, proof)), ValueError("credential is not correct")