from ac_package.primitives.spe_enc import SPE


theta = [("theta%s" % i).encode("utf8") for i in range(3)]
gamma = [("gamma%s" % i).encode("utf8") for i in range(3)]


def setup_module(module):
    print()
    print("__________Setup___Test SPE Encryption________")
    global spe, pp, sk_shares, pk_shares, M
    spe = SPE(2, n=5)
    (pp, sk_shares, pk_shares) = spe.setup()
    (g1, g2, order, BG, t) = pp
    gt = BG.pair(g1, g2)
    M = gt.mul(gt)

def test_enc_decrypt():
    "create aggregate pk, encryption, decryption and decryption keys"
    # create a subset of pk shares
    filter = [pk_shares[0], None, pk_shares[2]]
    # encryption key
    pk = spe.agg_keys(pp, filter)
    L = 1  # level
    # encryption
    ct = spe.enccrypt(pp, pk, M, f=theta, L=L)

    # generate decryption keys shares
    (dk_list, mk_list) = spe.share_KeyGen(pp, sk_shares=sk_shares, theta=theta, gamma=gamma)
    #key combiniation
    (dk, mk) = spe.keyGen_comb(dk_list, mk_list)

    # decryption using decryption key dk
    M_new = spe.decrypt(pp, dk, ct)
    assert M.eq(M_new), ValueError("incorrect decryption")

def test_delegtae():
    "generate a new key usgin delegation keys and test enc and decrypt for this new key"
    # create a subset of pk shares and  encryption key
    filter = [pk_shares[0], None, pk_shares[2]]
    pk = spe.agg_keys(pp, filter)
    # generate decryption keys shares
    #filter2 = [sk_shares[0], sk_shares[1]]
    (dk_list, mk_list) = spe.share_KeyGen(pp, sk_shares = sk_shares, theta=theta, gamma=gamma)

    # key combiniation
    (dk, mk) = spe.keyGen_comb(dk_list, mk_list)
    # create new key in delegate
    theta_hat = [gamma[0], gamma[2]]
    dk_new, delegate_key = spe.delegtae(dk, mk, theta_hat, gamma)

    #encryption for this new key
    theta.append(gamma[0])
    theta.append(gamma[2])
    print(theta)
    L =len(theta_hat) + 1 ## privious level was 1
    ct_new = spe.enccrypt(pp, pk, M, f= theta, L=L)
    # decryotion for this new key
    M_new = spe.decrypt(pp, dk_new, ct_new)
    assert M.eq(M_new), ValueError("incorrect decryption")

    ### add more element into the dk and check enc/dec____________________________________________________
    # theta_hat_new = [gamma[1]]
    # dk_new_new, delegate_key = spe.delegtae(dk, mk, theta_hat_new, gamma)
    # theta.append(gamma[1])
    # print(theta)
    # L = len(theta_hat) + L  ## privious level was 1
    # ct_new_new = spe.enccrypt(pp, pk, M, f=theta, L=L)
    #
    # M_new_new = spe.decrypt(pp, dk_new_new, ct_new_new)
    # assert M.eq(M_new_new), ValueError("incorrect decryption")


