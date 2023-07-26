from bplib.bp import BpGroup
from ac_package.primitives.spseq_uc import EQC_Sign


message1_str = ["age = 30", "name = Alice ", "driver license = 12"]
message2_str = ["genther = male", "componey = XX ", "driver license type = B"]
sub_mess_str = ["Insurance = 2 ", "Car type = BMW"]

def setup_module(module):
    print()
    print("__________Setup___Test SPEQ-UC Signature________")
    global sign_scheme
    global pp
    global BG
    global sk
    global vk
    global sk_u
    global pk_u
    BG = BpGroup()
    sign_scheme =EQC_Sign(BG, 5)
    pp, alpha = sign_scheme.setup()
    (sk, vk) = sign_scheme.sign_keygen(pp_sign=pp, l_message=10)
    (sk_u, pk_u) = sign_scheme.user_keygen(pp)

def test_sign():
   cred_root = sign_scheme.sign\
   (pp, pk_u, sk, messages_vector = [message1_str,message2_str])
   (sigma, commitment_vector, opening_vector) = cred_root
   assert(sign_scheme.verify(pp, vk, pk_u, commitment_vector, sigma)), ValueError("signiture is not correct")

def test_changerep():
    mu, psi = BG.order().random(), BG.order().random()
    (sigma, update_key, commitment_vector, opening_vector) = sign_scheme.sign(pp, pk_u, sk, messages_vector=[message1_str, message2_str], k_prime=4)

    (sigma_prime, rndmz_commitment_vector, rndmz_opening_vector, rndmz_pk_u, chi) = sign_scheme.change_rep(pp, vk, pk_u, commitment_vector, opening_vector, sigma, mu, psi, B=False, update_key=None)
    assert (sign_scheme.verify(pp, vk, rndmz_pk_u, rndmz_commitment_vector, sigma_prime)), ValueError("CahngeRep signiture is not correct")


def test_changerep_uk():
    mu, psi = BG.order().random(), BG.order().random()
    (sigma, update_key, commitment_vector, opening_vector) = sign_scheme.sign(pp, pk_u, sk, messages_vector=[message1_str, message2_str], k_prime=4)

    (sigma_prime, rndmz_update_key, rndmz_commitment_vector, rndmz_opening_vector, rndmz_pk_u, chi)=sign_scheme.change_rep(pp, vk, pk_u, commitment_vector, opening_vector, sigma, mu, psi, B=True, update_key=update_key)
    assert (sign_scheme.verify(pp, vk, rndmz_pk_u, rndmz_commitment_vector, sigma_prime)), ValueError("CahngeRep signiture with update key UK is not correct")


def test_changerel_from_sign():
    (sigma, update_key, commitment_vector, opening_vector) = sign_scheme.sign(pp, pk_u, sk, messages_vector=[message1_str, message2_str], k_prime=4)

    (Sigma_tilde, Commitment_L, Opening_L, Commitment_vector_new, Opening_vector_new) =sign_scheme.change_rel(pp, sub_mess_str, 3, sigma, commitment_vector, opening_vector,
                           update_key)

    assert (sign_scheme.verify(pp, vk, pk_u, Commitment_vector_new, Sigma_tilde)), ValueError("CahngeRel Signiture from Sign is not correct")


def test_changerel_from_rep():
    mu, psi = BG.order().random(), BG.order().random()

    (sigma, update_key, commitment_vector, opening_vector) = sign_scheme.sign(pp, pk_u, sk, messages_vector=[message1_str, message2_str], k_prime=4)
    (sigma_prime, rndmz_update_key, rndmz_commitment_vector, rndmz_opening_vector, rndmz_pk_u, chi) = sign_scheme.change_rep(pp, vk, pk_u, commitment_vector, opening_vector, sigma, mu, psi, B=True,
                           update_key=update_key)

    (Sigma_tilde, Commitment_L, Opening_L, Commitment_vector_new, Opening_vector_new) =sign_scheme.change_rel(pp, sub_mess_str, 3, sigma_prime, rndmz_commitment_vector, rndmz_opening_vector, rndmz_update_key, mu)
    assert(sign_scheme.verify(pp, vk, rndmz_pk_u, Commitment_vector_new, Sigma_tilde)), ValueError("CahngeRel Signiture from Rep is not correct")


def test_convert():
    (sigma, update_key, commitment_vector, opening_vector) = sign_scheme.sign(pp, pk_u, sk, messages_vector=[message1_str, message2_str], k_prime=4)
    (sk_new, PK_u_new) = sign_scheme.user_keygen(pp)

    sigma_orpha = sign_scheme.send_convert_sig(vk, sk_u, sigma)
    sigma_new = sign_scheme.receive_convert_sig(vk, sk_new, sigma_orpha)
    assert(sign_scheme.verify(pp, vk, PK_u_new, commitment_vector, sigma_new))
