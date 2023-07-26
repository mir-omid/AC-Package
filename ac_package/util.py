from bplib.bp import G1Elem
from termcolor import colored
from coconut.scheme import *
from coconut.utils import *


# ==================================================
# polynomial utilities
# ==================================================


# ==================================================
# Setup parameters:
# ==================================================

## this class generates bilinear pairing BG

class GenParameters:

    def __init__(self):
        self.e = BpGroup()
        self.g1, self. g2 = self.e.gen1(), self.e.gen2()
        self.Order = self.e.order()

    # getter methods
    def get_e(self):
        return self.e

    def get_Order(self):
        return self.Order

    def get_g1(self):
        return self.g1

    def get_g2(self):
        return self.g2


def ec_sum(list):
    """ sum EC points list """
    ret = list[0]
    for i in range(1, len(list)):
        ret = ret + list[i]
    return ret

def product_GT(list_GT):
    """ pairing product equations of a list """
    ret_GT = list_GT[0]
    for i in range(1, len(list_GT)):
        ret_GT = ret_GT * (list_GT[i])
    return ret_GT

# ==================================================
# Attribute Representation:
# ==================================================
def eq_relation(message_vector, mu):
    message_representive = []
    if isinstance(message_vector[0], list):
        for message in message_vector:
             message_representive.append([message[i] * mu  for i in range(len(message))])
    elif isinstance(message_vector, list):
        message_representive = [message * mu for message in message_vector]
    else:
        print("not correct format, insert a list of group elements or a list of list")
    return message_representive

def eq_dh_relation(dh_message_vector, mu, opsilon):
    # dh_message_representive = []
    # if isinstance(dh_message_vector[0], list):
    #     for message in dh_message_vector:
    #         for i in range(len(message)):
    #             [M, N] = message[i]
    #             temp = [M * mu, N * opsilon]
    #         dh_message_representive.append(temp)
    # elif isinstance(dh_message_vector, list):
    #     dh_message_representive = [[M * mu, N * opsilon] for [M, N] in dh_message_vector]
    # else:
    #     print("not correct format, insert a list or lisf of list")
    # return dh_message_representive
    dh_message_representive = [[item[0] * (mu * opsilon), item[1] * opsilon] for item in dh_message_vector]
    return dh_message_representive


def convert_mess_to_groups(message_vector):
    """
    :param: get a vector of strings or vector of vector strings as message_vector
    :return: return a vector of group elements in G1
    """
    message_group_vector = []
    if type(message_vector[0])== str:
        message_group_vector = [BpGroup().hashG1(message.encode()) for message in message_vector]
    else:
        for message in message_vector:
            temp = [BpGroup().hashG1(message[i].encode()) for i in range(len(message))]
            message_group_vector.append(temp)

    return message_group_vector

def convert_mess_to_bn(messages):
    if type(messages)==str:
        Conver_message = Bn.from_binary(str.encode(messages))
    elif isinstance(messages, set) or isinstance(messages, list):
        try:
            Conver_message = list(map(lambda item: Bn.from_binary(str.encode(item)), messages))
        except:
            print(colored('insert all messages as string', 'green'))
    else:
        print(colored('message type is not correct', 'green'))
    return Conver_message


    # if isinstance(messages, set) or isinstance(messages, list)  == False:
    #     print(colored('message type is not correct', 'green'))
    # else:
    #     try:
    #         Conver_message = list(map(lambda item: Bn.from_binary(str.encode(item)), messages))
    #     except:
    #         print(colored('insert all messages as string', 'green'))
    # return Conver_message


def index_dh_message(m_vector, id):
    assert  m_vector is list
    h = BpGroup().hashG1(id.export())
    index_dh_message = [(m * h, m * BpGroup().gen2()) for m in m_vector]
    return index_dh_message

def tag_dh_message(pp, T_vec, m_vector):
    """
     :param tag: get a tag in G2
     :param m_vector: get a vector of strings
     :return: return a vector of tag DH messagse
    """
    (group, order, g1, g2, e, pp_pedersen) = pp
    tag_dh_message = []
    [T_1, T_2] = T_vec

    if isinstance(m_vector[0], list):
        for i in range(len(m_vector)):
            messages_Bn = convert_mess_to_bn(m_vector[i])
            for i in range(len(messages_Bn)):
                th_message  = [messages_Bn[i] * T_vec[i], messages_Bn[i] * g2]
                tag_dh_message.append(th_message)

    elif isinstance(m_vector, list):
        messages_Bn = convert_mess_to_bn(m_vector)
        tag_dh_message = [[messages_Bn[i] * T_vec[i], messages_Bn[i] * g2] for i in range(len(messages_Bn))]
    else:
        print("not correct format, insert a list or lisf of list that all elements are string")
    return tag_dh_message


    # h = BpGroup().hashG1(tag.export())
    # conver_message_to_Bn = convert_mess_to_bn(m_vector)
    # tag_dh_message = [[m * h, m * tag] for m in conver_message_to_Bn]
    # return tag_dh_message


# h = BG.hashG1(tag.export())
# if m is list():
#    return conver_message = [(m * h, m * tag) for m in m_vector]
# else:
#    return conver_message = (m * h, m * tag)


# ==================================================
# Trapdoor (pedersen) commitment
# ==================================================

def pedersen_setup(group):
   """ generate an pedersen parameters with a Trapdoor d (only used in POK) """
   g = group.gen1()
   o = group.order()
   group =group
   d = o.random()
   h = d * g
   trapdoor = d
   pp_pedersen = (group, g, o, h)
   return (pp_pedersen, trapdoor)

def pedersen_committ(pp_pedersen, m):
    """ commit/encrypts the values of a message (g^m) """
    (G, g, o, h) = pp_pedersen
    r = o.random()
    if type(m) is Bn:
        pedersen_commit = r * h + m * g
    else:
        pedersen_commit = r * h + m
    pedersen_open = (r, m)
    return (pedersen_commit, pedersen_open)

def pedersen_dec(pp_pedersen, pedersen_open, pedersen_commit):
    """ decrypts/decommit the message """
    (G, g, o, h) = pp_pedersen
    (r, m) = pedersen_open
    if type(m) == Bn:
        c2 = r * h + m * g
    else:
        c2 = r * h + m
    return c2== pedersen_commit


# ==================================================
# (hash based) commitment (Hashcommit)
# ==================================================

" not implemented yet "
def Hashcommit_setup(group):
    return None

def Hashcommit_commit(pp_pedersen, m):
    return None

def Hashcommit_dec(pp_pedersen, pedersen_open, pedersen_commit):
    return None




