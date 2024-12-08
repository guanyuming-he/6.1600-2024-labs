from hashall import *
from hashbig import *

# return password, where toy_hash(password) = <HASH_OUTPUT_BY_GRADESCOPE>
def problem_2a():
    # First, this can generate a-z strings fast
    # 26^9 > 2^40 
    # but for handling collisions, 
    # I will make it one item longer
    powers = [ int(26**n) for n in range(11) ]
    letters = "abcdefghijklmnopqrstuvwxyz"
    # assert here in case I miss a letter!
    assert len(letters) == 26

    def gen_string(istr: int):
        """
        The hint says that the password will
        be a string of a-z.
        There are 26 letters. And the string
        can be seen as a 26-base number,
        a_0 * 26^0 + a_1 * 26^1 + ...

        This function finds the array {a_n}
        and returns
        { letter[a_n] }, where letter[i] gives the 
        letter at i.
        """
        # find the largest i for which 26^i <= istr
        i = len(powers) - 1
        while powers[i] > istr:
            i = i-1 

        # result string
        # in python strings are immutable,
        # so I have to join all characters
        # together, which is slow.
        ret = ''
        # the remainder
        r = istr
        # now we have the i, iterate to 0
        while i >= 0:
            # a_i 
            ai = r // power[i]
            r = r - ai*power[i]
            ret = ret + letters[ai]
            # don't forget this
            i -= 1 

        return ret

    password = None
    return password

# return password, where toy_hash(password) is in hashes.txt
def problem_2c():
    password = None
    return password

# return probability of being in bin k
def problem_3a(B, N):
    prob = None
    return prob

# return probability of both balls being in bin k
def problem_3b(B,N):
    prob = None
    return prob

# return number of ball pairs
def problem_3c(B):
    prob = None
    return prob

# return reasonable upper bound
def problem_3d(B,N):
    prob = None
    return prob
    
# return reasonable upper bound
def problem_3e(L,N):
    prob = None
    return prob

# return h1,h2 where H(h1) == H(h2)
def problem_4b():
    h1 = None
    h2 = None
    return h1,h2



