from hashall import *
from hashbig import *
from tqdm import tqdm

import q2a

# return password, where toy_hash(password) = <HASH_OUTPUT_BY_GRADESCOPE>
def problem_2a():
    password:str = None
    gen = q2a.gen_str();

    for i in tqdm(range(2**48)):
        password = next(gen)
        if (toy_hash(password.encode("ascii")).hex() == "01bceba8ff08"):
            break

    print(f"2a: password = {password}")
    return password

# return password, where toy_hash(password) is in hashes.txt
def problem_2c():
    password:str = None
    # Assume the hint about q2a applies here:
    # password is a string over [a-z]
    gen = q2a.gen_str();

    with open("hashes.txt") as file:
        hash_strings = set(line.strip() for line in file)
        
        for i in tqdm(range(2**48)):
            password = next(gen)
            if (toy_hash(password.encode("ascii")).hex() in hash_strings):
                break;

    print(f"2c: password = {password}")
    return password

# return probability of being in bin k
def problem_3a(B, N):
    prob = 1/N
    return prob

# return probability of both balls being in bin k
def problem_3b(B,N):
    prob = 1/N**2
    return prob

# return number of ball pairs
def problem_3c(B):
    prob = B*(B-1) / 2
    return prob

# return reasonable upper bound
def problem_3d(B,N):
    # An upper bound is the sum of all probabilities
    # that two balls falls into a specific bin.
    # Note that it can't be larger than 1.
    prob = min(problem_3c(B)*N*problem_3b(B,N), 1)
    return prob
    
# return reasonable upper bound
def problem_3e(L,N):
    # It's little confusing for the lab to say that
    # for _each_ x, H(x) is independent and uniformly chosen.
    # What it means is that the values of H look like independent
    # and uniformly distributed.

    # Note that the size of {0,1}^N = 2^N.
    prob = problem_3d(L,2**N)
    return prob

# return h1,h2 where H(h1) == H(h2)
def problem_4b():
    h1 = None
    h2 = None
    return h1,h2


# Tests
if __name__ == "__main__":
    problem_2c()
