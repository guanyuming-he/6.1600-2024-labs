import time
import hashlib
from ecdsa import SigningKey, NIST256p

from datetime import datetime

def problem_1a(date_string, public_key):
    """
    Guany:
    %d turns float into int, forcing the precision to be at most 1 second.
    So I just have to try all seconds of a day.

    First, I have to find out how many seconds have passed since the epoch as a
    base. Then, add seconds to it until 24*3600.
    """
    date = datetime.strptime(date_string, "%Y-%m-%d")
    epoch = datetime(1970, 1, 1)
    base:int = (date-epoch).days * 24*3600

    for i in range(base, base+24*3600):
        b = b'%d' % i 
        h = hashlib.sha256(b).digest()
        secexp = int.from_bytes(h, "big")

        sk = SigningKey.from_secret_exponent(
            secexp,curve=NIST256p
        )
        if sk.verifying_key == public_key:
            return sk
    

def problem_2b(sig1, sig2, Hm1, Hm2):
    pass
