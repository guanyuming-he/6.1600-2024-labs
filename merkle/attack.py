from common import H, H_empty, H_kv, H_internal, traversal_path, Proof

class AttackOne:
    """
    Well, first we need to understand how to trick the client into thinking what
    we give was right.

    The client stores a root_hash, which equals the hash of the root after the
    insertion.

    It would be a sequence of hashing of node+sibling, starting from H_kv().
    The order of node+sibling is decided by the key's hash.

    Second, we need to understand what we can do to alter the information.
    First, the client will use which ever key we give it, which will be
    different from the real key for the attack to be meaningful. Thus, the order
    of node+sibling at each level is altered. Fortunately, for a tree of only 1
    insertion, the silbings are all empty anyway, so it doesn't really matter.

    What we need to do here, is for the H_kv() to have the same value for a
    different key, which is easily solved by letting the new key be have less or
    more characters in the key+val concat.
    """
    def __init__(self, s):
        self._store = s

    def attack_fake_key(self):
        return b"hell"

    def lookup(self, key):
        proof = self._store.lookup(b"hello")
        proof.key = b"hell"
        proof.val = b"oworld"
        return proof

class AttackTwo:
    """
    This scenario is immediately more difficult, since the more than 1000 keys
    and len(concat) < 100 forbids us to just simply manipulate the concat point.

    However, note another vulnerability in Client: when validating, it uses
    proof.key and proof.val, which we can manipulate. And it does not check if
    proof.key = path_key.

    However again, after the client validates the root hash, it does check if
    the key of the proof equals the key passed in.

    As such, we need to forge a proof with the same key, such that the resulted
    hash value of the proof equals the previous root hash.

    It seems pretty impossible, as the different concats are restrained, and
    SHA256 is strong collision resistant.

    However, note that c.insert(k,v) happens after a = attack.AttackTwo(s).
    It means we can already do something to an empty store before the client
    inserts (k, v). Of course, we can't just insert them before c.insert(k,v),
    because the client maintains the root_hash INDEPENDENTLY of the remote
    store. However, just simply let the attack returns an empty proof before
    lookup is called will do the trick, I suppose. 

    More generally, another vulnerability that I overlooked is that, so long as
    the client sees the proof matches the previous root_hash, it will calculate
    the new root_hash from the proof, which we can control quite arbitrarily.

    To conclude, what we can do are
    1. For the first insert, returns a proof that results in the empty hash,
    but is different from an empty tree, such that, after the insertion, the
    recomputed root hash from the proof is different from the one that would be
    resulted from an empty tree with the insertion. It seems pretty unclear how
    I can do that, as H_empty = b'' which is not in the range of SHA256. So it
    can only result from a proof of (None, None, []) 

    2. For the subsequent lookups, return a proof that results in the previous
    root_hash, but with a different key. If 1 cannot be done, then what I can do
    is like, choose any hash from len(k+v) <= 100, and then give a proof such
    that proof.key != k and root_hash(proof) = chosen hash. Of course, it is
    different than finding a collision in SHA256, as root_hash(proof) can be a
    result of multiple SHA256 hashes.

    Mathematically, it is like, choose both x := ck||cv (chosen k,v) and
    sequence (y_i)_{i=1}^n, such that H(x) = G_n, where G_1 := H(y_1), G_{i+1}
    := H(G_i||y_{i+1}).

    It is quite different from collision finding, and is actually easily doable.
    We can choose those (y_i)_{i=1}^n first, and then simply let 
    x := G_{n-1}||y_n when n>2 and x := G_1 when n = 2.
    However, what we need is 1000 such sequences (y_i) each of which's y_1 is a
    ak||av (attack k,v) and len(y_1) <= 100.

    Well, although x can't be a concatenation of more than 100 characters, x
    could be the hash from a concatenation of more than 100 characters. 
    That is, x = H(k||v) where k,v can have more than 1000 combinations.
    Thus, we let
    n = 2, 
    y_1 = k||v, y_2 = b'',
    and x = G_1 = H(y_1)
    """
    def __init__(self, s):
        self._store = s
        # just let x = H(k||v) where k||v always equal to 1024 of b'1'.
        # x is a 256/8 = 32 bytes b-string, < 100.
        self._pre_x = b'1' * 1024
        self._x = H(self._pre_x)

    def attack_fake_keys(self) -> set:
        return set([
            self._pre_x[:i] for i in range(1, 1001)
        ])

    def attack_key_value(self):
        # just split x in any way.
        return self._x[:16], self._x[16:]

    def lookup(self, key):
        # [y_2] 
        siblings = [H_empty()]
        return Proof(
            # y_1
            key, self._pre_x[len(key):],
            siblings
        )

class AttackThree:
    """
    Guany:
    With the limits, we are required to give a proof p such that
    p.key = p.val = None, and
    H(p.sibling) = root_hash after 1000 key insertions.

    It is not very hard, as we can just query the store to get a proof,
    and compute the preimage of the root hash from it.
    """
    def __init__(self, s):
        self._store = s

    def lookup(self, key):
        true_proof = self._store.lookup(key)
        # Compute the preimage of the root hash.
        h_node = \
            H_kv(true_proof.key, true_proof.val) \
            if true_proof.key is not None or true_proof.val is not None \
            else H_empty()

        path = traversal_path(true_proof.key)
        # It cannot be empty as we have 1000 keys.
        max_len = min(len(path), len(true_proof.siblings))
        traverse = reversed(list(zip(path, true_proof.siblings)))
        preimg: str = None
        i: int = 0;
        # Compute the hash until we are about to reach the root.
        for (leaf_dir, sib) in traverse:
            c = [None, None]
            c[int(leaf_dir)]        = h_node
            c[int(not leaf_dir)]    = sib
            if (i < max_len-1):
                h_node = H_internal(c)
            else:
                # Don't calcualate the hash
                preimg = b''.join(c)
            i += 1

        return Proof(None, None, [preimg])
        

class AttackFour:
    def __init__(self, s):
        self._store = s

    def insert(self, key, val):
        return self._store.insert(key, val)

    def attack_fake_key(self):
        return b''

    def lookup(self, key):
        return self._store.lookup(key)
