"""
The hint says that the password will
be a string of a-z.

It is a hidden assumption that the max length of the strings will be small,
given that the lab is confident we can run it under 5 mins.

Formally, the strings form the set \Sigma^n, i.e., all strings of length <=
n from the alphabet \Sigma := [a-z].

The first idea of mine is to treat each as a 26-base number,
a_0 * 26^0 + a_1 * 26^1 + ...,
then we can get everything of the form
[b-z]*[a-z]. (Except the last digit, all previous ones cannot be a, because
a acts like zero). But getting those that start will all a's is a problem.

The second idea is to perform a walk on the tree
                              (root)
                                 |
          -------------------------------------------------
         |         |         |         ...         |       |
         a         b         c                   ...       z
         |                                             |
  ------------------                             ------------------
 |    |    |    ...  |                           |    |    |   ...  |
 aa  ab   ac        az                          za   zb   zc       zz

This is pretty good, if we are using an iterative algorithm to walk the
tree. Of course, one doesn't want to iterative from the beginning every time
we ask for the next string, so it's better to write the generation routines
in a generator, which Python has native support.
"""

letters = "abcdefghijklmnopqrstuvwxyz"
# assert here in case I miss a letter!
assert len(letters) == 26

from collections import deque

def gen_str():
    # a list can act as a queue.
    # use list.pop(0) to dequeue
    # and list.append() to enqueue.

    queue = deque();
    queue.append('')

    # produce strings indefinitely
    # the loop is like a breadth-first walk on the tree.
    while (True):
        base = queue.popleft()
        for l in letters:
            next_str:str = str(base+l)
            yield next_str
            queue.append(next_str)
