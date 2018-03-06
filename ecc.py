# -*- coding: utf-8 -*-
"""
Created on Sat Nov  4 22:15:23 2017

@author: prateek
"""

import collections
import random
import sys

def inv(n, q):
    """div on PN modulo a/b mod q as a * inv(b, q) mod q
    >>> assert n * inv(n, q) % q == 1
    """
    for i in range(q):
        if (n * i) % q == 1:
            return i
        pass
    assert False, "unreached"
    pass


def sqrt(n, q):
    """sqrt on PN modulo: returns two numbers or exception if not exist
    >>> assert (sqrt(n, q)[0] ** 2) % q == n
    >>> assert (sqrt(n, q)[1] ** 2) % q == n
    """
    assert n < q
    for i in range(1, q):
        if i * i % q == n:
            return (i, q - i)
        pass
    raise Exception("not found")


Coord = collections.namedtuple("Coord", ["x", "y"])


class EC(object):
    """System of Elliptic Curve"""
    def __init__(self, a, b, q):
        """elliptic curve as: (y**2 = x**3 + a * x + b) mod q
        - a, b: params of curve formula
        - q: prime number
        """
        assert 0 < a and a < q and 0 < b and b < q and q > 2
        assert (4 * (a ** 3) + 27 * (b ** 2))  % q != 0
        self.a = a
        self.b = b
        self.q = q
        # just as unique ZERO value representation for "add": (not on curve)
        self.zero = Coord(0, 0)
        pass

    def is_valid(self, p):
        if p == self.zero: return True
        l = (p.y ** 2) % self.q
        r = ((p.x ** 3) + self.a * p.x + self.b) % self.q
        return l == r

    def at(self, x):
        """find points on curve at x
        - x: int < q
        - returns: ((x, y), (x,-y)) or not found exception
        >>> a, ma = ec.at(x)
        >>> assert a.x == ma.x and a.x == x
        >>> assert a.x == ma.x and a.x == x
        >>> assert ec.neg(a) == ma
        >>> assert ec.is_valid(a) and ec.is_valid(ma)
        """
        assert x < self.q
        ysq = (x ** 3 + self.a * x + self.b) % self.q
        y, my = sqrt(ysq, self.q)
        return Coord(x, y), Coord(x, my)

    def neg(self, p):
        """negate p
        >>> assert ec.is_valid(ec.neg(p))
        """
        return Coord(p.x, -p.y % self.q)

    def add(self, p1, p2):
        """<add> of elliptic curve: negate of 3rd cross point of (p1,p2) line
        >>> d = ec.add(a, b)
        >>> assert ec.is_valid(d)
        >>> assert ec.add(d, ec.neg(b)) == a
        >>> assert ec.add(a, ec.neg(a)) == ec.zero
        >>> assert ec.add(a, b) == ec.add(b, a)
        >>> assert ec.add(a, ec.add(b, c)) == ec.add(ec.add(a, b), c)
        """
        if p1 == self.zero: return p2
        if p2 == self.zero: return p1
        if p1.x == p2.x and (p1.y != p2.y or p1.y == 0):
            # p1 + -p1 == 0
            return self.zero
        if p1.x == p2.x:
            # p1 + p1: use tangent line of p1 as (p1,p1) line
            l = (3 * p1.x * p1.x + self.a) * inv(2 * p1.y, self.q) % self.q
            pass
        else:
            l = (p2.y - p1.y) * inv(p2.x - p1.x, self.q) % self.q
            pass
        x = (l * l - p1.x - p2.x) % self.q
        y = (l * (p1.x - x) - p1.y) % self.q
        return Coord(x, y)

    def mul(self, p, n):
        """n times <mul> of elliptic curve
        >>> m = ec.mul(p, n)
        >>> assert ec.is_valid(m)
        >>> assert ec.mul(p, 0) == ec.zero
        """
        r = self.zero
        m2 = p
        # O(log2(n)) add
        while 0 < n:
            if n & 1 == 1:
                r = self.add(r, m2)
                pass
            n, m2 = n >> 1, self.add(m2, m2)
            pass
        # [ref] O(n) add
        #for i in range(n):
        #    r = self.add(r, p)
        #    pass
        return r
        
    '''def encryption(a,k1,bpub,g):
      a=2
      k=max(k1.x,k1.y)
      for i in range(1,k):
          x=a*k+i
          y_pos,y_neg=ec.at(x)
          if(isinstance(x,y_pos)):
              y=y_pos
              break
      x_cord=ec.mul(g,k)
      y_cord=ec.add((x,y),ec.mul(bpub,k))
      print("%d",x_cord)
      print("%d",y_cord)'''
          
          
    def order(self, g):
        """order of point g
        >>> o = ec.order(g)
        >>> assert ec.is_valid(a) and ec.mul(a, o) == ec.zero
        >>> assert o <= ec.q
        """
        assert self.is_valid(g) and g != self.zero
        for i in range(1, self.q + 1):
            if self.mul(g, i) == self.zero:
                return i
            pass
        raise Exception("Invalid order")
    pass

class ElGamal(object):
    """ElGamal Encryption
    pub key encryption as replacing (mulmod, powmod) to (ec.add, ec.mul)
    - ec: elliptic curve
    - g: (random) a point on ec
    """
    def __init__(self, ec, g):
        assert ec.is_valid(g)
        self.ec = ec
        self.g = g
        self.n = ec.order(g)
        pass

    def gen(self, priv):
        """generate pub key
        - priv: priv key as (random) int < ec.q
        - returns: pub key as points on ec
        """
        return self.ec.mul(g, priv)

    def enc(self, plain, pub, r):
        """encrypt
        - plain: data as a point on ec
        - pub: pub key as points on ec
        - r: randam int < ec.q
        - returns: (cipher1, ciper2) as points on ec
        """
        assert self.ec.is_valid(plain)
        assert self.ec.is_valid(pub)
        return (self.ec.mul(g, r), self.ec.add(plain, self.ec.mul(pub, r)))

    def dec(self, cipher, priv):
        """decrypt
        - chiper: (chiper1, chiper2) as points on ec
        - priv: private key as int < ec.q
        - returns: plain as a point on ec
        """
        c1, c2 = cipher
        assert self.ec.is_valid(c1) and ec.is_valid(c2)
        return self.ec.add(c2, self.ec.neg(self.ec.mul(c1, priv)))
    pass


class DiffieHellman(object):
    """Elliptic Curve Diffie Hellman (Key Agreement)
    - ec: elliptic curve
    - g: a point on ec
    """
    def __init__(self, ec, g):
        self.ec = ec
        self.g = g
        self.n = ec.order(g)
        pass

    def gen(self, priv):
        """generate pub key"""
        assert 0 < priv and priv < self.n
        return self.ec.mul(self.g, priv)

    def secret(self, priv, pub):
        """calc shared secret key for the pair
        - priv: my private key as int
        - pub: partner pub key as a point on ec
        - returns: shared secret as a point on ec
        """
        assert self.ec.is_valid(pub)
        assert self.ec.mul(pub, self.n) == self.ec.zero
        return self.ec.mul(pub, priv)
    pass


class DSA(object):
    """ECDSA
    - ec: elliptic curve
    - g: a point on ec
    """
    def __init__(self, ec, g):
        self.ec = ec
        self.g = g
        self.n = ec.order(g)
        pass

    def gen(self, priv):
        """generate pub key"""
        assert 0 < priv and priv < self.n
        return self.ec.mul(self.g, priv)

    def sign(self, hashval, priv, r):
        """generate signature
        - hashval: hash value of message as int
        - priv: priv key as int
        - r: random int 
        - returns: signature as (int, int)
        """
        assert 0 < r and r < self.n
        m = self.ec.mul(self.g, r)
        return (m.x, inv(r, self.n) * (hashval + m.x * priv) % self.n)

    def validate(self, hashval, sig, pub):
        """validate signature
        - hashval: hash value of message as int
        - sig: signature as (int, int)
        - pub: pub key as a point on ec
        """
        assert self.ec.is_valid(pub)
        assert self.ec.mul(pub, self.n) == self.ec.zero
        w = inv(sig[1], self.n)
        u1, u2 = hashval * w % self.n, sig[0] * w % self.n
        p = self.ec.add(self.ec.mul(self.g, u1), self.ec.mul(pub, u2))
        return p.x % self.n == sig[0]
    pass


if __name__ == "__main__":
    # shared elliptic curve system of examples
    ec = EC(1, 18,199)
    g, _ = ec.at(7)
    assert ec.order(g) <= ec.q
    
    # ElGamal enc/dec usage
    eg = ElGamal(ec, g)
    # mapping value to ec point
    # "masking": value k to point ec.mul(g, k)
    #("imbedding" on proper n:use a point of x as 0 <= n*v <= x < n*(v+1) < q)
    

    
    #print("len of mapping is",len(mapping))
    
    
    '''for x in range(0,len(message)):
        plain = mapping[ord(message[x])]
        #print(pub)
        #print(plain)
        cipher = eg.enc(plain, pub, 15)
        li_cipher.append(cipher)
   # print("li_cipher is",li_cipher,len(li_cipher))    
    for x in range(0,len(li_cipher)):
        decoded = eg.dec(li_cipher[x], priv)
        li_plain.append(decoded)
    print("li_plain is ",li_plain)    
    for x in range(0,len(li_plain)):
        conver=li_plain[x]
        index=-1
        for j in mapping:
            index=index+1
            if(j.x==conver.x and j.y==conver.y):
                break 
        print(chr(index))'''
    '''mess=(decoded.x-1)/eg.n
    print(mess)'''
    
    
    
    # ECDH usage
    #print("here using diffie hellman")    
    
    dh = DiffieHellman(ec, g)
    
    apriv = random.randint(1,ec.order(g))
    #print("A private key is %d\n",apriv)
    apub = dh.gen(apriv)
    
    #print("A generated public key is %d\n",apub)
    
    bpriv = random.randint(1,ec.order(g))
    #print("B private key is %d\n",bpriv)
    bpub = dh.gen(bpriv)
    
    #print("B public key is %d\n",bpub)
    
   # cpriv = 7
    #cpub = dh.gen(cpriv)
    # same secret on each pair
    k1=dh.secret(apriv, bpub)
    #print("A generated secret key is %d", k1)
    
    
    k2=dh.secret(bpriv, apub)
    #print("B genereted secret key is %d",k2)
    
    #ec.encryption(k1,bpub,g)
    
   # assert dh.secret(apriv, cpub) == dh.secret(cpriv, apub)
    #assert dh.secret(bpriv, cpub) == dh.secret(cpriv, bpub)
    
    # not same secret on other pair
    #assert dh.secret(apriv, cpub) != dh.secret(apriv, bpub)
    #assert dh.secret(bpriv, apub) != dh.secret(bpriv, cpub)
    #assert dh.secret(cpriv, bpub) != dh.secret(cpriv, apub)
    
    
    # ECDSA usage
    #plain_text='a';
    
   # x=ord(plain_text)
    
    '''a=2
    k=max(k1.x,k1.y)
    for i in range(1,k):
          x=a*k+i
          y_pos=((x ** 3) + x +18)**1/2
          if(isinstance(y_pos,int)):
              j=i
              y=y_pos%19
              break
    print("value of x is  and y is ",x,y) 
    x_cord=ec.mul(g,k)
    mul=ec.mul(bpub,k)
    X=Coord(x,y)
    y_cord=ec.add(X,mul)
    print("value of x part of cipher is and value of y part of cipher is \n",x_cord,y_cord)
    
    
    #print("%d\n",mul)oord
    
    mul_dec=ec.mul(x_cord,bpriv)
    p1=-mul_dec.y
    p=Coord(mul_dec.x,p1)
    add_dec=ec.add(y_cord,p)
    print("value at decryption is",add_dec.x,add_dec.y)
    mess=(final_x-1)/k
    print(mess)
    
    
    dsa = DSA(ec, g)
    
    priv = 11
    pub = eg.gen(priv)
    hashval = 128
    r = 7
    
    sig = dsa.sign(hashval, priv, r)
    assert dsa.validate(hashval, sig, pub)'''
pass 
mapping= [ec.mul(g, i) for i in range(eg.n)]
li_cipher=list()
priv = random.randint(1,ec.order(g))
pub = eg.gen(priv)
li_plain=list()
class Enc_dec:
   def _init_(self):
       self=None
   
   def enc(self,message):
        global mapping 
        global li_cipher
        #li_cipher=list()
        global priv
        global pub
        
        for x in range(0,len(message)):
               plain =mapping[ord(message[x])]
               cipher = eg.enc(plain, pub, 15)
               li_cipher.append(cipher)
        ciph = li_cipher
        return ciph
         
   def dec(self,li_cipher):
        #global li_cipher

        global mapping
        plain_rev =list()
        global li_plain
        global priv
        for x in range(0,len(li_cipher)):
               decoded = eg.dec(li_cipher[x], priv)
               li_plain.append(decoded)

        for x in range(0,len(li_plain)):
               conver=li_plain[x]
               index=-1
               for j in mapping:
                     index=index+1
                     if(j.x==conver.x and j.y==conver.y):
                          break 
               #print(chr(index))
               plain_rev.append(chr(index))
        return plain_rev
               
t=Enc_dec()  
message="sssdvdlvisj"     
cipher=t.enc(message)
plain_re=t.dec(cipher)

print '\n\n'
print cipher
print '\n\n'
#print ''.join(plain_re)
        
        
    
        
