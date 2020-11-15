import random
import struct

#fnction for finding gcd of two numbers using euclidean algorithm
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

#uses extened euclidean algorithm to get the d value
#for more info look here: https://crypto.stackexchange.com/questions/5889/calculating-rsa-private-exponent-when-given-public-exponent-and-the-modulus-fact
# will also be explained in class

def get_d(e,z):
	x=0
	y=1
	lx=1
	ly=0
	oe=e
	oz=z

	while z != 0:
		q=e//z
		(e, z)=(z, e%z)
		(x, lx)=((lx - (q*x)), x)
		(y, ly)=((ly - (q*y)), y)

		if lx<0:
			lx +=oz
		if ly<0:
			ly +=oe
	return lx

def is_prime (num):
    if num > 1:

        # Iterate from 2 to n / 2 
       for i in range(2, num//2):

           # If num is divisible by any number between 
           # 2 and n / 2, it is not prime 
           if (num % i) == 0:
               return False
               break
           else:
               return True
    else:
        return False


def generate_keypair(p, q):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError('Both numbers must be prime.')
    elif p == q:
        raise ValueError('p and q cannot be equal')
    ###################################your code goes here#####################################
    n = p*q
    z = (p-1)*(q-1)

    for i in range(2,n):
      if(gcd(i,z) == 1):
        e = i
        break
    d=get_d(e, z)
    return ((e, n), (d, n))


def encrypt(pk, plaintext):
    cipher = pow(plaintext, pk[0],pk[1])
    return cipher


def decrypt(pk, ciphertext):
    plainBytes = pow(ciphertext,pk[0],pk[1])
    return struct.pack("B",plainBytes)
