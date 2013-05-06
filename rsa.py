import random, unittest, itertools, math, argparse, os
from time import clock

def kapow(base,expo,m):
	"""calculates base^expo (mod m) given the arguments are integers, expo >= 0, m>1"""
	assert(set([type(base),type(expo),type(m)]).issubset(set([int,long])))
	assert(expo >= 0)
	assert(m > 0)
	if m == 1:
		return 0
	acc = 1
	while expo != 0:
		if expo % 2 == 1:
			acc = acc * base % m
		base = base * base % m
		expo //= 2
	return acc

def km(n):
	"""returns (k,m) that satisfies n-1 == 2^k * m"""
	k = 0
	m = n-1
	q,r = divmod(m,2)
	while r == 0:
		k += 1
		m = q
		q,r = divmod(m,2)
	return k,m

def miller_rabin_repeated(n,maxtries):
	"""PRE: m%2 == 0
	Runs the Miller-Rabin primality test at most [maxtries]
	times on an odd [n] and if MR deems n to be composite
	returns False, otherwise True"""
	k,m = km(n) # n-1 == 2^k + m where m is odd

	for c in xrange(maxtries):
		maybe_prime = False
		b = kapow(random.randint(1,n-1),m,n)
		if b == 1:
			# maybe prime
			continue
		for i in xrange(k): # i = 1..k-1
			if b == n-1: # n -1 = -1 mod n
				# maybe prime
				maybe_prime = True
				break
			b = kapow(b,2,n)
		if maybe_prime:
			continue
		else:
			return False
	return True

def probably_prime(n): return miller_rabin_repeated(n,100)

def gen_prime(least, most, max_tries = 10000):
	"""Returns (p,g) where
	p is prime
	least <= p <= most and
	g is the number of guesses it took to find p in [least,most].
	Raises an exception if max_tries are exceded"""
	tries = 0
	while tries < max_tries:
		n = random.randrange(least + (1 - (least%2)),most,2)
		tries += 1
		if probably_prime(n):
			return (n,tries)
	raise Exception("maxtries exceeded")
	
def ext_euclid(a,b):
	"""Returns (ax+by,x,y) s.th gcd(a,b) = ax+by"""
	a1,a2 = 1,0
	b1,b2 = 0,1
	while b != 0:
		q, r = divmod(a,b)
		a,b = b,r
		a1,a2,b1,b2 = b1,b2,a1-q*b1,a2-q*b2
	return a,a1,a2

def gen_de(phi, n, max_tries = 10000):
	"""Returns (d,e, tries) such that de%phi == 1 by guessing 
	e at most max_tries times(tries is the needed number of guesses."""
	tries = 0
	while tries < max_tries:
		e = random.randrange(math.ceil(math.log(n,2)),phi,2)
		tries += 1
		n, x, y = ext_euclid(e,phi)
		if n == 1:
			d = x%phi # the mod op might be superfluous
			return d,e,tries
	raise Exception("maximum tries exceeded")


def encrypt(message, e, n):
	"""encrypts message with the public key e in Z_n a la RSA"""
	return kapow(message,e,n)

def decrypt(ciphertext, d, n):
	"""decrypts message with the private key d in Z_n a la RSA"""
	return kapow(ciphertext, d, n)
	
def decode_string(num):
	"""Turns an integer from base 256 into a string of characters where each position represents the decimal number of the characters ASCII number"""
	str = []
	while num > 0:
		q,r = divmod(num,256)
		str.append(chr(r))
		num = q
	return ''.join(str)
	
def encode_string(str):
	"""Turns a multicharacter string into a numerical representation in base 256 where each character is represented in a decimal form (ASCII)"""
	acc = 0
	for s in str[::-1]:
		acc = acc * 256 + ord(s)
	return acc
	
def encrypt_text(text, l, e, n):
	"""Encrypts a string by splitting it into chunks of [l] characters and encrypting it with the public key consisting of [e] and [n] The first chunk is a special header, an integer indicating the number of zeros that the plaintext was padded with."""
	numzeros = (l - (len(text) % l)) % l
	text += numzeros * '0'
	chunks = len(text) / l
	cipher = [str(encrypt(numzeros,e,n))]
	for i in range(chunks):
		cipher.append(str(encrypt(encode_string(text[l*i:l*i+l]),e,n)))
	return cipher
		
def decrypt_text(cipher, l, d, n):
	"""Decrypts a list of encrypted chunks (representing [l] characters) using the private key consisting of [d] and [n]. The first chunk is a special header, an integer indicating the number of zeros that the plaintext was padded with."""
	plain = []
	numzeros = decrypt(int(cipher[0]),d,n)
	for c in cipher[1:]:
		plain.append(decode_string(decrypt(int(c),d,n)))
	plaintext = ''.join(plain)
	return plaintext[0:len(plaintext)-numzeros]

def main():
	# example for help text
	prog = os.path.basename(__file__)
	examples = "examples:\n\n"
	examples+= "  generate keys:\n"
	examples+= "  " + prog + " -g priv.key pub.key\n\n"
	examples+= "  encrypt the file plain.txt:\n"
	examples+= "  " + prog + " -e plain.txt pub.key cipher.txt\n\n"
	examples+= "  decrypt the file cipher.txt:\n"
	examples+= "  " + prog + " -d cipher.txt priv.key plain.txt"

	# setup command line arguments
	parser = argparse.ArgumentParser(
		description='Generation of keys and encryption/decryption using the RSA algorithm.',
		usage='%(prog)s ',
		formatter_class=argparse.RawDescriptionHelpFormatter,
		epilog=examples)
	parser.add_argument('-g', help="Generate keys and store them in the files PRIV and PUB.", dest="generate", nargs=2, metavar=('PRIV','PUB'), type=argparse.FileType('w'))
	parser.add_argument('-e', help="Encrypt the file PLAIN using the key PRIV and save to CIPHER.", dest="encrypt", nargs=3, metavar=('PLAIN','PUB', 'CIPHER'), type=argparse.FileType('a+'))
	parser.add_argument('-d', help="Decrypt the file CIPHER using the key PUB and save to PLAIN.", dest="decrypt", nargs=3, metavar=('CIPHER','PRIV', 'CIPHER'), type=argparse.FileType('a+'))
	parser.add_argument('-l', help="The chunksize in number of characters (only used for encryption/decryption)", type=int, default=2)
	parser.add_argument('-t', help="Run tests and collect statistics in the file STATS.", dest="test", metavar=('STATS'), type=argparse.FileType('w+'))
	args = parser.parse_args()
	
	# check exclusivity of arguments
	n = (1 if args.generate else 0) + (1 if args.decrypt else 0) + (1 if args.encrypt else 0) + (1 if args.test else 0)
	if n != 1:
		print("error: it's either -g or -d or -e or -t\nerror: you need to specify exactly one of them.")
		exit(1)
		
	# generate a public/private key pair and save to files
	if args.generate:
		privfile = args.generate[0]
		pubfile = args.generate[1]
	
		least, most = 2**255, 2**256
		((p,t1),(q,t2)) = [gen_prime(least,most) for i in range(2)]
		n = p * q
		phi = (p-1)*(q-1)
		d,e,t3 = gen_de(phi,n)
		
		print "n:",n.bit_length()
		assert(n.bit_length() < 513)
		
		assert(d*e%phi == 1)
		
		content = "\n".join(map(str,[n,e]))
		pubfile.write(content)
		pubfile.close()
		
		content = "\n".join(map(str,[n,d,p,q]))
		privfile.write(content)
		privfile.close()
		
		print("keys have been successfully generated")
		
	# decrypt a cipher text using a private key from a file
	elif args.decrypt:
		cipherfile = args.decrypt[0]
		keyfile = args.decrypt[1]
		plainfile = args.decrypt[2]
		
		keyfile.seek(0)
		content = keyfile.read().split()
		if len(content) < 2:
			print("error: invalid key file")
			exit(1)
		keyfile.close()
			
		n = int(content[0])
		d = int(content[1])
		#p = int(content[2])
		#q = int(content[3])
		l = args.l
		
		cipherfile.seek(0)
		cipher = cipherfile.read().split("\n")
		plain = decrypt_text(cipher,l,d,n)
		plainfile.write(plain)
		
		print("cipehrtext has been successfully decrypted")
		plainfile.close()
		cipherfile.close()
		
	# encrypt a plain text using a public key from a file
	elif args.encrypt:
		plainfile = args.encrypt[0]
		keyfile = args.encrypt[1]
		cipherfile = args.encrypt[2]
		
		keyfile.seek(0)
		content = keyfile.read().split()
		if len(content) != 2:
			print("error: invalid key file")
			exit(1)
		keyfile.close()
			
		n = int(content[0])
		e = int(content[1])
		l = args.l
		
		plainfile.seek(0)
		plain = plainfile.read()
		cipher = encrypt_text(plain,l,e,n)
		cipherfile.write("\n".join(cipher))
		
		print("plaintext has been successfully encrypted")
		plainfile.close()
		cipherfile.close()
		
	# run tests and collect statistics
	elif args.test:
		l_range = [1,2,3,8,16,32,128]
		text_range = [1,2,3,4]
		pq_range = [8,16,32,64,512]
		de_range = [8,16,32,64,512]
		
		statsfile = args.test
		
		statsfile.write("   pq |  text |   l | generation time (ms) | encryption time (ms) | decryption time (ms)\n")
		
		proc = 0
		proc_step = 100.0 / (len(pq_range) * len(text_range) * len(l_range))
		
		for pq in pq_range:
				
			least, most = 2**(pq-1), 2**pq
			gen_start = clock()
			((p,t1),(q,t2)) = [gen_prime(least,most) for i in range(2)]
			gen_time = clock() - gen_start
			n = p * q
			phi = (p-1)*(q-1)
			d,e,t3 = gen_de(phi,n)
			
			assert(d*e%phi == 1)
			if d*e%phi != 1:
				print("d*e % phi != 1")
				continue
			statsfile.write(" =====+=======+=====+======================+======================+=====================\n")
		
			for text in text_range:
				fname = "plain_"+str(text)+".txt"
				pfile = open(fname, "r")
				plain = pfile.read()
				pfile.close()
				tlen = len(plain)
				
				if text != 1:
					statsfile.write(" -----+-------+-----+----------------------+----------------------+---------------------\n")
				
				for l in l_range:
					print("completed " + str(round(proc,2)) + "%")
					proc += proc_step
					enc_start = clock()
					cipher = encrypt_text(plain,l,e,n)
					enc_time = clock() - enc_start
					
					dec_start = clock()
					plainX = decrypt_text(cipher,l,d,n)
					dec_time = clock() - dec_start
					
					t_g = round(gen_time * 1000,0)
					e_g = round(enc_time * 1000,0)
					d_g = round(dec_time * 1000,0)
					statsfile.write("%5s | %5s | %3s | %20i | %20i | %20i\n" % (pq, tlen, l, t_g, e_g, d_g))
		
		print("testing completed running")
		statsfile.close()
	
if __name__ == '__main__':
	main()
