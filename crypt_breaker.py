from threading import Thread 
import optparse
import crypt 

''' Bruteforce crypt hash with salt '''
def with_salt(filename, password):
	''' First two characters of unix crypt hash are the salt '''
	''' Rest of this function is the same as above '''
	salt = password[:2]
	with open(filename, "r") as wordlist:
		for words in wordlist.readlines():
			words = words.strip("\n")
			print("[*] Trying password: " + words)
			encrypted_words = crypt.crypt(words,salt)
			if encrypted_words == password:
				print("[+] Password found: " + words)
				exit(0)
		#print("[-] Password not in list")

if __name__ == "__main__":
	parser = optparse.OptionParser("[*] Usage: prog -f hashfile -w wordlist")
	parser.add_option('-f', type='string', help="HashFile", dest="hfile")
	parser.add_option('-w', type='string', help="WordList", dest="wfile")
	(option, args) = parser.parse_args()
	if (option.hfile == None) | (option.wfile == None):
		print(parser.usage)
	else:
		pfile = option.wfile
		hfile = option.hfile 
		with open(hfile, "r") as pass_file:
			for line in pass_file.readlines():
				if ":" in line:
					user = line.split(":")[0]
					password_hash = line.split(":")[1].strip("\n")
					#print(password_hash)
					print("[*] Cracking password for: " + user)
					t = Thread(target=with_salt, args=(pfile, password_hash))
					t.start()
					#with_hash(password_hash)
