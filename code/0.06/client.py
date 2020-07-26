from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import socket 
import utils 
import time
import p2p 
import sys 
import os 

def greeting():
	start = '\033[1m'
	stop = '\033[0m'
	l1 = '      :::    ::: :::::::::: :::        :::        ::::::::  :::'
	l2 = '     :+:    :+: :+:        :+:        :+:       :+:    :+: :+: '
	l3 = '    +:+    +:+ +:+        +:+        +:+       +:+    +:+ +:+  '
	l4 = '   +#++:++#++ +#++:++#   +#+        +#+       +#+    +:+ +#+   '
	l5 = '  +#+    +#+ +#+        +#+        +#+       +#+    +#+ +#+    '
	l6 = ' #+#    #+# #+#        #+#        #+#       #+#    #+#         '
	l7 = '###    ### ########## ########## ########## ########  ###      '
	print start
	sequence = [l1,l2,l3,l4,l5,l6,l7]
	for letter in sequence:
		print letter
		time.sleep(0.2)
	time.sleep(2)
	os.system('clear')
	print stop

def welcome():
	lay1=  '\033[1m _                      \n'\
		  '| | \033[3m Welcome To   \033[0m\033[1m          '
	lay2 = '| |    _   _ _ __ __  __\n'\
		   "| |   | | | | '_ \\\\ \\/ /"
	lay3 = '| |___| |_| | | | |>  < \n'\
		   '\\_____/\\__, |_| |_/_/\\_\\'
	lay4 = '        __/ |           \n'\
		   '       |___/            \n'\
		   '==================================\033[0m'
	
	greeting()
	print lay1
	time.sleep(0.15)
	print lay2
	time.sleep(0.15)
	print lay3
	time.sleep(0.15)
	print lay4

def register():
	if not os.path.isdir(os.getcwd()+'/LynxData/'):
		os.mkdir('LynxData')
		os.mkdir('LynxData/Creds')
	uname, pword = create_credentials()

def create_credentials():
	uname = raw_input('Enter Username:\n')
	matched = False
	while not matched:
		cmd = "#!/bin/bash\n echo 'Enter Password:'; read -s PASS; echo $PASS >> cmd.txt\n#EOF"
		open('tmp.sh','wb').write(cmd)
		os.system('bash tmp.sh; rm tmp.sh')
		password = utils.swap('cmd.txt', True).pop()
		# Double Check it twice before creating 
		cmd2 = "#!/bin/bash\n echo 'Re-Enter Password:'; read -s PASS; echo $PASS >> cmd.txt\n#EOF"
		open('tmp.sh','wb').write(cmd2)
		os.system('bash tmp.sh; rm tmp.sh')
		password_check = utils.swap('cmd.txt', True).pop()
		if password == password_check:
			print '[*] Username and Password Created'
			matched = True
		elif (len(password) > 7):
			print '[x] Password must be longer than 7 Characters!'
		else:
			print '[X] The two password entries did not match!'
	# Save Them, Encrypted with private key (also saved)
	key = RSA.generate(2048)
	private_key = key.exportKey()
	public_key = key.publickey()
	file_out = open(os.getcwd()+"/LynxData/Creds/%s.pem" % uname, "wb")
	file_out.write(key.exportKey('PEM'))
	file_out.close()

	# Encrypt the session key with the public RSA key
	cipher_rsa = PKCS1_OAEP.new(public_key)
	cred_file_dat = b'%s@%s:%s' % (uname, utils.get_ext_ip(), password)
	enc_cred_data = cipher_rsa.encrypt(cred_file_dat)
	open(os.getcwd()+'/LynxData/%s.creds' % uname, 'wb').write(enc_cred_data)

	return uname, password	

def load_credentials():
	if not os.path.isdir(os.getcwd()+'/LynxData/'):
		print '[!!] No credentials Found. Plese Register First!'
		exit()

	get_key = 'ls LynxData/*.pem'
	key_name = utils.cmd(get_key, False).pop()
	cred_name = key_name.split('.pem')[0]+'.creds'
	private_key = RSA.importKey(open(os.getcwd()+'/%s' % key_name).read())
	raw_creds = PKCS1_OAEP.new(private_key).decrypt(open(cred_name,'rb').read())
	uname = raw_creds.split('@')[0]
	ip_addr = raw_creds.split('@')[1].split(':')[0]
	password = raw_creds.split(':')[1]
	return uname, ip_addr, password, private_key

def main():
	# Sign up Via the Commandline 
	if not os.path.isdir(os.getcwd()+'/LynxData') or '-register' in sys.argv:
		welcome()
		register()

	# These will be used for basically any operation so do it once at top
	name, addr, creds, p_key = load_credentials()
	pub = p_key.publickey()
	good, skey = p2p.handshake(name, pub, True)
	if good:
		print '[*] Encrypted Communication Successful with Remote Server'
	

if __name__ == '__main__':
	main()

