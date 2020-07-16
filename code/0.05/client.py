from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import numpy as np
import base64
import socket 
import utils 
import p2p
import sys
import os 

def get_credentials():
	local_key = base64.b64decode(open(utils.cmd('ls LynxData/*.key',False).pop(),'rb').read())
	enc_local = open(utils.cmd('ls LynxData/*.cred',False).pop(), 'rb').read()
	dec_local = utils.DecodeAES(AES.new(local_key), enc_local)
	open('tmp.cred','wb').write(dec_local)
	username, ip, passwd = utils.load_credentials(os.getcwd()+'/tmp.cred')
	os.remove('tmp.cred')
	return username, ip, passwd

def save_credentials(uname, pword, addr):
	if not os.path.isdir(os.getcwd()+'LynxData'):
		os.mkdir('LynxData')
	data = '%s ...\n%s@%s' % (pword, uname, addr)
	key = get_random_bytes(32)
	open('LynxData/%s.key'%uname,'wb').write(base64.b64encode(key))
	encrypted_data = utils.EncodeAES(AES.new(key), data)
	open('LynxData/%s.cred'%uname,'wb').write(encrypted_data)

def load_key(uname):
	if not os.path.isdir('LynxData'):
		print('NO USERDATA!')
		return ''
	elif not os.path.isfile('LynxData/%s.key'%uname):
		print('NO USERDATA!')
		return ''
	else:
		return base64.b64decode(open(os.getcwd()+'/LynxData/%s.key'%uname,'rb').read())

def request_credentials():
	uname = raw_input('Enter Username:\n')
	cmd = "#!/bin/bash\n echo 'Enter Password:'; read -s PASS; echo $PASS >> cmd.txt\n#EOF"
	open('tmp.sh','wb').write(cmd)
	os.system('bash tmp.sh; rm tmp.sh')
	password = utils.swap('cmd.txt', True).pop()
	return uname, password


def start_headless():
	# Create a username and password
	u, p = request_credentials()
	save_credentials(u, p)


def welcome():
	lynx=  '\033[1m _                      \n'\
		  '| | \033[3m Welcome To   \033[0m\033[1m          \n'\
		  '| |    _   _ _ __ __  __\n'\
		  "| |   | | | | '_ \\\\ \\/ /\n"\
		  '| |___| |_| | | | |>  < \n'\
		  '\\_____/\\__, |_| |_/_/\\_\\\n'\
		  '        __/ |           \n'\
		  '       |___/            \033[0m'
	print lynx

def main():

	if '-headless' in sys.argv:
		welcome()
		# run setup and service from commandline (no browser)
		if not os.path.isdir(os.getcwd()+'/LynxData'):
			start_headless()
		else:
			username, ip, passwd = get_credentials()
			print '[o] Successfully Logged in as \033[1m\033[32m%s\033[0m' % username
		# check in with mothership
		if p2p.check_status(p2p.get_server_addr()):
			print '[o] Connected to Remote Server'
			# TODO: try to register username with remote server
			latency = np.mean(p2p.check_ping())
			print '[o] Mean Ping time: %fms' % latency
		else:
			print '[x] Failled to Connect to Server'

		# display commands like checking for peers, or uploading shares

	if '-stat' in sys.argv:
		p2p.check_ping()


if __name__ == '__main__':
	main()