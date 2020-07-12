from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import base64
import socket 
import utils 
import os 

def get_credentials():
	local_key = base64.b64decode(open(utils.cmd('ls LynxData/*.key',False).pop(),'rb').read())
	enc_local = open(utils.cmd('ls LynxData/*.cred',False).pop(), 'rb').read()
	dec_local = utils.DecodeAES(AES.new(local_key), enc_local)
	open('tmp.cred','wb').write(dec_local)
	username, ip, passwd = utils.load_credentials(os.getcwd()+'/tmp.cred')
	os.remove('tmp.cred')
	return username, ip, passwd

def save_credentials(uname, pword):
	if not os.path.isdir(os.getcwd()+'LynxData'):
		os.mkdir('LynxData')
	data = '%s ...\n%s@null' % (pword, uname)
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