from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import socket 
import utils 
import time 
import sys 
import os 


class BackendAPI:
	inbound = 54123
	users = {}
	running = False

	def __init__ (self):
		self.actions = {}
		self.serve = utils.start_listener(self.inbound)
		self.setup()
		self.run()

	def setup(self):
		if not os.path.isdir(os.getcwd()+'/LynxData'):
			os.mkdir('LynxData')
		if not os.path.isfile(os.getcwd()+'/LynxData/server.pem'):
			k = RSA.generate(2048)
			file_out = open(os.getcwd()+'/LynxData/server.pem', 'wb')
			file_out.write(k.exportKey('PEM'))
		else:
			k = self.load_server_key()

	def load_server_key():
		return RSA.importKey(open(os.getcwd()+'/LynxData/server.pem').read())

	def run(self):
		self.running = True 
		start_t, start_d = utils.create_timestamp()
		print '\033[1m[*] Starting \033[32mLYNX BackendAPI\033[0m\033[1m'\
			  ' Server %s - %s [*]\033[0m' % (start_d, start_t)
		

		while self.running:
			try:
				# Accept A Client connection (Blocks Here Until recieivng a client!!)
				client, client_info = self.serve.accept()
				client_ip = client_info[0]
				# Check whether IP is known (Diff. peers can have same IP tho! bc NAT)
				
				#

				#

				# Close the connection 
				client.close()
			except KeyboardInterrupt:
				self.shutdown
				try:
					client.close()
				except socket.error:
					pass

				
				

	def shutdown(self):
		self.running = False
		self.serve.close()
		end_t, end_d = utils.create_timestamp()
		print '[!!] Server Killed [%s - %d]' % (end_d, end_t)

def main():
	BackendAPI()


if __name__ == '__main__':
	main()

