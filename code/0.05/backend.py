from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import socket 
import base64
import utils
import time 
import sys 
import os 



class BackendLynxAPI:
	session_secret = ''
	inbound  = 54123
	outbound = 32145 
	running = False
	peers = {}
	sessions = {}

	def __init__(self):
		self.actions = {'STATUS': self.status_check}
		# TODO: Load Known Peers?
		self.server = self.start_listener()
		self.running = True
		self.run()
		

	def start_listener(self):
		"""
		START_LISTENER
		"""
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.bind(('0.0.0.0', self.inbound))
			s.listen(5)
		except socket.error:
			print '[!!] Cannot Create Socket'
			return []
		return s

	def run(self): 
 		"""
 		RUN
 		"""
		while self.running:
			session_secret = base64.b64encode(get_random_bytes(32))
			try:
				# Listen
				client, client_info = self.server.accept()
				client_ip = client_info[0]
				# TODO: If new client do a handshake to set up encryption!
				# Handle Clients
				raw_request = client.recv(2048)
				try:
					api_fcn = raw_request.split(' ???? ')[0]
					api_req = raw_request.split(' ???? ')[1]
					# if the api function requested exists, handle request
					if api_fcn in self.actions.keys():
						print '[o] %s is requesting API Action: %s' % (client_ip, api_fcn)
						client = self.actions[api_fcn](client, client_ip, api_req)
				except IndexError:
					print '[!!] Malformed API reequest from %s' % client_ip
					pass
				# Close connection after handling
				client.close()
			except socket.error:
				print '[!!] Server Error'
				pass
			except KeyboardInterrupt:
				self.running = False
				# This may happen while a client is connected. 
				# Kill any client connections when shutting down.
				try:
					client.close()
				except socket.error:
					pass
				pass

		print '[*] Shutting Down BackendLynxAPI Server [*]'
		self.server.close()


	def status_check(self, c, ci, req):
		"""
		Most basic API request, to simplify notify remote end that they have connected
		successully to the server and API request was handled okay. 
		"""
		# TODO: encrypt reply with session key!
		reply = 'OK, Message Recieved'
		c.send('%s' % self.session_secret)
		result = c.recv(1024)
		if result == self.session_secret:
			c.send(reply)
		else:
			c.send('That does not sound correct!')
		return c


def main():
	backend_api = BackendLynxAPI()

if __name__ == '__main__':
	main()

