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
		self.actions = {'STATUS': self.status_check,
						'SEND': self.client_log_send,
						'READ': self.client_read_msg,
						'CHECK': self.client_check_msg}
		# TODO: Load Known Peers?
		self.setup()
		self.server = self.start_listener()
		self.running = True
		self.run()
	
	def setup(self):
		# Create the inbox for p2p messages
		if not os.path.isdir(os.getcwd()+'/LynxData/Messages'):
			os.mkdir(os.getcwd()+'/LynxData/Messages')

	def start_listener(self):
		"""
		START_LISTENER
		"""
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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
						client = self.actions[api_fcn](client, client_info, api_req)
				except IndexError:
					print '[!!] Malformed API reequest from %s' % client_ip
					print raw_request
					# ^^^^ ONLY FOR DEBUGGING!!!
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
		c.send(req)
		print '[*] Sending Reply %s' % req
		return c

	def client_log_send(self, c, ci, req):
		recipient = req.split(' :::: ')[0]
		message = req.split(' :::: ')[1].split(' ;;;; ')[0]
			
		if len(req.split(' ;;;; ')[0].split(' ')) > 2:
			print 'Alt'
			title = '%sFOR%s' % (req.split(' ;;;; ')[1], recipient.replace('.','-'))
		else:
			title = '%sFOR%s' % (ci[0].replace('.','-'),recipient.replace('.','-'))
		print title
		if not os.path.isfile(os.getcwd()+'/LynxData/Messages/%s' % title):
			open(os.getcwd()+'/LynxData/Messages/%s' % title,'wb').write(message)
		else:
			open(os.getcwd()+'/LynxData/Messages/%s' % title,'a').write(message)
		c.send('SUCCESS')
		return c

	def client_read_msg(self, c, ci, req):
		sender = req.split(' :::: ')[0]
		recipient = ci[0]
		title = req
		if not os.path.isfile(os.getcwd()+'/LynxData/Messages/%s' % title):
			c.send('No Message Found')
		else:
			c.send(open(os.getcwd()+'/LynxData/Messages/%s' % title, 'rb').read())
		# DELETE?
		os.remove(os.getcwd()+'/LynxData/Messages/%s' % title)
		return c

	def client_check_msg(self, c, ci, req):
		ip = ci[0]
		cmd = 'ls LynxData/Messages/*FOR%s' % ip.replace('.','-')
		messages = utils.cmd(cmd,False)
		if utils.cmd('echo $?',False).pop().replace('\n','') != '0':
			c.send('You have no new messages')
		else:
			result = ''
			for msg in messages:
				result += msg + '\n'
			c.send('You Have %d Messages\n%s' % (len(messages), result))
		return c

def main():
	print '[*] Starting LYNX Backend Server [*]'
	backend_api = BackendLynxAPI()

if __name__ == '__main__':
	main()

