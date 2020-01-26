import socket
import time
import sys
import os


def create_timestamp():
    date = time.localtime(time.time())
    mo = str(date.tm_mon)
    day = str(date.tm_mday)
    yr = str(date.tm_year)

    hr = str(date.tm_hour)
    min = str(date.tm_min)
    sec = str(date.tm_sec)

    date = mo + '/' + day + '/' + yr
    timestamp = hr + ':' + min + ':' + sec
    return date, timestamp


def create_listener():
    created = False
    while not created:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(('0.0.0.0', 80))
            s.listen(5)
            created = True
        except socket.error:
            print '[!!] Error Creating Listener...'
            time.sleep(10)
    print '[*] Listener Started'
    return s


# TODO: Create a logfile
date, localtime = create_timestamp()
log_file_name = date.replace('/','')+'_'+localtime.split(':')[0]+localtime.split(':')[1]+'.log'
open(log_file_name, 'wb').write('[*] Server Started %s -%s' % (date, localtime))
# Load Known Users
users = {}
os.system('ls ../*.pass >> passwords.txt')
for name in open('passwords.txt', 'rb').readlines():
    try:
        username = name.split('../')[1].split('.pass')[0].replace('\n', '')
        users[username] = open(name.replace('\n', '')).read()
    except IndexError:
        pass
print users

# Start Server
runtime = 3600; tic = time.time()
# Start a listening socket on port 80
handler = create_listener()
running = True
clients = []
# Accept incoming requests
try:
    while running and (time.time() - tic) < runtime:
        client, client_addr = handler.accept()
        clients.append(client_addr[0])
        request = client.recv(2048)
        # print request
        # Serve login page to new connections, and handle logins
        if 'GET / HTTP/1.1' in request.split('\r\n'):
            client.send(open('login.html', 'rb').read())
        # Login attempts
        if len(request.split('username='))>1:
            uname = request.split('username=')[1].split('&')[0]
            passwd = request.split('password=')[1].split('%')[0]
            if users[uname] == passwd:
                print '\033[1m[*] %s Has Logged in Successfully \033[0m' % uname
                # TODO: Dynamically Generate success page, and user dashboards
                open(log_file_name, 'a').write('[*] %s has logged in SUCCESSFULLY as %s\n' % (client_addr[0], uname))
            else:
                open(log_file_name, 'a').write('[!] %s FAILED to login as %s\n' % (client_addr[0], uname))
                print '[*] Login failure or %s' % uname
                client.send(open('login.html', 'rb').read())
        client.close()
        # HTTP 100 Continue: The server has received the request headers,
        # and the client should proceed to send the request body
        #
        # HTTP 200 OK: The request is OK (this is the standard response for successful HTTP requests)

except KeyboardInterrupt:
    print '[!!] Server Killed'
    running = False
    pass
handler.close()

