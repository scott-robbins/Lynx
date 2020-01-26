import multiprocessing
import html_engine
import engine
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


def refresh_users():
    unames = {}
    os.system('ls ../*.pass >> passwords.txt')
    for name in open('passwords.txt', 'rb').readlines():
        try:
            username = name.split('../')[1].split('.pass')[0].replace('\n', '')
            unames[username] = open(name.replace('\n', '')).read()
        except IndexError:
            pass
    return unames


def run(handler, registered_users):
    clients = []
    running = True
    # Accept incoming requests
    try:
        while running and (time.time() - tic) < runtime:
            client, client_addr = handler.accept()
            clients.append(client_addr[0])
            request = client.recv(2048)
            registered_users = refresh_users()
            # Serve login page to new connections, and handle logins
            if 'GET / HTTP/1.1' in request.split('\r\n'):
                client.send(open('login.html', 'rb').read())
            # Display logo
            elif 'GET /assets/img/logo.png HTTP/1.1' in request.split('\r\n'):
                user_agent = ''
                for element in request.split('\r\n'):
                    if 'User-Agent:' in element.split(':'):
                        try:
                            user_agent = element.split('User-Agent:')[1].replace('\n', '')
                        except IndexError:
                            pass
                client.send(open('assets/img/logo.png', 'rb').read())
                try:
                    os.remove('info.html')
                except OSError:
                    pass
            # Display information about downloading the client
            elif 'GET /favicon.ico HTTP/1.1' in request.split('\r\n'):
                time.sleep(0.1)
            elif 'POST / HTTP/1.1' in request.split('\r\n'):
                user_agent = ''
                for ln in request.split('\r\n'):
                    if 'User-Agent:' in ln.split(':'):
                        try:
                            user_agent = ln.split('User-Agent:')[1].replace('\n', '')
                        except IndexError:
                            pass
                open(log_file_name, 'a').write('[*] %s is submitting login information.\nUser Agent: %s\n' %
                                               (client_addr[0], user_agent))
                # print request
            # Login attempts TODO: Encrypt how credentials are sent over the wire
            if len(request.split('username=')) > 1:
                uname = request.split('username=')[1].split('&')[0]
                passwd = request.split('password=')[1].split('%')[0]
                if uname in registered_users.keys() and registered_users[uname] == passwd:
                    print '\033[1m[*] %s Has Logged in Successfully from %s\033[0m' % (uname, client_addr[0])
                    open(log_file_name, 'a').write('[*] %s has logged in SUCCESSFULLY as %s\n' % (client_addr[0], uname))
                    success_page = html_engine.generate_success(uname)
                    client.send(open(success_page, 'rb').read())
                    os.remove(success_page)
                else:
                    open(log_file_name, 'a').write('[!] %s FAILED to login as %s\n' % (client_addr[0], uname))
                    print '[*] Login failure for %s' % uname
                    client.send(open('login.html', 'rb').read())

            client.close()
            # HTTP 100 Continue: The server has received the request headers,
            # and the client should proceed to send the request body
            #
            # HTTP 200 OK: The request is OK (this is the standard response for successful HTTP requests)

    except KeyboardInterrupt:
        print '[!!] Server Killed'
        os.system('../kill_listeners.sh >> /dev/null 2>&1')
        running = False
        pass
    handler.close()


if __name__ == '__main__':
    # Create Log File
    date, localtime = create_timestamp()
    log_file_name = date.replace('/', '') + '_' + localtime.split(':')[0] + localtime.split(':')[1] + '.log'
    open(log_file_name, 'wb').write('[*] Server Started %s -%s\n' % (date, localtime))
    # Load Known Users
    users = refresh_users()
    print '[*] %d Registered Users ' % len(users.keys())
    runtime = 3600

    # Start listener daemon for new user credential uploads
    os.system('$(python engine.py -l %d)&' % runtime)

    # Start HTTP Server
    tic = time.time()
    # Start a listening socket on port 80
    run(create_listener(), users)

