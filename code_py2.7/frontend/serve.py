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


def run(handler):
    clients = []
    active_clients = {}
    running = True
    # Accept incoming requests
    try:
        while running and (time.time() - tic) < runtime:
            client, client_addr = handler.accept()
            # clients.append(client_addr[0])
            try:
                request = client.recv(2048)
            except socket.error:
                print '[*] %s disconnected unexpectedly' % client_addr[0]
                pass
            registered_users = refresh_users()
            user_agent = ''
            for ln in request.split('\r\n'):
                if 'User-Agent:' in ln.split(' '):
                    try:
                        user_agent = ln.split('User-Agent:')[1].replace('\n', '')
                    except IndexError:
                        pass
            if client_addr[0] not in list(set(clients)):
                new_client = True
            else:
                new_client = False
            # Serve login page to new connections, and handle logins
            if 'GET / HTTP/1.1' in request.split('\r\n'):
                client.send(open('login.html', 'rb').read())
            # Display logo
            elif 'GET /assets/img/logo.png HTTP/1.1' in request.split('\r\n'):
                client.send(open('assets/img/logo.png', 'rb').read())
                try:
                    os.remove('info.html')
                except OSError:
                    continue
            # Display information about downloading the client
            elif 'GET /favicon.ico HTTP/1.1' in request.split('\r\n'):
                time.sleep(0.1)
            elif 'POST / HTTP/1.1' in request.split('\r\n'):
                open(log_file_name, 'a').write('[*] %s is submitting login information.\nUser Agent: %s\n' %
                                               (client_addr[0], user_agent))
            elif 'GET /inbox HTTP/1.1' in request.split('\r\n') and not new_client:
                print '[*] Serving %s their inbox' % client_addr[0]

            elif 'GET /info HTTP/1.1' in request.split('\r\n'):
                print '[*] Serving %s information' % client_addr[0]
                html_engine.display_information(client_addr[0], user_agent)
                client.send(open('info.html', 'rb').read())
                os.remove('info.html')
            elif 'GET /LocalShares HTTP/1.1' in request.split('\r\n'):
                print '[*] Serving %s html rendering of their local share folder' % client_addr[0]
                structure = html_engine.render_file_structure('../SHARED')
                client.send(structure)

            elif 'GET /FAQ HTTP/1.1' in request.split('\r\n'):
                print '[*] Serving %s the FAQ page' % client_addr[0]
                client.send(open('assets/faq.html', 'rb').read())
            # Login attempts TODO: Encrypt how credentials are sent over the wire
            if len(request.split('username=')) > 1:
                uname = request.split('username=')[1].split('&')[0]
                passwd = request.split('password=')[1].split('%')[0]
                if uname in registered_users.keys() and registered_users[uname] == passwd:
                    print '\033[1m[*] %s Has Logged in Successfully from %s\033[0m' % (uname, client_addr[0])
                    open(log_file_name, 'a').write('[*] %s has logged in SUCCESSFULLY as %s\n' % (client_addr[0], uname))
                    active_clients[uname] = [passwd]
                    clients.append(uname)
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
        os.system('sh ../kill_listeners.sh >> /dev/null 2>&1')
        running = False
        pass
    handler.close()


if __name__ == '__main__':
    runtime = 3600 * 24  # While under development the server(s) only run for 1 day each trial
    # Create Log File
    date, localtime = create_timestamp()
    log_file_name = date.replace('/', '') + '_' + localtime.split(':')[0] + localtime.split(':')[1] + '.log'
    open(log_file_name, 'wb').write('[*] Server Started %s -%s\n' % (date, localtime))
    # Load Known Users
    users = refresh_users()
    print '[*] %d Registered Users ' % len(users.keys())

    # Start listener daemon for new user credential uploads
    os.system('$(python engine.py -l %d) & ' % runtime)

    # Start HTTP Server
    tic = time.time()
    # Start a listening socket on port 80
    run(create_listener())

