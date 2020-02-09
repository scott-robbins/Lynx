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


class HttpServer:
    tic = 0

    def __init__(self):
        self.tic = time.time()
        self.requests = {'GET / HTTP/1.1': self.show_login,
                         'GET /assets/img/logo.png HTTP/1.1': self.display_logo,
                         'GET /favicon.ico HTTP/1.1': time.sleep(0.1),
                         'POST / HTTP/1.1': self.submit,
                         'GET /FAQ HTTP/1.1': self.show_faq}

    @staticmethod
    def get_user_agent(request):
        user_agent = ''
        for ln in request.split('\r\n'):
            if 'User-Agent:' in ln.split(' '):
                try:
                    user_agent = ln.split('User-Agent:')[1].replace('\n', '')
                except IndexError:
                    pass
        return user_agent

    def show_login(self, c):
        status = True
        try:
            c.send(open('login.html', 'rb').read())
        except socket.error:
            status = False
        return c, status

    def display_logo(self, c):
        status = True
        try:
            c.send(open('assets/img/logo.png', 'rb').read())
        except socket.error:
            status = False
            pass
        try:
            os.remove('info.html')
        except OSError:
            status = False
            pass
        return c, status

    def submit(self, c):
        state = True
        msg = '[*] %s is submitting login information.\n' % c.getpeername()
        try:
            open(log_file_name, 'a').write(msg)
        except OSError:
            state = False
        return c, state

    def show_faq(self, c):
        status = True
        try:
            c.send(open('assets/faq.html', 'rb').read())
        except socket.error:
            status = False
        return c, status

def run(handler):
    server = HttpServer()
    clients = []
    active_clients = {}
    running = True
    # Accept incoming requests
    try:
        while running and (time.time() - server.tic) < runtime:
            client, client_addr = handler.accept()
            if client_addr[0] not in list(set(clients)):
                d, l = create_timestamp()
                new_client = True
                open(log_file_name,'a').write('[*] %s has connected [%s]\n' % (client_addr[0], l))
            else:
                new_client = False
            try:
                request = client.recv(2048)
            except socket.error:
                print '[*] %s disconnected unexpectedly' % client_addr[0]
                continue
            registered_users = refresh_users()

            user_agent = server.get_user_agent(request)

            query = request.split('\r\n')

            # Handle all requests with http server
            if query in server.requests.keys():
                client, status = server.requests[query](client)

            # Requests that I havent figured out with the server class
            if 'GET /inbox HTTP/1.1' in query and not new_client:
                print '[*] Serving %s their inbox' % client_addr[0]

            elif 'GET /info HTTP/1.1' in query:
                print '[*] Serving %s information' % client_addr[0]
                html_engine.display_information(client_addr[0], user_agent)
                client.send(open('info.html', 'rb').read())
                os.remove('info.html')
            if 'GET /Shares HTTP/1.1' in query and not new_client:
                print '[*] Serving %s html rendering of their local share folder' % client_addr[0]
                client.send(html_engine.render_file_structure('../SHARED/'))
            if 'GET /Upload HTTP/1.1' in query and not new_client:
                print '[*] %s is uploading a file to the server' % client_addr[0]
                client = html_engine.display_upload_page(client)
                time.sleep(0.1)

            # LOGIN
            if len(request.split('username=')) > 1:
                d, l = create_timestamp()
                open(log_file_name, 'a').write('[*] %s is attempting to login [%s]\n' % (client_addr[0], l))
                uname = request.split('username=')[1].split('&')[0]
                passwd = request.split('password=')[1].split('%')[0]
                if uname in registered_users.keys() and registered_users[uname] == passwd:
                    print '\033[1m[*] %s Has Logged in Successfully from %s\033[0m' % (uname, client_addr[0])
                    open(log_file_name, 'a').write('[*] %s has logged in SUCCESSFULLY as %s\n' % (client_addr[0], uname))
                    active_clients[uname] = [passwd]
                    clients.append(client_addr[0])
                    success_page = html_engine.generate_success(uname)
                    client.send(open(success_page, 'rb').read())
                    os.remove(success_page)
                else:
                    open(log_file_name, 'a').write('[!] %s FAILED to login as %s\n' % (client_addr[0], uname))
                    print '[*] Login failure for %s' % uname
                    client.send(open('login.html', 'rb').read())
            client.close()

    except KeyboardInterrupt:
        print '[!!] Server Killed'
        os.system('sh ../kill_listeners.sh >> /dev/null 2>&1')
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
    # tic = time.time()
    # Start a listening socket on port 80
    run(create_listener())

