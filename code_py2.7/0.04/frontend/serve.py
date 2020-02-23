from Crypto.Random import get_random_bytes
import html_engine
import base64
import socket
import utils
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
            os.system('sh ../kill_listeners.sh >> /dev/null 2>&1')
            time.sleep(12)
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
    # Start HTTP Server
    server = HttpServer()
    clients = []
    active_clients = {}
    running = True
    # Accept incoming requests
    try:
        while running and (time.time() - server.tic) < runtime:
            client, client_addr = handler.accept()
            if client_addr[0] not in list(set(clients)):
                new_client = True
            else:
                new_client = False
            try:
                request = client.recv(2048)
            except socket.error:
                print '[*] %s disconnected unexpectedly' % client_addr[0]
                continue

            query = request.split('\r\n')

            # Login attempts
            if 'POST / HTTP/1.1' == query[0]:
                field = query.pop()
                server.submit_login(client,field,active_clients,client_addr)

            elif query[0] in server.actions.keys():
                client = server.actions[query[0]](client, query, query[0], client_addr)

            elif 'GET /Inbox HTTP/1.1' in query and not new_client and not os.path.isfile('messages.txt'):
                print '[*] %s is creating their inbox' % client_addr[0]
                client.send(open('assets/empty_inbox.html','rb').read())

            # Close client connection
            client.close()

    except KeyboardInterrupt:
        d, l = create_timestamp()
        print '[!!] Server Killed [%s - %s]' % (d, l)
        os.system('sh ../kill_listeners.sh >> /dev/null 2>&1')
        pass
    handler.close()


class HttpServer:
    tic = 0
    known = {}

    def __init__(self):
        self.tic = time.time()
        self.actions = {'GET / HTTP/1.1': self.home_page,
                        'GET /assets/img/logo.png HTTP/1.1': self.logo,
                        'GET img/logo.png HTTP/1.1': self.logo,
                        'GET /favicon.ico HTTP/1.1': self.logo,
                        'GET /assets/img/im.jpeg HTTP/1.1': self.feed,
                        'GET img/im.jpeg HTTP/1.1': self.feed,
                        'POST / HTTP/1.1': self.login,
                        'GET /info HTTP/1.1': self.show_info,
                        'GET /Shares HTTP/1.1': self.get_shares,
                        'GET /FAQ HTTP/1.1': self.serve_faq,
                        'GET /Upload HTTP/1.1': self.upload_page,
                        'GET /Peers HTTP/1.1': self.display_peers,
                        'GET /Inbox HTTP/1.1': self.show_mailbox,
                        'GET /Mailbox HTTP/1.1': self.show_mailbox,
                        'GET /index.html HTTP/1.1': self.home_page,
                        'GET /BTC HTTP/1.1': self.serve_btc_price_watch,
                        'GET /CameraFeed HTTP/1.1': self.camera_feed}
        self.add_shared_files()

    def add_shared_files(self):
        files = os.listdir('../SHARED/Downloadable')
        for name in files:
            query_string = 'GET /SHARED/Downloadable/%s HTTP/1.1' % name
            self.actions[query_string] = self.file_download

    @staticmethod
    def file_download(c, f, q, ci):
        file_name = q.split('HTTP/1.1')[0].split('GET')[1].replace(' ','')
        print '[*] %s is downloading %s' % (ci[0], file_name)
        if os.path.isfile('..'+file_name):
            c.send(open('..'+file_name, 'rb').read())
        return c

    @staticmethod
    def get_user_agent(query):
        user_agent = ''
        for ln in query:
            if 'User-Agent:' in ln.split(' '):
                try:
                    user_agent = ln.split('User-Agent:')[1].replace('\n', '')
                except IndexError:
                    pass
        return user_agent

    def home_page(self, c, full_query, query, client_ip):
        print '[*] Serving homepage to %s' % client_ip[0]
        if client_ip in self.known.values():
            success_page = html_engine.generate_success(self.known[client_ip])
            c.send(open(success_page, 'rb').read())
            os.remove(success_page)
        else:
            c.send(open('login.html', 'rb').read())
        return c

    def display_peers(self, c, f, q, ci):
        if ci[0] in self.known.keys():
            print '[*] Showing %s active peer list' % ci[0]
            content = html_engine.show_active()
            c.send(content)
        else:
            forbidden = open('assets/forbidden.html', 'rb').read()
            c.send(forbidden)
        return c

    @staticmethod
    def show_mailbox(c,f,g,ci):
        c.send(html_engine.show_inbox_in())
        return c

    @staticmethod
    def logo(c,full_query, query, client_ip):
        c.send(open('assets/img/logo.png', 'rb').read())
        try:
            os.remove('info.html')
        except OSError:
            pass
        return c

    @staticmethod
    def feed(c, full_query, query, client_ip):
        c.send(open('assets/img/im.jpeg', 'rb').read())
        return c

    @staticmethod
    def login(c, full_query, query, client_ip):
        user_agent = ''.join(full_query[1:3])
        open(log_file_name, 'a').write('[*] %s is submitting login information.\nUser Agent: %s\n' %
                                       (client_ip[0], user_agent))
        return c

    @staticmethod
    def pause(a, b, c, d):
        time.sleep(0.1)
        return a

    @staticmethod
    def show_info(c, f, q, client_addr):
        user_agent = ''.join(q[1:3])
        print '[*] Serving %s information' % client_addr[0]
        html_engine.display_information(client_addr[0], user_agent)
        c.send(open('info.html', 'rb').read())
        os.remove('info.html')
        return c

    def get_shares(self, c, f, q, c_addr):
        self.add_shared_files()
        user_agent = ''.join(f[1:3])
        if c_addr[0] not in self.known.keys():
            # print self.known
            msg = '[!!] %s Has NOT LOGGED IN and tried to access Shared/ Files page\n' \
                  '[*] UserAgent:\n%s' % (c_addr[0], user_agent)
            print msg
            open(log_file_name, 'a').write(msg)
            return c
        print '[*] Serving %s html rendering of their local share folder' % c_addr[0]
        c.send(html_engine.render_file_structure('../SHARED/'))
        return c

    def submit_login(self, c, request, active_clients, c_addr):
        try:
            registered_users = refresh_users()
            uname = request.split('username=')[1].split('&')[0]
            passwd = request.split('password=')[1]
            if uname in registered_users.keys() and registered_users[uname] == passwd:
                print '\033[1m[*] %s Has Logged in Successfully from %s\033[0m' % (uname, c_addr[0])
                open(log_file_name, 'a').write('[*] %s has logged in SUCCESSFULLY as %s\n' % (c_addr[0], uname))
                active_clients[uname] = [passwd]
                self.known[c_addr[0]] = uname
                success_page = html_engine.generate_success(uname)
                c.send(open(success_page, 'rb').read())
                os.remove(success_page)
            else:
                open(log_file_name, 'a').write('[!] %s FAILED to login as %s\n' % (c_addr[0], uname))
                print '[*] Login failure for %s' % uname
                c.send(open('login.html', 'rb').read())
        except IndexError:
            pass
        return c

    @staticmethod
    def serve_faq(c, f, q, c_addr):
        print '[*] Serving %s the FAQ page' % c_addr[0]
        try:
            c.send(open('assets/faq.html', 'rb').read())
        except socket.error:
            pass
        return c

    def upload_page(self, c, f, q, c_addr):
        if c_addr[0] in self.known.keys():
            print '[*] %s is uploading a file to the server' % c_addr[0]
            c = html_engine.display_upload_page(c)
            time.sleep(0.1)
        else:
            forbidden = open('assets/forbidden.html', 'rb').read()
            c.send(forbidden)
        return c

    def serve_btc_price_watch(self,c,f,g,c_addr):
        user_agent = ''.join(f[1:5])
        if c_addr[0] not in self.known.keys():
            print self.known
            msg = '[!!] %s Has NOT LOGGED IN and tried to access Shared/ Files page\n' \
                  '[*] UserAgent:\n%s' % (c_addr[0], user_agent)
            print msg
            open(log_file_name, 'a').write(msg)
            return c

        print '[*] Serving %s BTC Price Watch page' % c_addr[0]
        c.send(html_engine.btc_price_tracking()[0])
        return c

    def camera_feed(self, c, f, q, c_addr):
        if c_addr[0] in self.known.keys():
            header = '<!DOCTYPE html>\n<html>\n <body>\n' \
                     '<meta charset="UTF-8" http-equiv="refresh" content="25;url=CameraFeed">\n'
            if os.path.isfile('../SHARED/im.jpeg'):
                os.system('mv ../SHARED/im.jpeg assets/img/im.jpeg')
                body = '<img src="assets/img/im.jpeg" alt="Feed" height="600">'
            elif os.path.isfile('assets/img/im.jpeg'):
                body = '<img src="assets/img/im.jpeg" alt="Feed" height="600">'
            elif os.path.isfile('../SHARED/im.jpeg.gz'):
                os.system('gzip -d ../SHARED/im.jpeg.gz; mv ../SHARED/im.jpeg assets/img/im.jpeg')
                body = '<img src="assets/img/im.jpeg" alt="Feed" height="600">'
            else:
                print '[!!] No LiveFeed Image Available'
                body = '<img src="assets/img/logo.png" alt="FeedDown" height="400">'
            d, l = utils.create_timestamp()
            stamp = '<h1> %s  -  %s </h1>\n' % (d, l)
            footer = stamp+'<body>\n</html>'
            content = header + body + footer
            c.send(content)
        else:
            forbidden = open('assets/forbidden.html', 'rb').read()
            c.send(forbidden)
        return c


if __name__ == '__main__':
    runtime = 3600 * 72  # While under development the server(s) only run for 3 day each trial
    # Create Log File
    date, localtime = create_timestamp()
    log_file_name = date.replace('/', '') + '_' + localtime.split(':')[0] + localtime.split(':')[1] + '.log'
    open(log_file_name, 'wb').write('[*] Server Started %s -%s\n====================' % (date, localtime))
    # Load Known Users
    users = refresh_users()
    print '[*] Server Started %s -%s\n' % (date, localtime)
    print '[*] %d Registered Users ' % len(users.keys())

    # Start listener daemon for new user credential uploads
    os.system('$(python engine.py -l %d) &>&1 ' % runtime)

    # Start a listening socket on port 80
    run(create_listener())

    # Display Date/timestamp on shutdown
    d, l = create_timestamp()
    print '[!!] Shutting down Server [%s - %s]' % (d, l)
