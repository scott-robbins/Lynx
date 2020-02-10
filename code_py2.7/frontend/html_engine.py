import utils
import time
import sys
import os


def hyperlink(url, label):
    return '<a href="%s">%s</a>' % (url, label)


def generate_success(uname):
    # Load messages for username
    n_sent = 0
    n_received = 0
    if os.path.isfile('messages.txt'):
        msgs = {}
        for line in utils.swap('messages.txt', False):
            try:
                sender = line.split('->')[0]
                receiver = line.split('->')[1].split(':')[0]
                message = line.split(receiver)[1]
                msgs[message] = [sender, receiver]
                if sender == uname:
                    n_sent += 1
                if receiver == uname:
                    n_received += 1
            except IndexError:
                pass
    else:
        os.system('touch messages.txt')

    page_name = uname+'_success.html'
    header = '<!DOCTYPE html>\n<html>\n <head>\n<title> Inbox </title>\n<meta charset="utf-8">\n' \
             '<meta name="viewport" content="width=device-width, initial-scale=1">\n'

    style = '<style>*{\n\tbox-sizing:border-box;\n}\nbody{\n\tfont-family: Arial, Helvetica, sans-serif;\n}\n' \
            '\nheader{\n\tbackground-color: #666;\n\tpadding: 10px;\n\ttext-align:center;\n\tfont-size: 10px;\n' \
            '\tcolor: white;\n}\n\nnav {\n\tfloat: left;\n\twidth: 30%;\n\theight: 500px;\n\tbackground: #ccc;\n' \
            '\tpadding: 20px;\n}\n\nnav ul {\n\tlist-style-type: square;\n\tpadding: 0;\n}\n' \
            'article {\n\tfloat: left;\n\tpadding: 20px;\n\twidth: 70%;\n\tbackground-color: #f1f1f1;' \
            '\n\theight: 500px;\n}\n\nsection:after{\n\tcontent: "",\n\tdisplat: table;\n\tclear: both\n}\n' \
            'footer {\n\tbackground-color: #777;\n\tpadding: 10px;\n\ttext-align: center;\n\tcolor: white;\n}\n' \
            '@media (max-width: 600px) {\n\tnav, article {\n\twidth: 100%\n\theight: auto;\n\t}\n}\n</style>\n</head>\n'

    body = '<body>\n\n<header>\n\t<h2> Home </h2>\n</header>\n\n<section>\n\t<nav>\n\t\t<ul>\n\n' \
           '\t\t\t<li> <a href="/Upload"> File Upload </a></li>\n' \
           '\t\t\t<li> <a href="/Shares"> Shared Files </a></li>\n'\
           '\t\t\t<li> <a href="/info"> Information </a></li>\n\n' \
           '\t\t\t<li> <a href="/FAQ"> FAQ </a></li>\n\n' \
           '\t\t\t<li> <a href="/Peers"> Active Peers </a></li>\n\n'\
           '\t\t\t<li> <a href="/Mailbox"> Messages </a></li>\n\n'\
           '</nav>\n\t<article>\n\t\t<h1> Activity Log </h1>\n\t\t<p> %d Messages Received </p>\n' \
           '\t\t<p> %d Messages Sent </p>\n\t</article>\n</section>\n\n' % (n_received, n_sent)
    footer = '<footer>\n\t<p> Lynx Mail </p>\n</footer>\n</body>\n</html>'
    content = header+style+body+footer
    open(page_name, 'wb').write(content)
    return page_name


def show_active():
    peers = []
    if os.path.isfile('registered.txt'):
        peers = utils.swap('registered.txt', False)

    lines = {}
    for p in peers:
        try:
            uname = p.split('@')[0]
            addrs = p.split('@')[1].split('=')[0]
            lines[uname] = '<li> User: %s    IP: %s</li>\n' % (uname, addrs)
        except IndexError:
            break
            pass
    n_peers = len(list(set(lines.keys())))
    header = '<!DOCTYPE html>\n<html>\n <body>\n' \
             '<div style="background-color:PowderBlue;color:white;padding:30px;">\n' \
             '<h2> %d Active Nodes </h2>\n<ul>\n' % n_peers
    for name in list(set(lines.keys())):
        header += lines[name]
    header += '</ul>\n'
    footer = '<body>\n</html>'
    return header + footer


def display_information(client_addr, user_agent):
    header = '<!DOCTYPE html>\n<html>\n <body>\n'
    box = '<div style="background-color:MediumSeaGreen;color:white;paddding:20px;">\n' \
          '<title>Information</title>\n<h2> About Lynx</h2>\n' \
          '<section>' \
          '<p> Thus far Lynx has been a pet project in my evenings after work and on the weekends. It started<br>\n' \
          'as a LAN based system for executing commands on my Raspberry Pis to do different things. One was<br>\n' \
          'a stick up cam aimed at the front steps, one was crawling the web and tracking the price of bitcoin, <br>\n' \
          'You get the picture.<br>\n' \
          'Then I started experimenting with virtual hosting, a few months later I discovered DynamicDNS, <br>\n' \
          'and well here we are...' \
          '</section>'
    footer = '<body>\n</html>'
    content = header + box + footer
    open('info.html', 'wb').write(content)
    return 'info.html'


def display_upload_page(client):
    client.send(open('assets/upload.html', 'rb').read())
    return client


def render_file_structure(file_path):
    """
    RENDER_FILE_STRUCTURE - given a dictionary of files and a list of directories
    build a tree of nested lists in html to render on screen.
    :param directory:
    :return html_content:
    """
    header = '<!DOCTYPE html>\n<html>\n <body>\n'
    footer = '<body>\n</html>'
    content = '<h2> %s </h2>\n<ul>\n' % file_path
    directory, empty = utils.crawl_dir(file_path, False, False)
    print '[*] %d Files found ' % len(directory['file'])
    top_dirs = []
    where = {}
    for f in directory['file']:
        element = f.split(file_path).pop()
        if len(element.split('/')) > 2:
            d = element.split('/')[1].split('/')[0]
            top_dirs.append(d)
            where[f] = d
        else:
            where[f] = ''
    top_dirs = list(set(top_dirs))
    if len(top_dirs) > 1:
        print '!'
        for folder in top_dirs:
            content += '<li> %s </li>\n' % folder
            more = '<ul>\n'
            for fname in directory['file']:
                dloc = where[fname]
                if dloc == folder:
                    more += '<li> %s </li>\n' % fname.replace('//','/')
            more += '</ul>\n'
            if len(more):
                content += more
    elif len(top_dirs) <= 1:
        m = '<ul>\n'
        for fname in directory['file']:
            m +='<li> %s </li>\n' % fname.replace('//','/')
        m += '</ul>\n'
        content += m
    page = header + content + footer
    return page


def show_inbox_in():
    if not os.path.isfile('inbox.txt'):
        os.system('touch inbox.txt')
        return open('assets/empty_inbox.html', 'rb').read()
    else:
        head = '<! DOCTYPE html>\n<html lang="en">\n<head>\n' \
               '\t<meta charset="UTF-8">\n' \
               '\t<title> Inbox </title>\n</head>\n</body>\n'
        body = ''
        footer = '</body>\n</html>'
        return head + body + footer


if '-t' in sys.argv:
    test_dir = '../SHARED'
    content = render_file_structure(test_dir)
    print content

