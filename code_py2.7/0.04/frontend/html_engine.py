import numpy as np
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

    if os.path.isdir('../SHARED'):
        n_shared = len(os.listdir('../SHARED'))
    else:
        n_shared = 0

    page_name = uname+'_success.html'
    header = '<!DOCTYPE html>\n<html>\n <head>\n<title> Dashboard </title>\n<meta charset="utf-8">\n' \
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
           '\t\t\t<li> <a href="/Shares"> Shared Files </a></li>\n'\
           '\t\t\t<li> <a href="/BTC"> Bitcoin Price </a></li>\n'\
           '\t\t\t<li> <a href="/info"> Information </a></li>\n\n' \
           '\t\t\t<li> <a href="/FAQ"> FAQ </a></li>\n\n' \
           '\t\t\t<li> <a href="/Peers"> Active Peers </a></li>\n\n'\
           '\t\t\t<li> <a href="/Mailbox"> Messages </a></li>\n\n'\
           '\t\t\t<li> <a href="/Upload"> File Upload </a></li>\n'\
           '\t\t\t<li> <a href="/Security"> Security</a></li>\n'\
           '\t\t\t<li> <a href="/CameraFeed"> Live Video Feed </a></li>\n\n'\
           '</nav>\n\t<article>\n\t\t<h1> Activity Log </h1>\n\t\t<p> %d Messages Received </p>\n' \
           '\t\t<p> %d Messages Sent </p>\n\t</article>\n</section>\n\n' % (n_received, n_sent)
    footer = '<footer>\n\t<p> {Lynx} - %s -  Homepage </p>\n</footer>\n</body>\n</html>' % uname
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
             '<div style="background-color:PowderBlue;color:black;padding:30px;">\n' \
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
    header = '<!DOCTYPE html>\n<html>\n <body>\n' \
             '<meta charset="UTF-8" http-equiv="refresh" content="30;url=/Shares">\n'
    footer = '<body>\n</html>'
    content = '<h2> %s </h2>\n<ul>\n' % file_path
    directory, hashes = utils.crawl_dir(file_path, True, False)
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
        for folder in top_dirs:
            content += '<li> %s </li>\n' % folder
            more = '<ul>\n'
            for fname in directory['file']:
                dloc = where[fname]
                h = hashes['"' +fname.replace('//','/')+ '"']
                if dloc == folder:
                    more += '<li> %s : \t%s </li>\n' %\
                    (hyperlink('/Shared/'+fname.replace('//','/'),fname.replace('//','/')), h)
            more += '</ul>\n'
            if len(more):
                content += more
    elif len(top_dirs) <= 1:
        m = '<ul>\n'
        for fname in directory['file']:
            h = hashes['"'+fname.replace('//', '/')+'"']
            m += '<li> %s : %s </li>\n' % \
                 (hyperlink('/Shared/' + fname.replace('//', '/'), fname.replace('//', '/')), h)
        m += '</ul>\n'
        content += m

    # TODO: Search out Peer's Shared files and add them here/make them downloadable as well

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


def parse_data(file_path):
    raw_data = utils.swap(file_path, False)
    usd_data = []
    eur_data = []
    gbp_data = []
    header = raw_data.pop(0)
    for entry in raw_data:
        usd = float(entry.split('USD: ')[1].split('\tEUR')[0])
        eur = float(entry.split('EUR: ')[1].split('\tGBP')[0])
        gbp = float(entry.split('GBP: ')[1].replace('\n', ''))
        usd_data.append(usd)
        eur_data.append(eur)
        gbp_data.append(gbp)
    parsed_data = {'usd': usd_data, 'eur': eur_data, 'gbp': gbp_data}
    return parsed_data, header


def btc_price_tracking():
    name = 'btc_usd.html'
    if os.path.isfile(name):
        os.remove(name)
    current_date, current_time = utils.create_timestamp()

    '''      Find BTC/code/price_data.txt       '''
    # TODO: Block erroneous output on failed command
    if utils.cmd('find ~/BTC/code/price_log.txt'):
        data_loc = utils.cmd('find ~/BTC/code/price_log.txt').pop()
    else:
        print 'Searching again...'
        os.system('find /home/BTC/code/price*')
        data_loc = utils.cmd('find /home/BTC/code/price*').pop()

    price_data, stamp = parse_data(data_loc)
    date = stamp.split(' - ')[0].split(' ')[2]

    n_points = len(price_data['usd'])-1
    current_usd_price = price_data['usd'][n_points]
    current_gbp_price = price_data['gbp'][n_points]
    current_eur_price = price_data['eur'][n_points]

    start_time = stamp.split(' - ')[1].replace('\n', '')
    mo = date.split('/')[0]
    day = int(date.split('/')[1].split('/')[0])
    this_mo = current_date.split('/')[0]
    today = int(current_date.split('/')[1].split('/')[0])

    usd_maxima, usd_mean = np.array(price_data['usd']).max(), np.array(price_data['usd']).mean()
    eur_maxima, eur_mean = np.array(price_data['eur']).max(), np.array(price_data['eur']).mean()
    gbp_maxima, gbp_mean = np.array(price_data['gbp']).max(), np.array(price_data['gbp']).mean()

    # TODO: Use a 24hr link and parse that
    link_24hr = 'http://api.bitcoincharts.com/v1/weighted_prices.json'

    if mo == this_mo:
        d_days = today - day
        print 'N Days Diff: %d' % d_days

    meandiff_usd = current_usd_price - usd_mean
    meandiff_eur = current_eur_price - eur_mean
    meandiff_gbp = current_gbp_price - gbp_mean

    if meandiff_usd < 0:    # Handle the USD Case
        usd_c1 = 'Tomato'
        usdd = '-'
    elif meandiff_usd > 0:
        usd_c1 = 'Green'
        usdd = '+'
    else:
        usd_c1 = 'DodgerBlue'
        usdd = ''

    if meandiff_eur < 0:    # Handle the Euro Case
        eur_c1 = 'Tomato'
        eurd = '-'
    elif meandiff_eur > 0:
        eur_c1 = 'Green'
        eurd = '+'
    else:
        eur_c1 = 'DodgerBlue'
        eurd = ''

    if meandiff_gbp < 0:    # Handle the Pound Case
        gbp_c1 = 'Tomato'
        gbpd = '-'
    elif meandiff_gbp > 0:
        gbp_c1 = 'Green'
        gbpd = '+'
    else:
        gbp_c1 = 'DodgerBlue'
        gbpd = ''

    eur_c2 = 'white'
    usd_c2 = 'white'
    gbp_c2 = 'white'

    points = np.array(price_data['usd'])
    height = 400
    '''     Build the HTML for webpage          '''
    euro = u"\N{euro sign}".encode('utf-8')
    pound = u"\N{pound sign}".encode('utf-8')
    header = '<!DOCTYPE html>\n<html>\n' \
             '<meta charset="UTF-8" http-equiv="refresh" content="30;url=BTC">\n'
    title = '<head>\n<title> BTC Price </title>\n</head>\n' \
            '<h2> BTC Price Tracking \t[Running for %d Days]</h2>' % d_days
    ticker = '<div style="background-color:%s;color:%s;padding:30px;">\n' \
             '<p> $%f  - Maximum: $%f  - Mean: $%f  [%s$%d]</p>\n</div>\n' % \
             (usd_c1, usd_c2, current_usd_price, usd_maxima, usd_mean, usdd, meandiff_usd)

    ticker += '<div style="background-color:%s;color:%s;padding:30px;">\n' \
              '<p> %s%f  - Maximum: %s%f - Mean: %s%f  [%s%s%d]</p>\n\n</div>\n' % \
              (eur_c1, eur_c2, euro,  current_eur_price, euro, eur_maxima, euro, eur_mean, eurd, euro, meandiff_eur)

    ticker += '<div style="background-color:%s;color:%s;padding:30px;">\n' \
              '<p> %s%f  - Maximum: %s%f - Mean: %s%f  [%s%s%d]</p>\n\n</div>\n' % \
              (gbp_c1, gbp_c2, pound, current_gbp_price, pound, gbp_maxima, pound, gbp_mean, gbpd,pound, meandiff_gbp)
    title += ticker

    # Data must come in as vector of line data as f(x)
    graph_data = 'var c = document.getElementById("price_data");\n' \
                 'var ctx = c.getContext("2d");\n'
    p = np.array(price_data['usd'])
    scaled_y = (p /p.max())* 300.
    height = np.array(scaled_y).max() + 20
    for x in range(len(points) - 1):
        graph_data += 'ctx.lineTo(%d,%d);\nctx.stroke();\n' % (x, scaled_y[x])

    body = '</body>\n' \
           '<canvas id="price_data" width="%d" height="%d" style="border:1px solid #d3d3d3;">\n' \
           'This browser does not support the HTML5 canvas tag</canvas>\n<script>\n' \
           % (height, height)
    body += graph_data

    footer = '</script>\n</html>\n'
    content = header + title + body + footer
    open(name, 'wb').write(content)
    return content, points


if '-t' in sys.argv:
    test_dir = '../SHARED'
    content, dat = btc_price_tracking()

