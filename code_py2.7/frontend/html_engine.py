import utils
import time
import sys
import os


def hyperlink(url, label):
    return '<a href="%s">%s</a>' % (url, label)


def generate_success(uname):
    page_name = uname+'_success.html'
    header = '<!DOCTYPE html>\n<html>\n <body>\n'
    box = '<div style="background-color:DodgerBlue;color:white;padding:30px;">\n' \
          '<h2>LOGIN SUCCESSFUL</h2>\n<p>Welcome to Lynx, %s. You are one of a few peers participating in<br>' \
          'a exciting peer to peer experiment. By Reaching this page you have demonstrated that you have <br>\n' \
          'downloaded the client and created a password.<p>\n' \
          '</div>' % (uname, )
    opt_bar = '<nav>\n' \
              '<a href="/RemoteShares"> Remote Files </a> \n' \
              '<a href="/LocalShares"> My Shared Files</a>'\
              '<a href="/info"> Information </a>\n' \
              '<a href="/FAQ"> FAQ </a>\n' \
              '</nav>'
    footer = '<body>\n</html>'
    content = header+opt_bar+box+footer
    open(page_name, 'wb').write(content)
    return page_name


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


def render_file_structure(file_path):
    """
    RENDER_FILE_STRUCTURE - given a dictionary of files and a list of directories
    build a tree of nested lists in html to render on screen.
    :param directory:
    :return html_content:
    """
    header = '<!DOCTYPE html>\n<html>\n <body>\n'
    footer = '<body>\n</html>'
    '''
    <h2>A Nested List</h2>
    <p>List can be nested (lists inside lists):</p>
    
    <ul>
      <li>Coffee</li>
      <li>Tea
        <ul>
          <li>Black tea</li>
          <li>Green tea</li>
        </ul>
      </li>
      <li>Milk</li>
    </ul>
    '''
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
    open('local.html','wb').write(page)
    return page


if '-t' in sys.argv:
    test_dir = '/home/Lynx/code_py2.7/SHARED'
    content = render_file_structure(test_dir)
    print content

