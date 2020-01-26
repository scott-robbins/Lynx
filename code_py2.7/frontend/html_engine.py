import time
import sys
import os


def generate_success(uname):
    page_name = uname+'_success.html'
    header = '<!DOCTYPE html>\n<html>\n <body>\n'
    box = '<div style="background-color:DodgerBlue;color:white;padding:30px;">\n' \
          '<h2>LOGIN SUCCESSFUL</h2>\n<p>Welcome to Lynx, %s. You are one of a few peers participating in<br>' \
          'a exciting peer to peer experiment. By Reaching this page you have demonstrated that you have <br>\n' \
          'downloaded the client and created a password.<p>\n' \
          '</div>' % (uname, )

    footer = '<body>\n</html>'
    content = header+box+footer
    open(page_name, 'wb').write(content)
    return page_name
