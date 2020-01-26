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

    footer = '<body>\n</html>'
    content = header+box+footer
    open(page_name, 'wb').write(content)
    return page_name


def display_information(client_addr, user_agent):
    header = '<!DOCTYPE html>\n<html>\n <body>\n'
    box = '<div style="background-color:MediumSeaGreen;color:white;paddding:30px;">\n' \
          '<title>Information<title>\n<h2> How to Join Lynx</h2>\n' \
          '<p> Lynx is a experimental peer to peer network. Many attempts have been made, and forms of' \
          'peer to peer file sharing are successful, but most have either been plagued with inherent <br>\n' \
          'centrality, or are difficult to trust because the protocol/code is not made public. <br>\n' \
          'In addition to research, the mission of Lynx is to return to roots of what peer to peer designs have' \
          'to offer.<p>\n'
    l = 'Visit "https://github.com/scott-robbins/Lynx" to download the latest client (Linux Only).'
    link = hyperlink('https://github.com/scott-robbins/Lynx', l)
    footer = '<body>\n</html>'
    content = header + box + link + footer
    open('info.html', 'wb').write(content)
    return 'info.html'
