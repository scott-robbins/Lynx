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
              '<a href="/inbox"> Inbox </a> \n' \
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
          '<title>Information</title>\n<h2> How to Join Lynx</h2>\n' \
          '<section>' \
          '<p> Thus far Lynx has been a pet project in my evenings after work and on the weekends. It started<br\n' \
          'as a LAN based system for executing commands on my Raspberry Pis to do different things... One was<br\n' \
          'a stick up cam aimed at the front steps, one was crawling the web and tracking the price of bitcoin, <br>\n' \
          'And then I started experimenting with virtual hosting... A few months later I discovered DynamicDNS, <br>\n' \
          'and well here we are...' \
          '</section>'
    l = 'Visit "https://github.com/scott-robbins/Lynx" to download the latest client (Linux Only).'
    footer = '<body>\n</html>'
    content = header + box + footer
    open('info.html', 'wb').write(content)
    return 'info.html'
