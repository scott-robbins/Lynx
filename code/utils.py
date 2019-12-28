from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import base64
import sys
import os


def swap(file_name, destroy):
    data = []
    for line in open(file_name, 'r').readlines():
        data.append(line.replace('\n', ''))
    if destroy:
        os.remove(file_name)
    return data


def cmd(shell):
    os.system('%s >> tmp.txt' % shell)
    return swap('tmp.txt', True)


def arr2str(arr):
    content = ''
    for e in arr:
        content += e + ' '
    return content


def arr2lines(arr):
    content = ''
    for line in arr:
        content += line + '\n'
    return content


def get_lan_ip():
    ip = ''
    cmd1 = 'ifconfig | grep BROADCAST | grep RUNNING'
    nic = cmd(cmd1).pop().split(':')[0]
    cmd2 = 'ifconfig %s  | grep netmask' % nic
    try:
        ip = cmd(cmd2).pop().split(' netmask ')[0].split(' inet ')[1]
    except IndexError:
        pass
    return ip



