from Crypto.Cipher import AES
import security
import connect
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


def create_password():
    if os.path.isfile('pass'):
        opt = raw_input('It Looks like you already have a password. '
                        'Do you want to reset it now? (y/n):')
        if opt != ('y' or 'Y'):
            k = security.get_keys()
        else:
            k = security.get_keys()
    else:
        k = security.get_keys()
    pwd = security.EncodeAES(AES.new(k), raw_input('Enter Password: '))
    open('pass', 'wb').write(pwd)


if 'create_password' in sys.argv:
    create_password()
