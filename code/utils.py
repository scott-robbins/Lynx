import security
import connect
import sys


def swap(file_name, destroy):
    data = []
    for line in open(file_name, 'r').readlines():
        data.append(line.replace('\n', ''))
    if destroy:
        os.remove(file_name)
    return data


if 'create_password' in sys.argv:
    security.create_password()
