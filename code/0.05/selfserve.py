from flask import Flask, render_template, redirect, url_for, request
import numpy as np
import base64
import client
import utils
import p2p
import os

app = Flask(__name__)


@app.route('/#privacy')
def tos():
    return render_template('privacy.html')


@app.route("/", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if os.path.isdir(os.getcwd() + 'LynxData'):
            # TODO: If username exists have user choose another!!!
            unames_raw = utils.cmd('ls LynxData/*.key')
            for name in unames_raw:
                uname = name.replace('.key', '')
                if uname == username:
                    return redirect(request.url)
        # REGISTER USER
        client.save_credentials(username, utils.get_ext_ip(), password)
        # FORWARD TO SUCCESS PAGE
        return redirect(request.url + 'success/' + username)

    if not os.path.isdir('LynxData'):
        return render_template("sign_up.html")
    else:  # User is already registered, so serve dash
        username, addr, pword = client.get_credentials()
        return redirect(request.url + 'enter/%s' % username)


@app.route('/success/<name>')
def success(name):
    '''
    SUCCESS directs users to splash screen
    '''
    username, addr, pword = client.get_credentials()
    return render_template('welcome.html', name=name)


@app.route('/enter/<user>')
def home(user):
    print '[*] %s has Logged In' % user
    has_shares = 'False'
    shared = {}
    if os.path.isdir(os.getcwd() + '/LynxData/Shares'):
        has_shares = 'True'
        dirdata, hashes = utils.crawl_dir('LynxData/Shares', True, False)
        shared['n'] = len(dirdata['file'])
        print dirdata
    # Get Current Date and Time
    locald, localt = utils.create_timestamp()

    # check in with backend server
    status = p2p.check_status(p2p.get_server_addr())
    latency = np.mean(p2p.check_ping())
    have_new, message_data = p2p.check_msg()
    return render_template('user_dash.html',
                           username=user.upper(),
                           share_files=has_shares,
                           connected=status,
                           date=locald,
                           time=localt,
                           delay=latency,
                           share=shared,
                           new_messages=have_new)


@app.route('/Shares')
def show_local_shares():
    if not os.path.isdir(os.getcwd() + '/LynxData/Shares'):
        os.mkdir('LynxData/Shares')

    shared, hashes = utils.crawl_dir(os.getcwd() + '/LynxData/Shares', True, False)
    print shared
    return render_template('file_system.html', shares=shared)


@app.route('/favicon.ico')
def icon():
    return open('assets/logo.png', 'rb').read()


@app.route('/logo.png')
def logo():
    return open('assets/logo.png', 'rb').read()


@app.route('/bar.png')
def bar_logo():
    return open('assets/bar.png', 'rb').read()


@app.route('/Status')
def display_network_status():
    # Show basic connectivity with lynx-network
    ping = p2p.check_ping()
    return render_template('network_status.html', ping_data=ping)


@app.route('/Settings')
def user_settings():
    username, addr, pword = client.get_credentials()
    return render_template('settings.html', username=username)


@app.route('/Upload')
def uploads():
    if not os.path.isdir('LynxData/Shares'):
        os.mkdir('LynxData/Shares')
    return render_template('upload.html')


@app.route("/handleUpload", methods=['POST'])
def handleFileUpload():
    if 'upload' in request.files:
        upload = request.files['upload']
        if upload.filename != '':
            print '[*] File %s uploaded' % upload.filename
            upload.save(os.path.join(os.getcwd() + '/LynxData/Shares/', upload.filename))
        return redirect('/')


@app.route('/Messages')
def show_messages():
    have_new, message_data = p2p.check_msg()
    lines = message_data.split('\n')
    lines.pop(-1)
    return render_template('messages.html',
                           new_messages=have_new,
                           content=lines)


@app.route('/read_message/<msg_id>')
def read_message(msg_id):
    found, data = p2p.read_msg(msg_id)
    print 'displaying %s' % data
    return render_template('read_message.html', title=msg_id, msg_found=found, msg_data=data)


@app.route('/Compose')
def create_message_form():
    # TODO: Create this template!
    return render_template('create_message.html')


@app.route('/Peers')
def show_peers():

    return render_template('peers.html')

if __name__ == '__main__':
    app.run(port=80)
