from flask import Flask, render_template, redirect, url_for, request
import base64
import client
import utils
import os

app = Flask(__name__)

@app.route('/#privacy')
def tos():
	return render_templace('privacy.html')

@app.route("/", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if os.path.isdir(os.getcwd()+'LynxData'):
        	# TODO: If username exists have user choose another!!!
        	unames_raw = utils.cmd('ls LynxData/*.key')
        	for name in unames_raw:
        		uname = name.replace('.key','')
        		if uname == username:
        			return redirect(request.url)
        # REGISTER USER
        client.save_credentials(username, password)
        # FORWARD TO SUCCESS PAGE
        return redirect(request.url+'success/'+username)

    if not os.path.isdir('LynxData'):
    	return render_template("sign_up.html")
    else:  # User is already registered, so serve dash
    	username, addr, pword = client.get_credentials()
    	return redirect(request.url+'enter/%s' % username)

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
	has_shares = False
	if os.path.isdir('LynxData/Shared'):
		has_shares = True
	return render_template('user_dash.html',
						   username=user,
						   share_files=has_shares)

@app.route('/shares')
def show_local_shares():
	if os.path.isdir(os.getcwd()+'LynxData/Shares'):
		shared, hashes = utils.crawl_dir(os.getcwd()+'LynxData/Shares')
	else:
		os.mkdir('LynxData/Shares')
		shared, hashes = utils.crawl_dir(os.getcwd()+'LynxData/Shares')
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

if __name__ == '__main__':
   app.run(port=80)
