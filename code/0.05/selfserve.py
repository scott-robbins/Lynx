from flask import Flask, render_template, redirect, url_for, request
import base64
import client
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
        # TODO: If username exists have user choose another!!!
        # REGISTER USER
        client.save_credentials(username, password)
        # FORWARD TO SUCCESS PAGE
        return redirect(request.url+'/enter/'+username)

    if not os.path.isdir('LynxData'):
    	return render_template("sign_up.html")
    else:  # User is already registered, so serve dash
    	username, addr, pword = client.get_credentials()
    	return redirect(request.url+'/enter/%s' % username)

@app.route('/success/<name>')
def success(name):
	username, addr, pword = client.get_credentials()
	return render_template('welcome.html', name=name)

@app.route('/enter/<user>')
def home(user):
	print '[*] %s has Logged In' % user
	return render_template('user_dash.html', username=user)


if __name__ == '__main__':
   app.run(port=80)
