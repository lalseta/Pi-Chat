from flask import Flask
from flask import request
from flask import redirect
from flask import session
from flask import render_template
from flask_socketio import SocketIO
from flask_socketio import emit
import utils.user_helper as user_helper
from flask import jsonify
from wrappers import Authenticated
import utils.globals as universal

app = Flask(__name__)
Flask.secret_key = "SOME SECRET KEY HERE"
socketio = SocketIO(app)

if __name__ == '__main__':
    socketio.run(app)

universal.client_users = []
universal.pi_users = []
universal.admin_users = []

universal.namespaces = {
    "client_users": [],
    "pi_users": []
}


def sync_users():
    global universal
    universal.client_users = user_helper.load_client_users()
    universal.pi_users = user_helper.load_pi_users()
    universal.admin_users = user_helper.load_admin_users()


@app.route('/', methods=['GET'])
def home_page():
    return redirect('/login', 302)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        sync_users()
        try:
            data = request.form;
            email = data['email']
            password = data['password']
        except AttributeError:
            return render_template('login/user_login.html', error = "Email and Password are required")

        for user in universal.client_users:
            if user['email'] == email and user['password'] == password:
                session['auth_user'] = user
                break
            else:
                session['auth_user'] = {}

        if session['auth_user'] == {}:
            for user in universal.pi_users:
                if user['email'] == email and user['password'] == password:
                    session['auth_user'] = user
                    break
                else:
                    session['auth_user'] = {}
        if session['auth_user'] != {}:
            return redirect("/chats", 302)
        else:
            return render_template('login/user_login.html', error = "Check your email and password combination")
    else:
        if 'account_created' in request.args:
            return render_template('login/user_login.html', message = "Account created successfully")
        else:
            return render_template('login/user_login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    sync_users()
    if request.method == 'GET':
        return render_template('/signup/signup_client.html')
    else:
        try:
            data = request.form
            first_name = data['first_name']
            last_name = data['last_name']
            email = data['email']
            password = data['password']
        except KeyError:
            return render_template('signup/signup_client.html', error = "All fields are require and should be valid")

        is_unique = True
        for user in universal.client_users:
            if user['email'] == email:
                is_unique = False
                break
        for user in universal.pi_users:
            if user['email'] == email:
                is_unique = False
                break
        for user in universal.admin_users:
            if user['email'] == email:
                is_unique = False
                break

        if is_unique:
            status = user_helper.write_client_users({
                "first_name": first_name,
                "last_name": last_name,
                "email": email,
                "password": password
            })

            if status:
                return redirect('/login?account_created=true', 302)
            else:
                return render_template('signup/signup_client.html', error = "Unable to register right now!")
        else:
            return render_template('signup/signup_client.html', error = "Account already exists!")


@app.route('/logout', methods=['GET'])
def logout():
    session['auth_user'] = {}
    if 'redirect_url' in request.args:
        return redirect('/admin/login', 302)
    else:
        return redirect('/login', 302)


@app.route('/chats', methods=['GET'])
@Authenticated.require_authentication
def chat_view():
    return render_template('chats/index.html')


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        sync_users()
        try:
            data = request.form
            email = data['email']
            password = data['password']
        except AttributeError:
            return render_template('admin/admin_login.html', error = "Email and Password are required")

        for user in universal.admin_users:
            if user['email'] == email and user['password'] == password:
                session['auth_user'] = user
                break
            else:
                session['auth_user'] = {}

        if session['auth_user'] != {}:
            return redirect("/admin", 302)
        else:
            return render_template('admin/admin_login.html', error = "Check your email and password combination")
    else:
        return render_template('admin/admin_login.html')


@app.route('/admin', methods=['GET'])
@Authenticated.require_admin_authentication
def admin_show_active_users():
    sync_users()
    client_users = user_helper.load_client_users()
    pie_users = user_helper.load_pi_users()
    admin_users = user_helper.load_admin_users()
    is_active = False

    if request.args.get('filter') == 'active':
        is_active = True
        active_client_users = []
        for user in client_users:
            if 'isActive' in user:
                active_client_users.append(user)

        active_pi_users = []
        for user in pie_users:
            if 'isActive' in user:
                active_pi_users.append(user)

        active_admin_users = []
        for user in admin_users:
            if 'isActive' in user:
                active_admin_users.append(user)
        client_users = active_client_users
        pie_users = active_pi_users
        admin_users = active_admin_users

    return render_template('admin/index.html',
        client_users = client_users,
        pie_users = pie_users,
        admin_users = admin_users,
        is_active = is_active
    )


@app.route('/admin/pi', methods=['GET', 'POST'])
@Authenticated.require_admin_authentication
def admin_add_pie_user():
    sync_users()
    if request.method == 'POST':
        try:
            data = request.form
            first_name = data["first_name"]
            last_name = data['last_name']
            email = data['email']
            password = data['password']
            serial_number = data['serial_number']
        except KeyError:
            return render_template('admin/pi_signup.html', error = "All fields are required")

        is_unique = True
        for user in universal.client_users:
            if user['email'] == email:
                is_unique = False
                break
        for user in universal.pi_users:
            if user['email'] == email:
                is_unique = False
                break
        for user in universal.admin_users:
            if user['email'] == email:
                is_unique = False
                break

        if is_unique:
            status = user_helper.write_pie_users({
                "first_name": first_name,
                "last_name": last_name,
                "email": email,
                "password": password,
                "serial_number": serial_number,
                "isPieUser": True
            })

            if status:
                return render_template('admin/pi_signup.html', message = "Pi Successfully Registered!")
            else:
                return render_template('admin/pi_signup.html', error = "Unable to register the pi at the moment!")
        else:
            return render_template('admin/pi_signup.html', error = "User already registered!")
    else:
        return render_template('admin/pi_signup.html')


@socketio.on('connect')
def handle_connection():
    sync_users()
    auth_user = session['auth_user']
    if 'isPieUser' in auth_user:
        namespaces_pi_users = universal.namespaces['pi_users']
        namespaces_pi_users[:] = [d for d in namespaces_pi_users if  auth_user['email'] not in d.keys()]
        namespaces_pi_users.append({ auth_user['email']: request.sid })
        universal.namespaces['pi_users'] = namespaces_pi_users
        user_helper.make_user_active(auth_user, 'pi_users')
    elif 'isAdmin' in auth_user:
        user_helper.make_user_active(auth_user, 'admnin_users')
    else:
        namespaces_client_users = universal.namespaces['client_users']
        namespaces_client_users[:] = [d for d in namespaces_client_users if auth_user['email'] not in d.keys()]
        namespaces_client_users.append({ auth_user['email']: request.sid })
        universal.namespaces['client_users'] = namespaces_client_users
        user_helper.make_user_active(auth_user, 'client_users')
    sync_users()


@socketio.on('check_serial_number')
def check_serial_number(serial_number):
    print(serial_number)
    if 'serial_number' in session['auth_user']:
        if serial_number == session['auth_user']['serial_number']:
            pass
        else:
            session['auth_user'] = {}
            return redirect('/login', 302)


@socketio.on('disconnect')
def handle_disconnect():
    auth_user = session['auth_user']
    sync_users()
    if 'isPieUser' in auth_user:
        if request.sid in universal.namespaces['pi_users']:
            universal.namespaces['pi_users'].remove(request.sid)
        user_helper.make_user_offline(auth_user, 'pi_users')
    elif 'isAdmin' in auth_user:
        user_helper.make_user_offline(auth_user, 'admnin_users')
    else:
        if request.sid in universal.namespaces['client_users']:
            universal.namespaces['client_users'].remove(request.sid)
        user_helper.make_user_offline(auth_user, 'client_users')
    sync_users()


@socketio.on('user_connected', '')
def handle_user_connected():
     sync_users()
     if 'isPieUser' in session['auth_user']:
         users = []
         for user in universal.client_users:
             if 'isActive' in user:
                 users.append(user)
         emit('get_users', users, room=request.sid)
     else:
        users = []
        for user in universal.pi_users:
            if 'isActive' in user:
                users.append(user)
        emit('get_users', users, room=request.sid)


@socketio.on('send_message')
def handle_incoming_message(packet):
    sid = {}
    if 'to' in packet:
        email = packet['to']
        message = packet['message']
        for user in universal.namespaces['pi_users']:
            if ''+email in user:
                sid = user[email]
        if not sid:
            for user in universal.namespaces['client_users']:
                if ''+email in user:
                    sid = user[email]
        packet['from'] = session['auth_user']['email']
        user_helper.store_messages(packet)
        emit('receive_message', packet, room=sid)


@socketio.on('get_previous_messages')
def handle_get_previous_messages(user):
    toEmail = user['email']
    auth_user = session['auth_user']
    sid = {}
    messages = user_helper.read_previous_messages(toEmail)

    if 'isPieUser' in auth_user:
        for namespace_user in universal.namespaces['pi_users']:
            if '' + auth_user['email'] in namespace_user:
                sid = namespace_user[auth_user['email']]
    else:
        for namespace_user in universal.namespaces['client_users']:
            if '' + auth_user['email'] in namespace_user:
                sid = namespace_user[auth_user['email']]
    for message in messages:
        emit('receive_message', message, room=sid)
        user_helper.delete_message(message)
