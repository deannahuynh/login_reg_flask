from flask import Flask, render_template, request, redirect, session, flash
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt
import re

app = Flask(__name__)
app.secret_key = "keep it a secret"
bcrypt = Bcrypt(app)
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$') 

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['POST'])
def register():
    form = request.form

    if ('first_name' not in form) or ('last_name' not in form) or ('email' not in form) or ('password' not in form) or ('confirm_password' not in form):
        flash("All fields are required", "all_fields")

    if len(form['first_name']) < 2:
        flash("First name must contain at least 2 characters", "first_name")
    if not form['first_name'].isalpha() == True:
        flash("First name can only contain letters")

    if len(form['last_name']) < 2:
        flash("Last name must contain at least 2 characters", "last_name")
    if not form['last_name'].isalpha() == True:
        flash("Last name can only contain letters")

    if not EMAIL_REGEX.match(form['email']):
        flash("Invalid email address!", "email")

    print(form)
    mysql = connectToMySQL('login_and_reg')
    emails = mysql.query_db("SELECT email FROM users")
    print(emails)
    for item in emails:
        if form['email'] == item['email']:
            flash("Email already exists", "email")

    if len(form['password']) < 8:
        flash("Password must contain at least 8 characters", "password")
    
    if form['password'] != form['confirm_password']:
        flash("Passwords must match", "password")
    
    if not '_flashes' in session.keys():
        pw_hash = bcrypt.generate_password_hash(form['password'])
        print(pw_hash)
        mysql = connectToMySQL('login_and_reg')
        query = "INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES (%(fn)s, %(ln)s, %(em)s, %(pw)s, NOW(), NOW());"
        data = {
            "fn": form['first_name'],
            "ln": form['last_name'],
            "em": form['email'],
            "pw": pw_hash
        }
        user = mysql.query_db(query,data)
        session['user_id'] = user
        return redirect('/success')

    return redirect('/')


@app.route('/login', methods=['POST'])
def login():
    mysql = connectToMySQL('login_and_reg')
    query = "SELECT * FROM users WHERE email = %(email)s"
    data = {
        "email": request.form['email']
    }
    user = mysql.query_db(query, data)
    
    if len(user) > 0:
        print(user[0]['password'])
        print(request.form['password'])
        if bcrypt.check_password_hash(user[0]['password'], request.form['password']):
            session['user_id'] = user[0]['id']
            return redirect('/success')

    flash("You could not be logged in ")
    return redirect('/')


@app.route('/success')
def success():
    if 'user_id' not in session:
        return redirect('/')
    
    # get user info by id
    mysql = connectToMySQL('login_and_reg')
    query = "SELECT first_name, last_name FROM users WHERE id = %(id)s;"
    data = {
        "id": session['user_id']
    }
    user = mysql.query_db(query, data)

    # get all possible 
    mysql = connectToMySQL('login_and_reg')
    query = "SELECT * FROM users WHERE id != %(id)s"
    data = {
        'id': session['user_id']
    }
    receivers = mysql.query_db(query, data)
    print('receivers')

    # get message info for messages sent to user in session
    mysql = connectToMySQL('login_and_reg')
    query = "SELECT TIMESTAMPDIFF(HOUR, messages.created_at, NOW()) AS timesince, messages.id,senders.last_name AS senders_lastname, senders.first_name AS senders_firstname, messages.content, messages.created_at FROM users AS senders JOIN messages ON senders.id = messages.sender_id JOIN users AS receivers ON receivers.id = messages.receiver_id WHERE messages.receiver_id = %(id)s ORDER BY messages.created_at DESC;"
    data = {
        "id": session['user_id']
    }
    messages = mysql.query_db(query, data)
    print(messages)
    count = 0
    for items in messages:
        count += 1


    return render_template('logged_in.html', count = count, user = user[0]['first_name'], all_receivers = receivers, my_messages = messages)
    

@app.route('/post', methods=['POST'])
def post_message():
    mysql = connectToMySQL('login_and_reg')
    users = mysql.query_db("SELECT * FROM users")
    print('users')
    return redirect('/success/post')

@app.route('/success/post')
def message_posted():
    pass


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')





if __name__ == "__main__":
    app.run(debug=True)