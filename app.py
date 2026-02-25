from flask import Flask, render_template, request, redirect, url_for, flash, session
from functools import wraps
from db import get_db_connection
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key-change-this')

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Home page - Display all users
@app.route('/')
@login_required
def index():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT * FROM users ORDER BY id')
        users = cur.fetchall()
        cur.close()
        conn.close()
        # FIX: render dashboard.html instead of index.html
        return render_template('dashboard.html', users=users)
    except Exception as e:
        flash(f"Error: {str(e)}", 'error')
        return redirect(url_for('login'))

# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute('SELECT * FROM users WHERE email = %s', (email,))
            user = cur.fetchone()
            cur.close()
            conn.close()

            if user and len(user) >= 5:
                stored_password = user[4]  # password is at index 4
                
                password_valid = False
                if stored_password:
                    try:
                        password_valid = check_password_hash(stored_password, password)
                    except:
                        password_valid = (stored_password == password)
                
                if password_valid:
                    session['user_id'] = user[0]
                    session['user_name'] = user[1]
                    session['user_email'] = user[2]
                    flash('Login successful!', 'success')
                    return redirect(url_for('index'))
            
            flash('Invalid email or password!', 'error')

        except Exception as e:
            flash(f"Error: {str(e)}", 'error')

    return render_template('login.html')
# Register page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not name or not email or not password:
            flash('All fields are required!', 'error')
            return render_template('register.html')

        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return render_template('register.html')

        if len(password) < 6:
            flash('Password must be at least 6 characters!', 'error')
            return render_template('register.html')

        try:
            conn = get_db_connection()
            cur = conn.cursor()

            cur.execute('SELECT id FROM users WHERE email = %s', (email,))
            if cur.fetchone():
                flash('Email already registered! Please login.', 'error')
                cur.close()
                conn.close()
                return render_template('register.html')

            hashed_password = generate_password_hash(password)

            cur.execute("""
                INSERT INTO users (name, email, password)
                VALUES (%s, %s, %s)
            """, (name, email, hashed_password))

            conn.commit()
            cur.close()
            conn.close()

            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            flash(f"Error creating account: {str(e)}", 'error')

    return render_template('register.html')

# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# CREATE - Add new user
@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')

        if not name or not email:
            flash('Name and Email are required!', 'error')
            return render_template('create.html')

        try:
            conn = get_db_connection()
            cur = conn.cursor()

            cur.execute('SELECT id FROM users WHERE email = %s', (email,))
            if cur.fetchone():
                flash('Email already exists!', 'error')
                cur.close()
                conn.close()
                return render_template('create.html')

            cur.execute(
                'INSERT INTO users (name, email) VALUES (%s, %s)',
                (name, email)
            )
            conn.commit()
            cur.close()
            conn.close()
            flash('User created successfully!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            flash(f"Error creating user: {str(e)}", 'error')

    return render_template('create.html')

# UPDATE - Edit user
@app.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update(id):
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')

        if not name or not email:
            flash('Name and Email are required!', 'error')
            return render_template('update.html', user=(id, name, email))

        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute(
                'UPDATE users SET name = %s, email = %s WHERE id = %s',
                (name, email, id)
            )
            conn.commit()
            cur.close()
            conn.close()
            flash('User updated successfully!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            flash(f"Error updating user: {str(e)}", 'error')

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT * FROM users WHERE id = %s', (id,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if not user:
            flash('User not found!', 'error')
            return redirect(url_for('index'))

        return render_template('update.html', user=user)
    except Exception as e:
        flash(f"Error: {str(e)}", 'error')
        return redirect(url_for('index'))

# DELETE - Remove user
@app.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete(id):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('DELETE FROM users WHERE id = %s', (id,))
        conn.commit()
        cur.close()
        conn.close()
        flash('User deleted successfully!', 'success')
    except Exception as e:
        flash(f"Error deleting user: {str(e)}", 'error')

    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)