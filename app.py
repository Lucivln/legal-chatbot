from flask import Flask, jsonify, session, request, redirect, url_for, render_template, flash
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from functools import wraps
import requests
import os
import MySQLdb
import MySQLdb.cursors
import time
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.urandom(24)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'lv6043@srmist.edu.in'
app.config['MAIL_PASSWORD'] = '15@1004Ln'

mail = Mail(app)

# --- MySQL Config ---
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '1234'  # Replace with your actual password
app.config['MYSQL_DB'] = 'legal_chatbot_db'

mysql = MySQL(app)
bcrypt = Bcrypt(app)

# --- Ollama Config ---
OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
OLLAMA_MODEL = "indian-law-llama"

# --- Password Reset Helpers ---
def generate_token(email):
    serializer = URLSafeTimedSerializer(app.secret_key)
    return serializer.dumps(email, salt='password-reset-salt')

def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.secret_key)
    try:
        email = serializer.loads(
            token,
            salt='password-reset-salt',
            max_age=expiration
        )
        return email
    except Exception:
        return False

def send_reset_email(email):
    token = generate_token(email)
    reset_url = url_for('reset_password', token=token, _external=True)
    
    msg = Message(
        "Password Reset Request",
        sender=app.config['MAIL_USERNAME'],
        recipients=[email]
    )
    msg.body = f"""To reset your password, visit:
{reset_url}

If you didn't make this request, ignore this email.
"""
    mail.send(msg)

# --- Auth Decorators ---
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'email' not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

def role_required(*allowed_roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user_id = session.get('user_id')
            if not user_id:
                flash("Please log in first.", "warning")
                return redirect(url_for('login'))

            conn = mysql.connection
            cursor = conn.cursor()
            cursor.execute("""
                SELECT r.name    FROM roles r
                JOIN user_roles ur ON ur.role_id = r.id
                WHERE ur.user_id = %s
            """, (user_id,))
            roles = [row[0].lower() for row in cursor.fetchall()]  # Make role names lowercase
            cursor.close()

            if not any(role in allowed_roles for role in roles):
                flash("❌ Access denied: Admins only.", "danger")
                return redirect(url_for('dashboard'))

            return f(*args, **kwargs)
        return wrapper
    return decorator

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('login'))

        cursor = mysql.connection.cursor()
        cursor.execute("""
            SELECT r.name FROM user_roles ur
            JOIN roles r ON ur.role_id = r.id
            WHERE ur.user_id = %s
        """, (session['user_id'],))
        result = cursor.fetchone()
        cursor.close()

        if result and result[0].lower() == 'admin':
            return f(*args, **kwargs)
        else:
            flash('Access denied. Admins only.', 'danger')
            return redirect(url_for('dashboard'))  # or a suitable non-admin page
    return wrapper

# --- Helpers ---
def get_db_connection():
    """
    Create a new database connection
    """
    max_retries = 3
    retry_delay = 1  # seconds
    
    for attempt in range(max_retries):
        try:
            conn = MySQLdb.connect(
                host=app.config['MYSQL_HOST'],
                user=app.config['MYSQL_USER'],
                password=app.config['MYSQL_PASSWORD'],
                db=app.config['MYSQL_DB'],
                connect_timeout=10
            )
            return conn
        except MySQLdb.OperationalError as e:
            if attempt == max_retries - 1:
                raise
            time.sleep(retry_delay)

def query_ollama(prompt):
    if not prompt or prompt.strip() == "":
        raise ValueError("The provided query is empty or invalid.")
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt.strip(),
        "stream": False
    }
    try:
        response = requests.post(OLLAMA_URL, json=payload)
        response.raise_for_status()
        response_json = response.json()
        return response_json.get("response", "⚠️ No content received from model.")
    except requests.exceptions.RequestException as e:
        print(f"🛑 Ollama Error: {e}")
        return "⚠️ Failed to get a response from the legal AI model."

def store_embedding(input_text):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO legal_embeddings (input_text, output_embedding) VALUES (%s, %s)", (input_text, b'placeholder'))
    conn.commit()
    cursor.close()

# --- Routes ---
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET'])
def register_page():
    return render_template('register.html')

@app.route('/register', methods=['POST'])
def register():
    email = request.form['email']
    password_input = request.form['password']
    password = bcrypt.generate_password_hash(password_input).decode('utf-8')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    existing_user = cursor.fetchone()

    if existing_user:
        cursor.close()
        flash('⚠️ Email already registered. Please login instead.', 'warning')
        return redirect(url_for('login'))

    cursor.execute("INSERT INTO users (email, password) VALUES (%s, %s)", (email, password))
    user_id = cursor.lastrowid
    cursor.execute("INSERT INTO user_roles (user_id, role_id) VALUES (%s, %s)", (user_id, 2))  # Assuming role_id 2 = 'user'
    conn.commit()
    cursor.close()

    flash('✅ Registration successful! Please login.', 'success')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password_input = request.form['password']
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, password FROM users WHERE email = %s", (email,))
        result = cursor.fetchone()
        cursor.close()

        if result and bcrypt.check_password_hash(result[1], password_input):
            # Login successful, get user ID
            session['email'] = email
            session['user_id'] = result[0]

            # Check if the user is an admin
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT r.name
                FROM roles r
                JOIN user_roles ur ON ur.role_id = r.id
                WHERE ur.user_id = %s
            """, (session['user_id'],))
            roles = [row[0].lower() for row in cursor.fetchall()]  # Convert to lowercase
            cursor.close()

            if 'admin' in roles:
                return redirect(url_for('admin_panel'))
            else:
                return redirect(url_for('dashboard'))

        else:
            flash('❌ Invalid credentials. Try again.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        # Handle the "Ask Legal Query" option
        if 'user_query' in request.form:
            user_query = request.form['user_query']
            if not user_query:
                flash("Please enter a legal query.", "warning")
                return redirect(url_for('dashboard'))
            
            # Generate recommendations (personalized response from the AI model)
            try:
                recommendations = query_ollama(user_query)  
                return render_template('dashboard.html', email=session['email'], recommendations=recommendations)
            except Exception as e:
                flash(f"❌ Error: {str(e)}", "danger")
                return redirect(url_for('dashboard'))
    
    return render_template('dashboard.html', email=session['email'])

@app.route('/admin-panel')
@login_required
@role_required('admin')
def admin_panel():
    conn = mysql.connection
    cursor = conn.cursor()
    cursor.execute("""
        SELECT u.id, u.email, r.name AS name
        FROM users u
        LEFT JOIN user_roles ur ON u.id = ur.user_id
        LEFT JOIN roles r ON ur.role_id = r.id
        ORDER BY FIELD(r.name, 'Admin') DESC, u.email ASC
    """)
    users_roles = cursor.fetchall()
    cursor.close()

    return render_template('admin_users.html', users_roles=users_roles)

@app.route('/admin/users', methods=['GET', 'POST'])
@admin_required
def manage_users():
    cursor = mysql.connection.cursor()

    if request.method == 'POST':
        user_id = request.form.get('user_id')
        new_role = request.form.get('role', '').strip().lower()

        if not new_role:
            flash("❌ Please select a role before updating.", "warning")
        else:
            try:
                cursor.execute("DELETE FROM user_roles WHERE user_id = %s", (user_id,))
                cursor.execute("SELECT id FROM roles WHERE LOWER(name) = %s", (new_role,))
                role_id = cursor.fetchone()

                if role_id:
                    cursor.execute(
                        "INSERT INTO user_roles (user_id, role_id) VALUES (%s, %s)",
                        (user_id, role_id[0])
                    )
                    mysql.connection.commit()
                    flash(f"✅ Updated role for user ID {user_id} to {new_role.title()}.", "success")
                else:
                    flash("❌ Invalid role selected.", "danger")
            except Exception as e:
                mysql.connection.rollback()
                flash(f"❌ Error updating user role: {str(e)}", "danger")

    cursor.execute("""
        SELECT u.id, u.email, r.name
        FROM users u
        LEFT JOIN user_roles ur ON u.id = ur.user_id
        LEFT JOIN roles r ON ur.role_id = r.id
    """)
    users_roles = cursor.fetchall()
    cursor.close()

    return render_template('admin_users.html', users_roles=users_roles)

@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    results = []
    search_query = request.form.get('search_query', '').strip()
    case_type = request.form.get('case_type', '')
    start_date = request.form.get('start_date', '')
    end_date = request.form.get('end_date', '')
    boolean_query = 'boolean_query' in request.form  # checkbox

    # Build the base query
    query = "SELECT * FROM case_laws WHERE 1=1"
    params = []

    # Add search query conditions
    if search_query:
        if boolean_query:
            words = search_query.split()
            query += " AND (" + " OR ".join(["case_name LIKE %s OR case_summary LIKE %s OR case_law_text LIKE %s"] * len(words)) + ")"
            for word in words:
                like_word = f"%{word}%"
                params.extend([like_word, like_word, like_word])
        else:
            like_query = f"%{search_query}%"
            query += " AND (case_name LIKE %s OR case_summary LIKE %s OR case_law_text LIKE %s)"
            params.extend([like_query, like_query, like_query])

    # Add filters
    if case_type:
        query += " AND case_type = %s"
        params.append(case_type)

    if start_date:
        query += " AND case_date >= %s"
        params.append(start_date)

    if end_date:
        query += " AND case_date <= %s"
        params.append(end_date)

    try:
        # Use flask_mysqldb connection with DictCursor
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(query, tuple(params))
        results = cursor.fetchall()
        
        return render_template('search_results.html', 
                            results=results,
                            search_query=search_query,
                            case_type=case_type,
                            start_date=start_date,
                            end_date=end_date,
                            boolean_query=boolean_query)
                            
    except Exception as e:
        flash(f"Search error: {str(e)}", "danger")
        return redirect(url_for('view_cases'))
    finally:
        if 'cursor' in locals():
            cursor.close()

@app.route('/get_recommendations', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'user')
def get_recommendations():
    if request.method == 'POST':
        user_query = request.form.get('query')
        if not user_query:
            flash("⚠️ Please enter a query for recommendations.", "warning")
            return redirect(url_for('get_recommendations'))

        try:
            store_embedding(user_query)
            recommendations = query_ollama(user_query)
            return render_template('recommendations.html', recommendations=recommendations)
        except Exception as e:
            flash(f"❌ Error: {str(e)}", "danger")
            return redirect(url_for('dashboard'))
    return render_template('recommendations.html')

@app.route('/feedback', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'user')
def feedbacks():
    if request.method == 'POST':
        feedback_text = request.form.get('feedback_text')
        if feedback_text:
            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                # Get email from session (since that's what login_required checks)
                user_email = session['email']
                cursor.execute(
                    "INSERT INTO feedback (email, feedback_text) VALUES (%s, %s)", 
                    (user_email, feedback_text)
                )
                conn.commit()
                flash("✅ Thank you for your Feedback!", "success")
            except Exception as e:
                conn.rollback()
                flash(f"⚠️ Feedback error: {e}", "danger")
            finally:
                cursor.close()
        else:
            flash("⚠️ Please provide Feedback.", "warning")
        return redirect(url_for('feedbacks'))

    return render_template('feedback.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()
        
        if user:
            send_reset_email(email)  # Now defined
            flash('Password reset link sent to your email.', 'info')
            return redirect(url_for('login'))
        
        flash('Email not found.', 'danger')
    
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = confirm_token(token)
    if not email:
        flash('Invalid or expired reset link', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if new_password != confirm_password:
            flash('Passwords do not match', 'danger')
        elif len(new_password) < 8:
            flash('Password must be at least 8 characters', 'danger')
        else:
            hashed_pw = bcrypt.generate_password_hash(new_password).decode('utf-8')
            try:
                cursor = mysql.connection.cursor()
                cursor.execute(
                    "UPDATE users SET password = %s WHERE email = %s",
                    (hashed_pw, email)
                )
                mysql.connection.commit()
                flash('Password updated successfully! Please login', 'success')
                return redirect(url_for('login'))
            except Exception as e:
                mysql.connection.rollback()
                flash('Error updating password', 'danger')
            finally:
                cursor.close()
    
    return render_template('reset_password.html', token=token)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/ask-legal', methods=['POST'])
@login_required
def ask_legal():
    user_query = request.form.get('query')
    if not user_query:
        flash("⚠️ Please provide a query.", "warning")
        return redirect(url_for('dashboard'))

    try:
        response = query_ollama(user_query)
        return render_template('dashboard.html', email=session['email'], ai_response=response, user_query=user_query)
    except Exception as e:
        flash(f"❌ Error: {str(e)}", "danger")
        return redirect(url_for('dashboard'))

@app.route('/add_case', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def add_case():
    if request.method == 'POST':
        case_name = request.form['case_name']
        case_type = request.form['case_type']
        case_date = request.form['case_date']
        case_summary = request.form['case_summary']
        case_law_text = request.form['case_law_text']

        # Insert case into the database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO case_laws (case_name, case_type, case_date, case_summary, case_law_text)
            VALUES (%s, %s, %s, %s, %s)
        """, (case_name, case_type, case_date, case_summary, case_law_text))
        conn.commit()
        cursor.close()

        flash("✅ Landmark case added successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template('add_case.html')

@app.route('/view_cases')
@login_required
@role_required('admin', 'user')
def view_cases():
    try:
        conn = get_db_connection()
        with conn.cursor(MySQLdb.cursors.DictCursor) as cursor:
            cursor.execute("""
                SELECT id, case_name, case_type, case_date
                FROM case_laws 
                ORDER BY case_date DESC
                LIMIT 50
            """)
            cases = cursor.fetchall()
        return render_template('view_cases.html', cases=cases)
    except Exception as e:
        flash(f"Error loading cases: {str(e)}", "danger")
        return render_template('view_cases.html', cases=[])
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/search_cases', methods=['GET', 'POST'])
@login_required
def search_cases():
    if request.method == 'POST':
        keyword = request.form.get('keyword', '').strip()
        if not keyword:
            flash("Please enter a search term", "warning")
            return redirect(url_for('view_cases'))
            
        try:
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            query = """
                SELECT id, case_name, case_type, case_date
                FROM case_laws
                WHERE case_name LIKE %s OR case_type LIKE %s OR case_law_text LIKE %s
                ORDER BY case_date DESC
                LIMIT 50
            """
            like_term = f"%{keyword}%"
            cursor.execute(query, (like_term, like_term, like_term))
            results = cursor.fetchall()
            
            if not results:
                flash("No cases found matching your search", "info")
                return redirect(url_for('view_cases'))
                
            return render_template('search_results.html', results=results, keyword=keyword)
            
        except Exception as e:
            flash(f"Search error: {str(e)}", "danger")
            return redirect(url_for('view_cases'))
        finally:
            cursor.close()
    
    return redirect(url_for('view_cases'))

@app.route('/case/<int:case_id>')
@login_required
def case_details(case_id):
    try:
        conn = get_db_connection()
        with conn.cursor(MySQLdb.cursors.DictCursor) as cursor:
            cursor.execute("""
                SELECT id, case_name, case_type, case_date, case_law_text
                FROM case_laws
                WHERE id = %s
            """, (case_id,))
            case = cursor.fetchone()
            
            if not case:
                flash("Case not found", "danger")
                return redirect(url_for('view_cases'))
                
        return render_template('case_details.html', case=case)
    except Exception as e:
        flash(f"Error loading case details: {str(e)}", "danger")
        return redirect(url_for('view_cases'))
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/admin/view-feedbacks/<user_email>')
@login_required
@role_required('admin')
def view_user_feedbacks(user_email):
    try:
        # Create a new connection for this request
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get all feedbacks for the specified user
        cursor.execute("""
            SELECT feedback_text, created_at 
            FROM feedback 
            WHERE email = %s 
            ORDER BY created_at DESC
        """, (user_email,))
        
        # Convert results to list of dictionaries
        columns = [col[0] for col in cursor.description]
        feedbacks = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        # Close cursor and connection before returning
        cursor.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'feedbacks': feedbacks
        })
        
    except Exception as e:
        # Ensure connections are closed even if error occurs
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()
            
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/admin/manage-users')
@login_required
@role_required('admin')
def manageusers():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Get all users and their roles
        cursor.execute("""
            SELECT u.id, u.email, r.role 
            FROM users u
            LEFT JOIN user_roles r ON u.id = r.user_id
            ORDER BY u.email
        """)
        
        users_roles = cursor.fetchall()
        
        return render_template('admin_users.html', users_roles=users_roles)
        
    except Exception as e:
        flash(f"Error loading users: {str(e)}", "danger")
        return redirect(url_for('dashboard'))
        
    finally:
        cursor.close()
        conn.close()



# --- Run App ---
if __name__ == '__main__':
    app.run(debug=True)
