from flask import Flask, render_template, request, redirect, session, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# Configure database
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/student_management'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
course_students = db.Table('course_students',
    db.Column('course_id', db.Integer, db.ForeignKey('course.id')),
    db.Column('student_id', db.Integer, db.ForeignKey('user.id'))
)

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(20), unique=True, nullable=False)
    lecturer_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    lecturer = db.relationship('User', backref='courses_taught', foreign_keys=[lecturer_id])
    students = db.relationship('User', secondary='course_student', backref='courses_enrolled')

# Chat model for storing messages
class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(50), nullable=False)
    recipient = db.Column(db.String(50), nullable=False)  # Optional: For direct messages
    message = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.now())  # Automatically add timestamp


course_student = db.Table(
    'course_student',
    db.Column('course_id', db.Integer, db.ForeignKey('course.id')),
    db.Column('student_id', db.Integer, db.ForeignKey('user.id'))
)

# Database models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum('admin', 'lecturer', 'student'), nullable=False)


class Enrollment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)
    student = db.relationship('User', backref='enrollments')
    course = db.relationship('Course', backref='enrollments')


# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check user in database
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = user.role
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'lecturer':
                return redirect(url_for('lecturer_dashboard'))
            elif user.role == 'student':
                return redirect(url_for('student_dashboard'))
        else:
            return "Invalid username or password"

    return render_template('login.html')
@app.route('/chat', methods=['GET', 'POST'])
def chat():
    if 'user_id' not in session:
        return redirect('/login')

    # Display chat history
    chat_history = ChatMessage.query.order_by(ChatMessage.timestamp).all()

    if request.method == 'POST':
        # Get the message from the form
        sender = session['role']  # Use the logged-in user's role
        message = request.form['message']
        recipient = request.form.get('recipient', 'All')  # Optional: For direct messages

        # Save the message to the database
        new_message = ChatMessage(sender=sender, recipient=recipient, message=message)
        db.session.add(new_message)
        db.session.commit()
        return redirect('/chat')

    return render_template('chat.html', chat_history=chat_history)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# Admin Dashboard
@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if 'role' in session and session['role'] == 'admin':
        admins = User.query.filter_by(role='admin').all()
        lecturers = User.query.filter_by(role='lecturer').all()
        students = User.query.filter_by(role='student').all()
        courses = Course.query.all()
        return render_template('admin_dashboard.html', admins=admins, lecturers=lecturers, students=students, courses=courses)
    return redirect('/login')

# Lecturer Dashboard
@app.route('/lecturer_dashboard')
def lecturer_dashboard():
    if 'role' in session and session['role'] == 'lecturer':
        lecturer_id = session['user_id']
        courses = Course.query.filter_by(lecturer_id=lecturer_id).all()
        return render_template('lecturer_courses.html', courses=courses)
    return redirect('/login')

@app.route('/course_students/<int:course_id>', methods=['GET', 'POST'])
def course_students(course_id):
    if 'role' in session and session['role'] == 'lecturer':
        course = Course.query.get(course_id)

        if not course or course.lecturer_id != session['user_id']:
            return "Unauthorized access", 403

        students = User.query.filter_by(role='student').all()
        enrolled_students = [enrollment.student for enrollment in course.enrollments]

        if request.method == 'POST':
            student_id = request.form['student_id']
            action = request.form['action']

            if action == 'add':
                if not any(e.student_id == int(student_id) for e in course.enrollments):
                    enrollment = Enrollment(student_id=student_id, course_id=course_id)
                    db.session.add(enrollment)
                    db.session.commit()
            elif action == 'remove':
                enrollment = Enrollment.query.filter_by(student_id=student_id, course_id=course_id).first()
                if enrollment:
                    db.session.delete(enrollment)
                    db.session.commit()

            return redirect(url_for('course_students', course_id=course_id))

        return render_template('course_students.html', course=course, students=students, enrolled_students=enrolled_students)
    return redirect('/login')

# Student Dashboard
@app.route('/student_dashboard')
def student_dashboard():
    if 'role' in session and session['role'] == 'student':
        student_id = session['user_id']
        enrollments = Enrollment.query.filter_by(student_id=student_id).all()
        return render_template('student_dashboard.html', enrollments=enrollments)
    return redirect('/login')

@app.route('/manage_course_students/<int:course_id>', methods=['GET', 'POST'])
def manage_course_students(course_id):
    if 'role' in session and session['role'] == 'admin':
        course = Course.query.get(course_id)
        if not course:
            return "Course not found!", 404
        
        students = User.query.filter_by(role='student').all()

        if request.method == 'POST':
            student_id = request.form.get('student_id')
            action = request.form.get('action')

            student = User.query.get(student_id)
            if not student:
                return "Student not found!", 404

            if action == "add":
                course.students.append(student)
            elif action == "remove" and student in course.students:
                course.students.remove(student)

            db.session.commit()
            return redirect(f'/manage_course_students/{course_id}')

        return render_template('manage_course_students.html', course=course, students=students)
    return redirect('/login')


# Add, Edit, and Delete Courses
@app.route('/add_course', methods=['POST'])
def add_course():
    if 'role' in session and session['role'] == 'admin':
        name = request.form['name']
        code = request.form['code']
        lecturer_id = request.form['lecturer_id']
        course = Course(name=name, code=code, lecturer_id=lecturer_id)
        db.session.add(course)
        db.session.commit()
        return redirect('/admin_dashboard')
    return redirect('/login')

@app.route('/edit_course/<int:course_id>', methods=['GET', 'POST'])
def edit_course(course_id):
    if 'role' in session and session['role'] == 'admin':
        course = Course.query.get(course_id)
        if request.method == 'POST':
            course.name = request.form['name']
            course.code = request.form['code']
            course.lecturer_id = request.form['lecturer_id']
            db.session.commit()
            return redirect('/admin_dashboard')
        lecturers = User.query.filter_by(role='lecturer').all()
        return render_template('edit_course.html', course=course, lecturers=lecturers)
    return redirect('/login')

@app.route('/delete_course/<int:course_id>', methods=['POST'])
def delete_course(course_id):
    if 'role' in session and session['role'] == 'admin':
        course = Course.query.get(course_id)
        if course:
            db.session.delete(course)
            db.session.commit()
        return redirect('/admin_dashboard')
    return redirect('/login')

# Enroll in Courses
@app.route('/enroll_course/<int:course_id>', methods=['POST'])
def enroll_course(course_id):
    if 'role' in session and session['role'] == 'student':
        student_id = session['user_id']
        enrollment = Enrollment(student_id=student_id, course_id=course_id)
        db.session.add(enrollment)
        db.session.commit()
        return redirect('/student_dashboard')
    return redirect('/login')

@app.route('/update_user/<int:user_id>', methods=['GET', 'POST'])
def update_user(user_id):
    if 'role' in session and session['role'] == 'admin':
        user = User.query.get(user_id)
        if not user:
            return "User not found!", 404

        if request.method == 'POST':
            user.username = request.form['username']
            if request.form['password']:
                user.password = generate_password_hash(request.form['password'])
            user.role = request.form['role']
            db.session.commit()
            return redirect('/admin_dashboard')

        return render_template('update_user.html', user=user)
    return redirect('/login')

# Lecturer-specific Features
@app.route('/lecturer_courses')
def lecturer_courses():
    if 'role' in session and session['role'] == 'lecturer':
        lecturer_id = session['user_id']
        courses = Course.query.filter_by(lecturer_id=lecturer_id).all()
        return render_template('lecturer_courses.html', courses=courses)
    return redirect('/login')

@app.route('/lecturer_students/<int:course_id>')
def lecturer_students(course_id):
    if 'role' in session and session['role'] == 'lecturer':
        enrollments = Enrollment.query.filter_by(course_id=course_id).all()
        return render_template('lecturer_students.html', enrollments=enrollments)
    return redirect('/login')

@app.route('/add_student_to_course/<int:course_id>', methods=['GET', 'POST'])
def add_student_to_course(course_id):
    if 'role' in session and session['role'] in ['admin', 'lecturer']:
        course = Course.query.get(course_id)
        students = User.query.filter_by(role='student').all()
        enrolled_students = [enrollment.student_id for enrollment in course.enrollments]

        if request.method == 'POST':
            student_id = request.form['student_id']
            if student_id not in enrolled_students:
                enrollment = Enrollment(student_id=student_id, course_id=course_id)
                db.session.add(enrollment)
                db.session.commit()
            return redirect(url_for('view_course_students', course_id=course_id))

        return render_template('add_student_to_course.html', course=course, students=students, enrolled_students=enrolled_students)
    return redirect('/login')

@app.route('/view_course_students/<int:course_id>')
def view_course_students(course_id):
    if 'role' in session and session['role'] in ['admin', 'lecturer']:
        course = Course.query.get(course_id)
        enrollments = Enrollment.query.filter_by(course_id=course_id).all()
        return render_template('view_course_students.html', course=course, enrollments=enrollments)
    return redirect('/login')

@app.route('/add_student', methods=['POST'])
def add_student():
    if 'role' in session and session['role'] == 'admin':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)

        new_student = User(username=username, password=hashed_password, role='student')
        db.session.add(new_student)
        db.session.commit()
        return redirect('/admin_dashboard')
    return redirect('/login')

@app.route('/view_student_courses/<int:student_id>')
def view_student_courses(student_id):
    if 'role' in session and session['role'] == 'admin':
        student = User.query.get(student_id)
        if not student or student.role != 'student':
            return "Student not found!", 404
        return render_template('view_student_courses.html', student=student)
    return redirect('/login')

@app.route('/view_lecturer_courses/<int:lecturer_id>')
def view_lecturer_courses(lecturer_id):
    if 'role' in session and session['role'] == 'admin':
        lecturer = User.query.get(lecturer_id)
        if not lecturer or lecturer.role != 'lecturer':
            return "Lecturer not found!", 404
        return render_template('view_lecturer_courses.html', lecturer=lecturer)
    return redirect('/login')

@app.route('/admin_course_students/<int:course_id>')
def admin_course_students(course_id):
    if 'role' in session and session['role'] == 'admin':
        course = Course.query.get(course_id)
        if not course:
            return "Course not found!", 404

        enrolled_students = course.students  # Students already in the course
        all_students = User.query.filter_by(role='student').all()  # All students
        return render_template(
            'admin_course_students.html',
            course=course,
            enrolled_students=enrolled_students,
            all_students=all_students
        )
    return redirect('/login')


@app.route('/admin_add_student_to_course/<int:course_id>', methods=['POST'])
def admin_add_student_to_course(course_id):
    if 'role' in session and session['role'] == 'admin':
        student_id = request.form['student_id']
        course = Course.query.get(course_id)
        student = User.query.get(student_id)

        if not course or not student:
            return "Invalid course or student!", 404

        course.students.append(student)
        db.session.commit()
        return redirect(f'/admin_course_students/{course_id}')
    return redirect('/login')


@app.route('/admin_remove_student_from_course/<int:course_id>/<int:student_id>', methods=['POST'])
def admin_remove_student_from_course(course_id, student_id):
    if 'role' in session and session['role'] == 'admin':
        course = Course.query.get(course_id)
        student = User.query.get(student_id)

        if not course or not student:
            return "Invalid course or student!", 404

        course.students.remove(student)
        db.session.commit()
        return redirect(f'/admin_course_students/{course_id}')
    return redirect('/login')
@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'role' in session and session['role'] == 'admin':
        user = User.query.get(user_id)
        if user and user.role != 'admin':  # Prevent deletion of Admin users
            db.session.delete(user)
            db.session.commit()
        return redirect('/admin_dashboard')
    return redirect('/login')

@app.route('/add_user', methods=['POST'])
def add_user():
    if 'role' in session and session['role'] == 'admin':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        # Hash the password before storing it
        hashed_password = generate_password_hash(password)

        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/admin_dashboard')
    return redirect('/login')



# Create tables
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
