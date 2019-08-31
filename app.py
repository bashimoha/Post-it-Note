from flask import Flask, request, render_template, url_for, flash, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
# import flask_whooshalchemy\
# import flask_whooshalchemy as wa
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required

app = Flask(__name__)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=True
app.config['TRAP_HTTP_EXCEPTIONS']=True
app.config['SECRET_KEY']='266ab363d3399900a41fad7960e14e39'


ENV = 'prod'
if ENV == 'dev':
	app.debug = True
	app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///site.db'
else:
	app.debug = False
	app.config['SQLALCHEMY_DATABASE_URI']='postgres://yducqsuqswsxwq:1e2f13b10499081094fb1ee1fb6e62e0c791d40860649b6c46748e3e1ef0b72b@ec2-174-129-242-183.compute-1.amazonaws.com:5432/dacseqhigh7uvu'
# app.config['WHOOSH_BASE']='whoosh'
db = SQLAlchemy(app)
bycrypt = Bcrypt(app)
login_manager = LoginManager(app)


@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))


class User(db.Model, UserMixin):
	"""docstring for ClassName"""
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(20), nullable=False, unique=True)
	email = db.Column(db.String(120), nullable=False, unique=True)
	password = db.Column(db.String(60), nullable=False)
	notes = db.relationship('Note', backref='author', lazy=True)
	def __repr__(self):
		return f"User('{self.username}', '{self.email}')"

# 
class Note(db.Model):
	# __searchable__ =['text', 'id']

	id = db.Column(db.Integer, primary_key=True)
	text = db.Column(db.Text, nullable=False)
	complete=db.Column(db.Boolean)
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

	def __repr__(self):
		return f'{self.id} {self.text}'
		# return f"Note('{self.id} | {self.text}')"
	def __int__(self):
		return self.id

class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')

class LoginForm(FlaskForm):
	email = StringField('Email', validators=[DataRequired(), Email() ])

	password = PasswordField("Password", validators=[DataRequired()])

	remember = BooleanField('Remember Me')

	submit = SubmitField("Login") 

# wa.whoosh_index(app, Note)



@app.route('/')
@app.route('/home/')
def home():
	if current_user.is_authenticated:
		note = current_user.notes
		return render_template('index.html', notes=note)
	else:
		return render_template('index.html')

		

@app.route("/register", methods=['GET', 'POST'])
def register():
	if current_user.is_authenticated:
		# return redirect(url_for('home'))
		return redirect(url_for('home'))
	form = RegistrationForm()
	if form.validate_on_submit():
		hashed_password = bycrypt.generate_password_hash(form.password.data).decode('utf-8')
		user = User(username=form.username.data, email=form.email.data, password=hashed_password)
		db.session.add(user)
		db.session.commit()
		flash('Your Account has been created! you can log in', 'success')
		return redirect(url_for('home'))
	return render_template('register.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
	if current_user.is_authenticated:
		return redirect(url_for('home'))
	form = LoginForm()
	if form.validate_on_submit():
		user=User.query.filter_by(email=form.email.data).first()
		if user and bycrypt.check_password_hash(user.password, form.password.data):
			login_user(user, remember=form.remember.data)
			return redirect(url_for('home'))
			# return redirect(url_for('home'))
		else:
			flash('Login Unsuccessful. Please check email and password', 'danger')
	return render_template('login.html', title='Login', form=form)



#add new note to the database or update n
@app.route('/<update>/<id>',methods=['POST'])
@app.route('/add', methods=['POST'])
@login_required
def add(id=None, update=None):
	if id != None:
		obj = Note.query.get(id)
		# return f"<h1>{+5obj.text}</h1>"
		db.session.delete(obj)
		# db.session.commit()
		note = Note(text=request.form['text'], complete=False, author=current_user)
		db.session.add(note)
		db.session.commit()
	else:
		note = Note(text=request.form['text'], complete=False, author=current_user)
		db.session.add(note)
		db.session.commit()
	return redirect(url_for('home'))

#delete Post from the database
@app.route('/remove/<note_id>', methods=['POST'])
@login_required
def remove(note_id):
	obj = Note.query.get(note_id)
	db.session.delete(obj)
	db.session.commit()
	return redirect(url_for('home'))

@app.route('/delete', methods=['POST'])
@login_required
def delete():
	db.session.query(Note).delete()
	db.session.commit()
	return redirect(url_for('home'))

@app.route('/logout')
@login_required
def logout():
	logout_user()
	return redirect(url_for('home'))
@app.errorhandler(Exception)
def error401(error):
	return render_template('error.html')

@app.route('/about/')
def about():
	return render_template('about.html')

if __name__ == '__main__':
	app.run() 