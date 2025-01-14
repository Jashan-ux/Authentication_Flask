from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory ,session
from werkzeug.security import generate_password_hash, check_password_hash 
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user 
import re
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'
login_manager = LoginManager(app)
login_manager.login_view = 'login'
# CREATE DATABASE


class Base(DeclarativeBase):
    pass
    


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# CREATE TABLE IN DB


class User(UserMixin , db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))

    def set_password(self, passw):
        self.password = generate_password_hash(passw,  method = 'pbkdf2:sha512' , salt_length= 8)

    def check_password(self, passw):
        return check_password_hash(self.password, passw)


with app.app_context():
    db.create_all()


@app.route('/')
def home():
    return render_template("index.html" , logged_in = current_user.is_authenticated)


def is_valid_email(email):
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email) is not None

@app.route('/register' , methods = ["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        result = db.session.execute(db.select(User).where(User.email == email))
        # Note, email in db is unique so will only have one result.
        user = result.scalar()
        if user:
            # User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))
        
        if not is_valid_email(email):
            flash('Invalid email address!', 'danger')
            return redirect(url_for('register'))
        password = request.form.get("password")
        

        # creating new_user
        new_user = User(
            name =name,
            email =email,
            
        )
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)

        flash("Registartion successful")
        return render_template("secrets.html" , name = name)



    
    return render_template("register.html" , logged_in = current_user.is_authenticated)



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



@app.route('/login' , methods = ["GET" ,"POST"])
def login():
    if request.method =="POST":
        email = request.form.get("email")
        password =request.form.get("password")
        
        user = User.query.filter_by(email=email).first()
        
        if user is None:
            flash("That email does not exist, please try again.", "danger")
            return redirect(url_for('login'))

        if not user.check_password(password):
            flash("Password incorrect, please try again.", "danger")
            return redirect(url_for('login'))

# Login success
        if user and user.check_password(password):
            login_user(user)
            flash("Login successful!", "success")
            return render_template("secrets.html", name=user.name)
    return render_template("login.html" , logged_in = current_user.is_authenticated)


@app.route('/secrets')
@login_required
def secrets():
    
    return render_template("secrets.html", name = current_user.name )


@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged_out' , 'info')
    return redirect(url_for('login'))



@app.route('/download')
def download():
    return send_from_directory('static' , path = 'files/cheat_sheet.pdf' )


if __name__ == "__main__":
    app.run(debug=True)
