from flask import Flask, redirect, url_for, render_template, flash, session
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, EqualTo, Length
import pymysql
import os
from dotenv import load_dotenv


app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

db_config = {
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "host": os.getenv("DB_HOST"),
    "database": os.getenv("DB_NAME"),
}


def get_db_connection():
    return pymysql.connect(**db_config)


class RegisterForm(FlaskForm):
    username = StringField(
        "Username", validators=[InputRequired(), Length(min=4, max=20)]
    )
    password = PasswordField(
        "Password", validators=[InputRequired(), Length(min=6, max=20)]
    )
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[
            InputRequired(),
            EqualTo("password", message="Passwords must match"),
        ],
    )
    submit = SubmitField("Sign Up")


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired()])
    password = PasswordField("Password", validators=[InputRequired()])
    submit = SubmitField("Sign In")


@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = generate_password_hash(form.password.data)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            flash("Username already exists. Please choose a different one.", "danger")
        else:
            cursor.execute(
                "INSERT INTO users (username, password) VALUES (%s, %s)",
                (username, password),
            )
            conn.commit()
            cursor.close()
            conn.close()

            flash("Registration successful. You are now logged in.", "success")
            session["username"] = username
            return redirect(url_for("index"))

    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
        stored_password = cursor.fetchone()
        cursor.close()
        conn.close()

        if stored_password and check_password_hash(stored_password[0], password):
            session["username"] = username
            return redirect(url_for("index"))
        else:
            flash("Login failed. Check your username and/or password.", "danger")
    return render_template("login.html", form=form)


@app.route("/index")
def index():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("index.html", username=session["username"])


@app.route("/logout")
def logout():
    session.pop("username", None)
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
