# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import webapp2
from google.appengine.ext import db
import datetime
import jinja2
import string
import hashlib
import uuid
import re

jinja_environment = jinja2.Environment(autoescape=True,
                                       loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')))


# Error strings for template errors
username_error = "Not a valid username, try something else"
username_blank = "Enter a username"
password_error = "Enter a valid password"
password_blank = "Enter a password"
verification_error = "Passwords entered do not match "
email_error = "Enter a valid email address"

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")


def valid_password(password):
    return PASS_RE.match(password)


def valid_username(username):
    return USER_RE.match(username)


def valid_email(email):
    return EMAIL_RE.match(email)


class Users(db.Model):
    username = db.StringProperty(required=True)
    password_hash = db.StringProperty(required=True)
    salt = db.StringProperty(required=True)
    email = db.EmailProperty(required=False)


def hashed_key(key, salt=None):
    if not salt:
        salt = uuid.uuid4().hex
    hashed_key = hashlib.sha512(key + salt).hexdigest()
    return "%s|%s" % (hashed_key, salt)


def gen_user_cookie(user_id):
    hashed_user_id = hashed_key(user_id, "xadahiya").split("|")[0]
    return "%s|%s" % (user_id, hashed_user_id)


def validate_user_cookie(user_cookie):
    ''' validates a user cookie string and returns a user'''
    user_id, user_id_hash = user_cookie.split("|")
    if hashed_key(user_id, "xadahiya").split("|")[0] == user_id_hash:
        return Users.get_by_id(int(user_id))
    else:
        return None


class AuthenticatorPage(webapp2.RequestHandler):

    def get(self):
        self.response.headers['Content-Type'] = 'text/html'
        template_values = {}

        template = jinja_environment.get_template('signup.html')
        self.response.out.write(template.render(template_values))

    def post(self):
        # Username validation
        template_values = {}
        try:
            username = self.request.get("username")
            if not (username and valid_username(username)):
                template_values['username_error'] = username_error
        except:
            template_values['username_error'] = username_blank

        # Password validation
        try:
            password = self.request.get("password")
            verify = self.request.get("verify")
            if not (password and valid_password(password)):
                template_values['password_error'] = password_error
            elif password != verify:
                template_values['verification_error'] = verification_error
        except:
            template_values['password_error'] = password_blank

        # Email validation
        email = self.request.get("email")
        if email:
            if not valid_email(email):
                template_values['email_error'] = email_error

        if template_values:
            template = jinja_environment.get_template('signup.html')
            self.response.out.write(template.render(template_values))
        else:
            pass_hash_str = hashed_key(password)
            pass_hash, salt = pass_hash_str.split("|")
            print pass_hash, salt
            if email:
                user = Users(username=username,
                             password_hash=pass_hash, salt=salt, email=email)
                user_key = user.put()
                user_id = str(user_key.id())
            else:
                user = Users(username=username,
                             password_hash=pass_hash, salt=salt)
                user_key = user.put()
                user_id = str(user_key.id())

            user_cookie_str = gen_user_cookie(user_id)
            self.response.headers.add_header(
                'Set-Cookie', 'userid = %s; Path=/' % user_cookie_str)

            self.redirect("/user/welcome")


class LoginPage(webapp2.RequestHandler):

    def get(self):
        self.response.headers['Content-Type'] = 'text/html'

        # user_cookie = self.request.cookies.get('userid')
        # user = validate_user_cookie(user_cookie)
        # if not user:
        template_values = {}
        template = jinja_environment.get_template('login.html')
        self.response.out.write(template.render(template_values))
        # else:
        # self.redirect('/user/welcome')

    def post(self):
        template_values = {}
        username = self.request.get("username")
        password = self.request.get("password")
        if not username:
            template_values['error'] = "Please enter a username"
        usernames = db.GqlQuery(
            ' select *  from Users where username = :1 ', username)
        try:
            user = usernames[0]
            if not hashed_key(password, user.salt).split("|")[0] == user.password_hash:
                template_values['error'] = "Invalid Password"
                template_values['username'] = username
            # print user.password_hash, user.salt
        except:
            template_values['error'] = "Username does not exits"

        if template_values:
            template = jinja_environment.get_template('login.html')
            self.response.out.write(template.render(template_values))
        else:
            user_id = str(user.key().id())
            print user_id
            user_cookie_str = gen_user_cookie(user_id)
            self.response.headers.add_header(
                'Set-Cookie', 'userid = %s; Path=/' % user_cookie_str)

            self.redirect('user/welcome')


class AuthenticationSuccessPage(webapp2.RequestHandler):

    def get(self):
        self.response.headers['Content-Type'] = 'text/html'
        user_cookie = self.request.cookies.get('userid')
        if user_cookie:
            user = validate_user_cookie(user_cookie)
            if user:
                name = user.username
                template_values = {"name": name}
                template = jinja_environment.get_template(
                    'authenticationSuccess.html')
                self.response.out.write(template.render(template_values))
        else:
            self.redirect("/signup")


class LogoutPage(webapp2.RequestHandler):

    def get(self):
        self.response.delete_cookie('userid')
        self.redirect("/signup")

# Blog post database


class BlogPosts(db.Model):
    subject = db.StringProperty()
    content = db.TextProperty()
    date_created = db.DateTimeProperty(auto_now_add=True)


class BlogPage(webapp2.RequestHandler):

    def get(self):
        self.response.headers['Content-Type'] = 'text/html'
        q = BlogPosts.all()
        q.order('-date_created')
        template_values = {"data": q}
        template = jinja_environment.get_template('blog.html')
        self.response.out.write(template.render(template_values))


class PostPage(webapp2.RequestHandler):

    def get(self, id):
        self.response.headers['Content-Type'] = 'text/html'
        id = int(id)
        post = BlogPosts.get_by_id(id)
        # q.order('-date_created')
        template_values = {"data": post}
        template = jinja_environment.get_template('blogpost.html')
        self.response.out.write(template.render(template_values))


class BlogNewPostPage(webapp2.RequestHandler):

    def get(self):
        self.response.headers['Content-Type'] = 'text/html'
        template_values = {}
        template = jinja_environment.get_template('newpost.html')
        self.response.out.write(template.render(template_values))

    def post(self):
        template_values = {}
        subject = self.request.get("subject")
        content = self.request.get("content")
        # Handles errors messages
        if not subject and not content:
            template_values[
                'error'] = "You need to enter some data for a blog post :p"
        elif not content:
            template_values['error'] = "You need to enter some content"
            template_values['subject'] = subject
        elif not subject:
            template_values['error'] = "You need to enter a subject"
            template_values["content"] = content

        if template_values:
            template = jinja_environment.get_template('newpost.html')
            self.response.out.write(template.render(template_values))
        else:
            post = BlogPosts(subject=subject, content=content)
            post_id = post.put().id()
            # print key.id()
            self.redirect('/blog/' + str(post_id))

app = webapp2.WSGIApplication([('/signup', AuthenticatorPage),
    ('/user/welcome', AuthenticationSuccessPage),
    ('/blog', BlogPage), ('/blog/newpost', BlogNewPostPage),
    (r'/blog/(\d+)', PostPage), ('/login', LoginPage),
    ('/logout', LogoutPage),
], debug=True)
