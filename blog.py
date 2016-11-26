import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db


### Prepare Jinja Environment For rendering Templates.

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'mulusrblog'


#============ START OF UTILITY FUNCTIONS =================

def render_str(template, **params):
    """
    :param template: Name of the template to be rendered. e.g. front.html
    :param params: keyword argument to be passed to template. e.g. post=post, comment=comment
    :return: returns rendered jinja2 template using params.
    """
    t = jinja_env.get_template(template)
    return t.render(params)


### Prepare secure cookie value and return to user when user login or after user registers ###

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


### Check cookie value is valid every time user sends request ###

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


### Prepare Random String of 5 characters to be used for Preparing Secure Password. ###

def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


### Prepare Secure Password when user registers. ###

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


### Validate User Password When User Logs In. ###

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


#============ END OF UTILITY FUNCTIONS =================

class BlogHandler(webapp2.RequestHandler):
    """
    BlogHandler Provides Basic Functions such as Rendering Templates,
    Validating cookie values, Login, Logout User.
    All Request Classes will be child of BlogHandler.
    """
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


### User Datastore Model ###

def users_key(group='default'):
    """
    :param group:
    :return: Returns ancestor key for User Model
    """
    return db.Key.from_path('users', group)


class User(db.Model):
    """
    Datastore Model for Storing User Data.
    """
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


### Datastore Model For Blog ###

def blog_key(name='default'):
    """
    :param name:
    :return: Returns ancestory key for Blog Entry.
    """
    return db.Key.from_path('blogs', name)


class Post(db.Model):
    """
    Datastore Model for storing Blog Entries.
    """
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    created_by = db.ReferenceProperty(User, collection_name='post')
    last_modified = db.DateTimeProperty(auto_now=True)
    likes = db.IntegerProperty(default=0)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self, comment_key=comment_key())


### Datastore Model for storing Blog Id and User Id for Blogs Liked By User. ###

class Like(db.Model):
    post_id = db.IntegerProperty(required=True)
    user_id = db.IntegerProperty(required=True)


### Datastore Model For Blog Comments.###

def comment_key(name='default'):
    """
    :param name:
    :return: Returns ancestor key for comments.
    """
    return db.Key.from_path('comments', name)


class Comment(db.Model):
    """
    Datastore Model For Storing Blog Comments.
    """
    post = db.ReferenceProperty(Post, collection_name='blog_comments')
    user_id = db.IntegerProperty(required=True)
    comment = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    def render(self):
        self._render_text = self.comment.replace('\n', '<br>')
        return render_str("comment.html", c=self)


class BlogFront(BlogHandler):
    """
    Request Class will display front page of blog.
    path: /blog
    """
    def get(self):
        posts = Post.all().ancestor(blog_key()).order('-created')
        self.render('front.html', posts=posts, comment_key=comment_key())


class PostPage(BlogHandler):
    """
    Request Class will display permalink page for blog.
    path: /blog/<post_id>
    """
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post)


class NewPost(BlogHandler):
    """
    Request Class will allow user to post new blog.
    path: /blog/new
    """
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent=blog_key(), subject=subject, content=content, created_by=self.user)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)


class EditPost(BlogHandler):
    """
    Request class will allow user to edit blog post.
    path: /blog/<post_id>/edit
    """
    def get(self, post_id):
        if self.user:
            name = self.user.name
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post.created_by.name != name:
                error = "You are only allowed to Edit Blogs created by You."
                self.render("temporary.html", error=error)
            else:
                subject = post.subject
                content = post.content
                self.render("editpost.html", subject=subject, content=content)

        else:
            self.redirect("/login")

    def post(self, post_id):
        if self.user:
            name = self.user.name
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post.created_by.name != name:
                error = "You are only allowed to Edit Blogs created by You."
                self.render("temporary.html", error=error)
            else:
                subject = self.request.get('subject')
                content = self.request.get('content')
                if subject and content:
                    post.subject = subject
                    post.content = content
                    post.put()
                    self.redirect('/blog/%s' % str(post.key().id()))
                else:
                    error = "subject and content, please!"
                    self.render("editpost.html", subject=subject, content=content, error=error)

        else:
            self.redirect("/login")


class DeletePost(BlogHandler):
    """
    Request class will allow user to delete Blog post.
    path: /blog/<post_id>/delete
    """
    def get(self, post_id):
        if self.user:
            name = self.user.name
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post.created_by.name != name:
                error = "You are only allowed to Delete Blogs created by You."
                self.render("temporary.html", error=error)
            else:
                blog_comments = post.blog_comments
                for comment in blog_comments:
                    com_key = db.Key.from_path('Comment',
                                                   int(comment.key().id()), parent=comment_key())
                    db.delete(com_key)

                if db.delete(key) is None:
                    delete_message = "You entry is deleted successfully."
                    self.render("temporary.html", delete_message=delete_message)
                else:
                    error = "Your entry was not deleted."
                    self.render("temporary.html", error=error)
        else:
            self.redirect("/login")


class LikePost(BlogHandler):
    """
    Request Class will allow user to Like Blog post from any page.
    """
    def get(self, post_id):
        if self.user:
            name = self.user.name
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post.created_by.name == name:
                error = "You can not like your own posts."
                self.render("temporary.html", error=error)
            else:
                already_liked_post = Like.all().filter('post_id =', int(post_id))\
                    .filter('user_id =', int(self.user.key().id())).count()
                print(already_liked_post)
                if not already_liked_post:
                    Like(post_id=int(post_id), user_id=int(self.user.key().id())).put()
                    post.likes += 1
                    post.put()
                self.redirect('/blog')

        else:
            self.redirect("/login")


class NewComment(BlogHandler):
    """
    Request class will allow user to add comment to blog post.
    path: /blog/<post_id>/comment/new
    """
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            self.render('newcomment.html', post=post)

        else:
            self.redirect("/login")

    def post(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            comment = self.request.get('comment')
            if comment:
                Comment(parent=comment_key(), post=post,
                        user_id=self.user.key().id(), comment=comment).put()
                self.redirect('/blog')
            else:
                error = "comment, please!"
                self.render('newcomment.html', post=post, comment_error=error)

        else:
            self.redirect("/login")


class EditComment(BlogHandler):
    """
    Request class will allow user to edit posted comments to blog.
    path: /blog/<post_id>/comment/<comment_id>/edit
    """
    def get(self, post_id, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id), parent=comment_key())
            comment = db.get(key)
            if self.user.key().id() == comment.user_id:
                key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                post = db.get(key)
                self.render('editcomment.html', post=post, comment=comment)
            else:
                comment_error = "You are only allowed to edit or delete your own comments."
                self.render('temporary.html', comment_error=comment_error)

        else:
            self.redirect("/login")

    def post(self, post_id, comment_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            key = db.Key.from_path('Comment', int(comment_id), parent=comment_key())
            com = db.get(key)
            comment = self.request.get('comment')
            if comment:
                com.comment = comment
                com.put()
                self.redirect('/blog')
            else:
                error = "comment, please!"
                self.render('editcomment.html', post=post, comment=com, comment_error=error)

        else:
            self.redirect("/login")


class DeleteComment(BlogHandler):
    """
    Request class will allow user to delete posted comments to blog.
    path: /blog/<post_id>/comment/<comment_id>/delete
    """
    def get(self, post_id, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id), parent=comment_key())
            comment = db.get(key)
            if self.user.key().id() == comment.user_id:
                if db.delete(key) is None:
                    delete_message = "Comment was deleted successfully."
                    self.render('temporary.html', delete_message=delete_message)
                else:
                    error = "Something went wrong. Your entry was not deleted." \
                            " Please Try Again."
                    self.render('temporary.html', error=error)
            else:
                comment_error = "You are only allowed to edit or delete your own comments."
                self.render('temporary.html', comment_error=comment_error)

        else:
            self.redirect("/login")


### START OF HELPER FUNCTION FOR SIGN UP.###

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)

### END OF HELPER FUNCTION FOR SIGN UP.###


class Signup(BlogHandler):
    """
    Request class allows user to signup.
    path: /signup
    """
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):
    """
    Request class validates user entry in datastore before creating new user.
    """
    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
            self.login(u)
            self.redirect('/blog')


class Login(BlogHandler):
    """
    Request class allows user to login.
    path: /login
    """
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)


class Logout(BlogHandler):
    """
    Request class allows user to logout.
    path: /logout
    """
    def get(self):
        self.logout()
        self.redirect('/blog')


app = webapp2.WSGIApplication([('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/new', NewPost),
                               ('/blog/([0-9]+)/edit', EditPost),
                               ('/blog/([0-9]+)/delete', DeletePost),
                               ('/blog/([0-9]+)/like', LikePost),
                               ('/blog/([0-9]+)/comment/new', NewComment),
                               ('/blog/([0-9]+)/comment/([0-9]+)/edit', EditComment),
                               ('/blog/([0-9]+)/comment/([0-9]+)/delete', DeleteComment),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout)
                               ],
                              debug=True)
