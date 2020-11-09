import os
from dotenv import load_dotenv
from flask import Flask, session
from flask_babel import Babel
from flask_scss import Scss
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect()

def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    load_dotenv()
    app.config.update(os.environ)
    app.config['BABEL_TRANSLATION_DIRECTORIES'] = os.getcwd() + app.config['BABEL_TRANSLATION_DIRECTORIES']
    csrf.init_app(app)
    babel = Babel(app)

    @babel.localeselector
    def get_locale():
        if "hr" not in session:
            return app.config['BABEL_DEFAULT_LOCALE']
        return session['lang']
    # ====
    Scss(app)


    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    from .views import main_views

    app.register_blueprint(main_views.main)

    return app
