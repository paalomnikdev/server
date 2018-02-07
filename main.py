from flask import Flask, request, redirect, jsonify, url_for, flash, render_template
from flask_admin import Admin, AdminIndexView, expose
from flask_admin.contrib import sqla
from flask_admin.menu import MenuLink
from init import db
from flask_security import RoleMixin, UserMixin, SQLAlchemyUserDatastore, Security, utils, current_user, login_required
from wtforms.fields import PasswordField
import datetime
from pprint import pprint
import time
import atexit
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
import requests
import json


app = Flask(__name__, template_folder='templates', static_url_path='', static_folder='assets')
app.config.from_pyfile('settings.py')
app.secret_key = app.config['SECRET_KEY']

roles_users = db.Table(
    'roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
)


class RigStats(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rig_id = db.Column(db.Integer, index=True)
    gpu_number = db.Column(db.Integer)
    fan_speed = db.Column(db.String(255), default='0')
    power_limit = db.Column(db.String(255), default='0')
    temperature = db.Column(db.String(255), default='0')
    memory_overclock = db.Column(db.String(255), default='0')
    core_overclock = db.Column(db.String(255), default='0')

    @classmethod
    def find_by_rig_id_and_gpu_num(cls, rig_id, gpu_number):
        return cls.query.filter_by(rig_id=rig_id, gpu_number=gpu_number).first()

    @classmethod
    def find_by_rig_id(cls, rig_id):
        return cls.query.filter_by(rig_id=rig_id)

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()


class Rig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True)
    ip_address = db.Column(db.String(255), unique=True)
    active = db.Column(db.Boolean(), default=False)

    @classmethod
    def find_by_ip(cls, ip):
        return cls.query.filter_by(ip_address=ip).first()

    @classmethod
    def find_by_id(cls, id):
        return cls.query.filter_by(id=id).first()

    @classmethod
    def get_total(cls, active):
        return cls.query.filter_by(active=active).count()

    @classmethod
    def find_all(cls):
        return cls.query.all()

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()


class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

    def __str__(self):
        return self.name

    def __hash__(self):
        return hash(self.name)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean(), default=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.now())
    roles = db.relationship(
        'Role',
        secondary=roles_users,
        backref=db.backref('users', lazy='dynamic')
    )


user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)


class RigAdmin(sqla.ModelView):
    can_create = False
    can_delete = False
    can_edit = False
    list_template = 'rig_list_template.html'
    list_row_actions = ('detail_view',)
    column_searchable_list = ('ip_address', 'name')
    column_sortable_list = ('active', 'ip_address', 'name')
    column_filters = ('active', 'name')
    form_widget_args = {
        'ip_address': {
            'readonly': True
        },
        'active': {
            'onclick': 'return false;'
        },
    }

    @expose('/set-config/<rig_id>', methods=['POST'])
    def set_config(self, rig_id):
        params = request.form
        success = True
        try:
            rig = Rig.find_by_id(rig_id)
            pprint('http://{ip}/gpu-control/set-config'.format(ip=rig.ip_address))
            r = requests.post('http://{ip}/gpu-control/set-config'.format(ip=rig.ip_address), params)
            r = r.json()
            if 'success' not in r or not r['success']:
                success = False
        except:
            success = False
        return jsonify({'success': success})

    @expose('/details/<id>')
    def details_view(self, id):
        model = self.session.query(self.model).get(id)
        if not model:
            flash('Rig not found', 'error')
            return redirect('/admin/rig')
        if not model.active:
            flash('Rig is not active', 'error')
            return redirect('/admin/rig')

        try:
            rig_details = RigStats.find_by_rig_id(model.id)
        except:
            model.active = False
            model.save_to_db()
            flash('Rig is not active', 'error')
            return redirect('/admin/rig')
        return self.render('rig_details_template.html', model=model, rig_details=rig_details)


class UserAdmin(sqla.ModelView):
    column_searchable_list = ('email',)
    column_exclude_list = ('password',)
    form_excluded_columns = ('password', 'created_at')
    column_auto_select_related = True

    def is_accessible(self):
        return current_user.has_role('admin')

    def scaffold_form(self):
        form_class = super(UserAdmin, self).scaffold_form()
        form_class.password2 = PasswordField('New Password')
        return form_class

    def on_model_change(self, form, model, is_created):
        if len(model.password2):
            model.password = utils.hash_password(model.password2)


class RoleAdmin(sqla.ModelView):
    column_searchable_list = ('name', 'description')
    can_delete = False
    can_edit = False

    def is_accessible(self):
        return current_user.has_role('admin')


@app.route('/register', methods=['POST'])
def register_rig():
    secret = request.form.get('secret')
    if secret != app.config['SECRET_TOKEN']:
        return jsonify({'message': 'Who are you? I\'m not called you!Go away!'})
    name = request.form.get('name')
    ip_address = '{addr}:6789'.format(addr=request.remote_addr)
    rig = Rig.find_by_ip(ip_address)
    if rig is not None:
        rig.active = True
    else:
        rig = Rig()
        rig.ip_address = ip_address
        rig.name = name
        rig.active = True

    rig.save_to_db()

    try:
        stats = json.loads(request.form.get('stats'))
    except:
        stats = {}

    if stats:
        for key, value in stats.items():
            rig_stat = RigStats.find_by_rig_id_and_gpu_num(rig.id, key)
            if rig_stat is None:
                rig_stat = RigStats
            rig_stat.fan_speed = value['fan_speed']
            rig_stat.power_limit = value['power_limit']
            rig_stat.temperature = value['temperature']
            rig_stat.memory_overclock = value['memory_overclock']
            rig_stat.core_overclock = value['core_overclock']
            rig_stat.save_to_db()

    return jsonify({'message': 'Added successfully'})


@app.route('/')
@login_required
def index():
    return redirect('/admin')


@app.route('/.well-known/<path:path>')
def ssl_cert(path):
    return render_template('.well-known/' + path)


class MyAdminIndexView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_authenticated

    @expose('/')
    def index(self):
        return self.render(
            'homepage.html',
            online=Rig.get_total(True),
            offline=Rig.get_total(False)
        )


class LogoutMenuLink(MenuLink):

    def is_accessible(self):
        return current_user.is_authenticated


def check_rigs():
    with app.app_context():
        rigs = Rig.find_all()
        for rig in rigs:
            try:
                r = requests.get('http://{ip}/check-alive'.format(ip=rig.ip_address))
                r = r.json()
                if 'alive' in r and r['alive'] and 'result' in r and r['result']:
                    rig.active = True
                else:
                    rig.active = False

                for key, value in r['result'].items():
                    rig_stat = RigStats.find_by_rig_id_and_gpu_num(rig.id, key)
                    if rig_stat is None:
                        rig_stat = RigStats
                    rig_stat.fan_speed = value['fan_speed']
                    rig_stat.power_limit = value['power_limit']
                    rig_stat.temperature = value['temperature']
                    rig_stat.memory_overclock = value['memory_overclock']
                    rig_stat.core_overclock = value['core_overclock']
                    rig_stat.gpu_number = key
                    rig_stat.save_to_db()
            except:
                rig.active = False

            rig.save_to_db()


scheduler = BackgroundScheduler()
scheduler.start()
scheduler.add_job(
    func=check_rigs,
    trigger=IntervalTrigger(seconds=180),
    id='check_rigs',
    name='Checking rigs online',
    replace_existing=True,
    max_instances=1
)
atexit.register(lambda: scheduler.shutdown())


admin = Admin(
    app,
    name='rig-admin-{num}'.format(num=app.config['CLUSTER_NUMBER']),
    index_view=MyAdminIndexView(),
    template_mode='bootstrap3',
)

admin.add_view(UserAdmin(User, db.session))
admin.add_view(RoleAdmin(Role, db.session))
admin.add_view(RigAdmin(Rig, db.session))
admin.add_link(LogoutMenuLink(name='Logout', category='', url="/logout"))

if __name__ == '__main__':
    db.init_app(app)


    @app.before_first_request
    def create_tables():
        db.create_all()
        user_datastore.find_or_create_role(name='admin', description='Administrator')
        user_datastore.find_or_create_role(name='operator', description='Operator')

        encrypted_password = utils.hash_password('1')
        if not user_datastore.get_user('operator@example.com'):
            user_datastore.create_user(email='operator@example.com', password=encrypted_password)
        if not user_datastore.get_user('admin@example.com'):
            user_datastore.create_user(email='admin@example.com', password=encrypted_password)

        db.session.commit()

        user_datastore.add_role_to_user('operator@example.com', 'operator')
        user_datastore.add_role_to_user('admin@example.com', 'admin')

        db.session.commit()

    app.run(host=app.config['HOST'], debug=app.config['DEBUG'])
