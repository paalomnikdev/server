from main import app, user_datastore, utils
from init import db

if __name__ == "__main__":
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

    app.run()
