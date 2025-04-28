from app import db, User, app
from werkzeug.security import generate_password_hash

admin = User(
    username='admin',
    password=generate_password_hash('1234567890'),
    role='admin'
)

with app.app_context():
    db.session.add(admin)
    db.session.commit()

print("Admin user created successfully!")
