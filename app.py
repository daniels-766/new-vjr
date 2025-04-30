from flask import Flask, render_template, redirect, url_for, request, flash, session, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import random
from PIL import Image, ImageDraw, ImageFont, ImageFilter
import random, string, io
from sqlalchemy import text, or_
from flask_migrate import Migrate
from math import ceil
import pandas as pd
from datetime import datetime
from werkzeug.utils import secure_filename
import os
import io
from sqlalchemy.sql import func
from flask import render_template
from flask_apscheduler import APScheduler
from flask import jsonify

ALLOWED_EXTENSIONS = {'xls', 'xlsx'}

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/vjr_new'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 
app.config['MAX_CONTENT_LENGTH'] = 150 * 1024 * 1024
app.config['SECRET_KEY'] = 'b35dfe6ce150230940bd145823034486' 

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
migrate = Migrate(app, db)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

class Config:
    SCHEDULER_API_ENABLED = True

app.config.from_object(Config())
scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    id_system = db.Column(db.String(255))
    username = db.Column(db.String(255))
    phone = db.Column(db.String(15))
    email = db.Column(db.String(255))
    group = db.Column(db.Integer, db.ForeignKey('user_group.id'))  
    status = db.Column(db.String(10), default='active')
    password = db.Column(db.String(255))
    role = db.Column(db.String(50))
    num_sip = db.Column(db.String(255))
    pas_sip = db.Column(db.String(255))

    group_rel = db.relationship('UserGroup', backref=db.backref('users', lazy=True))

class UserGroup(db.Model):  
    __tablename__ = 'user_group' 
    id = db.Column(db.Integer, primary_key=True)
    company = db.Column(db.String(255))
    status = db.Column(db.String(10), default='active')
    overdue = db.Column(db.String(50))

class Data(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_no = db.Column(db.String(50))
    nama_nasabah = db.Column(db.String(255))
    alamat = db.Column(db.Text)
    pekerjaan = db.Column(db.String(255))
    waktu_peminjaman = db.Column(db.String(255))
    exp_date = db.Column(db.Date)
    phone = db.Column(db.String(255))
    pokok_pinjaman = db.Column(db.String(255))
    total_tagihan = db.Column(db.String(255))
    overdue = db.Column(db.String(255))
    nama_ec1 = db.Column(db.String(255))
    nomor_ec1 = db.Column(db.String(255))
    nama_ec2 = db.Column(db.String(255))
    phone_ec2 = db.Column(db.String(255))
    tanggal_upload = db.Column(db.DateTime, default=db.func.current_timestamp())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id')) 
    remark = db.Column(db.String(255), default='not_ptp')
    catatan = db.Column(db.Text)

    group_rel = db.relationship('User', backref=db.backref('data', lazy=True))  

class UserActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    activity = db.Column(db.String(255))
    route = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

    user = db.relationship('User', backref=db.backref('activities', lazy=True))

@scheduler.task('cron', id='delete_expired_data', hour=0)
def delete_expired_data():
    today = datetime.now().date()
    expired_data = Data.query.filter(Data.exp_date <= today).all()
    
    for data in expired_data:
        db.session.delete(data)
    
    db.session.commit()
    print(f"[Scheduler] {len(expired_data)} data dengan exp_date <= {today} berhasil dihapus otomatis.")

@scheduler.task('cron', id='delete_orphan_data', hour=0)
def delete_orphan_data():
    with app.app_context():
        orphan_data = Data.query.filter(Data.user_id == None).all()
        
        if orphan_data:
            for data in orphan_data:
                db.session.delete(data)
            db.session.commit()
            print(f"[Orphan Cleaner] {len(orphan_data)} data tanpa user_id dihapus.")

@app.before_request
def log_user_activity():
    if current_user.is_authenticated and current_user.role == 'user':
        ignored_routes = ['/static', '/favicon.ico', '/login', '/logout', '/log_user', '/activity', '/captcha_img']

        if any(request.path.startswith(ignored) for ignored in ignored_routes):
            return 
        
        current_route = request.path
        print(f"{current_user.username} mengakses {current_route}")

        activity_log = f"{current_user.username} mengakses {current_route}"
        
        new_activity = UserActivity(
            user_id=current_user.id,
            activity=activity_log,
            route=current_route
        )
        db.session.add(new_activity)

        try:
            db.session.commit() 
        except Exception as e:
            db.session.rollback()
            print(f"Error saving activity log: {e}")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/view_data')
def view_data():
    return render_template('upload_data.html', username=current_user.username)

@app.route('/manage_group')
@login_required
def manage_group():

    if current_user.role != 'admin':
        return redirect(request.referrer)

    groups = UserGroup.query.all()
    return render_template('manage_group.html', username=current_user.username, groups=groups, num_sip=current_user.num_sip,
        pas_sip=current_user.pas_sip)

@app.route('/update_group_status', methods=['POST'])
@login_required
def update_group_status():
    group_id = request.form['group_id']
    new_status = request.form['status']

    group = UserGroup.query.get(group_id)
    if group:
        group.status = new_status
        db.session.commit()
        flash('Group status updated successfully', 'success')
    else:
        flash('Group not found', 'danger')

    return redirect(url_for('manage_group'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        input_captcha = request.form.get('captcha_input')
        saved_captcha = session.get('captcha')

        if input_captcha != saved_captcha:
            flash('Kode verifikasi salah!', 'danger')
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()
        if user:
            if user.status == 'nonactive':
                flash('Akun sedang disable', 'danger')
                return redirect(url_for('login'))

            group = UserGroup.query.get(user.group)
            if group and group.status == 'nonactive':
                flash('Akun sedang disable', 'danger')
                return redirect(url_for('login'))

            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                flash('Username or Password is incorrect!', 'danger')
                return redirect(url_for('login'))

        flash('Username or Password is incorrect!', 'danger')
        return redirect(url_for('login'))

    session['captcha'] = str(random.randint(100000, 999999)) 
    return render_template('login.html', captcha=session['captcha'])

@app.route('/captcha_img')
def captcha_img():
    captcha_text = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    session['captcha'] = captcha_text

    width, height = 160, 60
    image = Image.new('RGB', (width, height), (255, 255, 255))
    font = ImageFont.truetype('arial.ttf', 28) 
    draw = ImageDraw.Draw(image)

    for i, char in enumerate(captcha_text):
        draw.text((10 + i * 24, 10), char, font=font, fill=(0, 0, 0))

    for _ in range(5):
        x1, y1 = random.randint(0, width), random.randint(0, height)
        x2, y2 = random.randint(0, width), random.randint(0, height)
        draw.line(((x1, y1), (x2, y2)), fill=(0, 0, 0), width=1)

    image = image.filter(ImageFilter.GaussianBlur(1))

    buffer = io.BytesIO()
    image.save(buffer, 'PNG')
    buffer.seek(0)
    return send_file(buffer, mimetype='image/png')

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return render_template('admin_dashboard.html', username=current_user.username, num_sip=current_user.num_sip,
        pas_sip=current_user.pas_sip)
    elif current_user.role == 'user':
        return render_template('client_dashboard.html', username=current_user.username, num_sip=current_user.num_sip,
        pas_sip=current_user.pas_sip)
    else:
        return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/add_group', methods=['POST'])
@login_required
def add_group():
    try:
        company = request.form['company']
        overdue = request.form['overdue']

        new_group = UserGroup(company=company, overdue=overdue)  
        db.session.add(new_group)
        db.session.commit()

        flash("Group added successfully!", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error: {str(e)}", "danger")

    return redirect(url_for('manage_users'))

@app.route('/add-account', methods=['POST'])
def add_account():
    id_system = request.form['id']
    username = request.form['username']
    password = request.form['password']
    phone = request.form['number']
    email = request.form['email']
    group_id = request.form['group']
    role = request.form['role']

    hashed_password = generate_password_hash(password)

    if role == 'admin':
        id_system = None
        phone = None
        email = None
        group_id = None 
        num_sip = None
        pas_sip = None
    else:
        num_sip = request.form.get('num_sip', None)  
        pas_sip = request.form.get('pas_sip', None)  

        if not group_id:
            flash('Group harus dipilih untuk user biasa.', 'error')
            return redirect(url_for('manage_users'))

    new_user = User(
        id_system=id_system, 
        username=username,
        password=hashed_password,
        phone=phone,  
        email=email,  
        group=group_id, 
        role=role,
        status='active',
        num_sip=num_sip,  
        pas_sip=pas_sip   
    )

    try:
        db.session.add(new_user)
        db.session.commit()
        flash('Akun berhasil ditambahkan.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Gagal menambahkan akun: {e}', 'error')

    return redirect(url_for('manage_users'))

@app.route('/manage-users', methods=['GET'])
def manage_users():
    page = request.args.get('page', 1, type=int)
    per_page = 10

    if current_user.role != 'admin':
        return redirect(request.referrer)

    users = User.query.filter_by(role='user').paginate(page=page, per_page=per_page, error_out=False)

    groups = UserGroup.query.filter_by(status='active').all()

    for user in users.items:
        group = UserGroup.query.filter_by(id=user.group).first()
        if group and group.status == 'nonactive':
            user.status = 'nonactive'

    return render_template('manage_account.html',
                           users=users.items,
                           groups=groups,
                           next_url=users.next_num,
                           prev_url=users.prev_num,
                           has_next=users.has_next,
                           has_prev=users.has_prev,
                           pages=users.pages,
                           current_page=page,
                           username=current_user.username,
                            num_sip=current_user.num_sip,
                            pas_sip=current_user.pas_sip)

@app.route('/delete-group', methods=['POST'])
@login_required
def delete_group():
    group_id = request.form['group']
    delete_option = request.form['delete']  

    try:
        group = UserGroup.query.get(group_id)

        if group:
            if delete_option == 'temp':
                group.status = 'nonactive'
                db.session.commit()
                flash('Group status updated to nonactive.', 'success')

            elif delete_option == 'perm':
                users_to_delete = User.query.filter_by(group=group.id).all()
                for user in users_to_delete:
                    db.session.delete(user)  

                db.session.delete(group) 
                db.session.commit()
                flash('Group and associated users deleted permanently.', 'success')
        else:
            flash('Group not found.', 'danger')

    except Exception as e:
        db.session.rollback()
        flash(f'Error: {str(e)}', 'danger')

    return redirect(url_for('manage_users'))

@app.route('/delete-account', methods=['POST'])
def delete_account():
    user_id = request.form['user_id']
    delete_type = request.form['delete_type']

    user = User.query.get(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('manage_users'))

    if delete_type == 'temp':
        user.status = 'nonactive'
        db.session.commit()
        flash('User temporarily disconnected.', 'warning')
    elif delete_type == 'perm':
        db.session.delete(user)
        db.session.commit()
        flash('User permanently deleted.', 'danger')

    return redirect(url_for('manage_users'))

@app.route('/update_user', methods=['POST'])
@login_required
def update_user():
    user_id = request.form['user_id']
    new_status = request.form['status']
    new_password = request.form['password']

    user = User.query.get(user_id)
    if user:
        user.status = new_status
        if new_password.strip():
            user.password = generate_password_hash(new_password)
        db.session.commit()
        flash('User updated successfully.', 'success')
    else:
        flash('User not found.', 'danger')

    return redirect(url_for('manage_users'))

@app.route('/upload_data', methods=['GET', 'POST'])
def upload_data():
    if current_user.role != 'admin':
        return redirect(request.referrer)

    if request.method == 'POST':
        file = request.files.get('file')
        user_id = request.form.get('user_id')
        exp_date = request.form.get('date')

        if not file or file.filename == '':
            flash('File tidak ditemukan.', 'danger')
            return redirect(url_for('upload_data'))

        if not user_id or not exp_date:
            flash('User dan tanggal exp harus diisi.', 'danger')
            return redirect(url_for('upload_data'))

        try:
            df = pd.read_excel(file)

            required_columns = [
                'Order Number', 'Nama Nasabah', 'No HP', 'Alamat', 'Pekerjaan', 'Waktu Peminjaman',
                'Total Tagihan', 'Overdue', 
                'Nama Emergency Contact 1', 'Nomor Emergency Contact 1',
                'Nama Emergency Contact 2', 'Nomor Emergency Contact 2'
            ]

            if not all(col in df.columns for col in required_columns):
                flash('Format kolom Excel tidak sesuai.', 'danger')
                return redirect(url_for('upload_data'))

            if df[required_columns].isnull().any().any():
                flash('Kolom yang diupload tidak lengkap.', 'danger')
                return redirect(url_for('upload_data'))

            for _, row in df.iterrows():
                data = Data(
                    order_no=row['Order Number'],
                    nama_nasabah=row['Nama Nasabah'],
                    phone=row['No HP'],
                    alamat=row['Alamat'],
                    waktu_peminjaman=row['Waktu Peminjaman'],
                    pekerjaan=row['Pekerjaan'],
                    pokok_pinjaman=row.get('Pokok Pinjaman', 0),  
                    total_tagihan=row['Total Tagihan'],
                    overdue=row['Overdue'],
                    nama_ec1=row['Nama Emergency Contact 1'],
                    nomor_ec1=row['Nomor Emergency Contact 1'],
                    nama_ec2=row['Nama Emergency Contact 2'],
                    phone_ec2=row['Nomor Emergency Contact 2'],
                    exp_date=exp_date,
                    tanggal_upload=datetime.now(),
                    user_id=user_id,
                    remark='not_ptp',
                    catatan=''
                )
                db.session.add(data)

            db.session.commit()
            flash('Data berhasil diupload.', 'success')

        except Exception as e:
            db.session.rollback()
            flash(f'Terjadi kesalahan: {e}', 'danger')

        return redirect(url_for('upload_data'))

    users = User.query.filter(User.status == 'active', User.role == 'user').all()
    return render_template('upload_data.html', users=users, username=current_user.username, num_sip=current_user.num_sip,
        pas_sip=current_user.pas_sip)

@app.route('/delete')
def delete():
    page = request.args.get('page', 1, type=int)
    per_page = 10  

    if current_user.role != 'admin':
        return redirect(request.referrer)
    
    user_data_summary = (
        db.session.query(
            User.id_system,
            User.username,
            func.count(Data.id).label('total_data'),
            func.max(Data.tanggal_upload).label('tanggal_upload'),
            UserGroup.company.label('group_name')
        )
        .join(Data, Data.user_id == User.id)
        .join(UserGroup, User.group == UserGroup.id)
        .group_by(User.id_system, User.username, UserGroup.company)
        .paginate(page=page, per_page=per_page, error_out=False) 
    )

    user_data_summary_items = user_data_summary.items  
    total_pages = user_data_summary.pages    
    current_page = user_data_summary.page  

    return render_template(
        'delete.html',
        username=current_user.username,
        user_data_summary=user_data_summary_items,
        total_pages=total_pages,
        current_page=current_page,
        num_sip=current_user.num_sip,
        pas_sip=current_user.pas_sip
    )

@app.route('/delete/<string:id_system>', methods=['POST'])
@login_required
def delete_user_data(id_system):
    try:
        user = User.query.filter_by(id_system=id_system).first()
        if not user:
            flash('User tidak ditemukan.', 'danger')
            return redirect(url_for('delete'))

        data_to_delete = Data.query.filter_by(user_id=user.id).all()
        for data in data_to_delete:
            db.session.delete(data)

        db.session.commit()
        flash('Data berhasil dihapus.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Terjadi kesalahan: {e}', 'danger')

    return redirect(url_for('delete'))

@app.route('/my-case')
@login_required
def my_case():
    query = Data.query.filter(Data.remark == 'not_ptp')

    if current_user.role != 'admin':
        flash("Access denied. Only admin can perform this action.", "danger")
        return redirect(request.referrer)

    keyword = request.args.get('keyword')
    if keyword:
        query = query.filter(
            or_(
                Data.order_no.ilike(f"%{keyword}%"),
                Data.nama_nasabah.ilike(f"%{keyword}%"),
                Data.phone.ilike(f"%{keyword}%")
            )
        )

    query_result = query.all()

    for d in query_result:
        try:
            d.pokok_pinjaman_int = int(d.pokok_pinjaman.replace('.', '').replace(',', '').strip())
        except:
            d.pokok_pinjaman_int = 0
        try:
            d.total_tagihan_int = int(d.total_tagihan.replace('.', '').replace(',', '').strip())
        except:
            d.total_tagihan_int = 0
        try:
            d.overdue = int(d.overdue)
        except:
            d.overdue = 0

    page = request.args.get('page', 1, type=int)
    per_page = 10
    total = len(query_result)
    start = (page - 1) * per_page
    end = start + per_page
    paginated_data = query_result[start:end]
    total_pages = (total + per_page - 1) // per_page

    query_params = request.args.to_dict()
    query_params.pop('page', None)

    return render_template(
        'my_case.html',
        username=current_user.username,
        data_list=paginated_data,
        current_page=page,
        total_pages=total_pages,
        query_params=query_params,
        num_sip=current_user.num_sip,
        pas_sip=current_user.pas_sip
    )

@app.route('/ptp')
@login_required
def ptp():
    query = Data.query.filter(Data.remark == 'ptp')

    if current_user.role != 'admin':
        return redirect(request.referrer)

    keyword = request.args.get('keyword')
    if keyword:
        query = query.filter(
            or_(
                Data.order_no.ilike(f"%{keyword}%"),
                Data.nama_nasabah.ilike(f"%{keyword}%"),
                Data.phone.ilike(f"%{keyword}%")
            )
        )

    min_principal = request.args.get('min_principal', type=int)
    max_principal = request.args.get('max_principal', type=int)
    if min_principal is not None or max_principal is not None:
        all_data = query.all()
        filtered_data = []
        for d in all_data:
            try:
                pokok = int(d.pokok_pinjaman.replace('.', '').replace(',', '').strip())
                if (
                    (min_principal is None or pokok >= min_principal) and
                    (max_principal is None or pokok <= max_principal)
                ):
                    d.pokok_pinjaman_int = pokok
                    filtered_data.append(d)
            except:
                continue
        query_result = filtered_data
    else:
        query_result = query.all()
        for d in query_result:
            try:
                d.pokok_pinjaman_int = int(d.pokok_pinjaman.replace('.', '').replace(',', '').strip())
            except:
                d.pokok_pinjaman_int = 0

    min_overdue = request.args.get('min_overdue', type=int)
    max_overdue = request.args.get('max_overdue', type=int)
    if min_overdue is not None or max_overdue is not None:
        temp = []
        for d in query_result:
            try:
                ovd = int(d.overdue)
                if (
                    (min_overdue is None or ovd >= min_overdue) and
                    (max_overdue is None or ovd <= max_overdue)
                ):
                    d.overdue = ovd
                    temp.append(d)
            except:
                continue
        query_result = temp

    for d in query_result:
        try:
            d.total_tagihan_int = int(d.total_tagihan.replace('.', '').replace(',', '').strip())
        except:
            d.total_tagihan_int = 0

    page = request.args.get('page', 1, type=int)
    per_page = 10
    total = len(query_result)
    total_pages = (total + per_page - 1) // per_page
    paginated_data = query_result[(page - 1) * per_page: page * per_page]

    query_params = request.args.to_dict()
    query_params.pop('page', None)

    return render_template(
        'ptp.html',
        username=current_user.username,
        data_list=paginated_data,
        current_page=page,
        total_pages=total_pages,
        query_params=query_params,
        num_sip=current_user.num_sip,
        pas_sip=current_user.pas_sip
    )

@app.route('/detail_data/<int:id>')
@login_required
def detail_data(id):
    data = Data.query.get_or_404(id)

    def format_rupiah(nominal):
        return f"Rp {nominal:,.0f}".replace(",", ".")

    try:
        data.pokok_pinjaman_int = int(data.pokok_pinjaman.replace('.', '').replace(',', '').strip())
        data.pokok_pinjaman_rp = format_rupiah(data.pokok_pinjaman_int)
    except:
        data.pokok_pinjaman_int = 0
        data.pokok_pinjaman_rp = "Rp0"

    try:
        data.total_tagihan_int = int(data.total_tagihan.replace('.', '').replace(',', '').strip())
        data.total_tagihan_rp = format_rupiah(data.total_tagihan_int)
    except:
        data.total_tagihan_int = 0
        data.total_tagihan_rp = "Rp0"

    return render_template('detail_data.html', data=data, username=current_user.username)

@app.route('/my-data')
@login_required
def my_data():
    query = Data.query.join(User).join(UserGroup, User.group == UserGroup.id).filter(Data.user_id == current_user.id, Data.remark == "not_ptp")

    if current_user.role != 'user':
        return redirect(request.referrer)

    keyword = request.args.get('keyword')
    if keyword:
        query = query.filter(
            or_(
                Data.order_no.ilike(f"%{keyword}%"),
                Data.nama_nasabah.ilike(f"%{keyword}%"),
                Data.phone.ilike(f"%{keyword}%")
            )
        )

    min_principal = request.args.get('min_principal', type=int)
    max_principal = request.args.get('max_principal', type=int)
    min_overdue = request.args.get('min_overdue', type=int)
    max_overdue = request.args.get('max_overdue', type=int)

    query_result = []
    for d in query:
        try:
            d.pokok_pinjaman_int = int(d.pokok_pinjaman.replace('.', '').replace(',', '').strip())
        except:
            d.pokok_pinjaman_int = 0
        try:
            d.total_tagihan_int = int(d.total_tagihan.replace('.', '').replace(',', '').strip())
        except:
            d.total_tagihan_int = 0
        try:
            d.overdue = int(d.overdue)
        except:
            d.overdue = 0

        if (
            (min_principal is None or d.pokok_pinjaman_int >= min_principal) and
            (max_principal is None or d.pokok_pinjaman_int <= max_principal) and
            (min_overdue is None or d.overdue >= min_overdue) and
            (max_overdue is None or d.overdue <= max_overdue)
        ):
            query_result.append(d)

    page = request.args.get('page', 1, type=int)
    per_page = 10
    total = len(query_result)
    start = (page - 1) * per_page
    end = start + per_page
    paginated_data = query_result[start:end]
    total_pages = (total + per_page - 1) // per_page

    query_params = request.args.to_dict()
    query_params.pop('page', None)

    group_obj = UserGroup.query.filter_by(id=current_user.group).first()
    group_name = group_obj.company if group_obj else 'N/A'

    return render_template(
        'user_my_case.html',
        username=current_user.username,
        group=current_user.group,
        group_name=group_name,
        id_system=current_user.id_system,
        data_list=paginated_data,
        current_page=page,
        total_pages=total_pages,
        query_params=query_params,
        num_sip=current_user.num_sip,
        pas_sip=current_user.pas_sip
    )

@app.route('/call')
@login_required
def call():
    nomor = request.args.get('nomor')
    if not nomor:
        return "Nomor tidak ditemukan.", 400
    return render_template(
        'call.html',
        nomor=nomor,
        sip_server="ld.infin8link.com:7060",
        domain="ld.infin8link.com:7060",
        username=current_user.num_sip,
        password=current_user.pas_sip
    )

@app.route('/user-ptp')
@login_required
def user_ptp():
    query = Data.query.filter(
        Data.remark == 'ptp',
        Data.user_id == current_user.id
    )

    if current_user.role != 'user':
        return redirect(request.referrer)

    keyword = request.args.get('keyword')
    if keyword:
        query = query.filter(
            or_(
                Data.order_no.ilike(f"%{keyword}%"),
                Data.nama_nasabah.ilike(f"%{keyword}%"),
                Data.phone.ilike(f"%{keyword}%")
            )
        )

    min_principal = request.args.get('min_principal', type=int)
    max_principal = request.args.get('max_principal', type=int)
    if min_principal is not None or max_principal is not None:
        all_data = query.all()
        filtered_data = []
        for d in all_data:
            try:
                pokok = int(d.pokok_pinjaman.replace('.', '').replace(',', '').strip())
                if (
                    (min_principal is None or pokok >= min_principal) and
                    (max_principal is None or pokok <= max_principal)
                ):
                    d.pokok_pinjaman_int = pokok
                    filtered_data.append(d)
            except:
                continue
        query_result = filtered_data
    else:
        query_result = query.all()
        for d in query_result:
            try:
                d.pokok_pinjaman_int = int(d.pokok_pinjaman.replace('.', '').replace(',', '').strip())
            except:
                d.pokok_pinjaman_int = 0

    min_overdue = request.args.get('min_overdue', type=int)
    max_overdue = request.args.get('max_overdue', type=int)
    if min_overdue is not None or max_overdue is not None:
        temp = []
        for d in query_result:
            try:
                ovd = int(d.overdue)
                if (
                    (min_overdue is None or ovd >= min_overdue) and
                    (max_overdue is None or ovd <= max_overdue)
                ):
                    d.overdue = ovd
                    temp.append(d)
            except:
                continue
        query_result = temp

    for d in query_result:
        try:
            d.total_tagihan_int = int(d.total_tagihan.replace('.', '').replace(',', '').strip())
        except:
            d.total_tagihan_int = 0

    page = request.args.get('page', 1, type=int)
    per_page = 10
    total = len(query_result)
    total_pages = (total + per_page - 1) // per_page
    paginated_data = query_result[(page - 1) * per_page: page * per_page]

    query_params = request.args.to_dict()
    query_params.pop('page', None)

    group_obj = UserGroup.query.filter_by(id=current_user.group).first()
    group_name = group_obj.company if group_obj else 'N/A'

    return render_template(
        'user_ptp.html',  
        username=current_user.username,
        data_list=paginated_data,
        group=current_user.group,
        group_name=group_name,
        id_system=current_user.id_system,
        current_page=page,
        total_pages=total_pages,
        query_params=query_params,
        num_sip=current_user.num_sip,
        pas_sip=current_user.pas_sip
    )

@app.route('/user_detail_data/<int:id>')
@login_required
def user_detail_data(id):
    data = Data.query.get_or_404(id)

    if current_user.role != 'user':
        return redirect(request.referrer)

    def format_rupiah(nominal):
        return f"Rp {nominal:,.0f}".replace(",", ".")

    try:
        data.pokok_pinjaman_int = int(data.pokok_pinjaman.replace('.', '').replace(',', '').strip())
        data.pokok_pinjaman_rp = format_rupiah(data.pokok_pinjaman_int)
    except:
        data.pokok_pinjaman_int = 0
        data.pokok_pinjaman_rp = "Rp0"

    try:
        data.total_tagihan_int = int(data.total_tagihan.replace('.', '').replace(',', '').strip())
        data.total_tagihan_rp = format_rupiah(data.total_tagihan_int)
    except:
        data.total_tagihan_int = 0
        data.total_tagihan_rp = "Rp0"

    return render_template('user_detail_data.html', 
        data=data, 
        username=current_user.username,
        num_sip=current_user.num_sip,
        pas_sip=current_user.pas_sip)

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@app.route('/ganti-sip', methods=['POST'])
@login_required
def ganti_sip():
    try:
        current_user.num_sip = request.form['num_sip']
        current_user.pas_sip = request.form['pas_sip']
        db.session.commit()
        flash("Nomor SIP berhasil diperbarui.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Terjadi kesalahan: {str(e)}", "danger")
    
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/submit-call', methods=['POST'])
@login_required
def submit_call():
    data_id = request.form.get('data_id')
    remark = request.form.get('remark')
    note = request.form.get('note')

    data = Data.query.filter_by(id=data_id, user_id=current_user.id).first()
    if not data:
        flash('Data tidak ditemukan atau tidak sesuai.', 'error')
        return redirect(url_for('my_data'))

    data.remark = remark
    if note is not None:
        data.catatan = note
    db.session.commit()

    flash('Data berhasil diperbarui.', 'success')
    return redirect(url_for('my_data'))

@app.route('/admin-submit-call', methods=['POST'])
@login_required
def admin_submit_call():
    data_id = request.form.get('data_id')
    remark = request.form.get('remark')
    note = request.form.get('note')

    data = Data.query.filter_by(id=data_id).first()
    if not data:
        flash('Data tidak ditemukan atau tidak sesuai.', 'error')
        return redirect(url_for('my_case'))

    data.remark = remark
    if note is not None:
        data.catatan = note
    db.session.commit()

    flash('Data berhasil diperbarui.', 'success')
    return redirect(url_for('my_case'))

@app.route('/submit-call-ptp', methods=['POST'])
@login_required
def submit_call_ptp():
    data_id = request.form.get('data_id')
    remark = request.form.get('remark')
    note = request.form.get('note')

    data = Data.query.filter_by(id=data_id, user_id=current_user.id).first()
    if not data:
        flash('Data tidak ditemukan atau tidak sesuai.', 'error')
        return redirect(url_for('user_ptp'))

    data.remark = remark
    if note is not None:
        data.catatan = note

    db.session.commit()
    flash('Data berhasil diperbarui.', 'success')
    return redirect(url_for('user_ptp'))

@app.route('/admin-submit-call-ptp', methods=['POST'])
@login_required
def admin_submit_call_ptp():
    data_id = request.form.get('data_id')
    remark = request.form.get('remark')
    note = request.form.get('note')

    print(f"Data ID: {data_id}, Remark: {remark}, Note: {note}")

    data = Data.query.filter_by(id=data_id).first()
    if not data:
        flash('Data tidak ditemukan atau tidak sesuai.', 'error')
        return redirect(url_for('ptp'))

    data.remark = remark
    if note is not None:
        data.catatan = note

    db.session.commit()
    flash('Data berhasil diperbarui.', 'success')
    return redirect(url_for('ptp'))

@app.route('/log_user')
@login_required
def log_user():
    if current_user.role != 'admin':
        return redirect(request.referrer)
    
    if current_user.role == 'admin':
        page = request.args.get('page', 1, type=int)  
        per_page = 10

        activities = UserActivity.query.order_by(UserActivity.timestamp.desc()).paginate(page=page, per_page=per_page, error_out=False)

        return render_template('log_user.html',
        activities=activities.items, 
        username=current_user.username,
        num_sip=current_user.num_sip,
        pas_sip=current_user.pas_sip,
        pagination=activities)  
    
    else:
        return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000, host='0.0.0.0')  