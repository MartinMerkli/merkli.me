#!/usr/bin/env python3

########################################################################################################################
# IMPORTS
########################################################################################################################


from flask import Flask, redirect, make_response, request, render_template, session, send_from_directory, jsonify
from time import time, sleep
from os import urandom, environ, listdir, remove
from hashlib import pbkdf2_hmac
from base64 import urlsafe_b64encode, urlsafe_b64decode
from datetime import timedelta, date, datetime
from json import load as json_load, dump as json_dump, loads as json_loads, dumps as json_dumps
from os.path import exists, join, dirname, getsize
from random import randint, uniform
from ssl import create_default_context
from smtplib import SMTP
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from threading import Lock
from logging import basicConfig as log_basicConfig, INFO as LOG_INFO, getLogger as GetLogger, Formatter as LogFormatter
from logging import FileHandler as LogFileHandler, StreamHandler as LogStreamHandler
from hashlib import sha256
from secrets import compare_digest
from sqlite3 import connect as sqlite_connect
from re import match as re_match
from magic import from_file as type_from_file
from werkzeug.utils import secure_filename
from flask_apscheduler import APScheduler
from urllib.request import Request, urlopen
from bs4 import BeautifulSoup


########################################################################################################################
# GENERAL SETUP
########################################################################################################################


app = Flask(__name__)

if not exists(join(app.root_path, 'resources', 'key.bin')):
    with open(join(app.root_path, 'resources', 'key.bin'), 'wb') as _f:
        _f.write(urandom(64))
with open(join(app.root_path, 'resources', 'key.bin'), 'rb') as _f:
    _secret_key = _f.read()
app.secret_key = _secret_key

with open(join(app.root_path, 'resources', 'themes.json'), 'r') as _f:
    _themes = json_load(_f)

with open(join(app.root_path, 'resources', 'blacklist.json'), 'r') as _f:
    blacklist = json_load(_f)


########################################################################################################################
# LOGGING SETUP
########################################################################################################################


def setup_logger(logger_name, log_file):
    logger = GetLogger(logger_name)
    formatter = LogFormatter('%(asctime)s\t%(message)s', datefmt='%Y-%m-%d_%H-%M-%S')
    file_handler = LogFileHandler(log_file, mode='a')
    file_handler.setFormatter(formatter)
    stream_handler = LogStreamHandler()
    stream_handler.setFormatter(formatter)
    logger.setLevel(LOG_INFO)
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)


log_basicConfig(filename='main.log', format='%(asctime)s\t%(message)s', datefmt='%Y-%m-%d_%H-%M-%S', level=LOG_INFO)

setup_logger('access', 'access.log')
access_log = GetLogger('access')

setup_logger('abuse_report', 'abuse_report.log')
abuse_report_log = GetLogger('abuse_report')

setup_logger('request_errors', 'request_errors.log')
request_errors_log = GetLogger('request_errors')


########################################################################################################################
# DATABASE SETUP
########################################################################################################################


conn_su = sqlite_connect('database.db', check_same_thread=False)
db_su = conn_su.cursor()

conn_nh = sqlite_connect('g21m.db', check_same_thread=False)
db_nh = conn_nh.cursor()

conn_zl = sqlite_connect('zitateliste.db', check_same_thread=False)
db_zl = conn_zl.cursor()


########################################################################################################################
# MISCELLANEOUS SETUP
########################################################################################################################


_file_types = {'application/x-bzip2': 'BZ2', 'text/css': 'CSS', 'text/csv': 'CSV',
               'application/msword': 'DOC', 'application/gzip': 'GZ', 'image/gif': 'GIF', 'text/html': 'HTML',
               'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'DOCX', 'image/jpeg': 'JPG',
               'text/javascript': 'JS', 'application/json': 'JSON', 'audio/mpeg': 'MP3', 'video/mp4': 'MP4',
               'video/mpeg': 'MPEG', 'application/vnd.oasis.opendocument.presentation': 'ODP', 'image/png': 'PNG',
               'application/vnd.oasis.opendocument.spreadsheet': 'ODS', 'application/pdf': 'PDF', 'image/tiff': 'TIFF',
               'application/vnd.oasis.opendocument.text': 'ODT', 'application/vnd.ms-powerpoint': 'PPT',
               'application/vnd.openxmlformats-officedocument.presentationml.presentation': 'PPTX',
               'application/rtf': 'RTF', 'application/x-tar': 'TAR', 'text/plain': 'TXT', 'audio/webm': 'WEBA',
               'video/webm': 'WEBM', 'image/webp': 'WEBP', 'application/vnd.ms-excel': 'XLS', 'application/zip': 'ZIP',
               'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'XLSX', 'application/xml': 'XML'}

_size_units = ['B', 'KB', 'MB', 'GB', 'TB']


########################################################################################################################
# DATES
########################################################################################################################


def get_current_time():
    return datetime.now().strftime('%Y-%m-%d_%H-%M-%S')


def calculate_human_time_span(date1, date2):
    timedelta_difference = datetime.strptime(date1, '%Y-%m-%d_%H-%M-%S') - datetime.strptime(date2, '%Y-%m-%d_%H-%M-%S')
    if timedelta_difference.days > 0:
        time_span = f"{timedelta_difference.days} Tagen"
    elif timedelta_difference.seconds < 60:
        time_span = f"{timedelta_difference.seconds} Sekunden"
    elif timedelta_difference.seconds < 3600:
        time_span = f"{timedelta_difference.seconds // 60} Minuten"
    elif timedelta_difference.seconds < 86400:
        time_span = f"{timedelta_difference.seconds // 3600} Stunden"
    else:
        time_span = 'unbekannter Zeit'
    return time_span


########################################################################################################################
# ACCOUNT
########################################################################################################################


def is_signed_in(cookies):
    if 'id' in cookies:
        result = db_su.execute('select valid from login where id = ?', (cookies['id'],)).fetchone()
        if result is None:
            return False
        if result[0] >= get_current_time():
            return True
    return False


def get_account(cookies, user_agent):
    platform = None
    if 'platform' in cookies:
        if cookies['platform'] in ['mobile', 'desktop']:
            platform = cookies['platform']
    if platform is None:
        if is_on_mobile(user_agent):
            platform = 'mobile'
        else:
            platform = 'desktop'
    if 'id' in cookies:
        result = db_su.execute('select valid, account from login where id = ?', (cookies['id'],)).fetchone()
        if result is None:
            return None, None, None, f"/stylesheets/{platform}/dunkel.css"
        if result[0] < get_current_time():
            return None, None, None, f"/stylesheets/{platform}/dunkel.css"
        result2 = db_su.execute('select id, name, mail, theme from accounts where id = ?', (result[1],)).fetchone()
        if result2 is None:
            return None, None, None, f"/stylesheets/{platform}/dunkel.css"
        return result2[0], result2[1], result2[2], f"/stylesheets/{platform}/{result2[3]}.css"
    return None, None, None, f"/stylesheets/{platform}/dunkel.css"


def is_admin(acc):
    return acc in ['M-Merkli']


def get_account_name(acc):
    result = db_su.execute('select name from accounts where id=?', (acc,)).fetchone()
    if result is None:
        return None
    return result[0]


########################################################################################################################
# QUOTES
########################################################################################################################


def get_zl_info(acc):
    result = db_zl.execute('select level, name, last_quote, last_action, last_conspiracy '
                           'from access where account=?', (acc,)).fetchone()
    if result is None:
        return 0, 'unknown', '2022-01-01', '2022-01-01', '2022-01-01'
    return result


def zl_combine(obj):
    result = db_zl.execute('select id, content from ' + obj).fetchall()
    r = {}
    if result is not None:
        for i, v in result:
            r[i] = json_loads(v)
    return r


def zl_next_id(obj):
    result = db_zl.execute('select id from ' + obj).fetchall()
    data = ['0']
    length = 4
    if obj == 'quotes':
        length = 6
    if result is not None:
        for i in range(len(result)):
            data.append(result[i][0])
    return str(int(max(data)) + 1).zfill(length)


def zl_current_time():
    return datetime.now().strftime('%Y-%m-%d_%H-%M')


########################################################################################################################
# LEARNING SETS
########################################################################################################################


def get_set_size(set_ids):
    parts = set_ids.split('-')
    r = 0
    for i in parts:
        result = json_loads(db_nh.execute('select content from exercises where id=?', (i,)).fetchone()[0])
        r += len(result)
    return r


def get_stats(acc, set_ids):
    stats = json_loads(db_nh.execute('select answers from statistics where account=?', (acc,)).fetchone()[0])
    r = {'wrong': 0, 'total': 0, 'correct': 0, 'answered': 0}
    for i in stats:
        if i.split('_')[0] == set_ids:
            r['wrong'] += stats[i]['wrong']
            r['correct'] += stats[i]['correct']
            r['answered'] += 1
    r['total'] = get_set_size(set_ids)
    return r


def get_set_name(set_id, max_length=None):
    parts = set_id.split('-')
    names = []
    for i in parts:
        result = db_nh.execute('select name from exercises where id=?', (i,)).fetchone()[0]
        names.append(result)
    r = ', '.join(names)
    if (max_length is None) or (len(r) < max_length):
        return r
    for i in range(len(names) - 1):
        r = ', '.join(names[:-(i + 1)]) + ', ...'
        if len(r) < max_length:
            return r
    return ''


def existing_sets(set_ids):
    r = []
    result = db_nh.execute('select id from exercises').fetchall()
    existing = []
    for i in result:
        existing.append(i[0])
    for i in set_ids.split('-'):
        if i in existing:
            r.append(i)
    return '-'.join(r)


def upload_set(f, ex_id):
    trigger_error = None
    if f[0] == '{':
        json_file = json_loads(f)
        content = {}
        counter = 0
        for i in json_file:
            accept = True
            for j in ['question', 'answer', 'answers', 'images', 'links', 'answer_images', 'answer_links',
                      'frequency']:
                if j not in json_file[i]:
                    accept = False
            if accept:
                if (not isinstance(json_file[i]['question'], str)) \
                        or (not isinstance(json_file[i]['answer'], str)) \
                        or (not isinstance(json_file[i]['answers'], list)) \
                        or (not isinstance(json_file[i]['images'], list)) \
                        or (not isinstance(json_file[i]['links'], list)) \
                        or (not isinstance(json_file[i]['answer_images'], list)) \
                        or (not isinstance(json_file[i]['answer_links'], list)) \
                        or (not isinstance(json_file[i]['frequency'], float)):
                    accept = False
            if accept:
                content[ex_id + '-' + hex(counter).zfill(4)] = json_file[i]
                counter += 1
        if not content:
            trigger_error = 'no valid json'
    else:
        content = {}
        lines = f.split('\n')
        counter = 0
        for line in lines:
            if '; ' in line:
                parts = line.split('; ')
                content[ex_id + '-' + hex(counter).zfill(4)] = {'question': parts[0], 'answer': parts[1],
                                                                'answers': [parts[1]],
                                                                'images': [], 'links': [], 'answer_images': [],
                                                                'answer_links': [], 'frequency': 1.0}
                counter += 1
        if not content:
            trigger_error = 'no valid text'
    return content, trigger_error


########################################################################################################################
# RANDOM
########################################################################################################################


def rand_base64(digits):
    while True:
        n = urlsafe_b64encode(urandom(digits)).decode()[:digits]
        result = db_su.execute('select * from used_ids where id=?', (n,)).fetchone()
        if result is None:
            db_su.execute('insert into used_ids values (?, ?)', (n, get_current_time()))
            conn_su.commit()
            return n


def rand_base16(digits):
    while True:
        n = urandom(digits).hex()[:digits]
        result = db_su.execute('select * from used_ids where id=?', (n,)).fetchone()
        if result is None:
            db_su.execute('insert into used_ids values (?, ?)', (n, get_current_time()))
            conn_su.commit()
            return n


def rand_salt():
    return urlsafe_b64encode(urandom(32)).decode()


########################################################################################################################
# MISCELLANEOUS
########################################################################################################################


def is_on_mobile(user_agent):
    strings = ['android', 'mobi', 'ipod', 'phone', 'blackberry']
    return any(string in user_agent.lower() for string in strings)


def send_mail(address, subject, message_plain, message):
    smtp_server = environ['SMTP_SERVER']
    smtp_port = int(environ['SMTP_PORT'])
    sender_email = environ['SMTP_ADDRESS']
    context = create_default_context()
    server = None
    m = MIMEMultipart('alternative')
    m['Subject'] = subject
    m['From'] = sender_email
    m['To'] = address
    part1 = MIMEText(message_plain, 'plain')
    part2 = MIMEText(message, 'html')
    m.attach(part1)
    m.attach(part2)
    try:
        server = SMTP(smtp_server, smtp_port)
        server.starttls(context=context)
        _mail_password = environ['SMTP_PASSWORD']
        server.login(sender_email, _mail_password)
        del _mail_password
        server.sendmail(sender_email, address, m.as_string())
    except Exception as error:
        return error
    finally:
        server.quit()
    return None


def g21m_activity(content, link):
    db_nh.execute('insert into activity values (?, ?, ?, ?)', (rand_base64(13), get_current_time(), content, link))
    conn_nh.commit()


########################################################################################################################
# PROTECTION
########################################################################################################################


def random_sleep():
    sleep(0.1 + uniform(0.0, 0.1))


def hash_password(password, salt):
    return urlsafe_b64encode(pbkdf2_hmac('sha3_512', urlsafe_b64decode(environ['HASH_PEPPER_1']) + password.encode() +
                                         urlsafe_b64decode(environ['HASH_PEPPER_2']), urlsafe_b64decode(salt),
                                         int(environ['HASH_ITERATIONS']))).decode()


def hash_ip(ip):
    return urlsafe_b64encode(sha256(bytes(map(int, ip.split('.')))).digest()).decode()


def scan_request(r):
    ip = r.access_route[-1]
    user_agent = r.user_agent.string
    path = r.full_path
    if r.remote_addr not in ['127.0.0.1', '0.0.0.0', None]:
        access_log.info(f'{hash_ip(ip)}\t{0}\t{int(is_signed_in(r.cookies))}\t{r.method}\t{path}\t{user_agent}')
        return 0
    score = db_su.execute('select score from ipv4 where address = ?', (ip,)).fetchone()
    if score is None:
        score = 2
        db_su.execute('insert into ipv4 values (?, ?, ?)', (ip, 'unknown', 2))
        conn_su.commit()
    else:
        score = score[0]
    if score == 0:
        access_log.info(f'{hash_ip(ip)}\t{0}\t{int(is_signed_in(r.cookies))}\t{r.method}\t{path}\t{user_agent}')
        return 0
    before = score
    
    if score < 3:
        if user_agent in blacklist['useragent_text']:
            score = min(score, 1)
        for i in blacklist['useragent_part']:
            if i in user_agent:
                score = min(score, 1)
        for i in blacklist['useragent_regex']:
            if re_match(i, user_agent):
                score = min(score, 1)
        if path in blacklist['path_text']:
            score = min(score, 1)
        for i in blacklist['path_part']:
            if i in path:
                score = min(score, 1)
        for i in blacklist['path_regex']:
            if re_match(i, path):
                score = min(score, 1)

    if before != score:
        db_su.execute('update ipv4 set score = ? where address = ?', (score, ip))
        conn_su.commit()
    
    access_log.info(f'{hash_ip(ip)}\t{score}\t{int(is_signed_in(r.cookies))}\t{r.method}\t{path}\t{user_agent}')
    return score


########################################################################################################################
# ALL REQUESTS
########################################################################################################################

@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(days=24)
    score = scan_request(request)
    if score == 0:
        return render_template('_banned.html', ip=request.access_route[-1]), 403


########################################################################################################################
# MAIN SITES
########################################################################################################################


@app.route('/', methods=['GET'])
def site():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        account = '<p>Nicht angemeldet</p>'
    else:
        account = f"<p>Angemeldet als<br>{name}</p>"
    platform = None
    cookie_set = False
    if 'platform' in request.cookies:
        if request.cookies['platform'] in ['mobile', 'desktop']:
            platform = request.cookies['platform']
            cookie_set = True
    if platform is None:
        if is_on_mobile(request.user_agent.string):
            platform = 'mobile'
        else:
            platform = 'desktop'
    if not cookie_set:
        response = make_response(render_template('index.html', stylesheet=stylesheet, account=account,
                                                 is_signed_in=not(acc is None)))
        response.set_cookie('platform', platform, timedelta(days=256))
        return response
    else:
        return render_template('index.html', stylesheet=stylesheet, account=account, is_signed_in=not(acc is None))


@app.route('/static/<path:file>', methods=['GET'])
def folder_static(file):
    return send_from_directory(join(app.root_path, 'static'), file)


@app.route('/stylesheets/<platform>/<theme>', methods=['GET'])
def folder_stylesheets(platform, theme):
    theme = theme.replace('.css', '')
    if platform not in ['desktop', 'mobile']:
        return error_404('invalid platform')
    if theme not in _themes:
        return error_404('invalid theme')
    with open(join(app.root_path, 'resources', platform + '_template.css'), 'r', encoding='utf-8') as f:
        template = f.read()
    for i in _themes[theme]:
        template = template.replace(f"§{i}§", _themes[theme][i])
    resp = make_response(template, 200)
    resp.mimetype = 'text/css'
    return resp


@app.route('/favicon.ico', methods=['GET'])
def file_favicon():
    platform = None
    cookie_set = False
    if 'platform' in request.cookies:
        if request.cookies['platform'] in ['mobile', 'desktop']:
            platform = request.cookies['platform']
            cookie_set = True
    if platform is None:
        if is_on_mobile(request.user_agent.string):
            platform = 'mobile'
        else:
            platform = 'desktop'
    if not cookie_set:
        response = make_response(send_from_directory(join(app.root_path, 'resources'), 'favicon.ico'))
        response.set_cookie('platform', platform, timedelta(days=256))
        return response
    else:
        return send_from_directory(join(app.root_path, 'resources'), 'favicon.ico')


@app.route('/melden/<_type>/<_id>', methods=['GET', 'POST'])
def folder_melden(_type, _id):
    if request.method == 'GET' and _id == '':
        acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
        if acc is None:
            account = '<p>Nicht angemeldet</p>'
        else:
            account = f"<p>Angemeldet als<br>{name}</p>"
        return render_template('melden.html', stylesheet=stylesheet, account=account,
                               is_signed_in=not(acc is None), _type=_type)
    elif request.method == 'GET':
        acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
        if acc is None:
            account = '<p>Nicht angemeldet</p>'
            acc = 'anonymous'
        else:
            account = f"<p>Angemeldet als<br>{name}</p>"
        abuse_report_log.info(f"{acc}\t{_type}\t{_id}")
        return render_template('melden_danke.html', stylesheet=stylesheet, account=account,
                               is_signed_in=not (acc is None))
    elif request.method == 'POST':
        acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
        if acc is None:
            account = '<p>Nicht angemeldet</p>'
            acc = 'anonymous'
        else:
            account = f"<p>Angemeldet als<br>{name}</p>"
        form = dict(request.form)
        if 'id' not in form:
            return error_422('required fields are empty')
        abuse_report_log.info(f"{acc}\t{_type}\t{form['id']}")
        return render_template('melden_danke.html', stylesheet=stylesheet, account=account,
                               is_signed_in=not (acc is None))
    else:
        return error_401('neither GET nor POST')


########################################################################################################################
# LEGAL
########################################################################################################################


@app.route('/impressum', methods=['GET'])
def site_impressum():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        account = '<p>Nicht angemeldet</p>'
    else:
        account = f"<p>Angemeldet als<br>{name}</p>"
    return render_template('impressum.html', stylesheet=stylesheet, account=account, is_signed_in=not(acc is None),
                           imprint_name=environ['IMPRINT_NAME'], imprint_address=environ['IMPRINT_ADDRESS'],
                           imprint_city=environ['IMPRINT_CITY'], imprint_mail=environ['IMPRINT_MAIL'])


@app.route('/datenschutz', methods=['GET'])
def site_datenschutz():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        account = '<p>Nicht angemeldet</p>'
    else:
        account = f"<p>Angemeldet als<br>{name}</p>"
    return render_template('datenschutz.html', stylesheet=stylesheet, account=account, is_signed_in=not(acc is None),
                           imprint_name=environ['IMPRINT_NAME'], imprint_address=environ['IMPRINT_ADDRESS'],
                           imprint_city=environ['IMPRINT_CITY'], imprint_mail=environ['IMPRINT_MAIL'])


@app.route('/nutzungsbedingungen', methods=['GET'])
def site_nutzungsbedingungen():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        account = '<p>Nicht angemeldet</p>'
    else:
        account = f"<p>Angemeldet als<br>{name}</p>"
    return render_template('nutzungsbedingungen.html', stylesheet=stylesheet, account=account,
                           is_signed_in=not(acc is None))


@app.route('/quelltext', methods=['GET'])
def site_quelltext():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        account = '<p>Nicht angemeldet</p>'
    else:
        account = f"<p>Angemeldet als<br>{name}</p>"
    return render_template('quelltext.html', stylesheet=stylesheet, account=account, is_signed_in=not(acc is None))


########################################################################################################################
# ACCOUNT
########################################################################################################################


@app.route('/konto/registrieren', methods=['GET'])
def site_konto_registrieren():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        account = '<p>Nicht angemeldet</p>'
    else:
        return redirect('/')
    return render_template('konto_registrieren.html', stylesheet=stylesheet, account=account,
                           is_signed_in=not(acc is None))


@app.route('/konto/registrieren2', methods=['POST'])
def site_konto_registrieren2():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        account = '<p>Nicht angemeldet</p>'
    else:
        return redirect('/')
    form = dict(request.form)
    for i in ['name', 'mail', 'password', 'password_repeat', 'agreement']:
        if i not in form:
            return error_422('required fields are empty')
    if len(form['password']) < 8:
        return render_template('_error.html', stylesheet=stylesheet, account=account, is_signed_in=not (acc is None),
                               page_title='Passwort zu kurz', title='Fehler: Passwort zu kurz',
                               link='/konto/registrieren',
                               message='Ihr Passwort muss mindestens 8 Zeichen lang sein.'), 422
    if form['password'] != form['password_repeat']:
        return render_template('_error.html', stylesheet=stylesheet, account=account, is_signed_in=not (acc is None),
                               page_title='Passwörter sind unterschiedlich',
                               title='Fehler: Passwörter sind unterschiedlich', link='/konto/registrieren',
                               message='Die Passwörter, welche Sie eingegeben haben, stimmen nicht überein.'), 422
    for i in ['<', '>', '"', '&']:
        if i in form['name']:
            return render_template('_error.html', stylesheet=stylesheet, account=account, is_signed_in=not (acc is None),
                                   page_title='illegaler Kontoname',
                                   title='illegaler Kontoname', link='/konto/registrieren',
                                   message='Ihr Kontoname enthält Zeichen, die nicht verwendet werden dürfen.'), 422
    result = db_su.execute('select * from accounts where mail=?', (form['mail'],)).fetchone()
    if result is not None:
        return render_template('_error.html', stylesheet=stylesheet, account=account, is_signed_in=not (acc is None),
                               page_title='Konto existiert', title='Fehler: Konto existiert schon',
                               link='/konto/registrieren',
                               message='Ein Konto mit der E-Mail-Adresse, die Sie eingegeben haben, '
                                       'existiert schon.'), 422
    mail_id = rand_base64(9)
    salt = rand_salt()
    hashed = hash_password(form['password'], salt)
    code = str(randint(100000, 999999))
    valid = (datetime.now() + timedelta(minutes=15)).strftime('%Y-%m-%d_%H-%M-%S')
    db_su.execute('insert into mail values (?, ?, ?, ?, ?, ?, ?, ?)',
                  (mail_id, form['name'], form['mail'], salt, hashed, int('newsletter' in form), valid, code))
    conn_su.commit()
    subject = 'E-Mail Verifikation [merkli.me]'
    message_plain = f"Ihr Code lautet: {code}"
    message = f"<html><body><h1>Ihr Code lautet: {code}</h1><p>Dieser Code ist 15 Minuten gültig, nachdem Sie Ihre " \
              f"E-Mail-Adresse eingegeben haben.</p></body></html>"
    mail_result = send_mail(form['mail'], subject, message_plain, message)
    if mail_result is None:
        resp = make_response(redirect('/konto/registrieren3'))
        resp.set_cookie('mch', mail_id, timedelta(minutes=15))
        return resp
    return render_template('_error.html', stylesheet=stylesheet, account=account, is_signed_in=not (acc is None),
                           page_title='Fehler beim Versenden der E-Mail', title='Fehler beim Versenden der E-Mail',
                           link='/konto/registrieren',
                           message='Es ist ein Fehler beim Versenden der E-Mail aufgetreten.'), 500


@app.route('/konto/registrieren3', methods=['GET'])
def site_konto_registrieren3():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        account = '<p>Nicht angemeldet</p>'
    else:
        return redirect('/')
    return render_template('konto_registrieren3.html', stylesheet=stylesheet, account=account,
                           is_signed_in=not(acc is None))


@app.route('/konto/registrieren4', methods=['POST'])
def site_konto_registrieren4():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        account = '<p>Nicht angemeldet</p>'
    else:
        return redirect('/')
    if 'mch' not in request.cookies:
        return redirect('/konto/registrieren')
    form = dict(request.form)
    if 'code' not in form:
        return error_422('required fields are empty')
    mail_id = request.cookies['mch']
    result = db_su.execute('select id, name, mail, salt, hash, newsletter, valid, code from mail where id=?',
                           (mail_id,)).fetchone()
    if result is None:
        return redirect('/konto/registrieren')
    if result[7] != form['code']:
        return render_template('_error.html', stylesheet=stylesheet, account=account, is_signed_in=not (acc is None),
                               page_title='falscher Code', title='Fehler: falscher Code',
                               link='/konto/registrieren3',
                               message='Der Code, den Sie eingegeben haben, ist falsch'), 422
    acc_id = rand_base64(8)
    db_su.execute('insert into accounts values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                  (acc_id, result[1], result[2], result[3], result[4], result[5], get_current_time(), 'dunkel', 0, 0))
    conn_su.commit()
    login = rand_base64(36)
    valid = (datetime.now() + timedelta(days=24)).strftime('%Y-%m-%d_%H-%M-%S')
    db_su.execute('insert into login values (?, ?, ?)', (login, acc_id, valid))
    conn_su.commit()
    resp = make_response(redirect('/'))
    resp.set_cookie('id', login, timedelta(days=24))
    return resp


@app.route('/konto/anmelden', methods=['GET'])
def site_konto_anmelden():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        account = '<p>Nicht angemeldet</p>'
    else:
        return redirect('/')
    return render_template('konto_anmelden.html', stylesheet=stylesheet, account=account, is_signed_in=not(acc is None))


@app.route('/konto/anmelden2', methods=['POST'])
def site_konto_anmelden2():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        account = '<p>Nicht angemeldet</p>'
    else:
        return redirect('/')
    form = dict(request.form)
    for i in ['mail', 'password']:
        if i not in form:
            return error_422('required fields are empty')
    result = db_su.execute('select id, mail, salt, hash from accounts where mail=?', (form['mail'], )).fetchone()
    if result is None:
        return render_template('_error.html', stylesheet=stylesheet, account=account, is_signed_in=not (acc is None),
                               page_title='falsche Anmeldedaten', title='falsche Anmeldedaten',
                               link='/konto/anmelden', message='Die E-Mail-Adresse und/oder das Passwort, das Sie '
                                                               'eingegeben haben, ist/sind falsch.'), 422
    if hash_password(form['password'], result[2]) != result[3]:
        return render_template('_error.html', stylesheet=stylesheet, account=account, is_signed_in=not (acc is None),
                               page_title='falsche Anmeldedaten', title='falsche Anmeldedaten',
                               link='/konto/anmelden', message='Die E-Mail-Adresse und/oder das Passwort, das Sie '
                                                               'eingegeben haben, ist/sind falsch.'), 422
    login = rand_base64(36)
    valid = (datetime.now() + timedelta(days=24)).strftime('%Y-%m-%d_%H-%M-%S')
    db_su.execute('insert into login values (?, ?, ?)', (login, result[0], valid))
    conn_su.commit()
    resp = make_response(redirect('/'))
    resp.set_cookie('id', login, timedelta(days=24))
    return resp


@app.route('/konto/abmelden', methods=['GET'])
def site_konto_abmelden():
    resp = make_response(redirect('/'))
    if 'id' in request.cookies:
        login = request.cookies['id']
        db_su.execute('update login set valid=? where id=?', (get_current_time(), login))
        conn_su.commit()
        resp.delete_cookie('id')
    return resp


@app.route('/konto/hash', methods=['GET'])
def site_konto_hash():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        account = '<p>Nicht angemeldet</p>'
    else:
        account = f"<p>Angemeldet als<br>{name}</p>"
    return render_template('konto_hash.html', stylesheet=stylesheet, account=account, is_signed_in=not(acc is None))


@app.route('/konto/hash2', methods=['POST'])
def site_konto_hash2():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        account = '<p>Nicht angemeldet</p>'
    else:
        account = f"<p>Angemeldet als<br>{name}</p>"
    form = dict(request.form)
    for i in ['password', 'password_repeat']:
        if i not in form:
            return error_422('required fields are empty')
    if form['password'] != form['password_repeat']:
        return render_template('_error.html', stylesheet=stylesheet, account=account, is_signed_in=not (acc is None),
                               page_title='Passwörter sind unterschiedlich',
                               title='Fehler: Passwörter sind unterschiedlich', link='/konto/registrieren',
                               message='Die Passwörter, welche Sie eingegeben haben, stimmen nicht überein.'), 422
    salt = rand_salt()
    hashed = hash_password(form['password'], salt)
    return render_template('konto_hash2.html', stylesheet=stylesheet, account=account, is_signed_in=not (acc is None),
                           salt=salt, hashed=hashed)


@app.route('/konto/einstellungen', methods=['GET'])
def site_konto_einstellungen():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        return error_401('not signed-in')
    else:
        account = f"<p>Angemeldet als<br>{name}</p>"
    result = db_su.execute('select id, name, newsletter, theme, iframe from accounts where id=?', (acc,)).fetchone()
    platform = None
    if 'platform' in request.cookies:
        if request.cookies['platform'] in ['mobile', 'desktop']:
            platform = request.cookies['platform']
    if platform is None:
        if is_on_mobile(request.user_agent.string):
            platform = 'mobile'
        else:
            platform = 'desktop'
    if result[4] == 1:
        iframe_current = 'aktivier'
        iframe_other = 'deaktivier'
    else:
        iframe_current = 'deaktivier'
        iframe_other = 'aktivier'
    if platform == 'mobile':
        platform_current = 'mobile'
        platform_other = 'desktop'
    else:
        platform_current = 'desktop'
        platform_other = 'mobile'
    theme_all = list(_themes.keys())
    if result[2] == 1:
        newsletter_current = 'aktivier'
        newsletter_other = 'deaktivier'
    else:
        newsletter_current = 'deaktivier'
        newsletter_other = 'aktivier'
    return render_template('konto_einstellungen.html', stylesheet=stylesheet, account=account,
                           is_signed_in=not(acc is None), info_name=result[1], info_id=result[0],
                           iframe_current=iframe_current, iframe_other=iframe_other, platform_current=platform_current,
                           platform_other=platform_other, theme_current=result[3], theme_all=theme_all,
                           newsletter_current=newsletter_current, newsletter_other=newsletter_other)


@app.route('/konto/einstellungen/passwort', methods=['POST'])
def site_konto_einstellungen_passwort():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        return error_401('not signed-in')
    else:
        account = f"<p>Angemeldet als<br>{name}</p>"
    form = dict(request.form)
    for i in ['password', 'password_new', 'password_repeat']:
        if i not in form:
            return error_422('required fields are empty')
    if len(form['password_new']) < 8:
        return render_template('_error.html', stylesheet=stylesheet, account=account, is_signed_in=not (acc is None),
                               page_title='Passwort zu kurz', title='Fehler: Passwort zu kurz',
                               link='/konto/registrieren',
                               message='Ihr Passwort muss mindestens 8 Zeichen lang sein.'), 422
    if form['password_new'] != form['password_repeat']:
        return render_template('_error.html', stylesheet=stylesheet, account=account, is_signed_in=not (acc is None),
                               page_title='Passwörter sind unterschiedlich',
                               title='Fehler: Passwörter sind unterschiedlich', link='/konto/registrieren',
                               message='Die Passwörter, welche Sie eingegeben haben, stimmen nicht überein.'), 422
    result = db_su.execute('select id, mail, salt, hash, newsletter from accounts where id=?', (acc,)).fetchone()
    if hash_password(form['password'], result[2]) != result[3]:
        return render_template('_error.html', stylesheet=stylesheet, account=account, is_signed_in=not (acc is None),
                               page_title='falsches Passwort', title='falsches Passwort',
                               link='/konto/anmelden',
                               message='Die das Passwort, das Sie eingegeben haben, ist falsch.'), 422
    salt = rand_salt()
    hashed = hash_password(form['password_new'], salt)
    db_su.execute('update accounts set salt=?, hash=? where id=?', (salt, hashed, acc))
    conn_su.commit()
    if result[4] == 1:
        user_agent = request.user_agent.string
        subject = 'Ihr Passwort wurde geändert. [merkli.me]'
        message_plain = f"Guten Tag, {name}\nDas Passwort zu Ihrem merkli.me-Konto wurde geändert. Bei diesem " \
                        f"Vorgang wurde der folgende User-Agent verwendet: {repr(user_agent)}. Falls Sie Ihr " \
                        f"Passwort nicht geändert haben, kontaktieren Sie sofort den*die Betreiber*in von merkli.me " \
                        f"(E-Mail-Adresse steht im Impressum; diese Adresse wird nur zur automatischen " \
                        f"Kommunikation genutzt) und ändern Sie die Passwörter von allen Konten, die Sie besitzen."
        message = f"<html lang=\"de\"><head><meta charset=\"UTF-8\"><title>Ihr Passwort wurde geändert. " \
                  f"[merkli.me]</title></head><body><p><b>Guten Tag, {name}</b></p><p>Das Passwort zu Ihrem " \
                  f"merkli.me-Konto wurde geändert. Bei diesem Vorgang wurde der folgende User-Agent verwendet: " \
                  f"</p><pre>{user_agent}</pre><p>Falls Sie Ihr Passwort nicht geändert haben, kontaktieren Sie " \
                  f"sofort den*die Betreiber*in von merkli.me <small>(E-Mail-Adresse steht im Impressum; diese " \
                  f"Adresse wird nur zur automatischen Kommunikation genutzt)</small> und ändern Sie die Passwörter " \
                  f"von allen Konten, die Sie besitzen.</p></body></html>"
        send_mail(mail, subject, message_plain, message)
    return render_template('_error.html', stylesheet=stylesheet, account=account, is_signed_in=not (acc is None),
                           page_title='Erfolg', title='Erfolg', link='/konto/einstellungen',
                           message='Ihr Passwort wurde erfolgreich geändert.'), 200


@app.route('/konto/einstellungen/aendern/<index>/<value>', methods=['GET'])
def folder_konto_einstellungen_aendern(index, value):
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        return error_401('not signed-in')
    else:
        account = f"<p>Angemeldet als<br>{name}</p>"
    resp = make_response(redirect('/konto/einstellungen'))
    if index == 'iframe' and value == 'aktivieren':
        db_su.execute('update accounts set iframe=1 where id=?', (acc,))
        conn_su.commit()
        return resp
    elif index == 'iframe' and value == 'deaktivieren':
        db_su.execute('update accounts set iframe=0 where id=?', (acc,))
        conn_su.commit()
        return resp
    elif index == 'benachrichtigungen' and value == 'aktivieren':
        db_su.execute('update accounts set newsletter=1 where id=?', (acc,))
        conn_su.commit()
        return resp
    elif index == 'benachrichtigungen' and value == 'deaktivieren':
        db_su.execute('update accounts set newsletter=0 where id=?', (acc,))
        conn_su.commit()
        return resp
    elif index == 'farbschema':
        db_su.execute('update accounts set theme=? where id=?', (value, acc))
        conn_su.commit()
        return resp
    elif index == 'plattform' and value in ['desktop', 'mobile']:
        resp.set_cookie('platform', value)
        return resp
    return render_template('_error.html', stylesheet=stylesheet, account=account, is_signed_in=not (acc is None),
                           page_title='Fehler', title='Fehler', link='/konto/einstellungen',
                           message='Ihre Anfrage konnte nicht verstanden werden.'), 400


########################################################################################################################
# G21m - ACTIVITY
########################################################################################################################


@app.route('/g21m/aktivität', methods=['GET'])
def site_g21m_aktivitaet():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        account = '<p>Nicht angemeldet</p>'
    else:
        account = f"<p>Angemeldet als<br>{name}</p>"
    result = db_nh.execute('select posted, content, link from activity order by posted desc').fetchall()
    if result is None:
        result = ((get_current_time(), 'Es ist anscheinend nichts interessantes passiert...', '/g21m/aktivität'),)
    elements = []
    for i in range(min(len(result), 64)):
        time_span = calculate_human_time_span(get_current_time(), result[i][0])
        elements.append([time_span, result[i][1], result[i][2]])
    return render_template('g21m_aktivität.html', stylesheet=stylesheet, account=account, is_signed_in=not(acc is None),
                           elements=elements)


########################################################################################################################
# G21m - COMMENTS
########################################################################################################################


@app.route('/g21m/kommentar/neu/<element>', methods=['POST'])
def folder_g21m_kommentar_neu(element):
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        return error_401('not signed-in')
    form = dict(request.form)
    if 'text' not in form:
        return error_422('required fields are empty')
    db_nh.execute('insert into comments values (?, ?, ?, ?, ?)',
                  (rand_base64(10), form['text'], acc, element, get_current_time()))
    conn_nh.commit()
    if len(element) == 6:
        url = f"/g21m/dokumente/vorschau/{element}"
    elif len(element) == 8:
        url = f"/g21m/lernsets/{element}"
    else:
        url = '/'
    g21m_activity(f"\"{name}\" hat einen neuen Kommentar verfasst.", url)
    return redirect(url)


########################################################################################################################
# G21m - CALENDAR
########################################################################################################################


@app.route('/g21m/kalender', methods=['GET'])
def site_g21m_kalender():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        account = '<p>Nicht angemeldet</p>'
    else:
        account = f"<p>Angemeldet als<br>{name}</p>"
    calendar_data = []
    result = db_nh.execute('select id, start_date, end_date, name, type from calendar order by start_date').fetchall()
    for i in result:
        calendar_data.append({'id': i[0], 'start_date': i[1], 'end_date': i[2], 'name': i[3], 'type': i[4]})
    now = datetime.now()
    return render_template('g21m_kalender.html', stylesheet=stylesheet, account=account, is_signed_in=not(acc is None),
                           calendar_data=calendar_data, year=now.year, month=now.month, day=now.day,
                           admin=is_admin(acc))


@app.route('/g21m/kalender/neu', methods=['POST'])
def site_g21m_kalender_neu():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if not is_admin(acc):
        return error_401('user does not have admin privileges')
    form = dict(request.form)
    for i in ['name', 'start', 'end', 'type']:
        if i not in form:
            return error_422('empty input fields')
    event_id = rand_base64(8)
    db_nh.execute('insert into calendar values (?, ?, ?, ?, ?)',
                  (event_id, form['start'], form['end'], form['name'], int(form['type'])))
    conn_nh.commit()
    url = '/g21m/kalender'
    g21m_activity(f"Es wurde ein neuer Termin in den Kalender eingetragen: \"{form['name']}\"", url)
    return redirect(url)


########################################################################################################################
# G21m - DOCUMENTS
########################################################################################################################


@app.route('/g21m/dokumente', methods=['GET'])
def site_g21m_dokumente():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        account = '<p>Nicht angemeldet</p>'
    else:
        account = f"<p>Angemeldet als<br>{name}</p>"
    result = db_nh.execute('select id, name, subject, owner, edited, created from documents order by edited desc'
                           ).fetchall()
    documents = []
    for i in result:
        file_path = join(app.root_path, 'g21m_documents', i[0])
        if not exists(file_path):
            continue
        file_size = getsize(file_path)
        exponent = 0
        while file_size >= 1000:
            file_size //= 1000
            exponent += 1
        file_size_string = f"{file_size}{_size_units[exponent]}"
        file_type = _file_types.get(type_from_file(file_path, mime=True), '---')
        documents.append([i[1], i[2], i[0], f"{file_type} {file_size_string}", i[5], i[4], get_account_name(i[3])])
    return render_template('g21m_dokumente.html', stylesheet=stylesheet, account=account, is_signed_in=not(acc is None),
                           documents=documents)


@app.route('/g21m/dokumente/vorschau/<file>', methods=['GET'])
def folder_g21m_dokumente_vorschau(file):
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        account = '<p>Nicht angemeldet</p>'
    else:
        account = f"<p>Angemeldet als<br>{name}</p>"
    result = db_nh.execute('select id, name, subject, owner, edited, created from documents where id=?', (file,)
                           ).fetchone()
    if result is None:
        return error_404('document not found')
    file_path = join(app.root_path, 'g21m_documents', result[0])
    file_size = getsize(file_path)
    exponent = 0
    while file_size >= 1000:
        file_size //= 1000
        exponent += 1
    file_info = f"{_file_types.get(type_from_file(file_path, mime=True), '---')} {file_size}{_size_units[exponent]}"
    document_download = secure_filename(result[1])
    result2 = db_nh.execute('select id, content, owner, subject, posted from comments where subject=?', (file,)
                            ).fetchall()
    comments = []
    for i in result2:
        comments.append([get_account_name(i[2]), i[4], i[0], i[1]])
    allow_iframe = False
    if acc is not None:
        result3 = db_su.execute('select iframe from accounts where id=?', (acc,)).fetchone()
        if result3 is None:
            return error_500('account conflict')
        allow_iframe = result3[0] == 1
    document_name = f"[{result[2]}] {result[1]}"
    return render_template('g21m_dokumente_vorschau.html', stylesheet=stylesheet, account=account,
                           is_signed_in=not(acc is None), document_name=document_name, file_info=file_info,
                           edited=result[4], created=result[5], owner=get_account_name(result[3]),
                           document_id=result[0], document_download=document_download, allow_iframe=allow_iframe,
                           comments=comments, is_owner=(result[3] == acc))


@app.route('/g21m/dokumente/download/<file>', methods=['GET'])
def folder_g21m_dokumente_download(file):
    result = db_nh.execute('select id, name from documents where id=?', (file.split('.')[0],)).fetchone()
    if result is None:
        return error_404('document not found')
    file_path = join(app.root_path, 'g21m_documents', file.split('.')[0])
    extension = _file_types.get(type_from_file(file_path, mime=True), 'BIN').lower()
    return redirect('/g21m/dokumente/herunterladen/' + file + '.' + extension)


@app.route('/g21m/dokumente/herunterladen/<file>', methods=['GET'])
def folder_g21m_dokumente_herunterladen(file):
    result = db_nh.execute('select id, name from documents where id=?', (file.split('.')[0],)).fetchone()
    if result is None:
        return error_404('document not found')
    file_path = join(app.root_path, 'g21m_documents', file.split('.')[0])
    resp = make_response(send_from_directory(join(app.root_path, 'g21m_documents'), file.split('.')[0]))
    resp.mimetype = type_from_file(file_path, mime=True)
    return resp


@app.route('/g21m/dokumente/neu', methods=['GET'])
def site_g21m_dokumente_neu():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        return error_401('not signed-in')
    account = f"<p>Angemeldet als<br>{name}</p>"
    return render_template('g21m_dokumente_neu.html', stylesheet=stylesheet, account=account,
                           is_signed_in=not(acc is None))


@app.route('/g21m/dokumente/neu/post', methods=['POST'])
def site_g21m_dokumente_neu_post():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        return error_401('not signed-in')
    form_data = dict(request.form)
    for i in ['name', 'subject']:
        if i not in form_data:
            return error_422('required field(s) in form is empty')
    doc_id = rand_base64(6)
    cur_time = get_current_time().split('_')[0]
    file = request.files['file']
    file.save(join(app.root_path, 'g21m_documents', doc_id))
    file.close()
    db_nh.execute('insert into documents values (?, ?, ?, ?, ?, ?)',
                  (doc_id, form_data['name'], form_data['subject'], acc, cur_time, cur_time))
    conn_nh.commit()
    url = '/g21m/dokumente/vorschau/' + doc_id
    g21m_activity(f"\"{name}\" hat das Dokument \"{form_data['name']}\" erstellt.", url)
    return redirect(url)


@app.route('/g21m/dokumente/aktualisieren/<file>', methods=['GET'])
def folder_g21m_dokumente_aktualisieren(file):
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        return error_401('not signed-in')
    account = f"<p>Angemeldet als<br>{name}</p>"
    result = db_nh.execute('select id, name, subject, owner, edited, created from documents where id=?', (file,)
                           ).fetchone()
    if result is None:
        return error_404('document not found')
    if result[3] != acc:
        return error_403('not owner of document')
    return render_template('g21m_dokumente_aktualisieren.html', stylesheet=stylesheet, account=account, doc_id=file,
                           is_signed_in=not(acc is None), name=result[1])


@app.route('/g21m/dokumente/update/<file>', methods=['POST'])
def folder_g21m_dokumente_update(file):
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        return error_401('not signed-in')
    form_data = dict(request.form)
    for i in ['name', 'subject']:
        if i not in form_data:
            return error_422('required field(s) in form is empty')
    result = db_nh.execute('select id, name, subject, owner, edited, created from documents where id=?', (file,)
                           ).fetchone()
    if result is None:
        return error_404('document not found')
    if result[3] != acc:
        return error_403('not owner of document')
    cur_time = get_current_time().split('_')[0]
    f = request.files['file']
    f.save(join(app.root_path, 'g21m_documents', file))
    f.close()
    db_nh.execute('update documents set name=?, subject=?, edited=? where id=?', (form_data['name'],
                                                                                  form_data['subject'], cur_time, file))
    conn_nh.commit()
    url = '/g21m/dokumente/vorschau/' + file
    g21m_activity(f"\"{name}\" hat das Dokument \"{form_data['name']}\" aktualisiert.", url)
    return redirect(url)


########################################################################################################################
# G21m - LEARNING
########################################################################################################################


@app.route('/g21m/lernsets', methods=['GET'])
def site_g21m_lernsets():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        account = '<p>Nicht angemeldet</p>'
        latest = []
        selected = []
    else:
        account = f"<p>Angemeldet als<br>{name}</p>"
        result2 = db_nh.execute('select account, answers, latest from statistics where account=?', (acc,)).fetchone()
        if result2 is None:
            db_nh.execute('insert into statistics values (?, ?, ?)', (acc, '{}', ''))
            conn_nh.commit()
            latest = []
            selected = []
        else:
            latest = result2[2].split(' ')
            selected = latest
    result = db_nh.execute('select id, name, subject, owner, edited, content from exercises '
                           'order by edited desc, subject, name').fetchall()
    sets = []
    for i in result:
        sets.append([i[0], i[0] in selected, i[1], i[2], get_account_name(i[3]), i[4].split('_')[0]])
    show_last_learned = len(latest) > 0
    learned_elements = []
    for i in latest:
        if i == '':
            continue
        stats = get_stats(acc, i)
        if stats['total'] != 0:
            progress = f"{round((stats['correct'] + stats['wrong']) / stats['total'] * 100)}%"
        else:
            progress = '--%'
        if stats['correct'] + stats['wrong'] != 0:
            grade = f"~{round(stats['correct'] / (stats['correct'] + stats['wrong']) * 5 + 1, 2)}"
        else:
            grade = '~-'
        learned_elements.append([get_set_name(i), progress, grade, '/g21m/lernen/' + i])
    return render_template('g21m_lernsets.html', stylesheet=stylesheet, account=account, is_signed_in=not(acc is None),
                           sets=sets, show_last_learned=show_last_learned, learned_elements=learned_elements)


@app.route('/g21m/lernsets/start', methods=['POST'])
def site_g21m_lernsets_start():
    form_data = dict(request.form)
    sets = existing_sets('-'.join(form_data))
    if sets == '':
        acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
        if acc is None:
            account = '<p>Nicht angemeldet</p>'
        else:
            account = f"<p>Angemeldet als<br>{name}</p>"
        return render_template('_error.html', stylesheet=stylesheet, account=account, is_signed_in=not (acc is None),
                               page_title='Keine Auswahl', title='Keine Lernsets ausgewählt', link='/g21m/lernsets',
                               message='Sie müssen mindestens ein Lernset auswählen.'), 422
    return redirect('/g21m/lernen/' + sets)


@app.route('/g21m/lernen/<ids>', methods=['GET'])
def folder_g21m_lernen(ids):
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        account = '<p>Nicht angemeldet</p>'
    else:
        account = f"<p>Angemeldet als<br>{name}</p>"
    result = db_nh.execute('select answers from statistics where account=?', (acc,)).fetchone()
    if result is None:
        db_nh.execute('insert into statistics values (?, ?, ?)', (acc, '{}', ''))
        conn_nh.commit()
        stats = {}
    else:
        stats = json_loads(result[0])
    result2 = db_nh.execute('select id, name, subject, content from exercises').fetchall()
    sets = {}
    for i in result2:
        if i[0] in ids:
            sets[i[0]] = {'name': f"[{i[2]}] {i[1]}", 'exercises': json_loads(i[3])}
    return render_template('g21m_lernen.html', stylesheet=stylesheet, account=account, is_signed_in=not(acc is None),
                           stats=stats, sets=sets)


@app.route('/g21m/lernsets/statistiken/<ids>/<ex_id>/<int:toggle>', methods=['POST'])
def folder_g21m_lernsets_statistiken(ids, ex_id, toggle):
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    sets = existing_sets(ids)
    if sets == '' or ex_id == '' or toggle not in [0, 1]:
        return 'invalid request', 400
    if acc is None:
        return 'not signed-in', 401
    parts = ex_id.split('_')
    result = db_nh.execute('select answers from statistics where account=?', (acc,)).fetchone()
    if result is None:
        db_nh.execute('insert into statistics values (?, ?, ?)', (acc, '{}', ''))
        conn_nh.commit()
        stats = {}
    else:
        stats = json_loads(result[0])
    ex = f"{sets}_{parts[1]}"
    if ex not in stats:
        stats[ex] = {'correct': 0, 'wrong': 0}
    if toggle == 1:
        stats[ex]['correct'] += 1
    else:
        stats[ex]['wrong'] += 1
    db_nh.execute('update statistics set answers=? where account=?', (stats, acc))
    return 'success', 200


@app.route('/g21m/lernsets/anleitung', methods=['GET'])
def site_g21m_lernsets_anleitung():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        account = '<p>Nicht angemeldet</p>'
    else:
        account = f"<p>Angemeldet als<br>{name}</p>"
    return render_template('g21m_lernsets_anleitung.html', stylesheet=stylesheet, account=account,
                           is_signed_in=not(acc is None))


@app.route('/g21m/lernsets/neu', methods=['GET'])
def site_g21m_lernsets_neu():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        return error_401('not signed-in')
    account = f"<p>Angemeldet als<br>{name}</p>"
    return render_template('g21m_lernsets_neu.html', stylesheet=stylesheet, account=account,
                           is_signed_in=not(acc is None))


@app.route('/g21m/lernsets/neu/post', methods=['POST'])
def site_g21m_lernsets_neu_post():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        return error_401('not signed-in')
    form_data = dict(request.form)
    for i in ['name', 'subject']:
        if i not in form_data:
            return error_422('required field(s) in form is empty')
    ex_id = rand_base16(8)
    cur_time = get_current_time().split('_')[0]
    file = request.files['file']
    f = file.stream.read().decode()
    file.close()
    try:
        content, trigger_error = upload_set(f, ex_id)
    except Exception as error:
        return error_403(error)
    if trigger_error is not None:
        return error_422(trigger_error)
    db_nh.execute('insert into exercises values (?, ?, ?, ?, ?, ?)',
                  (ex_id, form_data['name'], form_data['subject'], acc, cur_time, content))
    conn_nh.commit()
    url = '/g21m/lernen/' + ex_id
    g21m_activity(f"\"{name}\" hat das Lernset \"{form_data['name']}\" erstellt.", url)
    return redirect(url)


@app.route('/g21m/lernsets/aktualisieren', methods=['GET'])
def site_g21m_lernsets_aktualisieren():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        return error_401('not signed-in')
    account = f"<p>Angemeldet als<br>{name}</p>"
    return render_template('g21m_lernsets_aktualisieren.html', stylesheet=stylesheet, account=account,
                           is_signed_in=not(acc is None))


@app.route('/g21m/lernsets/aktualisieren/post', methods=['POST'])
def site_g21m_lernsets_aktualisieren_post():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        return error_401('not signed-in')
    form_data = dict(request.form)
    for i in ['id', 'name', 'subject']:
        if i not in form_data:
            return error_422('required field(s) in form is empty')
    ex_id = form_data['id']
    result = db_nh.execute('select id, name, subject, owner, edited, content from exercises where id=?',
                           (ex_id,)).fetchone()
    if result is None:
        return error_404('exercise set not found')
    if result[3] != acc:
        return error_403('not owner of exercise set')
    file = request.files['file']
    f = file.stream.read().decode()
    file.close()
    try:
        content, trigger_error = upload_set(f, ex_id)
    except Exception as error:
        return error_422(error)
    if trigger_error is not None:
        return error_422(trigger_error)
    db_nh.execute('insert into exercises values (?, ?, ?, ?, ?, ?)',
                  (ex_id, form_data['name'], form_data['subject'], acc, result[4], content))
    conn_nh.commit()
    url = '/g21m/lernen/' + ex_id
    g21m_activity(f"\"{name}\" hat das Lernset \"{form_data['name']}\" aktualisiert.", url)
    return redirect(url)


########################################################################################################################
# G21m - MENSA
########################################################################################################################


@app.route('/g21m/menüplan', methods=['GET'])
def site_g21m_menuplan():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        account = '<p>Nicht angemeldet</p>'
    else:
        account = f"<p>Angemeldet als<br>{name}</p>"
    with open(join(app.root_path, 'resources/mensa.json'), 'r') as f:
        result = json_load(f)
    weekdays = result['days']
    data = []
    for i, weekday in enumerate(weekdays):
        day = [weekday, []]
        for _, (title, text) in enumerate(zip(result['titles'][i], result['texts'][i])):
            day[1].append([title, text])
        data.append(day.copy())
    return render_template('g21m_menüplan.html', stylesheet=stylesheet, account=account, is_signed_in=not(acc is None),
                           data=data)

########################################################################################################################
# ZITATELISTE - QUOTES
########################################################################################################################


@app.route('/zitateliste/zitate', methods=['GET'])
def site_zitateliste_zitate():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        return error_401('not signed-in')
    level, zl_name, last_q, last_a, last_c = get_zl_info(acc)
    if level < 1:
        return error_403('not enough permissions')
    account = f"<p>Angemeldet als<br>{zl_name}</p>"
    data = []
    if level >= 3:
        result = zl_combine('quotes')
        for i in result:
            quote_times = list(result[i].keys())
            current = max(quote_times)
            prepared = result[i][current]
            prepared['edited'] = current
            prepared['id'] = i
            if (level < 6 and (zl_name in prepared['author'])) \
                    or (level >= 6 and ('zensiert' not in prepared['tags'])) \
                    or level >= 9:
                data.append(prepared)
    db_zl.execute('update access set last_quote=? where account=?', (zl_current_time(), acc))
    conn_zl.commit()
    return render_template('zitateliste_zitate.html', stylesheet=stylesheet, account=account,
                           is_signed_in=not (acc is None), data=json_dumps(data, ensure_ascii=False), last=last_q)


@app.route('/zitateliste/zitate/neu', methods=['GET'])
def site_zitateliste_zitate_neu():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        return error_401('not signed-in')
    level, zl_name, last_q, last_a, last_c = get_zl_info(acc)
    if level < 2:
        return error_403('not enough permissions')
    account = f"<p>Angemeldet als<br>{zl_name}</p>"
    current_time = zl_current_time()
    return render_template('zitateliste_zitate_neu.html', stylesheet=stylesheet, account=account,
                           is_signed_in=not (acc is None), current_time=current_time)


@app.route('/zitateliste/zitate/neu/post', methods=['POST'])
def site_zitateliste_zitate_neu_post():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        return error_401('not signed-in')
    level, zl_name, last_q, last_a, last_c = get_zl_info(acc)
    if level < 2:
        return error_403('not enough permissions')
    form_data = dict(request.form)
    for i in ['quote', 'author', 'context', 'time', 'tags']:
        if i not in form_data:
            return error_422('required field(s) in form is empty')
    current_time = zl_current_time()
    data = {current_time: {'text': form_data['quote'], 'author': form_data['author'], 'time': form_data['time'],
                           'tags': form_data['tags'].split(' '), 'comments': form_data['context'], 'changed': zl_name}}
    if level >= 7:
        db_zl.execute('insert into quotes values (?, ?)', (zl_next_id('quotes'), json_dumps(data, ensure_ascii=False)))
    else:
        db_zl.execute('insert into proposed values (?, ?, ?, ?)',
                      (rand_base64(8), acc, 'quotes', json_dumps(data, ensure_ascii=False)))
    conn_zl.commit()
    return redirect('/zitateliste/zitate')


@app.route('/zitateliste/zitate/bearbeiten/<quote>', methods=['GET'])
def folder_zitateliste_zitate_bearbeiten(quote):
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        return error_401('not signed-in')
    level, zl_name, last_q, last_a, last_c = get_zl_info(acc)
    if level < 7:
        return error_403('not enough permissions')
    account = f"<p>Angemeldet als<br>{zl_name}</p>"
    result = db_zl.execute('select content from quotes where id=?', (quote,)).fetchone()
    if result is None:
        return error_404('quote not found')
    data = json_loads(result[0])
    quote_times = list(data.keys())
    current = data[max(quote_times)]
    if ('geschützt' in current['tags'] or 'zensiert' in current['tags']) and level < 9:
        return error_403('not enough permissions')
    return render_template('zitateliste_zitate_bearbeiten.html', stylesheet=stylesheet, account=account,
                           is_signed_in=not (acc is None), id=quote, quote=current['text'], author=current['author'],
                           time=current['time'], context=current['comments'], tags=' '.join(current['tags']))


@app.route('/zitateliste/zitate/update/<quote>', methods=['POST'])
def folder_zitateliste_zitate_update(quote):
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        return error_401('not signed-in')
    level, zl_name, last_q, last_a, last_c = get_zl_info(acc)
    if level < 7:
        return error_403('not enough permissions')
    result = db_zl.execute('select content from quotes where id=?', (quote,)).fetchone()
    if result is None:
        return error_404('quote not found')
    form_data = dict(request.form)
    for i in ['quote', 'author', 'context', 'time', 'tags']:
        if i not in form_data:
            return error_422('required field(s) in form is empty')
    data = json_loads(result[0])
    quote_times = list(data.keys())
    current = data[max(quote_times)]
    if ('geschützt' in current['tags'] or 'zensiert' in current['tags']) and level < 9:
        return error_403('not enough permissions')
    data[zl_current_time()] = {'text': form_data['quote'], 'author': form_data['author'], 'time': form_data['time'],
                               'tags': form_data['tags'].split(' '), 'comments': form_data['context'],
                               'changed': zl_name}
    db_zl.execute('update quotes set content=? where id=?', (json_dumps(data, ensure_ascii=False), quote))
    conn_zl.commit()
    return redirect('/zitateliste/zitate')


@app.route('/zitateliste/zitate/geschichte/<quote>', methods=['GET'])
def folder_zitateliste_zitate_geschichte(quote):
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        return error_401('not signed-in')
    level, zl_name, last_q, last_a, last_c = get_zl_info(acc)
    if level < 3:
        return error_403('not enough permissions')
    account = f"<p>Angemeldet als<br>{zl_name}</p>"
    result = db_zl.execute('select content from quotes where id=?', (quote,)).fetchone()
    if result is None:
        return error_404('quote not found')
    data = json_loads(result[0])
    quote_times = list(data.keys())
    quote_times.sort()
    current = data[max(quote_times)]
    if (('zensiert' in current['tags']) and level < 9) or ((zl_name not in current['author']) and level < 6):
        return error_403('not enough permissions')
    versions = []
    for i in quote_times:
        versions.append([i, data[i]['changed'], data[i]['text'], data[i]['author'], data[i]['comments'],
                         ' '.join(data[i]['tags']), data[i]['time']])
    return render_template('zitateliste_zitate_geschichte.html', stylesheet=stylesheet, account=account,
                           is_signed_in=not (acc is None), id=quote, versions=versions)


@app.route('/zitateliste/zitate/rangliste', methods=['GET'])
def site_zitateliste_zitate_rangliste():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        return error_401('not signed-in')
    level, zl_name, last_q, last_a, last_c = get_zl_info(acc)
    if level < 4:
        return error_403('not enough permissions')
    account = f"<p>Angemeldet als<br>{zl_name}</p>"
    people = {}
    result = zl_combine('quotes')
    for i in result:
        quote_times = list(result[i].keys())
        current = max(quote_times)
        authors = result[i][current]['author'].split(';')
        authors2 = []
        for j in authors:
            if j not in authors2:
                authors2.append(j)
        for j in authors2:
            if j in people:
                people[j] += 1
            else:
                people[j] = 1
    ranking = []
    for j in people:
        rank = str(people[j]).zfill(4)
        ranking.append(f"[{rank}] {j}")
    ranking.sort()
    ranking.reverse()
    return render_template('zitateliste_zitate_rangliste.html', stylesheet=stylesheet, account=account,
                           is_signed_in=not (acc is None), ranking=ranking)


@app.route('/zitateliste/zitate/zitate.json', methods=['GET'])
def file_zitateliste_zitate_zitate():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        return error_401('not signed-in')
    level, zl_name, last_q, last_a, last_c = get_zl_info(acc)
    if level < 8:
        return error_403('not enough permissions')
    return jsonify(zl_combine('quotes'))


########################################################################################################################
# ZITATELISTE - ACTIONS
########################################################################################################################


@app.route('/zitateliste/aktionen', methods=['GET'])
def site_zitateliste_aktionen():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        return error_401('not signed-in')
    level, zl_name, last_q, last_a, last_c = get_zl_info(acc)
    if level < 2:
        return error_403('not enough permissions')
    account = f"<p>Angemeldet als<br>{zl_name}</p>"
    data = []
    if level >= 6:
        result = zl_combine('actions')
        for i in result:
            edit_times = list(result[i].keys())
            current = max(edit_times)
            prepared = result[i][current]
            prepared['edited'] = current
            prepared['id'] = i
            if ('zensiert' not in prepared['tags']) or level >= 9:
                data.append(prepared)
    db_zl.execute('update access set last_action=? where account=?', (zl_current_time(), acc))
    conn_zl.commit()
    return render_template('zitateliste_aktionen.html', stylesheet=stylesheet, account=account,
                           is_signed_in=not (acc is None), data=json_dumps(data, ensure_ascii=False), last=last_a)


@app.route('/zitateliste/aktionen/neu', methods=['GET'])
def site_zitateliste_aktionen_neu():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        return error_401('not signed-in')
    level, zl_name, last_q, last_a, last_c = get_zl_info(acc)
    if level < 2:
        return error_403('not enough permissions')
    account = f"<p>Angemeldet als<br>{zl_name}</p>"
    current_time = zl_current_time()
    return render_template('zitateliste_aktionen_neu.html', stylesheet=stylesheet, account=account,
                           is_signed_in=not (acc is None), current_time=current_time)


@app.route('/zitateliste/aktionen/neu/post', methods=['POST'])
def site_zitateliste_aktionen_neu_post():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        return error_401('not signed-in')
    level, zl_name, last_q, last_a, last_c = get_zl_info(acc)
    if level < 2:
        return error_403('not enough permissions')
    form_data = dict(request.form)
    for i in ['text', 'time', 'tags']:
        if i not in form_data:
            return error_422('required field(s) in form is empty')
    current_time = zl_current_time()
    data = {current_time: {'text': form_data['text'], 'time': form_data['time'],
                           'tags': form_data['tags'].split(' '), 'changed': zl_name}}
    if level >= 7:
        db_zl.execute('insert into actions values (?, ?)',
                      (zl_next_id('actions'), json_dumps(data, ensure_ascii=False)))
    else:
        db_zl.execute('insert into proposed values (?, ?, ?, ?)',
                      (rand_base64(8), acc, 'actions', json_dumps(data, ensure_ascii=False)))
    conn_zl.commit()
    return redirect('/zitateliste/aktionen')


@app.route('/zitateliste/aktionen/bearbeiten/<action>', methods=['GET'])
def folder_zitateliste_aktionen_bearbeiten(action):
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        return error_401('not signed-in')
    level, zl_name, last_q, last_a, last_c = get_zl_info(acc)
    if level < 7:
        return error_403('not enough permissions')
    account = f"<p>Angemeldet als<br>{zl_name}</p>"
    result = db_zl.execute('select content from actions where id=?', (action,)).fetchone()
    if result is None:
        return error_404('action not found')
    data = json_loads(result[0])
    edit_times = list(data.keys())
    current = data[max(edit_times)]
    if ('geschützt' in current['tags'] or 'zensiert' in current['tags']) and level < 9:
        return error_403('not enough permissions')
    return render_template('zitateliste_aktionen_bearbeiten.html', stylesheet=stylesheet, account=account,
                           is_signed_in=not (acc is None), id=action, text=current['text'],
                           time=current['time'], tags=' '.join(current['tags']))


@app.route('/zitateliste/aktionen/update/<action>', methods=['POST'])
def folder_zitateliste_aktionen_update(action):
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        return error_401('not signed-in')
    level, zl_name, last_q, last_a, last_c = get_zl_info(acc)
    if level < 7:
        return error_403('not enough permissions')
    result = db_zl.execute('select content from actions where id=?', (action,)).fetchone()
    if result is None:
        return error_404('action not found')
    form_data = dict(request.form)
    for i in ['text', 'time', 'tags']:
        if i not in form_data:
            return error_422('required field(s) in form is empty')
    data = json_loads(result[0])
    edit_times = list(data.keys())
    current = data[max(edit_times)]
    if ('geschützt' in current['tags'] or 'zensiert' in current['tags']) and level < 9:
        return error_403('not enough permissions')
    data[zl_current_time()] = {'text': form_data['text'], 'time': form_data['time'],
                               'tags': form_data['tags'].split(' '), 'changed': zl_name}
    db_zl.execute('update actions set content=? where id=?', (json_dumps(data, ensure_ascii=False), action))
    conn_zl.commit()
    return redirect('/zitateliste/aktionen')


@app.route('/zitateliste/aktionen/geschichte/<action>', methods=['GET'])
def folder_zitateliste_aktionen_geschichte(action):
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        return error_401('not signed-in')
    level, zl_name, last_q, last_a, last_c = get_zl_info(acc)
    if level < 6:
        return error_403('not enough permissions')
    account = f"<p>Angemeldet als<br>{zl_name}</p>"
    result = db_zl.execute('select content from actions where id=?', (action,)).fetchone()
    if result is None:
        return error_404('action not found')
    data = json_loads(result[0])
    edit_times = list(data.keys())
    edit_times.sort()
    current = data[max(edit_times)]
    if ('zensiert' in current['tags']) and level < 9:
        return error_403('not enough permissions')
    versions = []
    for i in edit_times:
        versions.append([i, data[i]['changed'], data[i]['text'], ' '.join(data[i]['tags']), data[i]['time']])
    return render_template('zitateliste_aktionen_geschichte.html', stylesheet=stylesheet, account=account,
                           is_signed_in=not (acc is None), id=action, versions=versions)


@app.route('/zitateliste/aktionen/aktionen.json', methods=['GET'])
def file_zitateliste_aktionen_aktionen():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        return error_401('not signed-in')
    level, zl_name, last_q, last_a, last_c = get_zl_info(acc)
    if level < 8:
        return error_403('not enough permissions')
    return jsonify(zl_combine('actions'))


########################################################################################################################
# ZITATELISTE - CONSPIRACIES
########################################################################################################################


@app.route('/zitateliste/manmunkelt', methods=['GET'])
def site_zitateliste_manmunkelt():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        return error_401('not signed-in')
    level, zl_name, last_q, last_a, last_c = get_zl_info(acc)
    if level < 2:
        return error_403('not enough permissions')
    account = f"<p>Angemeldet als<br>{zl_name}</p>"
    data = []
    if level >= 5:
        result = zl_combine('conspiracies')
        for i in result:
            edit_times = list(result[i].keys())
            current = max(edit_times)
            prepared = result[i][current]
            prepared['edited'] = current
            prepared['id'] = i
            if ('zensiert' not in prepared['tags']) or level >= 9:
                data.append(prepared)
    db_zl.execute('update access set last_conspiracy=? where account=?', (zl_current_time(), acc))
    conn_zl.commit()
    return render_template('zitateliste_manmunkelt.html', stylesheet=stylesheet, account=account,
                           is_signed_in=not (acc is None), data=json_dumps(data, ensure_ascii=False), last=last_c)


@app.route('/zitateliste/manmunkelt/neu', methods=['GET'])
def site_zitateliste_manmunkelt_neu():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        return error_401('not signed-in')
    level, zl_name, last_q, last_a, last_c = get_zl_info(acc)
    if level < 2:
        return error_403('not enough permissions')
    account = f"<p>Angemeldet als<br>{zl_name}</p>"
    current_time = zl_current_time()
    return render_template('zitateliste_manmunkelt_neu.html', stylesheet=stylesheet, account=account,
                           is_signed_in=not (acc is None), current_time=current_time)


@app.route('/zitateliste/manmunkelt/neu/post', methods=['POST'])
def site_zitateliste_manmunkelt_neu_post():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        return error_401('not signed-in')
    level, zl_name, last_q, last_a, last_c = get_zl_info(acc)
    if level < 2:
        return error_403('not enough permissions')
    form_data = dict(request.form)
    for i in ['text', 'time', 'tags']:
        if i not in form_data:
            return error_422('required field(s) in form is empty')
    current_time = zl_current_time()
    data = {current_time: {'text': form_data['text'], 'time': form_data['time'],
                           'tags': form_data['tags'].split(' '), 'changed': zl_name}}
    if level >= 7:
        db_zl.execute('insert into conspiracies values (?, ?)',
                      (zl_next_id('conspiracies'), json_dumps(data, ensure_ascii=False)))
    else:
        db_zl.execute('insert into proposed values (?, ?, ?, ?)',
                      (rand_base64(8), acc, 'conspiracies', json_dumps(data, ensure_ascii=False)))
    conn_zl.commit()
    return redirect('/zitateliste/manmunkelt')


@app.route('/zitateliste/manmunkelt/bearbeiten/<conspiracy>', methods=['GET'])
def folder_zitateliste_manmunkelt_bearbeiten(conspiracy):
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        return error_401('not signed-in')
    level, zl_name, last_q, last_a, last_c = get_zl_info(acc)
    if level < 7:
        return error_403('not enough permissions')
    account = f"<p>Angemeldet als<br>{zl_name}</p>"
    result = db_zl.execute('select content from conspiracies where id=?', (conspiracy,)).fetchone()
    if result is None:
        return error_404('conspiracy not found')
    data = json_loads(result[0])
    edit_times = list(data.keys())
    current = data[max(edit_times)]
    if ('geschützt' in current['tags'] or 'zensiert' in current['tags']) and level < 9:
        return error_403('not enough permissions')
    return render_template('zitateliste_manmunkelt_bearbeiten.html', stylesheet=stylesheet, account=account,
                           is_signed_in=not (acc is None), id=conspiracy, text=current['text'],
                           time=current['time'], tags=' '.join(current['tags']))


@app.route('/zitateliste/manmunkelt/update/<conspiracy>', methods=['POST'])
def folder_zitateliste_manmunkelt_update(conspiracy):
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        return error_401('not signed-in')
    level, zl_name, last_q, last_a, last_c = get_zl_info(acc)
    if level < 7:
        return error_403('not enough permissions')
    result = db_zl.execute('select content from conspiracies where id=?', (conspiracy,)).fetchone()
    if result is None:
        return error_404('conspiracy not found')
    form_data = dict(request.form)
    for i in ['text', 'time', 'tags']:
        if i not in form_data:
            return error_422('required field(s) in form is empty')
    data = json_loads(result[0])
    edit_times = list(data.keys())
    current = data[max(edit_times)]
    if ('geschützt' in current['tags'] or 'zensiert' in current['tags']) and level < 9:
        return error_403('not enough permissions')
    data[zl_current_time()] = {'text': form_data['text'], 'time': form_data['time'],
                               'tags': form_data['tags'].split(' '), 'changed': zl_name}
    db_zl.execute('update conspiracies set content=? where id=?', (json_dumps(data, ensure_ascii=False), conspiracy))
    conn_zl.commit()
    return redirect('/zitateliste/manmunkelt')


@app.route('/zitateliste/manmunkelt/geschichte/<conspiracy>', methods=['GET'])
def folder_zitateliste_manmunkelt_geschichte(conspiracy):
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        return error_401('not signed-in')
    level, zl_name, last_q, last_a, last_c = get_zl_info(acc)
    if level < 5:
        return error_403('not enough permissions')
    account = f"<p>Angemeldet als<br>{zl_name}</p>"
    result = db_zl.execute('select content from conspiracies where id=?', (conspiracy,)).fetchone()
    if result is None:
        return error_404('conspiracy not found')
    data = json_loads(result[0])
    edit_times = list(data.keys())
    edit_times.sort()
    current = data[max(edit_times)]
    if ('zensiert' in current['tags']) and level < 9:
        return error_403('not enough permissions')
    versions = []
    for i in edit_times:
        versions.append([i, data[i]['changed'], data[i]['text'], ' '.join(data[i]['tags']), data[i]['time']])
    return render_template('zitateliste_manmunkelt_geschichte.html', stylesheet=stylesheet, account=account,
                           is_signed_in=not (acc is None), id=conspiracy, versions=versions)


@app.route('/zitateliste/manmunkelt/manmunkelt.json', methods=['GET'])
def file_zitateliste_manmunkelt_manmunkelt():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        return error_401('not signed-in')
    level, zl_name, last_q, last_a, last_c = get_zl_info(acc)
    if level < 8:
        return error_403('not enough permissions')
    return jsonify(zl_combine('conspiracies'))


########################################################################################################################
# ZITATELISTE - ZITLVO
########################################################################################################################


@app.route('/zitateliste/zitlvo.pdf', methods=['GET'])
def file_zitateliste_zitlvo():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        return redirect('/')
    level, zl_name, last_q, last_a, last_c = get_zl_info(acc)
    if level < 2:
        return redirect('/')
    return send_from_directory(join(app.root_path, 'resources'), 'ZitLVo.pdf')


########################################################################################################################
# CONTROL PANEL
########################################################################################################################


@app.route('/controlpanel', methods=['GET'])
def site_controlpanel():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        return error_401('not signed-in')
    if not is_admin(acc):
        return error_403('not enough permissions')
    account = f"<p>Angemeldet als<br>{name}</p>"
    return render_template('controlpanel.html', stylesheet=stylesheet, account=account, is_signed_in=not (acc is None))


@app.route('/controlpanel/action', methods=['POST'])
def site_controlpanel_post():
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        return error_401('not signed-in')
    if not is_admin(acc):
        return error_403('not enough permissions')
    account = f"<p>Angemeldet als<br>{name}</p>"
    form = dict(request.form)
    for i in ['action', 'password', 'database']:
        if i not in form:
            return error_422('required fields are empty')
    result2 = db_su.execute('select id, mail, salt, hash from accounts where id=?', (acc,)).fetchone()
    if result2 is None:
        return error_500('paradox: account exists and does not')
    if hash_password(form['password'], result2[2]) != result2[3]:
        return render_template('_error.html', stylesheet=stylesheet, account=account, is_signed_in=not (acc is None),
                               page_title='falsche Anmeldedaten', title='falsche Anmeldedaten',
                               link='/controlpanel', message='Falsches Passwort'), 422
    try:
        if form['database'] == 'su':
            result = db_su.execute(form['action']).fetchall()
            conn_su.commit()
        elif form['database'] == 'nh':
            result = db_nh.execute(form['action']).fetchall()
            conn_nh.commit()
        elif form['database'] == 'zl':
            result = db_zl.execute(form['action']).fetchall()
            conn_zl.commit()
        else:
            result = None
        if result is None:
            result = []
    except Exception as error:
        return error_500(error)
    return render_template('controlpanel_action.html', stylesheet=stylesheet, account=account,
                           is_signed_in=not (acc is None), table=result)


########################################################################################################################
# ERROR MESSAGES
########################################################################################################################


@app.errorhandler(400)
def error_400(error_message):
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        account = '<p>Nicht angemeldet</p>'
    else:
        account = f"<p>Angemeldet als<br>{name}</p>"
    request_errors_log.info(f"400\t{error_message}")
    return render_template('_error.html', stylesheet=stylesheet, account=account, is_signed_in=not (acc is None),
                           page_title='', title='', link='/',
                           message=''), 400


@app.errorhandler(401)
def error_401(error_message):
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        account = '<p>Nicht angemeldet</p>'
    else:
        account = f"<p>Angemeldet als<br>{name}</p>"
    request_errors_log.info(f"401\t{error_message}")
    return render_template('_error.html', stylesheet=stylesheet, account=account, is_signed_in=not (acc is None),
                           page_title='Fehlende Berechtigungen', title='Fehlende Berechtigungen', link='/',
                           message='Sie besitzen nicht genügend Berechtigungen, um auf diese Seite zugreifen zu können'
                           ), 401


@app.errorhandler(403)
def error_403(error_message):
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        account = '<p>Nicht angemeldet</p>'
    else:
        account = f"<p>Angemeldet als<br>{name}</p>"
    request_errors_log.info(f"403\t{error_message}")
    return render_template('_error.html', stylesheet=stylesheet, account=account, is_signed_in=not (acc is None),
                           page_title='Fehlende Berechtigungen', title='Fehlende Berechtigungen', link='/',
                           message='Sie besitzen nicht genügend Berechtigungen, um auf diese Seite zugreifen zu können'
                           ), 403


@app.errorhandler(404)
def error_404(error_message):
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        account = '<p>Nicht angemeldet</p>'
    else:
        account = f"<p>Angemeldet als<br>{name}</p>"
    request_errors_log.info(f"404\t{error_message}")
    return render_template('_error.html', stylesheet=stylesheet, account=account, is_signed_in=not (acc is None),
                           page_title='Seite nicht gefunden', title='Seite nicht gefunden', link='/',
                           message='Die Seite, welche Sie aufrufen möchten, wurde nicht gefunden. Möglicherweise haben '
                                   'Sie eine falsche Adresse (URL) eingegeben, die Seite existiert nicht mehr oder der '
                                   'Name wurde geändert.'), 404


@app.errorhandler(422)
def error_422(error_message):
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        account = '<p>Nicht angemeldet</p>'
    else:
        account = f"<p>Angemeldet als<br>{name}</p>"
    request_errors_log.info(f"422\t{error_message}")
    return render_template('_error.html', stylesheet=stylesheet, account=account, is_signed_in=not (acc is None),
                           page_title='Fehlerhafte Anfrage', title='Fehlerhafte Anfrage', link='/',
                           message='Ihre Anfrage enthält mindestens einen Fehler, aufgrund dessen Ihre Anfrage nicht '
                                   'verstanden werden kann. Die häufigste Fehlerquelle ist das Leerlassen von '
                                   'Pflichtfeldern in Eingabefeldern.'), 422


@app.errorhandler(500)
def error_500(error_message):
    acc, name, mail, stylesheet = get_account(request.cookies, request.user_agent.string)
    if acc is None:
        account = '<p>Nicht angemeldet</p>'
    else:
        account = f"<p>Angemeldet als<br>{name}</p>"
    request_errors_log.info(f"500\t{error_message}")
    return render_template('_error.html', stylesheet=stylesheet, account=account, is_signed_in=not (acc is None),
                           page_title='interner Fehler', title='interner Fehler', link='/',
                           message='Ein interner, unbekannter Fehler ist aufgetreten. Bitte kontaktieren Sie den*die '
                                   'Betreiber*in via E-Mail (die Adresse kann im Impressum gefunden werden.) wie '
                                   'dieser Fehler reproduziert werden kann.'), 400


########################################################################################################################
# GENERAL SETUP AFTER
########################################################################################################################


if __name__ == '__main__':
    try:
        app.run('0.0.0.0', 8000)
    except Exception as e:
        print(e)
    for _i in [conn_su, conn_nh, conn_zl]:
        try:
            _i.close()
        except Exception as e:
            print(e)
