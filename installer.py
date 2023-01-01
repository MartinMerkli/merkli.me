from sqlite3 import connect as sqlite_connect
from datetime import datetime


GUNICORN_CONF = """from os import environ


environ['SMTP_SERVER'] = 'url of your e-mail smtp server'
environ['SMTP_PORT'] = 'port of your e-mail smtp server'
environ['SMTP_ADDRESS'] = 'your e-mail address'
environ['SMTP_PASSWORD'] = 'the password for your e-mail account'
environ['IMPRINT_NAME'] = 'your full name'
environ['IMPRINT_ADDRESS'] = 'your address (first line)'
environ['IMPRINT_CITY'] = 'your address (second line)'
environ['IMPRINT_MAIL'] = 'your e-mail address'
environ['HASH_PEPPER_1'] = 'random url-safe base64 encoded data'
environ['HASH_PEPPER_2'] = 'random url-safe base64 encoded data'
environ['HASH_ITERATIONS'] = 'random integer between 1 and 1000000'
"""


def get_current_time():
    return datetime.now().strftime('%Y-%m-%d_%H-%M-%S')


def main():
    conn_su = sqlite_connect('database.db')
    db_su = conn_su.cursor()

    conn_nh = sqlite_connect('g21m.db')
    db_nh = conn_nh.cursor()

    conn_zl = sqlite_connect('zitateliste.db')
    db_zl = conn_zl.cursor()

    db_su.execute('create table used_ids (id text PRIMARY KEY, created text)')
    db_su.execute('create table ipv4 (address text PRIMARY KEY, owner text, score integer)')
    db_su.execute('create table accounts (id text PRIMARY KEY, name text, mail text, salt text, hash text, '
                  'newsletter integer, created text, theme text, banned integer, iframe integer)')
    db_su.execute('create table login (id text PRIMARY KEY, account text, valid text)')
    db_su.execute('create table mail (id text PRIMARY KEY, name text, mail text, salt text, hash text, '
                  'newsletter integer, valid text, code text)')

    db_nh.execute('create table statistics (account text PRIMARY KEY, answers text, latest text)')
    db_nh.execute('create table exercises (id text PRIMARY KEY, name text, subject text, owner text, edited text, '
                  'content text)')
    db_nh.execute('create table calendar (id text PRIMARY KEY, start_date text, end_date text, name text, '
                  'type integer)')
    db_nh.execute('create table activity (id text PRIMARY KEY, posted text, content text, link text)')
    db_nh.execute('create table documents (id text PRIMARY KEY, name text, subject text, owner text, edited text, '
                  'created text)')
    db_nh.execute('create table comments (id text PRIMARY KEY, content text, owner text, subject text, posted text)')

    db_zl.execute('create table quotes (id text PRIMARY KEY, content text)')
    db_zl.execute('create table actions (id text PRIMARY KEY, content text)')
    db_zl.execute('create table conspiracies (id text PRIMARY KEY, content text)')
    db_zl.execute('create table access (account text PRIMARY KEY, level integer, name text, '
                  'last_quote text, last_action text, last_conspiracy text)')
    db_zl.execute('create table proposed (id text PRIMARY KEY, account text, type text, content text)')

    for i in [conn_su, conn_nh, conn_zl]:
        i.commit()
        i.close()

    with open('gunicorn.conf.py', 'w') as f:
        f.write(GUNICORN_CONF)


if __name__ == '__main__':
    main()
