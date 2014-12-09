#!/usr/bin/python

# (c) 2012, Mark Theunissen <mark.theunissen@gmail.com>
# Sponsored by Four Kitchens http://fourkitchens.com.
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
---
module: mysql_user
short_description: MySQL データベースからユーザを追加または削除する
description:
   - MySQL データベースからユーザを追加または削除します。
version_added: "0.6"
options:
  name:
    description:
      - 追加または削除するユーザ（ロール）の名前です。
    required: true
    default: null
  password:
    description:
      - ユーザのパスワードを設定します。
    required: false
    default: null
  host:
    description:
      - MySQL ユーザ名の 'host' 部分です。
    required: false
    default: localhost
  login_user:
    description:
      - 認証されるユーザ名です。
    required: false
    default: null
  login_password:
    description:
      - 認証されるパスワードです。
    required: false
    default: null
  login_host:
    description:
      - データベースのホスト名です。
    required: false
    default: localhost
  login_port:
    description:
      - MySQL サーバのポートです。
    required: false
    default: 3306
    version_added: '1.4'
  login_unix_socket:
    description:
      - ローカル接続のための Unix ドメインソケットへのパスです。
    required: false
    default: null
  priv:
    description:
      - "MySQL の権限情報文字列で、フォーマットは C(db.table:priv1,priv2) です。"
    required: false
    default: null
  append_privs:
    description:
      - 既存の権限情報を上書きして priv で定義された値にするかどうかです。
    required: false
    choices: [ "yes", "no" ]
    default: "no"
    version_added: "1.4"
  state:
    description:
      - ユーザが存在すべきか、しないべきかです。C(absent) はユーザを削除します。
        the user.
    required: false
    default: present
    choices: [ "present", "absent" ]
  check_implicit_admin:
    description:
      - mysql が認証情報で認証する前に root/nopassword でログインする事を許可するかです。
    required: false
    default: false
    version_added: "1.3"
notes:
   - リモートホストには MySQLdb Python パッケージがインストールされている必要があります。Ubuntuは簡単で、apt-get install python-mysqldb になります。
   - I(login_password) と I(login_user) は認証で必要です。none は、 C(~/.my.cnf) から資格情報を取得しようとして、パスワード無しでデフォルトの C(root) となりフォールバックします。
   - "MySQL サーバはデフォルトの login_user がパスワード無しの 'root' でインストールされます。べき等性を保証する場合、少なくとも2つのタスクが playbook に必要です。1つ目は login_user/login_password の確認を行わないように root ユーザのパスワードを変更するものです。2つ目は新しい root の認証情報を ~/.my.cnf ファイルに含めるものです。その後の playbook 実行ではファイルから新しい認証情報が読み取られて成功するでしょう。"

requirements: [ "ConfigParser", "MySQLdb" ]
author: Mark Theunissen
'''

EXAMPLES = """
# データベースを作成し、同時にユーザ 'bob' をパスワード '12345' ですべての権限を持つようにする
- mysql_user: name=bob password=12345 priv=*.*:ALL state=present

# データベースを作成し、同時にユーザ 'bob' をパスワード '12345' で権限 'WITH GRANT OPTION' を持つようにする
- mysql_user: name=bob password=12345 priv=*.*:ALL,GRANT state=present

# ユーザ 'sally' が存在しない事を保証する
- mysql_user: login_user=root login_password=123456 name=sally state=absent

# Specify grants composed of more than one word
- mysql_user: name=replication password=12345 priv=*.*:"REPLICATION CLIENT" state=present

# ユーザ 'bob' からすべての権限を除き、パスワードを '12345' にする
- mysql_user: name=bob password=12345 priv=*.*:USAGE state=present

# privileges の文字列フォーマット例
mydb.*:INSERT,UPDATE/anotherdb.*:SELECT/yetanotherdb.*:ALL

# サーバに接続する login_unix_socket を使用した例
- mysql_user: name=root password=abc123 login_unix_socket=/var/run/mysqld/mysqld.sock

# root パスワードを設定するための .my.cnf ファイルの例
# 注意: client では mysql_user モジュールでは含むクォートでパスワードを囲まないでください。

[client]
user=root
password=n<_665{vS43y
"""

import ConfigParser
import getpass
import tempfile
try:
    import MySQLdb
except ImportError:
    mysqldb_found = False
else:
    mysqldb_found = True

VALID_PRIVS = frozenset(('CREATE', 'DROP', 'GRANT', 'GRANT OPTION',
                         'LOCK TABLES', 'REFERENCES', 'EVENT', 'ALTER',
                         'DELETE', 'INDEX', 'INSERT', 'SELECT', 'UPDATE',
                         'CREATE TEMPORARY TABLES', 'TRIGGER', 'CREATE VIEW',
                         'SHOW VIEW', 'ALTER ROUTINE', 'CREATE ROUTINE',
                         'EXECUTE', 'FILE', 'CREATE USER', 'PROCESS',
                         'RELOAD', 'REPLICATION CLIENT', 'REPLICATION SLAVE',
                         'SHOW DATABASES', 'SHUTDOWN', 'SUPER', 'ALL',
                         'ALL PRIVILEGES', 'USAGE',))

class InvalidPrivsError(Exception):
    pass

# ===========================================
# MySQL module specific support methods.
#

def user_exists(cursor, user, host):
    cursor.execute("SELECT count(*) FROM user WHERE user = %s AND host = %s", (user,host))
    count = cursor.fetchone()
    return count[0] > 0

def user_add(cursor, user, host, password, new_priv):
    cursor.execute("CREATE USER %s@%s IDENTIFIED BY %s", (user,host,password))
    if new_priv is not None:
        for db_table, priv in new_priv.iteritems():
            privileges_grant(cursor, user,host,db_table,priv)
    return True

def user_mod(cursor, user, host, password, new_priv, append_privs):
    changed = False
    grant_option = False

    # Handle passwords
    if password is not None:
        cursor.execute("SELECT password FROM user WHERE user = %s AND host = %s", (user,host))
        current_pass_hash = cursor.fetchone()
        cursor.execute("SELECT PASSWORD(%s)", (password,))
        new_pass_hash = cursor.fetchone()
        if current_pass_hash[0] != new_pass_hash[0]:
            cursor.execute("SET PASSWORD FOR %s@%s = PASSWORD(%s)", (user,host,password))
            changed = True

    # Handle privileges
    if new_priv is not None:
        curr_priv = privileges_get(cursor, user,host)

        # If the user has privileges on a db.table that doesn't appear at all in
        # the new specification, then revoke all privileges on it.
        for db_table, priv in curr_priv.iteritems():
            # If the user has the GRANT OPTION on a db.table, revoke it first.
            if "GRANT" in priv:
                grant_option = True
            if db_table not in new_priv:
                if user != "root" and "PROXY" not in priv and not append_privs:
                    privileges_revoke(cursor, user,host,db_table,grant_option)
                    changed = True

        # If the user doesn't currently have any privileges on a db.table, then
        # we can perform a straight grant operation.
        for db_table, priv in new_priv.iteritems():
            if db_table not in curr_priv:
                privileges_grant(cursor, user,host,db_table,priv)
                changed = True

        # If the db.table specification exists in both the user's current privileges
        # and in the new privileges, then we need to see if there's a difference.
        db_table_intersect = set(new_priv.keys()) & set(curr_priv.keys())
        for db_table in db_table_intersect:
            priv_diff = set(new_priv[db_table]) ^ set(curr_priv[db_table])
            if (len(priv_diff) > 0):
                if not append_privs:
                    privileges_revoke(cursor, user,host,db_table,grant_option)
                privileges_grant(cursor, user,host,db_table,new_priv[db_table])
                changed = True

    return changed

def user_delete(cursor, user, host):
    cursor.execute("DROP USER %s@%s", (user, host))
    return True

def privileges_get(cursor, user,host):
    """ MySQL doesn't have a better method of getting privileges aside from the
    SHOW GRANTS query syntax, which requires us to then parse the returned string.
    Here's an example of the string that is returned from MySQL:

     GRANT USAGE ON *.* TO 'user'@'localhost' IDENTIFIED BY 'pass';

    This function makes the query and returns a dictionary containing the results.
    The dictionary format is the same as that returned by privileges_unpack() below.
    """
    output = {}
    cursor.execute("SHOW GRANTS FOR %s@%s", (user, host))
    grants = cursor.fetchall()

    def pick(x):
        if x == 'ALL PRIVILEGES':
            return 'ALL'
        else:
            return x

    for grant in grants:
        res = re.match("GRANT (.+) ON (.+) TO '.+'@'.+'( IDENTIFIED BY PASSWORD '.+')? ?(.*)", grant[0])
        if res is None:
            raise InvalidPrivsError('unable to parse the MySQL grant string: %s' % grant[0])
        privileges = res.group(1).split(", ")
        privileges = [ pick(x) for x in privileges]
        if "WITH GRANT OPTION" in res.group(4):
            privileges.append('GRANT')
        db = res.group(2)
        output[db] = privileges
    return output

def privileges_unpack(priv):
    """ Take a privileges string, typically passed as a parameter, and unserialize
    it into a dictionary, the same format as privileges_get() above. We have this
    custom format to avoid using YAML/JSON strings inside YAML playbooks. Example
    of a privileges string:

     mydb.*:INSERT,UPDATE/anotherdb.*:SELECT/yetanother.*:ALL

    The privilege USAGE stands for no privileges, so we add that in on *.* if it's
    not specified in the string, as MySQL will always provide this by default.
    """
    output = {}
    for item in priv.split('/'):
        pieces = item.split(':')
        if '.' in pieces[0]:
            pieces[0] = pieces[0].split('.')
            for idx, piece in enumerate(pieces):
                if pieces[0][idx] != "*":
                    pieces[0][idx] = "`" + pieces[0][idx] + "`"
            pieces[0] = '.'.join(pieces[0])

        output[pieces[0]] = pieces[1].upper().split(',')
        new_privs = frozenset(output[pieces[0]])
        if not new_privs.issubset(VALID_PRIVS):
            raise InvalidPrivsError('Invalid privileges specified: %s' % new_privs.difference(VALID_PRIVS))

    if '*.*' not in output:
        output['*.*'] = ['USAGE']

    return output

def privileges_revoke(cursor, user,host,db_table,grant_option):
    # Escape '%' since mysql db.execute() uses a format string
    db_table = db_table.replace('%', '%%')
    if grant_option:
        query = ["REVOKE GRANT OPTION ON %s" % mysql_quote_identifier(db_table, 'table')]
        query.append("FROM %s@%s")
        query = ' '.join(query)
        cursor.execute(query, (user, host))
    query = ["REVOKE ALL PRIVILEGES ON %s" % mysql_quote_identifier(db_table, 'table')]
    query.append("FROM %s@%s")
    query = ' '.join(query)
    cursor.execute(query, (user, host))

def privileges_grant(cursor, user,host,db_table,priv):
    # Escape '%' since mysql db.execute uses a format string and the
    # specification of db and table often use a % (SQL wildcard)
    db_table = db_table.replace('%', '%%')
    priv_string = ",".join(filter(lambda x: x != 'GRANT', priv))
    query = ["GRANT %s ON %s" % (priv_string, mysql_quote_identifier(db_table, 'table'))]
    query.append("TO %s@%s")
    if 'GRANT' in priv:
        query.append("WITH GRANT OPTION")
    query = ' '.join(query)
    cursor.execute(query, (user, host))


def strip_quotes(s):
    """ Remove surrounding single or double quotes

    >>> print strip_quotes('hello')
    hello
    >>> print strip_quotes('"hello"')
    hello
    >>> print strip_quotes("'hello'")
    hello
    >>> print strip_quotes("'hello")
    'hello

    """
    single_quote = "'"
    double_quote = '"'

    if s.startswith(single_quote) and s.endswith(single_quote):
        s = s.strip(single_quote)
    elif s.startswith(double_quote) and s.endswith(double_quote):
        s = s.strip(double_quote)
    return s


def config_get(config, section, option):
    """ Calls ConfigParser.get and strips quotes

    See: http://dev.mysql.com/doc/refman/5.0/en/option-files.html
    """
    return strip_quotes(config.get(section, option))


def _safe_cnf_load(config, path):

    data = {'user':'', 'password':''}

    # read in user/pass
    f = open(path, 'r')
    for line in f.readlines():
        line = line.strip()
        if line.startswith('user='):
            data['user'] = line.split('=', 1)[1].strip()
        if line.startswith('password=') or line.startswith('pass='):
            data['password'] = line.split('=', 1)[1].strip()
    f.close()

    # write out a new cnf file with only user/pass
    fh, newpath = tempfile.mkstemp(prefix=path + '.')
    f = open(newpath, 'wb')
    f.write('[client]\n')
    f.write('user=%s\n' % data['user'])
    f.write('password=%s\n' % data['password'])
    f.close()

    config.readfp(open(newpath))
    os.remove(newpath)
    return config

def load_mycnf():
    config = ConfigParser.RawConfigParser()
    mycnf = os.path.expanduser('~/.my.cnf')
    if not os.path.exists(mycnf):
        return False
    try:
        config.readfp(open(mycnf))
    except (IOError):
        return False
    except:
        config = _safe_cnf_load(config, mycnf)

    # We support two forms of passwords in .my.cnf, both pass= and password=,
    # as these are both supported by MySQL.
    try:
        passwd = config_get(config, 'client', 'password')
    except (ConfigParser.NoOptionError):
        try:
            passwd = config_get(config, 'client', 'pass')
        except (ConfigParser.NoOptionError):
            return False

    # If .my.cnf doesn't specify a user, default to user login name
    try:
        user = config_get(config, 'client', 'user')
    except (ConfigParser.NoOptionError):
        user = getpass.getuser()
    creds = dict(user=user,passwd=passwd)
    return creds

def connect(module, login_user, login_password):
    if module.params["login_unix_socket"]:
        db_connection = MySQLdb.connect(host=module.params["login_host"], unix_socket=module.params["login_unix_socket"], user=login_user, passwd=login_password, db="mysql")
    else:
        db_connection = MySQLdb.connect(host=module.params["login_host"], port=int(module.params["login_port"]), user=login_user, passwd=login_password, db="mysql")
    return db_connection.cursor()

# ===========================================
# Module execution.
#

def main():
    module = AnsibleModule(
        argument_spec = dict(
            login_user=dict(default=None),
            login_password=dict(default=None),
            login_host=dict(default="localhost"),
            login_port=dict(default="3306"),
            login_unix_socket=dict(default=None),
            user=dict(required=True, aliases=['name']),
            password=dict(default=None),
            host=dict(default="localhost"),
            state=dict(default="present", choices=["absent", "present"]),
            priv=dict(default=None),
            append_privs=dict(type="bool", default="no"),
            check_implicit_admin=dict(default=False),
        )
    )
    user = module.params["user"]
    password = module.params["password"]
    host = module.params["host"]
    state = module.params["state"]
    priv = module.params["priv"]
    check_implicit_admin = module.params['check_implicit_admin']
    append_privs = module.boolean(module.params["append_privs"])

    if not mysqldb_found:
        module.fail_json(msg="the python mysqldb module is required")

    if priv is not None:
        try:
            priv = privileges_unpack(priv)
        except Exception, e:
            module.fail_json(msg="invalid privileges string: %s" % str(e))

    # Either the caller passes both a username and password with which to connect to
    # mysql, or they pass neither and allow this module to read the credentials from
    # ~/.my.cnf.
    login_password = module.params["login_password"]
    login_user = module.params["login_user"]
    if login_user is None and login_password is None:
        mycnf_creds = load_mycnf()
        if mycnf_creds is False:
            login_user = "root"
            login_password = ""
        else:
            login_user = mycnf_creds["user"]
            login_password = mycnf_creds["passwd"]
    elif login_password is None or login_user is None:
        module.fail_json(msg="when supplying login arguments, both login_user and login_password must be provided")

    cursor = None
    try:
        if check_implicit_admin:
            try:
                cursor = connect(module, 'root', '')
            except:
                pass

        if not cursor:
            cursor = connect(module, login_user, login_password)
    except Exception, e:
        module.fail_json(msg="unable to connect to database, check login_user and login_password are correct or ~/.my.cnf has the credentials")

    if state == "present":
        if user_exists(cursor, user, host):
            try:
                changed = user_mod(cursor, user, host, password, priv, append_privs)
            except SQLParseError, e:
                module.fail_json(msg=str(e))
            except InvalidPrivsError, e:
                module.mail_json(msg=str(e))
        else:
            if password is None:
                module.fail_json(msg="password parameter required when adding a user")
            try:
                changed = user_add(cursor, user, host, password, priv)
            except SQLParseError, e:
                module.fail_json(msg=str(e))
    elif state == "absent":
        if user_exists(cursor, user, host):
            changed = user_delete(cursor, user, host)
        else:
            changed = False
    module.exit_json(changed=changed, user=user)

# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.database import *
if __name__ == '__main__':
    main()
