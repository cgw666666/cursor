from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
import imaplib
import email
import re
import time
import html
import uuid
import random
import string
from email.header import decode_header
from email.utils import parseaddr
from html.parser import HTMLParser
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

# 配置MySQL数据库
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Cgw666..@14.103.174.252:3306/cursor_email_checker'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# 配置Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# 定义用户模型
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    remaining_searches = db.Column(db.Integer, default=3)  # 默认给予3次免费搜索
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def use_search_credit(self):
        """使用一次搜索次数，如果次数不足返回False"""
        if self.remaining_searches <= 0:
            return False
        self.remaining_searches -= 1
        db.session.commit()
        return True
    
    def add_search_credits(self, amount):
        """为用户添加搜索次数"""
        self.remaining_searches += amount
        db.session.commit()
        return True

# 定义搜索历史模型
class SearchHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    recipient_filter = db.Column(db.String(100))
    verification_code = db.Column(db.String(20))
    search_time = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref=db.backref('searches', lazy=True))

# 定义卡密模型
class Card(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    card_number = db.Column(db.String(50), unique=True, nullable=False)
    amount = db.Column(db.Integer, default=10)  # 充值的搜索次数
    is_used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    used_at = db.Column(db.DateTime)
    used_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    user = db.relationship('User', backref=db.backref('cards', lazy=True))

# 定义卡密使用记录
class CardUsageLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    card_id = db.Column(db.Integer, db.ForeignKey('card.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    used_at = db.Column(db.DateTime, default=datetime.utcnow)
    amount = db.Column(db.Integer)
    
    card = db.relationship('Card', backref=db.backref('usage_logs', lazy=True))
    user = db.relationship('User', backref=db.backref('card_usages', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class HTMLTextExtractor(HTMLParser):
    """从HTML中提取纯文本内容的解析器"""
    
    def __init__(self):
        super().__init__()
        self.result = []
        
    def handle_data(self, data):
        self.result.append(data)
        
    def get_text(self):
        return ''.join(self.result)

def html_to_text(html_content):
    """将HTML内容转换为纯文本"""
    extractor = HTMLTextExtractor()
    extractor.feed(html_content)
    return extractor.get_text()

def decode_str(s):
    result, encoding = decode_header(s)[0]
    if isinstance(result, bytes) and encoding:
        return result.decode(encoding)
    return result

def extract_verification_code(text):
    """从文本中提取验证码"""
    # 尝试匹配格式为 "X X X X X X" 的验证码 (每个数字之间有空格)
    spaced_pattern = r'\b\d\s+\d\s+\d\s+\d\s+\d\s+\d\b'
    spaced_match = re.search(spaced_pattern, text)
    if spaced_match:
        # 返回格式为 "X X X X X X" 的验证码
        return spaced_match.group(0)
    
    # 尝试匹配连续的6位数字 (没有空格)
    digit_pattern = r'\b\d{6}\b'
    digit_match = re.search(digit_pattern, text)
    if digit_match:
        return digit_match.group(0)
    
    # 尝试在"code is:"或"code:"之后匹配验证码
    code_pattern = r'code\s+is:?\s+([0-9\s]+)'
    code_match = re.search(code_pattern, text, re.IGNORECASE)
    if code_match:
        return code_match.group(1).strip()
    
    # 尝试在"验证码"或"verification code"附近查找数字
    verification_pattern = r'(验证码|verification\s+code).{0,30}?([0-9\s]{6,})'
    verification_match = re.search(verification_pattern, text, re.IGNORECASE)
    if verification_match:
        return verification_match.group(2).strip()
    
    return None

def get_email_body(msg):
    """提取邮件正文内容，优先使用纯文本格式，必要时转换HTML为纯文本"""
    plain_text = ""
    html_content = ""
    
    if msg.is_multipart():
        # 如果邮件包含多个部分，遍历所有部分
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))
            
            # 跳过附件
            if "attachment" in content_disposition:
                continue
                
            # 处理文本内容
            try:
                if content_type == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or 'utf-8'
                        plain_text += payload.decode(charset, errors='replace')
                elif content_type == "text/html":
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or 'utf-8'
                        html_content += payload.decode(charset, errors='replace')
            except Exception as e:
                print(f"解析邮件部分时出错: {e}")
    else:
        # 如果邮件是单一部分
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or 'utf-8'
                content = payload.decode(charset, errors='replace')
                if msg.get_content_type() == "text/plain":
                    plain_text = content
                elif msg.get_content_type() == "text/html":
                    html_content = content
        except Exception as e:
            print(f"解析邮件内容时出错: {e}")
    
    # 如果有纯文本内容，优先使用纯文本
    if plain_text:
        return plain_text
    
    # 如果只有HTML内容，转换为纯文本
    if html_content:
        try:
            return html_to_text(html_content)
        except:
            # A如果转换失败，尝试简单地删除HTML标签
            clean_text = re.sub(r'<[^>]+>', ' ', html_content)
            return re.sub(r'\s+', ' ', clean_text).strip()
    
    return "无法提取邮件内容"

def check_email(recipient_filter, auth_code, unread_only=True, from_cursor_only=True):
    try:
        # 固定使用的QQ邮箱账号
        fixed_email = "2641537225@qq.com"
        
        # Connect to QQ email IMAP server
        mail = imaplib.IMAP4_SSL('imap.qq.com', 993)
        
        # Login with fixed credentials
        mail.login(fixed_email, auth_code)
        
        # Select inbox
        mail.select('INBOX')
        
        # 根据设置决定搜索条件
        if unread_only:
            print("只搜索未读邮件")
            status, search_data = mail.search(None, 'UNSEEN')
        else:
            print("搜索所有邮件")
            status, search_data = mail.search(None, 'ALL')
        
        if status != 'OK' or not search_data[0]:
            print("未找到任何邮件")
            mail.logout()
            return None, []
        
        emails_found = []
        verification_code = None
        debug_info = []
        
        # Get the latest email
        email_ids = search_data[0].split()
        # 最多处理20封邮件以避免处理过多
        email_ids = email_ids[-20:] if len(email_ids) > 20 else email_ids
        
        for num in reversed(email_ids):
            status, data = mail.fetch(num, '(RFC822)')
            
            if status != 'OK':
                continue
            
            raw_email = data[0][1]
            msg = email.message_from_bytes(raw_email)
            
            # 获取发件人
            from_header = msg.get("From", "")
            from_name, from_addr = parseaddr(from_header)
            if from_name:
                from_name = decode_str(from_name)
            
            # Check the recipient (To:)
            to_header = msg.get("To", "")
            recipient = decode_str(to_header)
            
            # 获取主题
            subject = decode_str(msg.get("Subject", ""))
            
            # 调试信息
            debug_info.append(f"处理邮件: 发件人={from_name} <{from_addr}>, 主题={subject}")
            
            # 检查发件人是否包含"Cursor"
            is_from_cursor = "cursor" in from_addr.lower() or "cursor" in from_name.lower()
            
            # 如果设置了筛选发件人为Cursor，但邮件不是来自Cursor，则跳过
            if from_cursor_only and not is_from_cursor:
                debug_info.append(f"  非Cursor发送的邮件，跳过")
                continue
            
            # 检查收件人是否包含用户指定的筛选名称
            if recipient_filter and recipient_filter.lower() not in recipient.lower():
                debug_info.append(f"  收件人不匹配筛选条件，跳过")
                continue
            
            # 获取日期
            date = msg.get("Date", "")
            
            # 获取邮件正文 (纯文本)
            body = get_email_body(msg)
            
            email_info = {
                "from": f"{from_name} <{from_addr}>",
                "to": recipient,
                "date": date,
                "subject": subject,
                "body": body
            }
            
            # 自动提取验证码
            code = extract_verification_code(body)
            if code:
                debug_info.append(f"  找到验证码: {code}")
                email_info["verification_code"] = code
                verification_code = code
            else:
                debug_info.append(f"  未找到验证码")
            
            emails_found.append(email_info)
            
            # 如果是未读邮件并且已经处理完成，标记为已读
            if unread_only:
                mail.store(num, '+FLAGS', '\\Seen')
        
        # 将调试信息记录到日志
        print("\n".join(debug_info))
        
        mail.logout()
        
        # 如果找到了多封邮件，并且最后一封邮件中有验证码，将它作为最终验证码
        if emails_found and len(emails_found) > 0:
            for email in reversed(emails_found):  # 从最新的邮件开始检查
                if "verification_code" in email:
                    verification_code = email["verification_code"]
                    break
                
        return verification_code, emails_found
    
    except Exception as e:
        error_message = f"邮箱连接错误: {str(e)}"
        print(error_message)
        return None, [{"error": error_message}]

@app.route('/')
def index():
    if current_user.is_authenticated:
        return render_template('index.html')
    else:
        return redirect(url_for('login'))

@app.route('/check_emails', methods=['POST'])
@login_required
def check_emails_route():
    # 检查用户是否有足够的搜索次数
    if current_user.remaining_searches <= 0:
        return jsonify({
            "error": "您的搜索次数已用完，请充值后再试。",
            "need_recharge": True
        }), 402  # 402 Payment Required
    
    data = request.get_json()
    recipient_filter = data.get('recipient', '')
    unread_only = data.get('unreadOnly', True)
    from_cursor_only = data.get('fromCursorOnly', True)
    
    # 记录当前搜索次数，以便在没找到验证码时恢复
    original_remaining_searches = current_user.remaining_searches
    
    # 使用一次搜索次数
    if not current_user.use_search_credit():
        return jsonify({
            "error": "您的搜索次数已用完，请充值后再试。",
            "need_recharge": True
        }), 402
    
    # 固定的授权码
    auth_code = "lapcgudmtdbjebhh"
    
    verification_code, emails = check_email(
        recipient_filter, 
        auth_code,
        unread_only=unread_only,
        from_cursor_only=from_cursor_only
    )
    
    # 如果找到验证码，记录到搜索历史
    if verification_code:
        search_history = SearchHistory(
            user_id=current_user.id,
            recipient_filter=recipient_filter,
            verification_code=verification_code
        )
        db.session.add(search_history)
        db.session.commit()
    else:
        # 未找到验证码，恢复用户的搜索次数
        current_user.remaining_searches = original_remaining_searches
        db.session.commit()
    
    return jsonify({
        "verification_code": verification_code,
        "emails": emails,
        "remaining_searches": current_user.remaining_searches
    })

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if not user or not user.check_password(password):
            flash('用户名或密码错误')
            return redirect(url_for('login'))
            
        login_user(user)
        next_page = request.args.get('next')
        if not next_page or next_page.startswith('//'):
            next_page = url_for('index')
            
        return redirect(next_page)
        
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email', '')
        
        if User.query.filter_by(username=username).first():
            flash('用户名已被注册')
            return redirect(url_for('register'))
            
        user = User(username=username, email=email, remaining_searches=3)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        flash('注册成功，请登录')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/history')
@login_required
def history():
    searches = SearchHistory.query.filter_by(user_id=current_user.id).order_by(SearchHistory.search_time.desc()).all()
    return render_template('history.html', searches=searches)

@app.route('/instructions')
@login_required
def instructions():
    return render_template('instructions.html')

@app.route('/user/settings', methods=['GET', 'POST'])
@login_required
def user_settings():
    if request.method == 'POST':
        email = request.form.get('email')
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        
        if email:
            current_user.email = email
            
        if current_password and new_password:
            if current_user.check_password(current_password):
                current_user.set_password(new_password)
                flash('密码修改成功')
            else:
                flash('当前密码错误')
                return redirect(url_for('user_settings'))
                
        db.session.commit()
        flash('设置已更新')
        return redirect(url_for('user_settings'))
        
    return render_template('settings.html')

@app.route('/recharge', methods=['GET', 'POST'])
@login_required
def recharge():
    if request.method == 'POST':
        card_number = request.form.get('card_number')
        
        if not card_number:
            flash('请输入卡密', 'error')
            return redirect(url_for('recharge'))
        
        card = Card.query.filter_by(card_number=card_number).first()
        
        if not card:
            flash('无效的卡密', 'error')
            return redirect(url_for('recharge'))
            
        if card.is_used:
            flash('此卡密已被使用', 'error')
            return redirect(url_for('recharge'))
        
        # 使用卡密
        card.is_used = True
        card.used_at = datetime.utcnow()
        card.used_by = current_user.id
        
        # 为用户添加次数
        current_user.add_search_credits(card.amount)
        
        # 记录使用日志
        log = CardUsageLog(
            card_id=card.id,
            user_id=current_user.id,
            amount=card.amount
        )
        
        db.session.add(log)
        db.session.commit()
        
        flash(f'充值成功! 已添加 {card.amount} 次搜索次数', 'success')
        return redirect(url_for('index'))
        
    return render_template('recharge.html')

@app.route('/admin/cards', methods=['GET', 'POST'])
@login_required
def admin_cards():
    # 检查是否是管理员
    if current_user.username != 'admin':
        flash('无权访问此页面')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        num_cards = int(request.form.get('num_cards', 1))
        amount = int(request.form.get('amount', 10))
        
        cards = []
        for _ in range(num_cards):
            # 生成一个16位的随机卡密
            card_number = ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))
            card = Card(card_number=card_number, amount=amount)
            db.session.add(card)
            cards.append(card)
        
        db.session.commit()
        
        return render_template('admin_cards.html', cards=cards, just_generated=True)
    
    # 获取所有卡密
    cards = Card.query.order_by(Card.created_at.desc()).all()
    return render_template('admin_cards.html', cards=cards, just_generated=False)

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    # 检查是否是管理员
    if current_user.username != 'admin':
        flash('无权访问此页面', 'error')
        return redirect(url_for('index'))
    
    # 获取统计数据
    stats = {
        'user_count': User.query.count(),
        'total_searches': SearchHistory.query.count(),
        'card_count': Card.query.count(),
        'used_card_count': Card.query.filter_by(is_used=True).count()
    }
    
    # 获取所有用户
    users = User.query.order_by(User.id).all()
    
    # 获取搜索历史
    searches = SearchHistory.query.order_by(SearchHistory.search_time.desc()).limit(100).all()
    
    # 获取图表数据
    # 最近7天的搜索数据
    today = datetime.utcnow().date()
    search_data = []
    search_labels = []
    for i in range(6, -1, -1):
        date = today - timedelta(days=i)
        next_date = date + timedelta(days=1)
        count = SearchHistory.query.filter(
            SearchHistory.search_time >= date,
            SearchHistory.search_time < next_date
        ).count()
        search_data.append(count)
        search_labels.append(date.strftime('%m-%d'))
    
    # 最近7天的用户注册数据
    user_data = []
    user_labels = []
    for i in range(6, -1, -1):
        date = today - timedelta(days=i)
        next_date = date + timedelta(days=1)
        count = User.query.filter(
            User.created_at >= date,
            User.created_at < next_date
        ).count()
        user_data.append(count)
        user_labels.append(date.strftime('%m-%d'))
    
    chart_data = {
        'search_data': search_data,
        'search_labels': search_labels,
        'user_data': user_data,
        'user_labels': user_labels
    }
    
    return render_template('admin_dashboard.html', 
                          stats=stats, 
                          users=users, 
                          searches=searches, 
                          chart_data=chart_data)

@app.route('/admin/update_user', methods=['POST'])
@login_required
def admin_update_user():
    # 检查是否是管理员
    if current_user.username != 'admin':
        flash('无权进行此操作', 'error')
        return redirect(url_for('index'))
    
    user_id = request.form.get('user_id')
    email = request.form.get('email')
    remaining_searches = int(request.form.get('remaining_searches', 0))
    password = request.form.get('password')
    
    user = User.query.get(user_id)
    if not user:
        flash('用户不存在', 'error')
        return redirect(url_for('admin_dashboard'))
    
    user.email = email
    user.remaining_searches = remaining_searches
    
    if password:
        user.set_password(password)
    
    db.session.commit()
    
    flash(f'用户 {user.username} 更新成功', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/recharge_user', methods=['POST'])
@login_required
def admin_recharge_user():
    # 检查是否是管理员
    if current_user.username != 'admin':
        flash('无权进行此操作', 'error')
        return redirect(url_for('index'))
    
    user_id = request.form.get('user_id')
    amount = int(request.form.get('amount', 10))
    
    user = User.query.get(user_id)
    if not user:
        flash('用户不存在', 'error')
        return redirect(url_for('admin_dashboard'))
    
    user.remaining_searches += amount
    db.session.commit()
    
    flash(f'已为用户 {user.username} 充值 {amount} 次搜索次数', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_user')
@login_required
def admin_delete_user():
    # 检查是否是管理员
    if current_user.username != 'admin':
        flash('无权进行此操作', 'error')
        return redirect(url_for('index'))
    
    user_id = request.args.get('user_id')
    
    user = User.query.get(user_id)
    if not user:
        flash('用户不存在', 'error')
        return redirect(url_for('admin_dashboard'))
    
    if user.username == 'admin':
        flash('不能删除管理员账户', 'error')
        return redirect(url_for('admin_dashboard'))
    
    # 删除用户相关的所有记录
    SearchHistory.query.filter_by(user_id=user.id).delete()
    CardUsageLog.query.filter_by(user_id=user.id).delete()
    
    # 删除用户
    db.session.delete(user)
    db.session.commit()
    
    flash(f'用户 {user.username} 已删除', 'success')
    return redirect(url_for('admin_dashboard'))

def init_db():
    with app.app_context():
        db.create_all()
        
        # 如果没有用户，创建一个默认管理员用户
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', remaining_searches=999999)
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print('已创建默认管理员用户: admin/admin123')

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)