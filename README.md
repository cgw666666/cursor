# Cursor 验证码获取工具

这是一个基于Flask的Web应用，用于自动检查QQ邮箱中来自Cursor的验证码邮件，并提取验证码。

## 功能特点

- 多用户系统，支持用户注册、登录和个人设置
- 使用固定的QQ邮箱账号接收验证码邮件
- 通过收件人名称筛选邮件
- 自动识别并提取6位数字验证码
- 记录历史搜索和验证码结果
- 现代化的Web界面，支持移动设备
- 验证码一键复制功能

## 安装和使用

### 先决条件

- Python 3.6+
- pip (Python包管理器)
- MySQL 5.7+

### 安装步骤

1. 克隆或下载此仓库

2. 创建MySQL数据库
```bash
mysql -u root -p
CREATE DATABASE cursor_email_checker CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

3. 安装所需依赖
```bash
pip install -r requirements.txt
```

4. 修改配置
在app.py中更新MySQL连接设置，如果需要：
```python
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Cgw666..@localhost/cursor_email_checker'
```

5. 运行应用
```bash
python app.py
```

6. 在浏览器中访问 http://localhost:5000 使用应用，默认管理员账号: admin/admin123

## 使用说明

1. 使用默认账号登录或注册新账号
2. 在首页上输入收件人名称（用于筛选邮件）
3. 设置搜索选项（是否只搜索未读邮件、是否只搜索Cursor发送的邮件）
4. 点击"获取验证码"按钮
5. 系统将自动检查邮箱中符合条件的邮件，并尝试提取验证码
6. 如果找到验证码，将显示在页面上，您可以点击"复制"按钮复制验证码
7. 所有找到的邮件内容都会显示在页面下方，验证码会被高亮显示
8. 查看"历史记录"页面可以查看过去的搜索结果

## 技术细节

- 使用IMAP协议连接QQ邮箱
- 固定使用邮箱：2641537225@qq.com
- 使用正则表达式提取各种格式的验证码
- 支持HTML和纯文本邮件内容解析
- 基于Flask框架和Flask-Login的用户认证系统
- 使用SQLAlchemy ORM与MySQL数据库交互
- 响应式前端设计，兼容移动设备 
