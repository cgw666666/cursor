import imaplib
import email
import re
import time
import html
from email.header import decode_header
from email.utils import parseaddr
from html.parser import HTMLParser

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
            # 如果转换失败，尝试简单地删除HTML标签
            clean_text = re.sub(r'<[^>]+>', ' ', html_content)
            return re.sub(r'\s+', ' ', clean_text).strip()
    
    return "无法提取邮件内容"

def check_email(recipient_filter, auth_code):
    try:
        # 固定使用的QQ邮箱账号
        fixed_email = "2641537225@qq.com"
        
        # Connect to QQ email IMAP server
        mail = imaplib.IMAP4_SSL('imap.qq.com', 993)
        
        # Login with fixed credentials
        mail.login(fixed_email, auth_code)
        
        # Select inbox
        mail.select('INBOX')
        
        # Search for unread emails from Cursor
        status, data = mail.search(None, '(UNSEEN FROM "Cursor")')
        
        if status != 'OK' or not data[0]:
            print("没有找到新邮件！")
            mail.logout()
            return None
        
        emails_found = 0
        # Get the latest email
        for num in reversed(data[0].split()):
            status, data = mail.fetch(num, '(RFC822)')
            
            if status != 'OK':
                continue
            
            raw_email = data[0][1]
            msg = email.message_from_bytes(raw_email)
            
            # Check the recipient (To:)
            to_header = msg.get("To", "")
            recipient = decode_str(to_header)
            
            # 检查收件人是否包含用户指定的筛选名称
            if recipient_filter.lower() not in recipient.lower():
                continue
            
            emails_found += 1
            
            # 获取发件人
            from_header = msg.get("From", "")
            from_name, from_addr = parseaddr(from_header)
            if from_name:
                from_name = decode_str(from_name)
            
            # 获取主题
            subject = decode_str(msg.get("Subject", ""))
            
            # 获取日期
            date = msg.get("Date", "")
            
            # 获取邮件正文 (纯文本)
            body = get_email_body(msg)
            
            print("\n" + "="*50)
            print(f"邮件 {emails_found}:")
            print("="*50)
            print(f"发件人: {from_name} <{from_addr}>")
            print(f"收件人: {recipient}")
            print(f"日期: {date}")
            print(f"主题: {subject}")
            print("-"*50)
            print("邮件内容 (纯文本):")
            print("-"*50)
            print(body)
            print("="*50)
            
            # 自动提取验证码
            verification_code = extract_verification_code(body)
            if verification_code:
                print(f"\n检测到验证码: {verification_code}\n")
            
            # 标记邮件为已读
            mail.store(num, '+FLAGS', '\\Seen')
            
            # 如果找到验证码，返回它
            if verification_code:
                mail.logout()
                return verification_code
        
        mail.logout()
        return None
    
    except imaplib.IMAP4.error as e:
        print(f"IMAP错误: {e}")
        print("请确认邮箱已开启IMAP服务，授权码正确。")
        print("如何开启IMAP: 登录网页版QQ邮箱 -> 设置 -> 账户 -> POP3/IMAP/SMTP/Exchange/CardDAV/CalDAV服务")
        return None
    except Exception as e:
        print(f"连接错误: {e}")
        return None

def main():
    # 获取用户输入的收件人筛选名称
    recipient_filter = input("请输入收件人名称（用于筛选邮件，例如：张三）: ")
    
    # 固定的授权码
    auth_code = "lapcgudmtdbjebhh"
    
    print(f"正在监听来自Cursor的邮件，收件人包含「{recipient_filter}」的邮件...")
    print("温馨提示: 使用固定邮箱2641537225@qq.com进行接收")
    
    verification_code = None
    max_retries = 10
    retry_count = 0
    
    while not verification_code and retry_count < max_retries:
        verification_code = check_email(recipient_filter, auth_code)
        
        if verification_code:
            print(f"验证码: {verification_code}")
            break
        
        retry_count += 1
        if retry_count >= max_retries:
            print("已达到最大重试次数，程序结束。")
            break
            
        print(f"未找到验证码，10秒后重新检查...（尝试 {retry_count}/{max_retries}）")
        time.sleep(10)

if __name__ == "__main__":
    main() 