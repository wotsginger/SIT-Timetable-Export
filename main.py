import requests
from bs4 import BeautifulSoup
import base64
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from io import BytesIO
from PIL import Image
import json

# 定义用于AES加密的字符集
_chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678'
_chars_len = len(_chars)


def _rds(length):
    """生成指定长度的随机字符串"""
    return ''.join(random.choice(_chars) for _ in range(length))


def encryptAES(data, key):
    """模拟JavaScript中的 encryptAES 方法进行AES加密"""
    if not key:
        return data

    # 生成加密所需的随机前缀和IV
    random_prefix = _rds(64)
    iv = _rds(16)

    # 加密
    encrypted = _gas(random_prefix + data, key, iv)
    return encrypted


def _gas(data, key0, iv0):
    """使用AES CBC模式进行加密"""
    key = key0.strip().encode('utf-8')
    iv = iv0.encode('utf-8')

    # 使用AES CBC模式和PKCS7填充
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    encrypted_base64 = base64.b64encode(encrypted_bytes).decode('utf-8')

    return encrypted_base64


def save_data(data, filename):
    """保存数据为JSON文件"""
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)
    print(f"{filename} 文件已成功保存。将此文件导入小应生活APP即可解析课表。")


def fetch_timetable(session, csrf_token):
    """获取课程表数据并保存为JSON文件"""
    timetable_url = "http://jwxt.sit.edu.cn/jwglxt/kbcx/xskbcx_cxXsgrkb.html?gnmkdm=N253508"
    payload = {
        "xnm": "2024",  # 学年
        "xqm": "3",    # 学期
    }

    # 使用已有的会话对象发送POST请求
    response = session.post(timetable_url, data=payload)

    # 检查响应是否成功
    if response.status_code == 200:
        # 解析JSON数据
        timetable_data = response.json()
        # 保存为本地JSON文件
        save_data(timetable_data, "Timetable.json")
    else:
        print(f"获取课程表失败，状态码: {response.status_code}")


def login_to_oa_system():
    """登录OA系统"""

    print("请先启动Easyconnect并确保已经启动连接")
    # 提示用户输入用户名和密码
    username = input("请输入学号: ")
    password = input("请输入密码: ")

    # 创建一个会话对象
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
        "Referer": "https://authserver.sit.edu.cn/authserver/login"
    })

    # Step 1: 获取登录页面并解析隐藏字段
    oa_login_url = "https://authserver.sit.edu.cn/authserver/login"
    response = session.get(oa_login_url)
    soup = BeautifulSoup(response.text, 'html.parser')

    # 提取所有隐藏字段并确保存在name和value属性
    hidden_inputs = soup.find_all("input", type="hidden")
    login_data = {input.get("name"): input.get("value") for input in hidden_inputs if
                  input.get("name") and input.get("value")}

    # 获取加密盐值
    salt_element = soup.find('input', {'id': 'pwdDefaultEncryptSalt'})
    if salt_element:
        salt = salt_element['value']
    else:
        print("未能找到加密所需的盐值。请检查页面结构。")
        return

    # 获取验证码图片
    captcha_url = "https://authserver.sit.edu.cn/authserver/captcha.html"
    captcha_response = session.get(captcha_url)
    captcha_image = Image.open(BytesIO(captcha_response.content))
    captcha_image.show()

    # 提示用户输入验证码
    captcha_code = input("请输入验证码: ")

    # 加密密码
    encrypted_password = encryptAES(password, salt)

    # 填充登录表单数据
    login_data['username'] = username
    login_data['password'] = encrypted_password
    login_data['captchaResponse'] = captcha_code

    # 打印调试信息
    print("提交的数据: ", login_data)

    # Step 2: 提交登录表单
    login_response = session.post(oa_login_url, data=login_data)

    # 检查登录是否成功
    if "auth_username" in login_response.text or "安全退出" in login_response.text:
        print("登录成功！")

        # Step 3: 访问教务系统通过SSO
        jwxt_sso_url = "http://jwxt.sit.edu.cn/sso/jziotlogin"
        jwxt_sso_response = session.get(jwxt_sso_url)

        # Step 4: 直接访问课程表页面，先获取CSRF token
        course_schedule_url = "http://jwxt.sit.edu.cn/jwglxt/kbcx/xskbcx_cxXskbcxIndex.html?gnmkdm=N253508&layout=default"
        course_schedule_response = session.get(course_schedule_url)

        # 提取CSRF Token
        soup = BeautifulSoup(course_schedule_response.text, 'html.parser')
        csrf_token = soup.find('input', {'id': 'csrftoken'})['value']

        # 打印CSRF Token
        print("CSRF Token: ", csrf_token)

        # 使用CSRF Token获取课程表数据
        fetch_timetable(session, csrf_token)
    else:
        print("登录失败，请检查用户名和密码。")


if __name__ == "__main__":
    login_to_oa_system()
