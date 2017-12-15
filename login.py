import rsa
import base64
import json
import binascii
import requests
import re
import config

login_php_url = 'https://login.sina.com.cn/sso/prelogin.php?entry=account&callback=sinaSSOController.preloginCallBack&su=bGl1ZGl3ZWkxOCU0MHNpbmEuY29t&rsakt=mod&client=ssologin.js(v1.4.15)'

def encode_username(name):
    return base64.b64encode(bytes(name,encoding='utf-8'))

def encode_password(password,servertime,nonce,pubkey):
    rsaPubkey = int(pubkey,16)
    RSAKey = rsa.PublicKey(rsaPubkey,65537)  #public key
    codeStr = str(servertime)+'\t'+str(nonce)+'\n'+str(password) #根据js拼接方式构造明文
    pwd = rsa.encrypt(bytes(codeStr,'utf-8'),RSAKey)#使用rsa进行加密
    return binascii.b2a_hex(pwd) #将加密信息转换为16进制

def getParameters():
    website = requests.get(url=login_php_url).text
    jsonStr=re.findall(r'\((\{.*?\})\)', website)[0] #这段正则表达式粘来的=.=
    data = json.loads(jsonStr)#loads(response.read()),load(response), response has to have read() method
    servertime = data["servertime"]
    nonce = data["nonce"]
    pubkey = data["pubkey"]
    rsakv = data["rsakv"]
    return servertime, nonce, pubkey, rsakv

def get_post_data(username,passwd):
    eu = encode_username(username)
    servertime, nonce, pubkey, rsakv = getParameters()
    ep = encode_password(passwd, servertime, nonce, pubkey)
    post = {
        "cdult": "3",
        "domain": "sina.com.cn",
        "encoding": "UTF-8",
        "entry": "account",
        "from": "",
        "gateway": "1",
        "nonce": nonce,
        "pagerefer": "http://login.sina.com.cn/sso/logout.php",
        "prelt": "41",
        "pwencode": "rsa2",
        "returntype": "TEXT",
        "rsakv": rsakv,
        "savestate": "30",
        "servertime": servertime,
        "service": "sso",
        "sp": ep,
        "sr": "1366*768",
        "su" : eu,
        "useticket" : "0",
        "vsnf" : "1"
    }
    return post

def log_in(username,passwd):
    login_url = r'https://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.15)'
    post=get_post_data(username,passwd)
    session=requests.Session()
    responce=session.post(login_url,post)
    ret_json_info=json.loads(responce.content.decode('gbk'))
    try:
        if ret_json_info["retcode"] == "0":
            print("Login success!")
            state = True
            # 把cookies添加到headers中
            cookies = session.cookies.get_dict()
            cookies = [key + "=" + value for key, value in cookies.items()]
            cookies = "; ".join(cookies)
            session.headers["Cookie"] = cookies
        else:
            print("Login Failed! | " + ret_json_info["reason"])
    except Exception as e:
        print("Loading error --> " + e)
    return session

#设置请求时的headers
headers = {
    "Origin" : "https://login.sina.com.cn",
    "User-Agent" : "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.87 Safari/537.36",
    "Content-Type" : "application/x-www-form-urlencoded",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Referer" : "https://login.sina.com.cn/signup/signin.php?entry=sso",
    "Accept-Encoding" : "deflate, br",
    "Accept-Language" : "en-GB,en;q=0.8,zh-CN;q=0.6,zh;q=0.4"
}

log_in(config.user_name,config.user_passwd)
