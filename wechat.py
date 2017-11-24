import tornado.web
import tornado.options
import tornado.ioloop
import tornado.httpserver
import tornado.gen
import hashlib
import xmltodict
import time
from tornado.httpclient import AsyncHTTPClient, HTTPRequest
import json
import os
from urllib import parse

WECHAT_TOKEN = "lxhsec"
APPID = "wxe69e1d5d9b26ed0a"
APPSECRET = "e9e1c5c0b1fa9669d9a545fa7887c9e0"
tornado.options.define("port", default=8000,type=int, help="") 

class Qrcode(tornado.web.RequestHandler):
	"""获取带有场景值二维码"""
	@tornado.gen.coroutine
	def get(self):
		scene_id = self.get_argument("sid")
		try:
			token = yield Access_Token.get_access_token()
		except Exception as e:
			self.write("errmsg1: %s" % e)
		else:
			client = AsyncHTTPClient()
			"""接口获取ticket值"""
			url = "https://api.weixin.qq.com/cgi-bin/qrcode/create?access_token=%s" % token
			rep_post_data = {"expire_seconds": 604800, "action_name": "QR_SCENE", "action_info": {"scene": {"scene_id": scene_id}}}
			rep = HTTPRequest(
			url=url,
			method="POST",
			body=json.dumps(rep_post_data)
			)
			rep_data = yield client.fetch(rep)
			rep_json_data = json.loads(rep_data.body.decode("utf-8"))
			if "errcode" in rep_json_data:
				self.write("errmsg: get qrcode failed")
			else:
				code_url = rep_json_data['url']
				code_ticket = rep_json_data['ticket']
				self.write("<img src='https://mp.weixin.qq.com/cgi-bin/showqrcode?ticket=%s'/><br />" % code_ticket)
				self.write("<p>%s</p>" % code_url)

class Access_Token(object):
	
	_access_token = None
	_create_time = 0
	_expires_in = 0

	@classmethod
	@tornado.gen.coroutine
	def update_acces_token(cls):
		"""更新接口调用凭据"""
		client = AsyncHTTPClient()
		url = "https://api.weixin.qq.com/cgi-bin/token?grant_type=" \
		"client_credential&appid=%s&secret=%s" % (APPID, APPSECRET)
		rep = yield client.fetch(url)
		# print(rep.body)
		# print(rep.body.decode('utf-8'))
		jrep = json.loads(rep.body.decode('utf-8'))

		if "errcode" in jrep:
			raise Exception("server error")
		else:
			cls._access_token = jrep['access_token']
			cls._create_time = time.time()
			cls._expires_in = jrep['expires_in']

	@classmethod
	@tornado.gen.coroutine
	def get_access_token(cls):
		"""获取接口调用凭据"""
		if (time.time() - cls._create_time > (cls._expires_in - 200)):
			yield cls.update_acces_token()
			raise tornado.gen.Return(cls._access_token)
		else:
			raise tornado.gen.Return(cls._access_token)



class Wechat_handler(tornado.web.RequestHandler):
	"""对接微信服务器"""
	def prepare(self):
		signature = self.get_argument("signature")
		timestamp = self.get_argument("timestamp")
		nonce = self.get_argument("nonce")  
		tmp = [WECHAT_TOKEN, timestamp, nonce]
		tmp.sort()
		tmp = "".join(tmp)
		sigsha1 = hashlib.sha1(tmp.encode('utf-8')).hexdigest()
		if signature != sigsha1:
			self.send_error(403)
	def get(self):
		echostr = self.get_argument("echostr")
		self.write(echostr)

	def post(self):
		"""
<xml>
	<ToUserName><![CDATA[toUser]]></ToUserName>
	<FromUserName><![CDATA[fromUser]]></FromUserName> 
	<CreateTime>1348831860</CreateTime>
	<MsgType><![CDATA[text]]></MsgType>
	<Content><![CDATA[this is a test]]></Content>
	<MsgId>1234567890123456</MsgId>
 </xml>
		"""
		xml_data = self.request.body
		dict_data = xmltodict.parse(xml_data)
		data_type = dict_data['xml']['MsgType']
		"""处理用户发送的文本消息"""
		if 'text' == data_type:
			"""text"""
			content = dict_data['xml']['Content']
			rep_data = {
				"xml": {
					"ToUserName" : dict_data['xml']['FromUserName'],
					"FromUserName" : dict_data['xml']['ToUserName'],
					"CreateTime" : int(time.time()),
					"MsgType" : "text",
					"Content" : content,
				}
			}

	
		elif 'event' == data_type:
			"""处理关注事件"""
			if 'subscribe' == dict_data['xml']['Event']:
				"""未关注时，扫描二维码关注后开发者做出的回应"""
				rep_data = {
					"xml": 	{
						"ToUserName" : dict_data['xml']['FromUserName'],
						"FromUserName" : dict_data['xml']['ToUserName'],
						"CreateTime" : int(time.time()),
						"MsgType" : "text",
						"Content" : "welcome no args",
							}
						}
				if "EventKey" in dict_data['xml']:
					EventKey = dict_data['xml']['EventKey']
					scene_id = EventKey[8:]
					rep_data['xml']['Content'] = "subscribe welcome scene_id is: %s" % scene_id

			elif 'SCAN' == dict_data['xml']['Event']:
				"""已关注时，扫描二维码关注后开发者做出的回应"""
				rep_data = {
					"xml": 	{
						"ToUserName" : dict_data['xml']['FromUserName'],
						"FromUserName" : dict_data['xml']['ToUserName'],
						"CreateTime" : int(time.time()),
						"MsgType" : "text",
						"Content" : "welcome no args",
							}
						}
				scene_id = dict_data['xml']['EventKey']
				rep_data['xml']['Content'] = "SCAN welcome scene_id is: %s" % scene_id

			else:
				rep_data = None

		elif 'image' == data_type:
			"""处理用户发送的image消息"""
			content = dict_data['xml']['MediaId']
			rep_data = {
				"xml": {
					"ToUserName" : dict_data['xml']['FromUserName'],
					"FromUserName" : dict_data['xml']['ToUserName'],
					"CreateTime" : int(time.time()),
					"MsgType" : "image",
					"Image" : {"MediaId" : content}

				}
			}
		
		elif 'voice' == data_type:
			"""处理用户发送的语音消息"""
			content = dict_data['xml']['MediaId']
			rep_data = {
				"xml": {
					"ToUserName" : dict_data['xml']['FromUserName'],
					"FromUserName" : dict_data['xml']['ToUserName'],
					"CreateTime" : int(time.time()),
					"MsgType" : "voice",
					"Voice" : {"MediaId" : content}

				}
			}

		else:
			"""其他事件"""
			rep_data = {
				"xml": {
					"ToUserName" : dict_data['xml']['FromUserName'],
					"FromUserName" : dict_data['xml']['ToUserName'],
					"CreateTime" : int(time.time()),
					"MsgType" : "text",
					"Content" : "I love you",
				}
			}
		if rep_data:
			rep_xml = xmltodict.unparse(rep_data)
		else:
			rep_xml = ''
		self.write(rep_xml)

class Redicturl(tornado.web.RequestHandler):
	"""获取用户基本信息"""
	@tornado.gen.coroutine
	def get(self):
		code = self.get_argument("code")
		client = AsyncHTTPClient()
		url = "https://api.weixin.qq.com/sns/oauth2/access_token?" \
		"appid=%s&secret=%s&code=%s&grant_type=authorization_code" % (APPID, APPSECRET, code)
		rep = yield client.fetch(url)
		json_data_rep = json.loads(rep.body.decode("utf-8"))
		if "errcode" in json_data_rep:
			self.write("access_token get fail")
		else:
			access_token_user = json_data_rep['access_token']
			openid = json_data_rep['openid']
			url = "https://api.weixin.qq.com/sns/userinfo?" \
			"access_token=%s&openid=%s&lang=zh_CN" % (access_token_user, openid)
			get_user_rep = yield client.fetch(url)
			json_get_user_rep = json.loads(get_user_rep.body.decode("utf-8"))
			if "errcode" in json_get_user_rep:
				self.write("get user information fail")
			else:
				self.render("index.html", user=json_get_user_rep)


class CreateMenuHandler(tornado.web.RequestHandler):
	"""创建微信菜单"""
	@tornado.gen.coroutine
	def get(self):
		try:
			access_token = yield Access_Token.get_access_token() 
		except Exception as e:
			self.write("errmsg: %s" % e)
		else:
			menu_data = {
				"button":[
				{
					"type":"view",
					"name":"测试网页链接",
					"url":"https://open.weixin.qq.com/connect/oauth2/authorize?appid=%s&redirect_uri=%s&response_type=code&scope=snsapi_userinfo&state=1#wechat_redirect" % (APPID, parse.quote("http://104.236.28.181/wechat8000/profile"))
				},

				{
				"name": "菜单",
				"sub_button":[
						{
							"type": "view",
							"name": "搜狗搜索",
							"url": "http://www.soso.com/"
						},
						{
							"type": "view",
							"name": "百度",
							"url": "http://www.baidu.com/"
						},
						{
							"type": "view",
							"name": "360搜索",
							"url": "https://www.so.com/"
						}
				]}

			]}

			client = AsyncHTTPClient()
			url = "https://api.weixin.qq.com/cgi-bin/menu/create?access_token=%s" % access_token
			req = HTTPRequest(url, method="POST", body=json.dumps(menu_data, ensure_ascii=False))
			resp = yield client.fetch(req)
			ret = json.loads(resp.body.decode('utf-8'))
			if 0 == ret.get("errcode"):
				self.write("创建菜单成功")
			else:
				self.write(ret.get("errmsg", "创建菜单失败"))

def main():
	tornado.options.parse_command_line()
	app = tornado.web.Application([
		(r"/wechat8000", Wechat_handler),
		(r"/Qrcode", Qrcode),
		(r"/wechat8000/profile", Redicturl),
		(r"/menu", CreateMenuHandler),

		],
		template_path=os.path.join(os.path.dirname(__file__), "template")
		)
	http_server = tornado.httpserver.HTTPServer(app)
	http_server.listen(tornado.options.options.port)
	tornado.ioloop.IOLoop.current().start()


if __name__ == '__main__':
	main()