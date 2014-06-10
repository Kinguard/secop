import socket
try:
	import simplejson as json
except ImportError:
	import json

defaultdump = True
#defaultdump = False

class Client:

	def __init__(self, path="/tmp/secop"):
		self.con = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		self.con.connect(path)
		self._tid = 0

	def _dorequest(self, req, dump):
		req["tid"] = self._tid
		req["version"] = 1.0
		#print(req)
		s = json.dumps(req)
		b = bytes( s, 'utf-8')
		self.con.send(b)
		self._tid = self._tid + 1
		ret = self.con.recv(16384)
		return self._processreply(json.loads(ret.decode('utf-8')), dump)

	def _processreply(self, req, dump):
		if req["status"]["value"] == 0:
			if dump:
				print(json.dumps( req, indent=4 ))
			return (True,req)
		else:
			if dump:
				print("Request failed with error '%s'"%req["status"]["desc"])
			return (False,"Request failed with error '%s'"%req["status"]["desc"])


	def __del__(self):
		self.con.close()

class Secop(Client):

	def status(self, dump = defaultdump ):
		return self._dorequest({"cmd":"status"}, dump)

	def init(self, pwd, dump=defaultdump):
		req = {}
		req["cmd"]="init"
		req["pwd"]=pwd
		return self._dorequest(req,dump)

	def sockauth(self, dump=defaultdump):
		req = {}
		req["cmd"]="auth"
		req["type"]="socket"
		return self._dorequest(req,dump)

	def plainauth(self, user, password, dump=defaultdump):
		req = {}
		req["cmd"]="auth"
		req["type"]="plain"
		req["username"]=user
		req["password"]=password
		return self._dorequest(req,dump)

	def adduser(self, user, password, dump=defaultdump):
		req = {}
		req["cmd"]="createuser"
		req["username"]=user
		req["password"]=password
		return self._dorequest(req,dump)

	def removeuser(self, user, dump=defaultdump):
		req = {}
		req["cmd"]="removeuser"
		req["username"]=user
		return self._dorequest(req,dump)

	def getusers(self, dump=defaultdump):
		req = {}
		req["cmd"]="getusers"
		return self._dorequest(req,dump)

	def getservices(self, user, dump=defaultdump):
		req = {}
		req["cmd"]="getservices"
		req["username"] = user
		return self._dorequest(req,dump)

	def addservice(self, user, service, dump=defaultdump):
		req = {}
		req["cmd"]="addservice"
		req["username"] = user
		req["servicename"] = service
		return self._dorequest(req,dump)

	def removeservice(self, user, service, dump=defaultdump):
		req = {}
		req["cmd"]="removeservice"
		req["username"] = user
		req["servicename"] = service
		return self._dorequest(req,dump)

	def getacl(self, user, service,dump=defaultdump):
		req = {}
		req["cmd"]="getacl"
		req["username"] = user
		req["servicename"] = service
		return self._dorequest(req,dump)

	def addacl(self, user, service, acl, dump=defaultdump):
		req = {}
		req["cmd"]="addacl"
		req["username"] = user
		req["servicename"] = service
		req["acl"] = acl
		return self._dorequest(req,dump)

	def removeacl(self, user, service, acl, dump=defaultdump):
		req = {}
		req["cmd"]="removeacl"
		req["username"] = user
		req["servicename"] = service
		req["acl"] = acl
		return self._dorequest(req,dump)

	def hasacl(self, user, service, acl, dump=defaultdump):
		req = {}
		req["cmd"]="hasacl"
		req["username"] = user
		req["servicename"] = service
		req["acl"] = acl
		return self._dorequest(req,dump)

	def addidentifier(self, user, service, identifier, dump=defaultdump):
		req = {}
		req["cmd"]="addidentifier"
		req["username"] = user
		req["servicename"] = service
		req["identifier"] = identifier
		return self._dorequest(req,dump)

	def removeidentifier(self, user, service, identifier, dump=defaultdump):
		req = {}
		req["cmd"]="removeidentifier"
		req["username"] = user
		req["servicename"] = service
		req["identifier"] = identifier
		return self._dorequest(req,dump)

	def getidentifiers(self, user, service, dump=defaultdump):
		req = {}
		req["cmd"]="getidentifiers"
		req["username"] = user
		req["servicename"] = service
		return self._dorequest(req,dump)


