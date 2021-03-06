import unittest
from Secop import Secop
from subprocess import Popen
import signal
import os
import sys
import time

# Todo, find better user for this
conf = {
	"exe":["../../secop-build/secop","-u", "secop", "-g", "secop"],
	"sock":"/tmp/secop",
#	"db":"/tmp/secop.db"
	"db":"/var/opi/secop/secop.db"
}

def waitfile(file):
	found = False
	while not found:
		try:
			mode = os.stat(file)
			found = True
		except OSError:
			pass
		time.sleep(0.05)

class TestBase(unittest.TestCase):
	def _start(self):
		self.p = Popen(conf["exe"])
		waitfile(conf["sock"])
		self.s = Secop()

	def _stop(self):
		self.p.send_signal(signal.SIGTERM)
		self.p.wait()

	def setUp(self):
		try:
			os.unlink(conf["db"])
		except OSError:
			pass
		self._start()

	def tearDown(self):
		self._stop()


class TestSecop(TestBase):
	def test_01_status(self):
		(status, res) = self.s.status()
		self.assertTrue( status )
		self.assertEqual( res["status"]["value"], 0)
		self.assertEqual( res["server"]["api"], 1.0)
		self.assertEqual( res["server"]["state"], 1)

	def test_02_init(self):
		# Create db
		(status, res) = self.s.init("Secret password")
		self.assertTrue( status )
		self.assertEqual( res["status"]["value"], 0)
		(status, res) = self.s.status()
		self.assertEqual( res["server"]["state"], 2)
		#Test wrong password
		self._stop()
		self._start()
		(status, res) = self.s.init("Wrong password")
		self.assertFalse( status )
		# Try again with correct password
		(status, res) = self.s.init("Secret password")
		self.assertTrue( status )
		self.assertEqual( res["status"]["value"], 0)
		(status, res) = self.s.status()
		self.assertEqual( res["server"]["state"], 2)

	def test_03_user(self):
		# Initialise db
		(status, res) = self.s.init("Secret password")
		self.assertTrue( status )
		self.assertEqual( res["status"]["value"], 0)
		# Add one user in wrong state
		(status, res) = self.s.adduser("user","secret")
		self.assertFalse( status )

		#Authenticate
		(status, res) = self.s.sockauth()
		self.assertTrue( status )

		#Check status
		(status, res) = self.s.status()
		self.assertTrue( status )

		# Add one user
		(status, res) = self.s.adduser("user","secret")
		self.assertTrue( status )
		self.assertEqual( res["status"]["value"], 0)
		# Try adding it again
		(status, res) = self.s.adduser("user","secret")
		self.assertFalse( status )
		# remove user
		(status, res) = self.s.removeuser("user")
		self.assertTrue( status )
		# Add one user
		(status, res) = self.s.adduser("user","secret")
		self.assertTrue( status )
		# Add one user
		(status, res) = self.s.adduser("user2","secret2")
		self.assertTrue( status )
		# Get users
		(status, res) = self.s.getusers()
		self.assertTrue( status )
		self.assertEqual( len(res["users"]),2)
		# remove user
		(status, res) = self.s.removeuser("user2")
		self.assertTrue( status )
		# Get users
		(status, res) = self.s.getusers()
		self.assertTrue( status )
		self.assertEqual( len(res["users"]),1)

		(status, res) =self.s.addgroup("g1")
		self.assertTrue( status )
		(status, res) =self.s.addgroup("g2")
		self.assertTrue( status )
		(status, res) =self.s.addgroup("g3")
		self.assertTrue( status )

		(status, res) =self.s.getusergroups("user")
		self.assertTrue( status )
		self.assertEqual( len(res["groups"]),0)

		(status, res) =self.s.addgroupmember("g1", "user" )
		self.assertTrue( status )

		(status, res) =self.s.getusergroups("user")
		self.assertTrue( status )
		self.assertEqual( len(res["groups"]),1)

		(status, res) =self.s.addgroupmember("g3", "user" )
		self.assertTrue( status )

		(status, res) =self.s.getusergroups("user")
		self.assertTrue( status )
		self.assertEqual( len(res["groups"]),2)

		(status, res) =self.s.addgroupmember("g2", "user" )
		self.assertTrue( status )

		(status, res) =self.s.getusergroups("user")
		self.assertTrue( status )
		self.assertEqual( len(res["groups"]),3)

		(status, res) =self.s.removegroupmember("g1", "user" )
		self.assertTrue( status )
		(status, res) =self.s.getusergroups("user")
		self.assertEqual( len(res["groups"]),2)

	def test_04_groups(self):
		# Initialise db
		(status, res) = self.s.init("Secret password")
		self.assertTrue( status )
		self.assertEqual( res["status"]["value"], 0)

		#Authenticate
		(status, res) = self.s.sockauth()
		self.assertTrue( status )

		(status, res) = self.s.getgroups()
		self.assertTrue( status )
		self.assertEqual(0+1, len(res["groups"]) )

		(status, res) = self.s.addgroup("test")
		self.assertTrue( status )
		(status, res) = self.s.getgroups()
		self.assertTrue( status )
		self.assertEqual(1+1, len(res["groups"]) )

		(status, res) = self.s.addgroup("test2")
		self.assertTrue( status )
		(status, res) = self.s.getgroups()
		self.assertTrue( status )
		self.assertEqual(2+1, len(res["groups"]) )

		(status, res) = self.s.removegroup("Notest")
		self.assertFalse( status )

		(status, res) = self.s.removegroup("test2")
		self.assertTrue( status )
		(status, res) = self.s.getgroups()
		self.assertTrue( status )
		self.assertEqual(1+1, len(res["groups"]) )

		(status, res) = self.s.addgroupmember("NoGroup","mem1")
		self.assertFalse( status )

		(status, res) = self.s.addgroupmember("test","mem1")
		self.assertTrue( status )

		(status, res) = self.s.getgroupmembers("test")
		self.assertTrue( status )
		self.assertEqual(1, len(res["members"]) )
		(status, res) = self.s.addgroupmember("test","mem2")
		self.assertTrue( status )
		(status, res) = self.s.getgroupmembers("test")
		self.assertTrue( status )
		self.assertEqual(2, len(res["members"]) )

		(status, res) = self.s.getgroupmembers("NoGroup")
		self.assertFalse( status )

		(status, res) = self.s.removegroup("test")
		self.assertTrue( status )
		(status, res) = self.s.getgroups()
		self.assertTrue( status )
		self.assertEqual(0+1, len(res["groups"]) )

		(status, res) = self.s.removegroup("admin")
		self.assertFalse( status )
		(status, res) = self.s.getgroups()
		self.assertTrue( status )
		self.assertEqual(0+1, len(res["groups"]) )



	def test_05_services(self):
		# Initialise db
		(status, res) = self.s.init("Secret password")
		self.assertTrue( status )
		self.assertEqual( res["status"]["value"], 0)

		#Authenticate
		(status, res) = self.s.sockauth()
		self.assertTrue( status )

		# Add one user
		(status, res) = self.s.adduser("user","secret")
		self.assertTrue( status )
		self.assertEqual( res["status"]["value"], 0)
		#Get services
		(status, res) = self.s.getservices("user")
		self.assertTrue( status )
		self.assertEqual( len(res["services"]), 1)
		# Add service
		(status, res) = self.s.addservice("user","myservice")
		self.assertTrue( status )
		#Get services
		(status, res) = self.s.getservices("user")
		self.assertEqual( len(res["services"]), 2)
		#Remove service
		(status, res) = self.s.removeservice("user","myservice")
		self.assertTrue( status )
		#Get services
		(status, res) = self.s.getservices("user")
		self.assertEqual( len(res["services"]), 1)

	def test_06_identifiers(self):
		# Initialise db
		(status, res) = self.s.init("Secret password")
		#Authenticate
		(status, res) = self.s.sockauth()
		self.assertTrue( status )
		# Add one user
		(status, res) = self.s.adduser("user","secret")
		# Add service
		(status, res) = self.s.addservice("user","myservice")
		# Get identifiers
		(status, res) = self.s.getidentifiers("user","myservice")
		self.assertTrue( status )
		self.assertEqual( len(res["identifiers"]), 0)
		# Add identifier
		id = {}
		id["user"]="user"
		id["password"] = "S3cret"
		id["service"] = "http://www.hotmail.com"
		id["comment"] = "A test"
		(status, res) = self.s.addidentifier("user","myservice", id)
		self.assertTrue( status )
		# Get identifiers
		(status, res) = self.s.getidentifiers("user","myservice")
		self.assertTrue( status )
		self.assertEqual( len(res["identifiers"]), 1)
		# Remove identifier
		(status, res) = self.s.removeidentifier("user","myservice", id)
		self.assertTrue( status )
		# Get identifiers
		(status, res) = self.s.getidentifiers("user","myservice")
		self.assertTrue( status )
		self.assertEqual( len(res["identifiers"]), 0)
		# Add identifiers
		(status, res) = self.s.addidentifier("user","myservice", id)
		id2 = {}
		id2["user"]="user"
		id2["password"] = "S3cret"
		id2["service"] = "http://live.com"
		id2["comment"] = "A test"
		(status, res) = self.s.addidentifier("user","myservice", id2)
		# Get identifiers
		(status, res) = self.s.getidentifiers("user","myservice")
		self.assertEqual( len(res["identifiers"]), 2)
		# Remove identifier
		(status, res) = self.s.removeidentifier("user","myservice", id)
		self.assertTrue( status )
		# Get identifiers
		(status, res) = self.s.getidentifiers("user","myservice")
		self.assertEqual( len(res["identifiers"]), 1)
		# Remove identifier
		(status, res) = self.s.removeidentifier("user","myservice", id2)
		self.assertTrue( status )
		# Get identifiers
		(status, res) = self.s.getidentifiers("user","myservice")
		self.assertEqual( len(res["identifiers"]), 0)
		# Remove service
		(status, res) = self.s.removeservice("user","myservice")
		self.assertTrue( status )
		# Remove user
		(status, res) = self.s.removeuser("user")
		self.assertTrue( status )

	def test_07_acl(self):
		# Initialise db
		(status, res) = self.s.init("Secret password")
		#Authenticate
		(status, res) = self.s.sockauth()
		self.assertTrue( status )
		# Add one user
		(status, res) = self.s.adduser("user","secret")
		self.assertTrue( status )
		# Add service
		(status, res) = self.s.addservice("user","myservice")
		self.assertTrue( status )
		#Get ACL
		(status, res) = self.s.getacl("user","myservice")
		self.assertTrue( status )
		self.assertEqual( len(res["acl"]), 0 )
		#Has ACL
		(status, res) = self.s.hasacl("user","myservice","acl1")
		self.assertTrue( status )
		self.assertFalse( res["hasacl"] )
		#Add ACL
		(status, res) = self.s.addacl("user","myservice","acl1")
		self.assertTrue( status )
		#Has ACL
		(status, res) = self.s.hasacl("user","myservice","acl1")
		self.assertTrue( status )
		self.assertTrue( res["hasacl"] )
		#Get ACL
		(status, res) = self.s.getacl("user","myservice")
		self.assertTrue( status )
		self.assertEqual( len(res["acl"]), 1 )
		self.assertEqual( res["acl"][0], "acl1")
		#Add same ACL
		(status, res) = self.s.addacl("user","myservice","acl1")
		self.assertFalse( status )
		#Add ACL
		(status, res) = self.s.addacl("user","myservice","acl2")
		self.assertTrue( status )
		#Has ACL
		(status, res) = self.s.hasacl("user","myservice","acl1")
		self.assertTrue( status )
		self.assertTrue( res["hasacl"] )
		(status, res) = self.s.hasacl("user","myservice","acl2")
		self.assertTrue( status )
		self.assertTrue( res["hasacl"] )
		#Get ACL
		(status, res) = self.s.getacl("user","myservice")
		self.assertTrue( status )
		self.assertEqual( len(res["acl"]), 2 )
		#Remove ACL
		(status, res) = self.s.removeacl("user","myservice","acl2")
		self.assertTrue( status )
		(status, res) = self.s.hasacl("user","myservice","acl2")
		self.assertTrue( status )
		self.assertFalse( res["hasacl"] )
		#Get ACL
		(status, res) = self.s.getacl("user","myservice")
		self.assertTrue( status )
		self.assertEqual( len(res["acl"]), 1 )
		# Remove service
		(status, res) = self.s.removeservice("user","myservice")
		self.assertTrue( status )
		# Remove user
		(status, res) = self.s.removeuser("user")
		self.assertTrue( status )

	def test_08_attr(self):
		# Initialise db
		(status, res) = self.s.init("Secret password")
		#Authenticate
		(status, res) = self.s.sockauth()
		self.assertTrue( status )
		# Add one user
		(status, res) = self.s.adduser("user","secret","My Name")
		self.assertTrue( status )
		#Get attributes
		(status, res) = self.s.getattributes("user")
		self.assertTrue( status )
		self.assertEqual( len(res["attributes"]), 1 )
		#Get attribute
		(status, res) = self.s.getattribute("user","displayname")
		self.assertTrue( status )
		self.assertEqual( res["attribute"], "My Name" )
		(status, res) = self.s.getattribute("user","unknown")
		self.assertFalse( status )
		#Add attribute
		(status, res) = self.s.addattribute("user","eyecolor","green")
		(status, res) = self.s.getattribute("user","eyecolor")
		self.assertTrue( status )
		self.assertEqual( res["attribute"], "green" )
		(status, res) = self.s.getattributes("user")
		self.assertTrue( status )
		self.assertEqual( len(res["attributes"]), 2 )
		(status, res) = self.s.addattribute("user","eyecolor","green")
		self.assertTrue( status )
		(status, res) = self.s.addattribute("nouser","eyecolor","green")
		self.assertFalse( status )
		#Remove attribute
		(status, res) = self.s.removeattribute("user","eyecolor")
		self.assertTrue( status )
		(status, res) = self.s.getattributes("user")
		self.assertTrue( status )
		self.assertEqual( len(res["attributes"]), 1 )
		(status, res) = self.s.getattribute("user","eyecolor")
		self.assertFalse( status )
		(status, res) = self.s.removeattribute("user","eyecolor")
		self.assertFalse( status )

	def test_09_appid(self):
		# Initialise db
		(status, res) = self.s.init("Secret password")
		#Authenticate
		(status, res) = self.s.sockauth()
		self.assertTrue( status )

		# Add appid
		(status, res) = self.s.addappid("myappid")
		self.assertTrue( status )

		# Get appids
		(status, res) = self.s.getappids()
		self.assertTrue( status )
		self.assertEqual( len(res["appids"]), 1 )

		(status, res) = self.s.addappid("myappid")
		self.assertFalse( status )

		(status, res) = self.s.addappid("id2")
		self.assertTrue( status )
		(status, res) = self.s.getappids()
		self.assertTrue( status )
		self.assertEqual( len(res["appids"]), 2 )

		#remove appid
		(status, res) = self.s.removeappid("id2")
		self.assertTrue( status )
		(status, res) = self.s.getappids()
		self.assertTrue( status )
		self.assertEqual( len(res["appids"]), 1 )

		(status, res) = self.s.removeappid("id2")
		self.assertFalse( status )

	def test_10_appidentifiers(self):
		# Initialise db
		(status, res) = self.s.init("Secret password")
		#Authenticate
		(status, res) = self.s.sockauth()
		self.assertTrue( status )

		# Add appid
		(status, res) = self.s.addappid("myappid")
		self.assertTrue( status )

		# Add identifier
		id = {}
		id["user"]="user"
		id["password"] = "S3cret"
		id["service"] = "http://www.hotmail.com"
		id["comment"] = "A test"
		(status, res) = self.s.addappidentifier("myappid", id)
		self.assertTrue( status )


		#Get app identifiers
		(status, res) = self.s.getappidentifiers("myappid")
		self.assertTrue( status )

		self.assertEqual( len(res["identifiers"]), 1)

		rid = res["identifiers"][0]
		self.assertEqual( rid["user"], id["user"] )
		self.assertEqual( rid["password"], id["password"] )
		self.assertEqual( rid["service"], id["service"] )
		self.assertEqual( rid["comment"], id["comment"] )

		rid["user"]="New name"
		(status, res) = self.s.addappidentifier("myappid", rid)
		self.assertTrue( status )

		(status, res) = self.s.getappidentifiers("myappid")
		self.assertTrue( status )

		self.assertEqual( len(res["identifiers"]), 2)

		(status, res) = self.s.addappidentifier("wrong appid", rid)
		self.assertFalse( status )
		(status, res) = self.s.addappidentifier("", rid)
		self.assertFalse( status )

		# Remove identifier
		(status, res) = self.s.removeappidentifier("wrong appid", {})
		self.assertFalse( status )

		(status, res) = self.s.removeappidentifier("myappid", {})
		self.assertFalse( status )

		(status, res) = self.s.getappidentifiers("myappid")
		self.assertTrue( status )
		self.assertEqual( 2, len(res["identifiers"]))

		(status, res) = self.s.removeappidentifier("myappid", {"user":"New name"})
		self.assertTrue( status )

		(status, res) = self.s.getappidentifiers("myappid")
		self.assertTrue( status )
		self.assertEqual( 1, len(res["identifiers"]))

	def test_11_appacl(self):
		# Initialise db
		(status, res) = self.s.init("Secret password")
		#Authenticate
		(status, res) = self.s.sockauth()
		self.assertTrue( status )

		# Add appid
		(status, res) = self.s.addappid("myappid")
		self.assertTrue( status )

		# Add app acl
		(status, res) = self.s.addappacl("myappid","www-data")
		self.assertTrue( status )

		(status, res) = self.s.addappacl("myappid","www-data")
		self.assertFalse( status )

		(status, res) = self.s.addappacl("noappid","noent")
		self.assertFalse( status )
		(status, res) = self.s.addappacl("","")
		self.assertFalse( status )

		(status, res) = self.s.addappacl("myappid","")
		self.assertFalse( status )

		# Get app acl
		(status, res) = self.s.getappacl("myappid")
		self.assertTrue( status )
		self.assertEqual( 1, len(res["acl"]) )
		self.assertEqual( res["acl"][0], "www-data" )

		(status, res) = self.s.getappacl("wrongappid")
		self.assertFalse( status )

		(status, res) = self.s.getappacl("")
		self.assertFalse( status )

		(status, res) = self.s.addappacl("myappid","e2")
		self.assertTrue( status )
		(status, res) = self.s.getappacl("myappid")
		self.assertTrue( status )
		self.assertEqual( 2, len(res["acl"]) )

		# Remove app acl
		(status, res) = self.s.removeappacl("myappid","www-data")
		self.assertTrue( status )
		(status, res) = self.s.getappacl("myappid")
		self.assertTrue( status )
		self.assertEqual( 1, len(res["acl"]) )
		self.assertEqual( res["acl"][0], "e2" )

		(status, res) = self.s.removeappacl("myappid","www-data")
		self.assertFalse( status )

		(status, res) = self.s.removeappacl("myappid","e2")
		self.assertTrue( status )
		(status, res) = self.s.getappacl("myappid")
		self.assertTrue( status )
		self.assertEqual( 0, len(res["acl"]) )

		# Has app acl
		(status, res) = self.s.hasappacl("myappid","e1")
		self.assertTrue( status )
		self.assertFalse( res["hasacl"] )

		(status, res) = self.s.addappacl("myappid","e1")
		self.assertTrue( status )

		(status, res) = self.s.hasappacl("myappid","e1")
		self.assertTrue( status )
		self.assertTrue( res["hasacl"] )

		(status, res) = self.s.hasappacl("noapp","e1")
		self.assertFalse( status )

		(status, res) = self.s.hasappacl("","")
		self.assertFalse( status )


if __name__=='__main__':
	print "Start"
	unittest.main()
	print "Done!"
	exit(0)
	s = Secop()
	s.status()
	s.init("Secret password")
	s.status()
	s.sockauth()
	s.status()
	s.removeuser("kalle")
	s.removeuser("kalle")
	s.status()
	s.adduser("kalle", "S3cr3t")
	s.status()
	s.plainauth("kalle","S3cr3t")
	s.status()
	s.adduser("Pelle", "S3cr3t")
	s.adduser("Sven", "S3cr3t")
	s.getusers()
	s.addservice("Pelle", "Service1")
	s.addservice("Pelle", "Service2")
	s.addservice("Pelle", "Service3")
	s.addservice("Sven", "Service1")
	s.addservice("Sven", "Service2")
	s.addservice("Sven", "Service3")
	s.getservices("Sven")
	s.getservices("Pelle")
	s.removeservice("Sven", "Service1")
	s.removeservice("Sven", "Service1")
	s.removeservice("Svenska", "Service1")
	s.getservices("Sven")
	s.removeservice("Sven", "Service2")
	s.removeservice("Sven", "Service3")
	s.removeservice("Sven", "opiuser") #Error?
	s.getservices("Sven")

