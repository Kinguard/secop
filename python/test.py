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
	def test_1_status(self):
		(status, res) = self.s.status()
		self.assertTrue( status )
		self.assertEqual( res["status"]["value"], 0)
		self.assertEqual( res["server"]["api"], 1.0)
		self.assertEqual( res["server"]["state"], 1)

	def test_2_init(self):
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

	def test_3_user(self):
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

	def test_4_services(self):
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

	def test_5_identifiers(self):
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

	def test_6_acl(self):
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

	def test_7_attr(self):
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
		self.assertFalse( status )
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

