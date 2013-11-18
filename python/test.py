import unittest
from Secop import Secop
from subprocess import Popen
import signal
import os
import sys
import time

conf = {
	"exe":"../../kryptoapp-build/secop",
	"sock":"/tmp/secop",
	"db":"/tmp/secop.db"
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
		self.p = Popen([conf["exe"]])
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

