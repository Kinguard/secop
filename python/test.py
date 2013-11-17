import unittest
from Secop import Secop

class TestSecop(unittest.TestCase):
	
	def setUp(self):
		self.s = Secop()

	def test_status(self):
		(status, res) = self.s.status()
		self.assertTrue( status )
		self.assertEqual( res["status"]["value"], 0)
		self.assertEqual( res["server"]["api"], 1.0)

	def tearDown(self):
		pass
			
if __name__=='__main__':
	unittest.main()
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

