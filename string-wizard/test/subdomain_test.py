import unittest
from get_url_subdomain.get_subdomain import subdomain_extractor


class TestSubdomainExtractor(unittest.TestCase):
    def setUp(self):
        self.url1 = 'https://subdomain.example.com'
        self.url2 = 'HtTPs://subdomain.example.com'
        self.url3 = 'http://example.com'
        self.url4 = 'htTp://example.com'
        self.url5 = 'www.example.com'
        self.url6 = 'WwW.example1.example2.example3.com'

    def test_subdomain_extractor_https(self):
        self.assertEqual(subdomain_extractor(self.url1.lower()), 'subdomain')
        self.assertEqual(subdomain_extractor(self.url2.lower()), 'subdomain')

    def test_subdomain_extractor_http(self):
        self.assertEqual(subdomain_extractor(self.url3.lower()), 'example')
        self.assertEqual(subdomain_extractor(self.url4.lower()), 'example')

    def test_subdomain_extractor_www(self):
        self.assertEqual(subdomain_extractor(self.url5.lower()), 'www')
        self.assertEqual(subdomain_extractor(self.url6.lower()), "subdomains are: ['www', 'example1', 'example2'], but the main subdomain is: www")

    
if __name__ =='__main__':
    unittest.main()
