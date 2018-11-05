#!/usr/bin/env python
# GPLv3 by Kai Sisterhenn <sistason@sistason.de> github.com/sistason

from sys import argv
from os import listdir, path
import requests
import logging

class TubitLogin():
    """ Do login for cisco webauth sites.

    1. Init with the website-basics
    2. Login with the password
    3. Accept ToS/Aup
    """
    headers = {
        'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:24.0) Gecko/20100101 Firefox/24.0', 
        'Accept-Encoding':'gzip, deflate', 'Accept-Language':'en-US,en;q=0.5', 
        'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Content-Type' : 'application/x-www-form-urlencoded'}
    success = False
    tos_site = None
    login_site = None
    CERT = path.join(path.dirname(path.abspath(__file__)), 'ise-01.tubit.tu-berlin.de.pem')

    def __init__(self, usr, pw):
        self.usr, self.pw = usr, pw
        url_and_session = requests.get('http://www.heise.de', verify=False)
        if url_and_session.url.endswith("www.heise.de/") and not "redirect" in url_and_session.url:
            logging.info('Already logged in')
            self.success = True
            return

        url = requests.utils.urlparse(url_and_session.url)
        self.base = 'https://{0}:{1}'.format(url.hostname, url.port)
        self.loginpath = url.path
        self.query = url.query
        
        try:
            self.login_site = requests.get(url_and_session.url, headers=self.get_headers(url_and_session.url), verify=self.CERT)
        except requests.exceptions.SSLError as e:
            certs = [i for i in listdir(path.dirname(path.abspath(__file__))) if i.endswith('.pem') or i.endswith('.crt')]
            if not certs:
                certs = [i for i in listdir(path.dirname(path.abspath(__file__))) if path.isfile(i) and open(i).readline().startswith('-----BEGIN CERTIFICATE-----')]
                if not certs:
                    logging.error('Error! SSL Certificate is missing for "{0}"!'.format(self.base))
                    return
            try:
                cert_ = path.join(path.dirname(path.abspath(__file__)), certs[0])
                requests.pyopenssl.ssl.get_server_certificate((url.hostname, url.port), ca_certs=cert_)
                self.CERT = cert_
                self.login_site = requests.get(url_and_session.url, headers=self.get_headers(url_and_session.url), verify=self.CERT)
            except requests.exceptions.SSLError:
                logging.error('Error! SSL Certificate is invalid for "{0}"!'.format(self.base))
                return

    def work(self):
        self.login()
        self.accept_tos()

    def login(self):
        if self.login_site is None:
            return

        if self.login_site.status_code != 200:
            logging.info('Error while getting to login-page')
            logging.debug(self.login_site.text)

        searchstring = '<form name="loginForm" action="'
        self.loginsubmitpath = ''
        start = self.login_site.text.find(searchstring)
        if start != -1:
            find_ = self.login_site.text[start+len(searchstring):start+len(searchstring)+200]
            end = find_.find('"')
            self.loginsubmitpath = find_[:end]
        else:
            self.loginsubmitpath = 'LoginSubmit.action?from=LOGIN'
            
        url = self.base + '/portal/' + self.loginsubmitpath + '&' + self.query
        data={'user.username':self.usr, 'user.password':self.pw, 'Button':'Login', 'name':'portal'}
        headers=self.get_headers(self.base + '/' + self.loginpath)
        tos_site = requests.post(url, params=data, headers=headers, verify=self.CERT)

        all_ = tos_site.text
        if 'Accept' in all_[all_.find('<form',1): all_.find('</html>')]:
            logging.info('Sent Login, need to accept Policy...')
            self.tos_site = tos_site
        else:
            logging.info('Error after sending password')
            logging.debug(all_)
            self.tos_site = None


    def accept_tos(self):
        if self.tos_site is None:
            return

        searchstring = '<input type="hidden" name="token" value="'
        token = ''
        start = self.tos_site.text.find(searchstring)
        if start != -1:
            find_ = self.tos_site.text[start+len(searchstring):start+len(searchstring)+200]
            end = find_.find('"')
            token = find_[:end]
        else:
            logging.debug('Token not found')

        searchstring = '<form name="aupForm" action="'
        self.tossubmitpath = ''
        start = self.tos_site.text.find(searchstring)
        if start != -1:
            find_ = self.tos_site.text[start+len(searchstring):start+len(searchstring)+200]
            end = find_.find('"')
            self.tossubmitpath = find_[:end]
        else:
            self.tossubmitpath = 'AupSubmit.action?from=AUP'
            logging.debug('AupSubmit path not found')

        searchstring = "ise.portal.setPortalSessionId('"
        session_id = ''
        start = self.tos_site.text.find(searchstring)
        if start != -1:
            find_ = self.tos_site.text[start+len(searchstring):start+len(searchstring)+200]
            end = find_.find("'")
            session_id = find_[:end]
        else:
            logging.debug('session-id not found')


        data = {'aupAccepted':'true', 'token':token}
        url = self.base + '/portal/' + self.tossubmitpath
        headers = self.get_headers(self.base + '/' + self.loginsubmitpath)
        cookies = self.login_site.cookies
        cookies['portalSessionId'] = session_id #set by js, so needed here
        coa_site = requests.post(url, params=data, headers=headers, cookies=cookies, verify=self.CERT)
        if coa_site.status_code == 200:
            logging.info('Successfully accepted ToS')

            url = self.base + '/portal/DoCoA.action'
            data = {'delayToCoA':'0', 'coaType': 'REAUTH', 'waitForCoA': 'true', 'portalSessionId':session_id, 'token':token}
            headers = self.headers
            headers['Accept'] = '*/*'
            ret = requests.post(url, params=data, headers=headers, verify=self.CERT)
            if ret.status_code == 200:
                logging.info('Success!')
                self.success = True
            else:
                logging.info('Failed CoA')
                logging.debug(ret.text)

            return 

        logging.info('Failed to accept ToS')
        logging.debug(coa_site.text)

    def get_headers(self, referer):
        self.headers['Referer'] = referer
        return self.headers


if __name__ == '__main__':
    if len(argv) == 1:
        import getpass
        usr = raw_input('Tubit-Username: ')
        pw = getpass.getpass('Tubit-Pw:  ')
        logging.basicConfig(level=logging.DEBUG)
    else:
        with open(argv[1]) as f:
            usr, pw = f.read().split('\n')[:2]
        # yeah yeah, but project too small for argparse...
        if len(argv) > 2:
            if argv[2] == '-q':
                logging.basicConfig(level=logging.ERROR)
            elif argv[2] == '-v':
                logging.basicConfig(level=logging.DEBUG)
        else:
            logging.basicConfig(level=logging.INFO)


    login = TubitLogin(usr, pw)
    if not login.success:    
        login.work()
