# -*- coding: utf-8 -*-
import getpass
import os
import argparse
from bs4 import BeautifulSoup
import requests
import json
import re


class SlackSession:
    def __init__(self, domain):
        print "[+] Creating session"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0'
        })
        self.domain = "https://" + domain + ".slack.com/"
        self.dir = domain + ".slack.com"
        if not os.path.exists(self.dir):
            os.makedirs(self.dir)
        self.is_authed = False

    def auth(self, email, password):
        print "[+] Authenticating ..."
        login_soup = BeautifulSoup(self.session.get(self.domain).content)
        login_data = {}
        for form_input in login_soup.find("form", {"id": "signin_form"}).find_all("input"):
            login_data[form_input.get('name')] = form_input.get('value')
        login_data['email'] = email
        login_data['password'] = password
        if "You need to sign in to see this page" in self.session.post(self.domain, login_data).content:
            self.is_authed = False
        else:
            self.is_authed = True
        print "    ->" + ("authed" if self.is_authed else "error authenticating ...")
        return self.is_authed


class SlackFilesCrawler:
    def __init__(self, slack_session):
        self.slack_session = slack_session
        self.paginated = False
        self.page_count = -1

    def get_file_page(self, page=1):
        page_html = self.slack_session.session.get(self.slack_session.domain+"files?page=" + str(page)).content
        if not self.paginated:
            print "[+] Files pagination not performed yet ..." + str(page)
            page_soup = BeautifulSoup(page_html)
            for a in page_soup.find("div", {"class": "pagination"}).find_all('a'):
                if a.get_text() is not None and a.get_text().isdigit() and int(a.get_text()) > self.page_count:
                    self.page_count = int(a.get_text())
            print "   -> got " + str(self.page_count) + " pages"
        print "[+] Retrieving files on page #" + str(page)
        json_line = ""
        for line in page_html.split("\n"):
            if "boot_data.files" in line:
                json_line = line
        json_line = json_line.split("JSON.parse('")[1]
        json_line = json_line.replace("');", "")
        json_line = re.sub(r'\\([^\\])', r'\1', json_line)
        json_line = json_line.replace("\\\\", "\\")
        page_data = json.loads(json_line)
        return page_data

    def get_all_files(self):
        print "[+] Retrieving all files"
        files = self.get_file_page(1)
        for i in range(2, self.page_count+1):
            files += self.get_file_page(i)
        return files


class SlackFileUtil:
    def __init__(self, slack_session):
        self.slack_session = slack_session

    def download(self, slack_file):
        print "[+] Downloading " + (slack_file['name'] if 'name' in slack_file else "unnamed file")
        if not os.path.exists(self.slack_session.dir + "/files"):
            os.makedirs(self.slack_session.dir + "/files")
        try:
            local_filename = self.slack_session.dir + "/files/" + str(slack_file['created']) + "_" + slack_file['name']
            r = self.slack_session.session.get(slack_file['url_private_download'], stream=True)
            with open(local_filename, 'wb') as f:
                for chunk in r.iter_content(chunk_size=1024):
                    if chunk:
                        f.write(chunk)
                        f.flush()
            print "   -> Done ... (" + local_filename + ")"
        except KeyError:
            print "   -> Error with " + slack_file['name'] + ": not hosted in slack"
        except:
            print "   -> Error... File info :"
            print slack_file
            print "   -> Stacktrace"
            import traceback
            print(traceback.format_exc())
            local_filename = ""
        return local_filename


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", help="Your slack subdomain, http://[MY_DOMAIN].slack.com/")
    parser.add_argument("-e", "--email", help="Your slack email")
    parser.add_argument("-p", "--password", help="Your slack password")
    args = parser.parse_args()
    domain = args.domain
    email = args.email
    password = args.password
    if password is None:
        password = getpass.getpass("Password :")

    slack_session = SlackSession(domain)
    if not slack_session.auth(email, password):
        print "[+] Error, bad authentication"
        return

    slack_files_crawler = SlackFilesCrawler(slack_session)
    slack_files = slack_files_crawler.get_all_files()

    file_util = SlackFileUtil(slack_session)
    for slack_file in slack_files:
        file_util.download(slack_file)

if __name__ == '__main__':
    main()
