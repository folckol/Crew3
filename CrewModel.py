import base64
import json
import pprint
import random
import re
import ssl
import string
import traceback

import requests
import cloudscraper

import capmonster_python
import time

import web3
from bs4 import BeautifulSoup
from web3.auto import w3
from eth_account.messages import encode_defunct
# from TwitterModel import Account
import os


class Discord:

    def __init__(self, token, proxy, cap_key):

        self.cap = capmonster_python.HCaptchaTask(cap_key)
        self.token = token
        self.proxy = proxy

        # print(token)
        # print(proxy)
        # print(cap_key)

        self.session = self._make_scraper()
        self.ua = random_user_agent()
        self.session.user_agent = self.ua
        self.super_properties = self.build_xsp(self.ua)
        self.session.proxies = self.proxy

        self.cfruid, self.dcfduid, self.sdcfduid = self.fetch_cookies(self.ua)
        self.fingerprint = self.get_fingerprint()


    def JoinServer(self, invite):

        rer = self.session.post("https://discord.com/api/v9/invites/" + invite, headers={"authorization": self.token})

        # print(rer.text, rer.status_code)
        # print(rer.text)
        # print(rer.status_code)

        if "200" not in str(rer):
            site = "a9b5fb07-92ff-493f-86fe-352a2803b3df"
            tt = self.cap.create_task("https://discord.com/api/v9/invites/" + invite, site)
            # print(f"Created Captcha Task {tt}")
            captcha = self.cap.join_task_result(tt)
            captcha = captcha["gRecaptchaResponse"]
            # print(f"[+] Solved Captcha ")
            # print(rer.text)

            self.session.headers = {'Host': 'discord.com', 'Connection': 'keep-alive',
                               'sec-ch-ua': '"Chromium";v="92", " Not A;Brand";v="99", "Google Chrome";v="92"',
                               'X-Super-Properties': self.super_properties,
                               'Accept-Language': 'en-US', 'sec-ch-ua-mobile': '?0',
                               "User-Agent": self.ua,
                               'Content-Type': 'application/json', 'Authorization': 'undefined', 'Accept': '*/*',
                               'Origin': 'https://discord.com', 'Sec-Fetch-Site': 'same-origin',
                               'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Dest': 'empty',
                               'Referer': 'https://discord.com/@me', 'X-Debug-Options': 'bugReporterEnabled',
                               'Accept-Encoding': 'gzip, deflate, br',
                               'x-fingerprint': self.fingerprint,
                               'Cookie': f'__dcfduid={self.dcfduid}; __sdcfduid={self.sdcfduid}; __cfruid={self.cfruid}; __cf_bm=DFyh.5fqTsl1JGyPo1ZFMdVTupwgqC18groNZfskp4Y-1672630835-0-Aci0Zz919JihARnJlA6o9q4m5rYoulDy/8BGsdwEUE843qD8gAm4OJsbBD5KKKLTRHhpV0QZybU0MrBBtEx369QIGGjwAEOHg0cLguk2EBkWM0YSTOqE63UXBiP0xqHGmRQ5uJ7hs8TO1Ylj2QlGscA='}
            rej = self.session.post("https://discord.com/api/v9/invites/" + invite, headers={"authorization": self.token}, json={
                "captcha_key": captcha,
                "captcha_rqtoken": str(rer.json()["captcha_rqtoken"])
            })
            # print(rej.text())
            # print(rej.status_code)
            if "200" in str(rej):
                return 'Successfully Join 0', self.super_properties
            if "200" not in str(rej):
                return 'Failed Join'

        else:
            with self.session.post("https://discord.com/api/v9/invites/" + invite, headers={"authorization": self.token}) as response:
                # print(response.text)
                pass
            return 'Successfully Join 1', self.super_properties


    def _make_scraper(self):
        ssl_context = ssl.create_default_context()
        ssl_context.set_ciphers(
            "ECDH-RSA-NULL-SHA:ECDH-RSA-RC4-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-AES256-SHA:"
            "ECDH-ECDSA-NULL-SHA:ECDH-ECDSA-RC4-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-ECDSA-AES128-SHA:"
            "ECDH-ECDSA-AES256-SHA:ECDHE-RSA-NULL-SHA:ECDHE-RSA-RC4-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-RSA-AES128-SHA:"
            "ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-NULL-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-DES-CBC3-SHA:"
            "ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:AECDH-NULL-SHA:AECDH-RC4-SHA:AECDH-DES-CBC3-SHA:"
            "AECDH-AES128-SHA:AECDH-AES256-SHA"
        )
        ssl_context.set_ecdh_curve("prime256v1")
        ssl_context.options |= (ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1_3 | ssl.OP_NO_TLSv1)
        ssl_context.check_hostname = False

        return cloudscraper.create_scraper(
            debug=False,
            ssl_context=ssl_context
        )

    def build_xsp(self, ua):
        # ua = get_useragent()
        _,fv = self.get_version(ua)
        data = json.dumps({
            "os": "Windows",
            "browser": "Chrome",
            "device": "",
            "system_locale": "en-US",
            "browser_user_agent": ua,
            "browser_version": fv,
            "os_version": "10",
            "referrer": "",
            "referring_domain": "",
            "referrer_current": "",
            "referring_domain_current": "",
            "release_channel": "stable",
            "client_build_number": self.get_buildnumber(),
            "client_event_source": None
        }, separators=(",",":"))
        return base64.b64encode(data.encode()).decode()

    def get_version(self, user_agent):  # Just splits user agent
        chrome_version = user_agent.split("/")[3].split(".")[0]
        full_chrome_version = user_agent.split("/")[3].split(" ")[0]
        return chrome_version, full_chrome_version

    def get_buildnumber(self):  # Todo: make it permanently work
        r = requests.get('https://discord.com/app', headers={'User-Agent': 'Mozilla/5.0'})
        asset = re.findall(r'([a-zA-z0-9]+)\.js', r.text)[-2]
        assetFileRequest = requests.get(f'https://discord.com/assets/{asset}.js',
                                        headers={'User-Agent': 'Mozilla/5.0'}).text
        try:
            build_info_regex = re.compile('buildNumber:"[0-9]+"')
            build_info_strings = build_info_regex.findall(assetFileRequest)[0].replace(' ', '').split(',')
        except:
            # print("[-]: Failed to get build number")
            pass
        dbm = build_info_strings[0].split(':')[-1]
        return int(dbm.replace('"', ""))

    def fetch_cookies(self, ua):
        try:
            url = 'https://discord.com/'
            headers = {'user-agent': ua}
            response = self.session.get(url, headers=headers, proxies=self.proxy)
            cookies = response.cookies.get_dict()
            cfruid = cookies.get("__cfruid")
            dcfduid = cookies.get("__dcfduid")
            sdcfduid = cookies.get("__sdcfduid")
            return cfruid, dcfduid, sdcfduid
        except:
            # print(response.text)
            return 1

    def get_fingerprint(self):
        try:
            fingerprint = self.session.get('https://discord.com/api/v9/experiments', proxies=self.proxy).json()['fingerprint']
            # print(f"[=]: Fetched Fingerprint ({fingerprint[:15]}...)")
            return fingerprint
        except Exception as err:
            # print(err)
            return 1





def random_user_agent():
    browser_list = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{0}.{1}.{2} Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_{2}_{3}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{1}.{2}) Gecko/20100101 Firefox/{1}.{2}',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{0}.{1}.{2} Edge/{3}.{4}.{5}'
    ]

    chrome_version = random.randint(70, 108)
    firefox_version = random.randint(70, 108)
    safari_version = random.randint(605, 610)
    edge_version = random.randint(15, 99)

    chrome_build = random.randint(1000, 9999)
    firefox_build = random.randint(1, 100)
    safari_build = random.randint(1, 50)
    edge_build = random.randint(1000, 9999)

    browser_choice = random.choice(browser_list)
    user_agent = browser_choice.format(chrome_version, firefox_version, safari_version, edge_version, chrome_build, firefox_build, safari_build, edge_build)

    return user_agent

def generate_random_string(length=16):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choices(characters, k=length))

class QuestAccount:

    def __init__(self, proxy, address, tw_auth_token, tw_csrf, private, dsToken):

        self.discord_token = dsToken

        self.defaultProxy = proxy
        proxy = proxy.split(':')
        proxy = f'http://{proxy[2]}:{proxy[3]}@{proxy[0]}:{proxy[1]}'

        self.proxy = {'http': proxy,
                           'https': proxy}
        print(self.proxy)

        self.private = private
        self.address = web3.Web3.to_checksum_address(address)

        self.auth_token = tw_auth_token
        self.csrf = tw_csrf

        self.session = self._make_scraper()
        self.session.proxies = self.proxy
        self.session.user_agent = random_user_agent()
        adapter = requests.adapters.HTTPAdapter(max_retries=5)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)




    def _make_scraper(self):
        ssl_context = ssl.create_default_context()
        ssl_context.set_ciphers(
            "ECDH-RSA-NULL-SHA:ECDH-RSA-RC4-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-AES256-SHA:"
            "ECDH-ECDSA-NULL-SHA:ECDH-ECDSA-RC4-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-ECDSA-AES128-SHA:"
            "ECDH-ECDSA-AES256-SHA:ECDHE-RSA-NULL-SHA:ECDHE-RSA-RC4-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-RSA-AES128-SHA:"
            "ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-NULL-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-DES-CBC3-SHA:"
            "ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:AECDH-NULL-SHA:AECDH-RC4-SHA:AECDH-DES-CBC3-SHA:"
            "AECDH-AES128-SHA:AECDH-AES256-SHA"
        )
        ssl_context.set_ecdh_curve("prime256v1")
        ssl_context.options |= (ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1_3 | ssl.OP_NO_TLSv1)
        ssl_context.check_hostname = False

        return cloudscraper.create_scraper(
            debug=False,
            ssl_context=ssl_context
        )

    def login(self):

        # with self.session.get('https://zealy.io/', timeout=10) as response:
        #     print(response.text)

        payload = {'address': self.address}
        self.session.headers.update({'content-type': 'application/json',
                                     'accept': 'application/json',
                                     'origin': 'https://zealy.io',
                                     'referer': 'https://zealy.io/'})

        with self.session.post('https://api.zealy.io/authentification/wallet/nonce', json=payload, timeout=10) as response:

            print(response.text)

            id_ = response.json()['id']
            nonce = response.json()['nonce']

            message = encode_defunct(text=nonce)
            signed_message = w3.eth.account.sign_message(message, private_key=self.private)
            signature = signed_message["signature"].hex()

            payload = {"sessionId":id_,
                       "signature":signature,
                       "network":1}
            print(payload)

            with self.session.post('https://api.zealy.io/authentification/wallet/verify-signature', json=payload, timeout=10) as response:


                print(response.text)

                with self.session.get('https://api.zealy.io/users/me', timeout=10) as response:
                    print(response.text)
                    self.myId = response.json()['id']
                    return response.json()

    def loginDiscordVersion(self):

        with self.session.get(
                f'https://api.zealy.io/authentification/oauth2/redirect?type=discord&subdomain=root&location=%2Flogin',
                timeout=10, allow_redirects=False) as response:
            # print(str(response.headers))
            # print(response.text)
            link = response.headers['Location']
            # input(link)

            redirect_uri = link.split('redirect_uri=')[-1].split('&')[0]
            client_id = link.split('client_id=')[-1].split('&')[0]
            state = link.split('state=')[-1]

            with self.session.get(link, timeout=10) as response:
                # print(response.text)
                # input()

                # url = response.json()['loginUrl']
                #
                # state = url.split('state=')[-1].split('&')[0]
                # client_id = url.split('client_id=')[-1].split('&')[0]

                discord_headers = {
                    'authority': 'discord.com',
                    'authorization': self.discord_token,
                    'content-type': 'application/json',
                    'referer': f'https://discord.com/oauth2/authorize?client_id={client_id}&redirect_uri=https%3A%2F%2Fzealy.io%2Fredirect%3Fauth_type%3Ddiscord&response_type=code&scope=email%20identify%20connections%20guilds%20guilds.members.read&state={state}',
                    'x-super-properties': 'eyJvcyI6Ik1hYyBPUyBYIiwiYnJvd3NlciI6IkNocm9tZSIsImRldmljZSI6IiIsInN5c3RlbV9sb2NhbGUiOiJydS1SVSIsImJyb3dzZXJfdXNlcl9hZ2VudCI6Ik1vemlsbGEvNS4wIChNYWNpbnRvc2g7IEludGVsIE1hYyBPUyBYIDEwXzE1XzcpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS8xMDkuMC4wLjAgU2FmYXJpLzUzNy4zNiIsImJyb3dzZXJfdmVyc2lvbiI6IjEwOS4wLjAuMCIsIm9zX3ZlcnNpb24iOiIxMC4xNS43IiwicmVmZXJyZXIiOiIiLCJyZWZlcnJpbmdfZG9tYWluIjoiIiwicmVmZXJyZXJfY3VycmVudCI6IiIsInJlZmVycmluZ19kb21haW5fY3VycmVudCI6IiIsInJlbGVhc2VfY2hhbm5lbCI6InN0YWJsZSIsImNsaWVudF9idWlsZF9udW1iZXIiOjE3NDA1MSwiY2xpZW50X2V2ZW50X3NvdXJjZSI6bnVsbCwiZGVzaWduX2lkIjowfQ==',
                }

                payload = {"permissions": "0", "authorize": True}

                with self.session.post(
                        f'https://discord.com/api/v9/oauth2/authorize?client_id={client_id}&response_type=code&redirect_uri=https%3A%2F%2Fzealy.io%2Fredirect%3Fauth_type%3Ddiscord&scope=email%20identify%20connections%20guilds%20guilds.members.read&state={state}',
                        json=payload, timeout=15, headers=discord_headers) as response:
                    url = response.json()['location']
                    # print(url)

                    code = url.split('code=')[-1].split('&')[0]
                    state = url.split('state=')[-1]
                    print(url)

                    with self.session.get(url, timeout=15) as response:
                        # print(f'{self.id} - Discord connected')
                        # print(response.text)
                        # input()

                        with self.session.get(
                                f'https://api.zealy.io/authentification/discord/callback?code={code}&subdomain=join&state={state}') as response:
                            with self.session.get('https://api.zealy.io/users/me', timeout=10) as response:
                                print(response.text)
                                self.myId = response.json()['id']
                                return response.json()



    def TwitterConnect(self):


        with self.session.get(f'https://api.zealy.io/authentification/oauth2/redirect?location=%2Fc%2Fjoin%2Fusers%2F{self.myId}&type=twitter&subdomain=join', timeout=10) as response:
            # print(response.text)

            soup = BeautifulSoup(response.text, 'html.parser')
            oauth_token = soup.find('input', attrs={'name': 'redirect_after_login'}).get('value')
            oauth_token = oauth_token.split('oauth_token=')[-1]

            self.session.cookies.update({'auth_token': self.auth_token, 'ct0': self.csrf})
            with self.session.get(
                    f'https://api.twitter.com/oauth/authenticate?oauth_token={oauth_token}',
                    timeout=15) as response:
                soup = BeautifulSoup(response.text, 'html.parser')
                authenticity_token = soup.find('input', attrs={'name': 'authenticity_token'}).get('value')

                payload = {'authenticity_token': authenticity_token,
                           'redirect_after_login': f'https://api.twitter.com/oauth/authorize?oauth_token={oauth_token}',
                           'oauth_token': oauth_token}

                self.session.headers.update({'content-type': 'application/x-www-form-urlencoded'})
                # self.session.cookies.update({'auth_token': self.auth_token, 'ct0': self.csrf})

                with self.session.post(f'https://api.twitter.com/oauth/authorize', data=payload, timeout=15,
                                       allow_redirects=False) as response:


                    # self.session.cookies.update({'auth_token': self.auth_token, 'ct0': self.csrf})
                    # print(response.text)
                    soup = BeautifulSoup(response.text, 'html.parser')
                    link = soup.find('a', class_='maintain-context').get('href')

                    with self.session.get(link, timeout=15) as response:
                        if response.ok:
                            print('Twitter connected successfully')
                            return True
                        else:
                            print('Twitter connected error')
                            return False

    def DiscordConnect(self):

        with self.session.get(f'https://api.zealy.io/authentification/oauth2/redirect?location=%2Fc%2Fjoin%2Fusers%2F{self.myId}&type=discord&subdomain=join', timeout=10, allow_redirects=False) as response:
            # print(str(response.headers))
            # print(response.text)
            link = response.headers['Location']
            # input(link)

            redirect_uri = link.split('redirect_uri=')[-1].split('&')[0]
            client_id = link.split('client_id=')[-1].split('&')[0]
            state = link.split('state=')[-1]

            with self.session.get(link, timeout=10) as response:


                # print(response.text)
                # input()

                # url = response.json()['loginUrl']
                #
                # state = url.split('state=')[-1].split('&')[0]
                # client_id = url.split('client_id=')[-1].split('&')[0]

                discord_headers = {
                    'authority': 'discord.com',
                    'authorization': self.discord_token,
                    'content-type': 'application/json',
                    'referer': f'https://discord.com/oauth2/authorize?client_id={client_id}&redirect_uri=https%3A%2F%2Fzealy.io%2Fredirect%3Fauth_type%3Ddiscord&response_type=code&scope=email%20identify%20connections%20guilds%20guilds.members.read&state={state}',
                    'x-super-properties': 'eyJvcyI6Ik1hYyBPUyBYIiwiYnJvd3NlciI6IkNocm9tZSIsImRldmljZSI6IiIsInN5c3RlbV9sb2NhbGUiOiJydS1SVSIsImJyb3dzZXJfdXNlcl9hZ2VudCI6Ik1vemlsbGEvNS4wIChNYWNpbnRvc2g7IEludGVsIE1hYyBPUyBYIDEwXzE1XzcpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS8xMDkuMC4wLjAgU2FmYXJpLzUzNy4zNiIsImJyb3dzZXJfdmVyc2lvbiI6IjEwOS4wLjAuMCIsIm9zX3ZlcnNpb24iOiIxMC4xNS43IiwicmVmZXJyZXIiOiIiLCJyZWZlcnJpbmdfZG9tYWluIjoiIiwicmVmZXJyZXJfY3VycmVudCI6IiIsInJlZmVycmluZ19kb21haW5fY3VycmVudCI6IiIsInJlbGVhc2VfY2hhbm5lbCI6InN0YWJsZSIsImNsaWVudF9idWlsZF9udW1iZXIiOjE3NDA1MSwiY2xpZW50X2V2ZW50X3NvdXJjZSI6bnVsbCwiZGVzaWduX2lkIjowfQ==',
                }

                payload = {"permissions": "0", "authorize": True}

                with self.session.post(
                        f'https://discord.com/api/v9/oauth2/authorize?client_id={client_id}&response_type=code&redirect_uri=https%3A%2F%2Fzealy.io%2Fredirect%3Fauth_type%3Ddiscord&scope=identify%20guilds%20guilds.members.read&state={state}',
                        json=payload, timeout=15, headers=discord_headers) as response:
                    url = response.json()['location']
                    # print(url)

                    code = url.split('code=')[-1].split('&')[0]
                    state = url.split('state=')[-1]

                    with self.session.get(url, timeout=15) as response:
                        # print(f'{self.id} - Discord connected')
                        # print(response.text)

                        with self.session.get(f'https://api.zealy.io/authentification/discord/callback?code={code}&subdomain=join&state={state}') as response:
                            print('Discord connected successfully')
                            pass

    def GetRaffleData(self, id):

        with self.session.get(f'https://api.zealy.io/communities/{id}/questboard', timeout=15) as response:
            print(response.text)
            return response.json()

    def GetAllRaffles(self):

        with self.session.get('https://zealy.io/_next/data/JW9ZdQTySJGQo5p1mSNEG/en.json', timeout=15) as response:
            print(response.text)

    def AcceptInvite(self, inviteCode):

        payload = {"invitationId":inviteCode}

        with self.session.post('https://api.zealy.io/users/me/accept-invitation', json=payload, timeout=10) as response:
            print(response.text, 'Invite successfully')

    def ClaimReward(self, community, questCode, format, value=None):

        oo = generate_random_string()

        self.session.headers.update({f'content-type': f'multipart/form-data; boundary=----WebKitFormBoundary{oo}'})

        with open('file.txt', 'w') as file:
            if value != None:
                file.write(f'------WebKitFormBoundary{oo}\n'
                           'Content-Disposition: form-data; name="value"\n\n'
    
                           f'{value}\n'
                           f'------WebKitFormBoundary{oo}\n'
                           'Content-Disposition: form-data; name="questId"\n\n'
    
                           f'{questCode}\n'
                           f'------WebKitFormBoundary{oo}\n'
                           'Content-Disposition: form-data; name="type"\n\n'
    
                           f'{format}\n'
                           f'------WebKitFormBoundary{oo}--')
            else:
                file.write(f'------WebKitFormBoundary{oo}\n'
                           'Content-Disposition: form-data; name="questId"\n\n'

                           f'{questCode}\n'
                           f'------WebKitFormBoundary{oo}\n'
                           'Content-Disposition: form-data; name="type"\n\n'

                           f'{format}\n'
                           f'------WebKitFormBoundary{oo}--')

        r = ''
        with open('file.txt', 'rb') as f:
            r = f

            with self.session.post(f'https://api.zealy.io/communities/{community}/quests/{questCode}/claim', files={'file.txt': r}, timeout=10) as response:
                print(response.text)
                pass

        os.remove(f'{os.getcwd()}/file.txt')




if __name__ == '__main__':

    # print('asdawdawd')
    authTokens = []
    csrfs = []
    discordTokens = []
    proxys = []
    adresses = []
    privates = []

    with open('Files/Address.txt', 'r') as file:
        for i in file:
            adresses.append(i.rstrip())

    with open('Files/Discords.txt', 'r') as file:
        for i in file:
            discordTokens.append(i.rstrip())

    with open('Files/Privates.txt', 'r') as file:
        for i in file:
            privates.append(i.rstrip())

    with open('Files/Proxy.txt', 'r') as file:
        for i in file:
            proxys.append(i.rstrip())

    with open('Files/Twitters.txt', 'r') as file:
        for i in file:
            authTokens.append(i.rstrip().split('auth_token=')[-1].split(';')[0])
            csrfs.append(i.rstrip().split('ct0=')[-1].split(';')[0])

    def function(tw_auth_token, tw_csrf, proxy, address, private, dsToken):

        # tw_auth_token = 'fe005cccd263333127caa1b76fe6b44741b28afb'
        # tw_csrf = '0f59b7bd5f49ab13e4b7df02454346c05b569a6c77fcc086f96d8304ad1c85cab76a124228f426f7159fc50e9c32fe931735689cb3d2c8aa996c96067111869ff1ee44c809866f337f171cd3dfa1462b'
        # proxy = '45.137.195.50:6065:eygblzhp:8dkvatehardh'

        Acc = QuestAccount(proxy=proxy,
                           tw_csrf=tw_csrf,
                           tw_auth_token=tw_auth_token,
                           address=address,
                           private=private,
                           dsToken=dsToken
                           )

        try:
            data = Acc.login()
        except:
            data = Acc.loginDiscordVersion()
            # input()

        print(data)

        # if data['twitterUsername'] == None:
        #     Acc.TwitterConnect()
        #     Acc.session.headers.clear()
        #     Acc.session.headers.update({'content-type': 'application/json',
        #                                 'accept': 'application/json',
        #                                 'origin': 'https://zealy.io',
        #                                 'referer': 'https://zealy.io/'})
        #
        # if data['discordHandle'] == None:
        #     Acc.DiscordConnect()
        #     Acc.session.headers.clear()
        #     Acc.session.headers.update({'content-type': 'application/json',
        #                                 'accept': 'application/json',
        #                                 'origin': 'https://zealy.io',
        #                                 'referer': 'https://zealy.io/'})

        # Acc.GetAllRaffles()
        # Acc.GetRaffleData('OEBLOCK'.lower())
        Acc.AcceptInvite('e6z6Hl-4fnoWlrYSbsblD')
        # Account(auth_token=tw_auth_token,
        #         csrf=tw_csrf,
        #         proxy=proxy,
        #         name='1').Follow(1596825240235032576)
        time.sleep(2)
        Acc.ClaimReward('routerprotocol-3510', '8a058406-3abb-4db2-a119-7a3dfa2742fb', 'link', 'clicked')

        time.sleep(2)
        Acc.ClaimReward('routerprotocol-3510', 'e642b53d-9d7d-4fe6-9eb3-772f42065294', 'link', 'clicked')

        time.sleep(2)
        Acc.ClaimReward('routerprotocol-3510', 'd264d2fa-9bf7-4342-aa41-882a563d091a', 'twitter')

        time.sleep(2)
        Acc.ClaimReward('routerprotocol-3510', 'd3ea54f6-e1d3-4e77-a9c5-9cb4a448de53', 'telegram', 'joined')

        time.sleep(2)
        Acc.ClaimReward('routerprotocol-3510', '1b95b01a-4d51-4357-8a38-6a952fecff3b', 'telegram', 'joined')

        time.sleep(2)
        Acc.ClaimReward('routerprotocol-3510', 'e4039b01-6c77-4139-9d57-bd8a24d70e8d', 'link', 'clicked')

        time.sleep(2)
        Acc.ClaimReward('routerprotocol-3510', '6709114e-dcd8-46fd-a8f5-c3dee1f86eb8', 'link', 'clicked')

        time.sleep(2)
        Acc.ClaimReward('routerprotocol-3510', 'c2bec401-cf8d-45ae-a240-92030b4be399', 'twitter')

        time.sleep(2)
        Acc.ClaimReward('routerprotocol-3510', '1db467a2-ef12-4ae1-8195-1bff435b6b99', 'link', 'clicked')


    # print('asdawdawd')

    for i in range(16, len(authTokens)):
        try:
            print(f'{i} - Старт')
            function(tw_auth_token=authTokens[i],
                     tw_csrf=csrfs[i],
                     proxy=proxys[i],
                     address=adresses[i],
                     private=privates[i],
                     dsToken=discordTokens[i])
            print('-----------------------------------------------------')
            time.sleep(random.randint(30, 60))
        except:
            traceback.print_exc()












