try:
    import requests
except:
    print('[-] pip install requests')
    exit(0)
try:
    import colorama
    from colorama import Fore
    colorama.init(autoreset=True)
except:
    print('[-] pip install colorama')
    exit(0)
import time
r = requests.session()
Bb = Fore.LIGHTYELLOW_EX
print(Bb + """
           __  __ ____   _____  ____  _   _ 
          |  \/  |___ \ / ____|/ __ \| \ | |
          | \  / | __) | |  __| |  | |  \| |
          | |\/| ||__ <| | |_ | |  | | . ` |
          | |  | |___) | |__| | |__| | |\  |
          |_|  |_|____/ \_____|\____/|_| \_|

""", Fore.LIGHTGREEN_EX + "\n                  ( @_m3gon )", Fore.LIGHTBLUE_EX + "\n   (This tool is programmed by the programmer : @_m3gon)              \n",
      Fore.LIGHTYELLOW_EX + "             ( Report Instagram )\n\n"+Fore.RESET)
print(f'[{Fore.LIGHTBLUE_EX}#{Fore.RESET}] 1 - Spam')
print(f'[{Fore.LIGHTBLUE_EX}#{Fore.RESET}] 2 - Heat')
print(f'[{Fore.LIGHTBLUE_EX}#{Fore.RESET}] 3 - Self')
number = input('[?] Enter Number : ')
if number == '3':
    namefile = input('[?] Enter Name File In Account : ')
    target = input('[?] Enter Username Target : ')
    while True:
        def login():
            accountreport = []
            try:
                openfile = open(namefile, "r").read().splitlines()
                for account in openfile:
                    accountreport.append(account)
                    try:
                        username = account.split(':')[0]
                        password = account.split(':')[1]
                        url_login = 'https://www.instagram.com/accounts/login/ajax/'
                        headers_login = {
                            'Accept': '*/*',
                            'Accept-Encoding': 'gzip, deflate, br',
                            'Accept-Language': 'en-US,en;q=0.9',
                            'Cache-Control': 'no-cache',
                            'Connection': 'keep-alive',
                            'Content-Length': '286',
                            'Content-Type': 'application/x-www-form-urlencoded',
                            'Cookie': 'ig_did=E1069C00-B44A-4C3C-AEC6-2EDFF828476E; mid=YFNJ-gALAAFOnl3VaylOWdyOj2VX; ig_nrcb=1; shbid=13522; shbts=1617355655.3348231; csrftoken=HjBaZQxTmotNmTl14ghRoUTQEpN5PP0g',
                            'Host': 'www.instagram.com',
                            'Origin': 'https://www.instagram.com',
                            'Pragma': 'no-cache',
                            'Referer': 'https://www.instagram.com/',
                            'sec-ch-ua': '"Google Chrome";v="89", "Chromium";v="89", ";Not A Brand";v="99"',
                            'sec-ch-ua-mobile': '?0',
                            'Sec-Fetch-Dest': 'empty',
                            'Sec-Fetch-Mode': 'cors',
                            'Sec-Fetch-Site': 'same-origin',
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36',
                            'X-CSRFToken': 'HjBaZQxTmotNmTl14ghRoUTQEpN5PP0g',
                            'X-IG-App-ID': '936619743392459',
                            'X-IG-WWW-Claim': '0',
                            'X-Instagram-AJAX': '3de2d7ec996d',
                            'X-Requested-With': 'XMLHttpRequest'
                        }
                        data_login = {
                            'username': username,
                            'enc_password': f'#PWD_INSTAGRAM_BROWSER:0:1617894115:{password}',
                            'queryParams': '{}',
                            'optIntoOneTap': 'false'
                        }
                        # Send Request Login
                        req_login = requests.post(url_login, data=data_login, headers=headers_login)
                        # Logim Error
                        if ('"authenticated":false') in req_login.text:
                            print(f'[+] {Fore.LIGHTRED_EX}Login Error : {username} | {password}' + Fore.RESET)
                        # Login True
                        elif ('"authenticated":true') in req_login.text:
                            r.headers.update({'X-CSRFToken': req_login.cookies['csrftoken']})
                            print(f'\r[+] {Fore.LIGHTGREEN_EX}Login True : {username} | {password}' + Fore.RESET,
                                  end='')
                            # get sessionid
                            sessionid = str(req_login.cookies['sessionid'])
                            cookies = {'sessionid': sessionid}

                            def get_id_username():
                                url_id = f'https://www.instagram.com/{target}/?__a=1'
                                headers_id = {
                                    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                                    'accept-encoding': 'gzip, deflate, br',
                                    'accept-language': 'en-US,en;q=0.9',
                                    'cache-control': 'no-cache',
                                    'pragma': 'no-cache',
                                    'sec-ch-ua': '"Google Chrome";v="89", "Chromium";v="89", ";Not A Brand";v="99"',
                                    'sec-ch-ua-mobile': '?0',
                                    'sec-fetch-dest': 'document',
                                    'sec-fetch-mode': 'navigate',
                                    'sec-fetch-site': 'none',
                                    'sec-fetch-user': '?1',
                                    'upgrade-insecure-requests': '1',
                                    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36'
                                }
                                cookies = {'sessionid': sessionid}
                                try:
                                    req_id = requests.get(url_id, headers=headers_id, cookies=cookies).json()
                                    id_target = str(req_id['graphql']['user']['id'])
                                except Exception as x:
                                    print(x)
                                    exit(0)

                                def report_self():
                                    done = 0
                                    error = 0
                                    url_self = f'https://www.instagram.com/users/{id_target}/report/'
                                    headers_self = {
                                        'accept': '*/*',
                                        'accept-encoding': 'gzip, deflate, br',
                                        'accept-language': 'en-US,en;q=0.9',
                                        'cache-control': 'no-cache',
                                        'content-length': '37',
                                        'content-type': 'application/x-www-form-urlencoded',
                                        'origin': 'https://www.instagram.com',
                                        'pragma': 'no-cache',
                                        'referer': f'https://www.instagram.com/users/{id_target}/report/inappropriate',
                                        'sec-ch-ua': '"Google Chrome";v="89", "Chromium";v="89", ";Not A Brand";v="99"',
                                        'sec-ch-ua-mobile': '?0',
                                        'sec-fetch-dest': 'empty',
                                        'sec-fetch-mode': 'cors',
                                        'sec-fetch-site': 'same-origin',
                                        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36',
                                        'x-csrftoken': 'clEPPJAaS2ZiAhKXtiwMF8w2z9KQ2kBz',
                                        'x-ig-app-id': '936619743392459',
                                        'x-ig-www-claim': 'hmac.AR1YTbiNiOj-oFmz6or5-aLaGeSG8E7Lsos9CcSReFXVmuPW',
                                        'x-instagram-ajax': '3c8826838272',
                                        'x-requested-with': 'XMLHttpRequest'
                                    }
                                    data_self = {
                                        'source_name': '',
                                        'reason_id': '2',
                                        'frx_context': ''
                                    }
                                    req_self = requests.post(url_self, data=data_self, headers=headers_self,
                                                             cookies=cookies).text
                                    if (
                                            '"description":"We take your reports seriously. We look into every issue, and take action when people violate our Community Guidelines"') in req_self:
                                        done += 1
                                        print(f'\r[+] Done Self With Account {username}', end='')
                                        time.sleep(3)
                                    else:
                                        error += 1
                                        print(f'\r[-] Error Self With Account {username}', end='')
                                        time.sleep(3)
                                report_self()
                            get_id_username()
                        else:
                            print(f'\r[-] {Fore.LIGHTRED_EX}Please wait a few minutes before you try again', Fore.RESET,
                                  end='')
                    except:
                        print(
                            f'[-] {Fore.LIGHTRED_EX}Please tick after each username : include the password for the username',
                            Fore.RESET)
                        exit(0)
            except:
                print(f'[-] {Fore.LIGHTRED_EX} Not Found File To Name : {namefile}')
                exit(0)
        login()
if number == '1':
    namefile = input('[?] Enter Name File In Account : ')
    target = input('[?] Enter Username Target : ')
    while True:
        def login():
            accountreport = []
            try:
                openfile = open(namefile, "r").read().splitlines()
                for account in openfile:
                    accountreport.append(account)
                    try:
                        username = account.split(':')[0]
                        password = account.split(':')[1]
                        url_login = 'https://www.instagram.com/accounts/login/ajax/'
                        headers_login = {
                            'Accept': '*/*',
                            'Accept-Encoding': 'gzip, deflate, br',
                            'Accept-Language': 'en-US,en;q=0.9',
                            'Cache-Control': 'no-cache',
                            'Connection': 'keep-alive',
                            'Content-Length': '286',
                            'Content-Type': 'application/x-www-form-urlencoded',
                            'Cookie': 'ig_did=E1069C00-B44A-4C3C-AEC6-2EDFF828476E; mid=YFNJ-gALAAFOnl3VaylOWdyOj2VX; ig_nrcb=1; shbid=13522; shbts=1617355655.3348231; csrftoken=HjBaZQxTmotNmTl14ghRoUTQEpN5PP0g',
                            'Host': 'www.instagram.com',
                            'Origin': 'https://www.instagram.com',
                            'Pragma': 'no-cache',
                            'Referer': 'https://www.instagram.com/',
                            'sec-ch-ua': '"Google Chrome";v="89", "Chromium";v="89", ";Not A Brand";v="99"',
                            'sec-ch-ua-mobile': '?0',
                            'Sec-Fetch-Dest': 'empty',
                            'Sec-Fetch-Mode': 'cors',
                            'Sec-Fetch-Site': 'same-origin',
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36',
                            'X-CSRFToken': 'HjBaZQxTmotNmTl14ghRoUTQEpN5PP0g',
                            'X-IG-App-ID': '936619743392459',
                            'X-IG-WWW-Claim': '0',
                            'X-Instagram-AJAX': '3de2d7ec996d',
                            'X-Requested-With': 'XMLHttpRequest'
                        }
                        data_login = {
                            'username': username,
                            'enc_password': f'#PWD_INSTAGRAM_BROWSER:0:1617894115:{password}',
                            'queryParams': '{}',
                            'optIntoOneTap': 'false'
                        }
                        # Send Request Login
                        req_login = requests.post(url_login, data=data_login, headers=headers_login)
                        # Logim Error
                        if ('"authenticated":false') in req_login.text:
                            print(f'[+] {Fore.LIGHTRED_EX}Login Error : {username} | {password}' + Fore.RESET)
                        # Login True
                        elif ('"authenticated":true') in req_login.text:
                            r.headers.update({'X-CSRFToken': req_login.cookies['csrftoken']})
                            print(f'\r[+] {Fore.LIGHTGREEN_EX}Login True : {username} | {password}' + Fore.RESET,
                                  end='')
                            # get sessionid
                            sessionid = str(req_login.cookies['sessionid'])
                            cookies = {'sessionid': sessionid}

                            def get_id_username():
                                url_id = f'https://www.instagram.com/{target}/?__a=1'
                                headers_id = {
                                    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                                    'accept-encoding': 'gzip, deflate, br',
                                    'accept-language': 'en-US,en;q=0.9',
                                    'cache-control': 'no-cache',
                                    'pragma': 'no-cache',
                                    'sec-ch-ua': '"Google Chrome";v="89", "Chromium";v="89", ";Not A Brand";v="99"',
                                    'sec-ch-ua-mobile': '?0',
                                    'sec-fetch-dest': 'document',
                                    'sec-fetch-mode': 'navigate',
                                    'sec-fetch-site': 'none',
                                    'sec-fetch-user': '?1',
                                    'upgrade-insecure-requests': '1',
                                    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36'
                                }
                                cookies = {'sessionid': sessionid}
                                try:
                                    req_id = requests.get(url_id, headers=headers_id, cookies=cookies).json()
                                    id_target = str(req_id['graphql']['user']['id'])
                                except:
                                    print(f'[-] {Fore.LIGHTRED_EX} Not Found Id Username', Fore.RESET)
                                def report_spam():
                                    done = 0
                                    error = 0
                                    url_spam = f'https://www.instagram.com/users/{id_target}/report/'
                                    headers_spam = {
                                        'accept': '*/*',
                                        'accept-encoding': 'gzip, deflate, br',
                                        'accept-language': 'en-US,en;q=0.9',
                                        'cache-control': 'no-cache',
                                        'content-length': '37',
                                        'content-type': 'application/x-www-form-urlencoded',
                                        'origin': 'https://www.instagram.com',
                                        'pragma': 'no-cache',
                                        'referer': f'https://www.instagram.com/users/{id_target}/report/inappropriate',
                                        'sec-ch-ua': '"Google Chrome";v="89", "Chromium";v="89", ";Not A Brand";v="99"',
                                        'sec-ch-ua-mobile': '?0',
                                        'sec-fetch-dest': 'empty',
                                        'sec-fetch-mode': 'cors',
                                        'sec-fetch-site': 'same-origin',
                                        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36',
                                        'x-csrftoken': 'clEPPJAaS2ZiAhKXtiwMF8w2z9KQ2kBz',
                                        'x-ig-app-id': '936619743392459',
                                        'x-ig-www-claim': 'hmac.AR1YTbiNiOj-oFmz6or5-aLaGeSG8E7Lsos9CcSReFXVmuPW',
                                        'x-instagram-ajax': '3c8826838272',
                                        'x-requested-with': 'XMLHttpRequest'
                                    }
                                    data_spam = {
                                        'source_name': '',
                                        'reason_id': '1',
                                        'frx_context': ''
                                    }
                                    req_self = requests.post(url_spam, data=data_spam, headers=headers_spam, cookies=cookies).text
                                    if ('"description":"Your reports help keep our community free of spam."') in req_self:
                                        done += 1
                                        print(f'\r[+] Done Spam With Account @{username}', end='')
                                        time.sleep(3)
                                    else:
                                        error += 1
                                        print(f'\r[-] Error Spam With Account @{username}', end='')
                                        time.sleep(3)
                                report_spam()
                            get_id_username()
                        else:
                            print(f'\r[-] {Fore.LIGHTRED_EX}Please wait a few minutes before you try again', Fore.RESET,
                                  end='')
                    except:
                        print(
                            f'[-] {Fore.LIGHTRED_EX}Please tick after each username : include the password for the username',
                            Fore.RESET)
                        exit(0)
            except:
                print(f'[-] {Fore.LIGHTRED_EX} Not Found File To Name : {namefile}')
                exit(0)
        login()
if number == '2':
    namefile = input('[?] Enter Name File In Account : ')
    target = input('[?] Enter Username Target : ')
    while True:
        def login():
            accountreport = []
            try:
                openfile = open(namefile, "r").read().splitlines()
                for account in openfile:
                    accountreport.append(account)
                    try:
                        username = account.split(':')[0]
                        password = account.split(':')[1]
                        url_login = 'https://www.instagram.com/accounts/login/ajax/'
                        headers_login = {
                            'Accept': '*/*',
                            'Accept-Encoding': 'gzip, deflate, br',
                            'Accept-Language': 'en-US,en;q=0.9',
                            'Cache-Control': 'no-cache',
                            'Connection': 'keep-alive',
                            'Content-Length': '286',
                            'Content-Type': 'application/x-www-form-urlencoded',
                            'Cookie': 'ig_did=E1069C00-B44A-4C3C-AEC6-2EDFF828476E; mid=YFNJ-gALAAFOnl3VaylOWdyOj2VX; ig_nrcb=1; shbid=13522; shbts=1617355655.3348231; csrftoken=HjBaZQxTmotNmTl14ghRoUTQEpN5PP0g',
                            'Host': 'www.instagram.com',
                            'Origin': 'https://www.instagram.com',
                            'Pragma': 'no-cache',
                            'Referer': 'https://www.instagram.com/',
                            'sec-ch-ua': '"Google Chrome";v="89", "Chromium";v="89", ";Not A Brand";v="99"',
                            'sec-ch-ua-mobile': '?0',
                            'Sec-Fetch-Dest': 'empty',
                            'Sec-Fetch-Mode': 'cors',
                            'Sec-Fetch-Site': 'same-origin',
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36',
                            'X-CSRFToken': 'HjBaZQxTmotNmTl14ghRoUTQEpN5PP0g',
                            'X-IG-App-ID': '936619743392459',
                            'X-IG-WWW-Claim': '0',
                            'X-Instagram-AJAX': '3de2d7ec996d',
                            'X-Requested-With': 'XMLHttpRequest'
                        }
                        data_login = {
                            'username': username,
                            'enc_password': f'#PWD_INSTAGRAM_BROWSER:0:1617894115:{password}',
                            'queryParams': '{}',
                            'optIntoOneTap': 'false'
                        }
                        # Send Request Login
                        req_login = requests.post(url_login, data=data_login, headers=headers_login)
                        # Logim Error
                        if ('"authenticated":false') in req_login.text:
                            print(f'[+] {Fore.LIGHTRED_EX}Login Error : {username} | {password}' + Fore.RESET)
                        # Login True
                        elif ('"authenticated":true') in req_login.text:
                            r.headers.update({'X-CSRFToken': req_login.cookies['csrftoken']})
                            print(f'\r[+] {Fore.LIGHTGREEN_EX}Login True : {username} | {password}' + Fore.RESET,
                                  end='')
                            # get sessionid
                            sessionid = str(req_login.cookies['sessionid'])
                            cookies = {'sessionid': sessionid}

                            def get_id_username():
                                url_id = f'https://www.instagram.com/{target}/?__a=1'
                                headers_id = {
                                    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                                    'accept-encoding': 'gzip, deflate, br',
                                    'accept-language': 'en-US,en;q=0.9',
                                    'cache-control': 'no-cache',
                                    'pragma': 'no-cache',
                                    'sec-ch-ua': '"Google Chrome";v="89", "Chromium";v="89", ";Not A Brand";v="99"',
                                    'sec-ch-ua-mobile': '?0',
                                    'sec-fetch-dest': 'document',
                                    'sec-fetch-mode': 'navigate',
                                    'sec-fetch-site': 'none',
                                    'sec-fetch-user': '?1',
                                    'upgrade-insecure-requests': '1',
                                    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36'
                                }
                                cookies = {'sessionid': sessionid}
                                try:
                                    req_id = requests.get(url_id, headers=headers_id, cookies=cookies).json()
                                    id_target = str(req_id['graphql']['user']['id'])
                                except Exception as x:
                                    print(x)
                                    exit(0)

                                def report_heat():
                                    done = 0
                                    error = 0
                                    url_heat = f'https://www.instagram.com/users/{id_target}/report/'
                                    headers_heat = {
                                        'accept': '*/*',
                                        'accept-encoding': 'gzip, deflate, br',
                                        'accept-language': 'en-US,en;q=0.9',
                                        'cache-control': 'no-cache',
                                        'content-length': '37',
                                        'content-type': 'application/x-www-form-urlencoded',
                                        'origin': 'https://www.instagram.com',
                                        'pragma': 'no-cache',
                                        'referer': f'https://www.instagram.com/users/{id_target}/report/inappropriate',
                                        'sec-ch-ua': '"Google Chrome";v="89", "Chromium";v="89", ";Not A Brand";v="99"',
                                        'sec-ch-ua-mobile': '?0',
                                        'sec-fetch-dest': 'empty',
                                        'sec-fetch-mode': 'cors',
                                        'sec-fetch-site': 'same-origin',
                                        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36',
                                        'x-csrftoken': 'clEPPJAaS2ZiAhKXtiwMF8w2z9KQ2kBz',
                                        'x-ig-app-id': '936619743392459',
                                        'x-ig-www-claim': 'hmac.AR1YTbiNiOj-oFmz6or5-aLaGeSG8E7Lsos9CcSReFXVmuPW',
                                        'x-instagram-ajax': '3c8826838272',
                                        'x-requested-with': 'XMLHttpRequest'
                                    }
                                    data_heat = {
                                        'source_name': '',
                                        'reason_id': '6',
                                        'frx_context': ''
                                    }
                                    req_self = requests.post(url_heat, data=data_heat, headers=headers_heat, cookies=cookies).text
                                    if ('"description":"We take your reports seriously. We look into every issue, and take action when people violate our Community Guidelines"') in req_self:
                                        done += 1
                                        print(f'\r[+] Done Heat With Account {username}', end='')
                                        time.sleep(3)
                                    else:
                                        error += 1
                                        print(f'\r[-] Error Heat With Account {username}', end='')
                                        time.sleep(3)
                                report_heat()
                            get_id_username()
                        else:
                            print(f'\r[-] {Fore.LIGHTRED_EX}Please wait a few minutes before you try again', Fore.RESET,
                                  end='')
                    except:
                        print(
                            f'[-] {Fore.LIGHTRED_EX}Please tick after each username : include the password for the username',
                            Fore.RESET)
                        exit(0)
            except:
                print(f'[-] {Fore.LIGHTRED_EX} Not Found File To Name : {namefile}')
                exit(0)
        login()
