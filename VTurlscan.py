import requests
import json
import os
import time
import validators
def main():
    try:
        def apicheck():
                try:
                    api = input("please enter your virus total api key: ")
                    url = 'https://www.virustotal.com/vtapi/v2/url/report'
                    params = {'apikey': api, 'url': "https://google.com" }
                    requests.get(url, params=params)
                    return api
                except Exception as e:
                    print("that api code does not seem to be valid please try again")
                    apicheck()     
        print("valid api code")
        def pickurlandchecking():
            try:
                inputforurl = input("enter a url to scan: ")
                if inputforurl.startswith("http") == False:
                    inputforurl = "http://" + inputforurl
                valid = validators.url(inputforurl)
                if valid==True:
                    try:
                        requests.get(inputforurl)
                        dead = False
                    except:
                        dead = True
                    if dead == True:
                        print("Invalid url please try again")
                        pickurlandchecking()
                    return inputforurl
                    os.system("cls")
                else:
                    print("Invalid url please try again")
                    pickurlandchecking()
            except Exception as e:
                print(e)
        os.system("cls")
        def scanning():
            url = 'https://www.virustotal.com/vtapi/v2/url/scan'
            params = {'apikey': api, 'url': inputforurl }
            response = requests.post(url, data=params)
            ID = response.json()['scan_id']
            return ID
        def report():
            url = 'https://www.virustotal.com/vtapi/v2/url/report'
            params = {'apikey': api, 'resource': ID }
            response = requests.get(url, params=params)
            res = response.json()
            return res
        def shorten(permalink):
            try:
                  res = requests.get("http://tinyurl.com/api-create.php?url=" + permalink)
                  shorturl = res.text
                  return shorturl
            except Exception as e:
                  print(e)
        def makeitlooknicer():
            permalink = res['permalink']
            shorturl = shorten(permalink)
            ress = res['scans']
            yan = res['scans']['Yandex Safebrowsing']
            mal = res['scans']['MalwareDomainList']
            if 'detail' in yan: 
                del yan['detail']
            if 'detail' in mal: 
                del mal['detail']
            char_to_replace = {": {'detected': True, 'result': 'malicious site'},": " thinks this site is malicious",
                               ": {'detected': False, 'result': 'clean site'},": " thinks this site is clean",
                               ": {'detected': False, 'result': 'unrated site'},": " does not know the proper rating of this site",
                               "'": ""}
            repleaced = str(ress).replace("},", "}, \n")[1:][:-1] + ","
            for key, value in char_to_replace.items():
                repleaced = repleaced.replace(key, value)
            repleaced = repleaced + "\n The URL to VirusTotal scan results is: " + permalink + " or " + shorturl
            done = ""
            for line in repleaced.splitlines():
                if line[0:1] == " ":
                    done = done + line[1:] + "\n"
                else:
                    done = done + line + "\n"
            return done
    except Exception as e:
        print("a unknown error has occurred please try again later...")
        print(e)
        exit()
    api = apicheck()
    inputforurl = pickurlandchecking()
    ID = scanning()    
    res = report()
    repleaced = makeitlooknicer()
    print(repleaced)
if __name__ == '__main__':
    try:
       main()
    except KeyboardInterrupt:
        os.system("cls")
        print("exiting program...")
        exit()