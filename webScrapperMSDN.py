import requests
from bs4 import BeautifulSoup
import sys

if len(sys.argv) != 2:
    print("didn't get function name as cmd argv 2")
func_to_search = sys.argv[1]
if func_to_search[-1] == 'W':
    url = "https://www.google.com/search?q=" + func_to_search
else:
    url = "https://www.google.com/search?q=" + func_to_search +"+msdn"
CHROME_90_HEADERS = {'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36"}
page = requests.get(url, headers = CHROME_90_HEADERS)

soup = BeautifulSoup(page.content, 'html.parser')
results = soup.select('[class~=g]')
good_result = "No"
for x in results:
    if "docs.microsoft.com" in x.a['href']:
        good_result = x.a['href']
        break
    
if good_result != "No":
    page = requests.get(good_result, headers = {'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36"})
    soup = BeautifulSoup(page.content, 'html.parser')
    codes = soup.select('code')
    for x in codes:
        if x.has_attr("class"):
            print(x.text.strip())
            break
else:
    print("No result in msdn on google first page :(")


