# R-Meth - Reconnaissance Methodology

## Initial Information Gathering

*   Find Organization Name, NetName, AS Number:
    ```bash
    whois target.com | grep "NetName\|OrgName\|AS"
    ```
*   Lookup AS information via HackerTarget API:
    ```bash
    curl -s https://api.hackertarget.com/aslookup/?q=target.com
    ```
*   Find CIDR ranges associated with an AS Number (replace ASXXXXX):
    ```bash
    whois ASXXXXX | grep -E "CIDR|inetnum"
    ```
*   Get subdomains from crt.sh:
    ```bash
    curl -s https://crt.sh/\?q\=%.target.com\&output\=json | jq -r '.[].name_value' | sort -u
    ```
*   Get subdomains from [csprecon](https://github.com/edoardottt/csprecon):
    ```bash
    csprecon -l targets.txt
    ```
*   Get historical robots.txt entries from Web Archive:
    ```bash
    curl -s "http://web.archive.org/cdx/search/cdx?url=target.com/robots.txt&output=json" | jq '.[1:] | .[] | .[2]' | sort -u > historical_robots.txt
    ```
*   Scrape Pastebin for mentions of the target domain:
    ```bash
    curl -s "https://scrape.pastebin.com/api_scraping.php?limit=100" | grep -Eo "target\.com" | sort -u
    ```
*   Try to Find Some data by trufflehog:
    ```bash
    trufflehog s3 --bucket="", trufflehog github --repo="", trufflehog github --org="", trufflehog git "", trufflehog gcs --project-id="", trufflehog filesystem "", trufflehog postman --token=<postman api token> --workspace-id=<workspace id>
    ```

## Initial Automated Scans & Vulnerability Assessment

*   Start the recon process with some vulnerability assessments & automation easy recon (magicrecon, rapidscan, sniper, frogy2.0, raccon, openvas, omsedaus) for get some easy info.

## Reconnaissance Steps

1.  **Subdomain Collection (Initial):**
    *   Collect subdomains from:
        *   [https://shrewdeye.app/](https://shrewdeye.app/)
        *   [https://pentest-tools.com/](https://pentest-tools.com/)
        *   ShodanX
        *   crt.sh
        *   Amass
        *   from builtwith `https://github.com/m4ll0k/BBTz/blob/master/getrelationship.py`
    *   crt.sh command example:
        ```bash
        curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | anew crtsh_subs.txt
        ```

2.  **Subdomain Enumeration & DNS Scanning:**
    *   Find other subdomains using `assetfinder`, `subfinder`.
    *   Scan the DNS using `dnsrecon`, `dnsenum`.

3.  **DNS Exploitation & Analysis:**
    *   Use `cloudenum` after ensuring you have collected all subdomains.
    *   Check for DNS vulnerabilities/misconfigurations using `dnschef`, `dnstake`, `dnsdumpster`. Aim to exploit any DNS issues found.
    *   Use `theharvester`.
    *   Use `eyewitness` for getting screenshots on strange ports.

4.  **HTTP/HTTPS Probing & Information Gathering:**
    *   Probe collected subdomains with `httpx` (save live subs to `allsubs.txt` first):
        ```bash
        sudo httpx -l allsubs.txt -sc -td -title -wc -bp -cdn --websocket --follow-redirects
        sudo httpx -l allsubs.txt # (Basic probe for live status)
        ```

5.  **HTTP Vulnerability Scanning (Basic):**
    *   Use `HXCC-scanner`, `HexHTTP` with the list of live hosts from `httpx` to detect possible HTTP vulnerabilities.

6.  **Subdomain Takeover Check:**
    *   Use `subzy`:
        ```bash
        sudo subzy run --targets live_subs.txt
        ```
    *   If you find dangling CNAME records (`retailed CNAME`), use `dig` to confirm and try to claim the subdomain.

7.  **Further Automation & Secret Scanning:**
    *   Use automation tools like `rapidscan`, `sniper`.
    *   If a GitHub repository is found, use `trufflehog` to scan for secrets.

8.  **Manual Subdomain Discovery (Dorking):**
    *   Find more manual subdomains using Google dorking:
        *   [Zierax/GoogleDorker](https://github.com/Zierax/GoogleDorker)
        *   `googler` tool
        *   Manual Google Dorking

9.  **Port Scanning & Service Exploitation:**
    *   Use `nmap` and Shodan dorks for open ports.
    *   If services like SSH, FTP, SMTP, SFTP, etc., are found:
        *   Try to identify service versions.
        *   Search for exploits related to those versions.
    *   Example Shodan Dork for specific cert subject:
        ```
        Ssl.cert.subject.CN:"Roblox Corporation"
        ```

10. **HTTP Request Smuggling:**
    *   Use `smuggler` to check for request smuggling vulnerabilities (use live HTTP/S URLs from `httpx` output):
        ```bash
        cat httpx.txt | python smuggler.py | tee -a smuggler.txt
        ```
    *   *(Note: Ensure `smuggler.py` path is correct or it's in PATH)*

11. **API Discovery (Postman):**
    *   Use `Porch Pirate` to get API repos from Postman.
    *   Manually search on [web.postman.com](https://web.postman.com).

12. **Directory & File Fuzzing:**
    *   Use `ffuf` or `gobuster` and `nikto` to find hidden directories and files.

13. **Endpoint Discovery (Crawling & Archiving):**
    *   Use `waybackurls`, `gobuster` (dir mode), `gau`, `katana`, `hakrawler`.
    *   Separate the results by file type (js, php, xml, txt, aspx, html, sql, json).

14. **GitHub GraphQL Search:**
    *   Execute this query in [GitHub GraphQL Explorer](https://docs.github.com/en/graphql/overview/explorer) (replace `<<target>>`):
        ```graphql
        {
          "query": "query { search(query: \"<<target>>.com\", type: REPOSITORY, first: 10) { edges { node { ... on Repository { name url } } } } }"
        }
        ```

15. **Pattern Matching & Vulnerability Categorization:**
    *   Use `gf` (grep framework) to separate findings based on patterns (sqli, xss, ssrf, etc.).
    *   Use categorized findings with vulnerability scanners like `Xray`:
        *   Example for XSS:
            ```bash
            # Assuming xss_from_gf.txt contains URLs identified by gf patterns for XSS
            xargs -a xss_from_gf.txt -I@ sh -c './xray webscan --plugins xss --url "@" --html-output xss.html'
            ```

16. **JavaScript Analysis:**
    *   Use `jshunter`, `mantra`, `arjun`, `jsleak` to define parameters and find interesting APIs/endpoints in JS, PHP, ASPX files.
    *   Extract endpoints from JS files:
        ```bash
        cat urls.txt | grep ".js" | while read url; do curl -s "$url" | grep -Eo "https?://[^\"']+"; done | tee js_endpoints.txt
        ```
    *   Scan Js files by nuclei:
        ```bash
        nuclei -l js.txt -t ~/nuclei-templates/http/exposures/ -o js_bugs.txt
        ```
        *(Note: `urls.txt` should contain URLs, potentially from step 13)*

17. **Broken Link Hijacking:**
    *   Use `SocialHunter`: [https://github.com/utkusen/socialhunter](https://github.com/utkusen/socialhunter)

18. **API Endpoint Scanning:**
    *   Use `kiterunner` for scanning API targets.

19. **Web Screenshotting:**
    *   Use `eyewitness`:
        ```bash
        eyewitness --web -f live_subs.txt -d screenshots
        ```
        *(Note: `live_subs.txt` should contain live subdomains)*

20. **Vulnerability Scanning (Nuclei):**
    *   Run `nuclei` against live hosts:
        ```bash
        nuclei -l httpx.txt -rl 10 -bs 35 -c 50 -as -s critical,high,medium
        ```
        *(Note: Adjust `-rl`, `-bs`, `-c` based on your resources and target scope. `httpx.txt` is assumed output from httpx)*

21. **One-Liners for Low-Hanging Fruits:**
    *   **LFI (Local File Inclusion):**
        ```bash
        cat targets.txt | (gau || hakrawler || waybackurls || katana) | grep "=" | dedupe | httpx -silent -paths lfi_wordlist.txt -threads 100 -random-agent -x GET,POST -status-code -follow-redirects -mc 200 -mr "root:[x*]:0:0:"
        ```
        *(Requires: `targets.txt`, `lfi_wordlist.txt`, `gau`/`hakrawler`/`waybackurls`/`katana`, `dedupe`, `httpx`)*
    *   **OPRD (Open Redirect):**
        ```bash
        echo target.com | (gau || hakrawler || waybackurls || katana) | grep -a -i \=http | qsreplace 'http://evil.com' | while read host do;do curl -s -L $host -I | grep "http://evil.com" && echo -e "$host \033[0;31mVulnerable\n" ;done
        ```
        *(Requires: `gau`/`hakrawler`/`waybackurls`/`katana`, `qsreplace`, `curl`)*
    *   **SSRF (Server-Side Request Forgery) v1:**
        ```bash
        cat urls.txt | grep "=" | qsreplace "YOUR_BURP_COLLABORATOR_LINK" >> tmp-ssrf.txt; httpx -silent -l tmp-ssrf.txt -fr
        ```
        *(Requires: `urls.txt`, `qsreplace`, `httpx`, Burp Collaborator)*
    *   **SSRF (Server-Side Request Forgery) v2:**
        ```bash
        cat potential_ssrf.txt | qsreplace 'http://YOUR_COLLABORATOR_ID.burpcollaborator.net' | httpx -silent -status-code 302,200
        ```
        *(Requires: `potential_ssrf.txt`, `qsreplace`, `httpx`, Burp Collaborator)*
    *   **XSS (Cross-Site Scripting):**
        ```bash
        cat targets.txt | (gau || hakrawler || waybackurls || katana) | httpx -silent | Gxss -c 100 -p Xss | grep "URL" | cut -d '"' -f2 | sort -u | dalfox pipe
        ```
        *(Requires: `targets.txt`, `gau`/`hakrawler`/`waybackurls`/`katana`, `httpx`, `Gxss`, `dalfox`)*
    *   **SQLi (SQL Injection):**
        ```bash
        cat subs.txt | (gau || hakrawler || katana || waybackurls) | grep "=" | dedupe | anew tmp-sqli.txt && sqlmap -m tmp-sqli.txt --batch --random-agent --level 5 --risk 3 --dbs && for i in $(cat tmp-sqli.txt); do ghauri -u "$i" --level 3 --dbs --current-db --batch --confirm; done
        ```
        *(Requires: `subs.txt`, `gau`/`hakrawler`/`katana`/`waybackurls`, `dedupe`, `anew`, `sqlmap`, `ghauri`)*
    *   **CORS (Cross-Origin Resource Sharing Misconfiguration):**
        ```bash
        echo target.com | (gau || hakrawler || waybackurls || katana) | while read url;do target=$(curl -s -I -H "Origin: https://evil.com" -X GET $url) | if grep 'https://evil.com'; then echo "[Potentional CORS Found] $url";else echo "Nothing on $url";fi;done
        ```
        *(Requires: `gau`/`hakrawler`/`waybackurls`/`katana`, `curl`)*
    *   **Subdomain Takeover (WordPress Specific Example):**
        ```bash
        subfinder -d target.com -o subs_for_takeover.txt && nuclei -t ~/nuclei-templates/takeovers/wordpress/wp-xyz-takeover.yaml -l subs_for_takeover.txt
        ```
        *(Requires: `subfinder`, `nuclei`, specific nuclei template path)*

22. **Manual GitHub Dorking:**
    *   Search Gists (Example for JSON mentioning the target):
        `https://gist.github.com/search?l=JSON&q=*%2Atarget.com`
    *   Search Code:
        `https://github.com/search?q="target.com"&type=code`
    *   *(See more GitHub dorks in the Notes section)*

23. **Backup File Fuzzing:**
    *   Use `fuzzuli` to find backup files.

---

## Notes & Resources

*   **Clickjacking:** Check manually using tools like [clickjacker.io](http://clickjacker.io/).
*   **JS Beautifier:** Use [beautifier.io](https://beautifier.io/) or similar tools to make JavaScript readable.
*   **Manual Review:** Manually check interesting JS, PHP, TXT files. Test interesting endpoints manually.
*   **Tool Usage:** Use resource-intensive tools like `sniper` sparingly (time/resource consuming).
*   **Fuzzing:** Perform manual and automated fuzzing on interesting endpoints.
*   **WordPress:** Pay close attention to WordPress sites ("juicy shit!!").
*   **Organization:** Keep your results well-organized.
*   **Favicon Hash:** Get favicon hash for pivoting ([Favicon Hash API](https://favicon-hash.kmsec.uk/)):
    ```bash
    curl https://favicon-hash.kmsec.uk/api/?url=https://test.com/favicon.ico | jq
    ```
*   **Bug Bounty Target List:** Use this list for potential mass scanning (use responsibly): [https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/domains.txt](https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/domains.txt)
*   **Shodan Dorks (Golden):**
    *   `ssl:"target.com" http.status:200 http.title:"dashboard"`
    *   `org:"target.com" http.component:"jenkins" http.status:200`
    *   `ssl:"target.com" http.status:200 product:"ProFTPD" port:21`
    *   `http.html:"zabbix" vuln:CVE-2022-24255`
    *   `org:"target.com" http.title:"phpMyAdmin"`
    *   `ssl:"target.com" http.title:"BIG-IP" vuln:CVE-2020-5902`
    *   `ssl.cert.subject.cn:*.target.com http.title:"Dashboard [Jenkins]"`
    *   `http.html:"xoxb-"` (Slack Tokens)
    *   `http.html:"AKIA"` (AWS Keys)
    *   `http.html:"AIza"` (Google API Keys)
    *   `ssl.cert.subject.CN:"*.target.com"+200 http.title:"Admin"`
    *   `http.html:"The wp-config.php creation script uses this file"`
    *   `http.title:"Index Of /"`
    *   `http.title:"Directory Listing" org:organization-name`
    *   `product:"Splunk"` (Exploit e.g., `127.0.0.1:8000/en-US/splunkd/__raw/services/server/info/server-info?output_mode=json`)
    *   `Ssl:”domain” 200 http.title:”citrix gateway”`
    *   `http.title:"swagger UI" org:"Target"`
    *   `net:"I.P.v.4/CIDR" http.title:dashboard`
    *   `org:"Company Inc" http.title:dashboard`
    *   `asn:AS19551 http.title:"dashboard”` (Replace ASN)
    *   `org:Company http.status:"403"`
    *   `Set-Cookie:"mongo-express=" "200 OK"`
    *   `ssl.cert.subject.CN:"*.target.com" "230 login successful" port:"21"`
    *   `http.title:"Django REST framework"`

*   **Shodan CVE Checks:**
    *   `CVE-2023-35078` (MobileIron): `http.title:"MobileIron"` or `http.favicon.hash:362091310` ([Exploit POC](https://github.com/vchan-in/CVE-2023-35078-Exploit-POC))

*   **Google Dorks (Golden - Use on Bing too):**
    *   `site:docs.google.com/spreadsheets "Target"`
    *   `site:groups.google.com "Target"`
    *   `intitle:"Swagger UI" site:target.com`
    *   `site:target.com inurl:login | inurl:signin | intitle:Login | intitle:"sign in" | inurl:auth`
    *   `site:domain.com inurl:view inurl:private ext:pdf`
    *   `site:domain.com inurl:upload ext:pdf`
    *   `site:domain.com inurl:uploads ext:pdf`
    *   `site:domain.com inurl:internal ext:pdf`
    *   `site:domain.com inurl:storage ext:pdf`
    *   `site:domain.com inurl:download ext:pdf`
    *   `site:domain.com inurl:webview ext:pdf`
    *   `site:domain.com inurl:content ext:pdf`
    *   `site:domain.com inurl:_data ext:pdf`
    *   `site:domain.com inurl:<keyword> ext:pdf -docs -doc -documentation -form -draft -application -sample -template -public`
    *   `site:domain.com ext:py`
    *   `intitle:"Dashboard [Jenkins]" Credentials`
    *   `inurl:/api/v1/splashmodal site:domain.com`
    *   `site:domain.com "Choose File"`
    *   `site:domain.com "No file chosen"`
    *   `site:domain.com "Upload"`
    *   `site:domain.com "Upload here"`
    *   `site:domain.com "Upload a file"`
    *   `site:domain.com "Please upload your"`
    *   `site:*<*.target.com intext:"login" | intitle:"login" | inurl:"login" | intext:"username" | intitle:"username" | inurl:"username" | intext:"password" | intitle:"password" | inurl:"password"`
    *   `site:*.redacted.com -www -www1 -blog`

*   **GitHub Dorks (Golden):**
    *   `target.com SECRET_KEY | DB_PASSWORD`
    *   `target.com "INSERT INTO users"`
    *   `target.com "aws_access_key_id" "aws_secret_access_key"`
    *   `target.com "Authorization: Bearer"`
    *   `target.com "client_id" "client_secret"`
    *   `target.com "password="`
    *   `target.com "BEGIN RSA PRIVATE KEY"`
    *   `target.com "mongodb://username:password@"`
    *   `target.com "MYSQL_ROOT_PASSWORD"`
    *   `target.com "smtp_pass"`
    *   `target.com filename:vim_settings.xml`
    *   `service-now password | okta.com | looker.com secret "target"`
    *   `org:companyname "AWS_ACCESS_KEY_ID:"`
    *   `org:"company" ftp_user AND ftp_password AND ftp_host`
    *   Find users related to company: `https://github.com/search?q=COMPANY_NAME&type=users` (Use as link)
    *   `http.html:"apollo-adminservice"`

*   **Default Credentials to Try:**
    *   `admin:admin`
    *   `test:test`
    *   `admin:password`
    *   `admin:pass`
    *   `test@test.com:test`
    *   `test@company.com:test` (try with all domains that belong to company)
    *   `test@company.com:test@company.com`

*   **GitHub Dork List Resource:** [Haddix's GitHub Dorks](https://gist.github.com/jhaddix/1fb7ab2409ab579178d2a79959909b33)

*   **Fully Automated Scanner:** Consider [V3n0M-Scanner](https://github.com/v3n0m-Scanner/V3n0M-Scanner) for suspicious domains.

*   **Abandoned Asset Discovery:** Copy the copyright notice (e.g., "© 2024 Uber Technologies Inc.") from the target site and search Google for previous years to potentially find old/abandoned assets.

*   **WordPress Scanning:** If WordPress sites are found, use `wpscan`.

*   **Embedded Subdomain Credential Reuse:** If you find `embed.<target>.com`, try logging in with known credentials. Successful login might grant access to the main domain, possibly bypassing 2FA.

*   **File Metadata:** Use `exiftool` on any discovered PDFs or files.

*   **Google Analytics Pivot:** Look for Google Analytics Tracking IDs (`UA-XXXXXX-X`) and use [Reverse Analytics Lookup](https://dnslytics.com/reverse-analytics) to find more assets sharing the same ID.

*   **Zookeeper (Port 2181):** Check port 2181 (Zookeeper) for potential easy Remote Code Execution (RCE).

*   **PII Leak via Path Permutation:** Test API endpoints for PII leaks using variations like `/api/users/user@email.com` or `/api/users/1234`.

*   **Zeus Admin Panel (Port 9090):** Port 9090 might host a Zeus admin panel.

*   **Reverse Whois:** Find more information about a domain using [ViewDNS Reverse Whois](https://viewdns.info/reversewhois/).

*   **Dorking Helper:** Use [DorkMine](https://dorkmine.vercel.app/) for easier dork generation.

*   **OSINT Tools:** Enhance recon with [IntelTechniques](https://inteltechniques.com) and [Intelligence X](https://intelx.io).

*   **Mindmaps/Cheatsheets:** Refer to [Ignite Technologies Mindmaps](https://github.com/Ignitetechnologies/Mindmap).

*   **Google Dorking Site:** This site simplifies Google dorking for bug bounty: [Taksec Google Dorks](https://taksec.github.io/google-dorks-bug-bounty/).

*   **Version Exploitation:** If you find specific versions for Nginx, Apache, Jfrog, etc., search for related CVEs/exploits on Google, GitHub, ExploitDB, etc.

*   **Browser Console Endpoint Extraction:** Use this JavaScript snippet in the browser console to extract all linked endpoints from the current page:
    ```javascript
    (() => {
        const p = [...new Set([...document.querySelectorAll("a[href]")].map(a => new URL(a.href, location.href).pathname))],
            b = new Blob([p.join("\n")], { type: "text/plain" }),
            a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(b), download: `${location.hostname.replace(/^www\./,"")}.txt` });
        document.body.appendChild(a), a.click(), document.body.removeChild(a);
    })();
    ```
