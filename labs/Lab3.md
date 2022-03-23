
# Lab 3 - Web security

In this lab we will be focusing on analysing the security of web applications.
Web applications are extremely vulnerable in the sense that they mix a multitude of technologies and libraries and feature highly dynamic features and content that are often difficult to enclose and characterise.

Instead of focusing on exploitation, we will study how various existing analysis tools can support developers in detecting and fixing web vulnerabilities:
* SAST: As for low-level C programs, various vulnerability scanners such as [SonarCloud](https://sonarcloud.io/) and [LGTM](https://lgtm.com/) also have good support for analysis the source code of web applications written in various languages (HTTP/PHP/JS/TS/Java/etc).
* DAST: In particular for web applications, vulnerability assessment tools such as [BurpSuite Community Edition](https://portswigger.net/burp/communitydownload) and [OWASP Zed Attack Proxy](https://owasp.org/www-project-zap/) can be used to navigating web sites, analyse HTTP requests/responses and perform automatic dynamic scans for vulnerabilities.

There exists a myriad of vulnerable web applications, e.g. from the [OWASP Vulnerable Web Applications Directory (VWAD)](https://owasp.org/www-project-vulnerable-web-applications-directory/), that have been developed for demonstrating common web vulnerabilities and how to exploit them.
One of the most modern and complete among such pedagogical web applications is the [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/).

## Setting up the [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)

In this lab we will be looking into solving a few Juice Shop challenges. You will find a lot of information in the Juice Shop [companion guide](https://pwning.owasp-juice.shop/). 
Solving a challenge requires a basic understanding of an exploitation technique and crafting careful payloads that can get the attack done. In such a setting, reading previous [solutions](https://github.com/juice-shop/juice-shop/blob/master/SOLUTIONS.md) or looking at the project's [source code](https://github.com/juice-shop/juice-shop) is considered sort of cheating. For this lab, the focus is on analysing the vulnerabilities; we encourage you to search the many available additional resources for solving the challenges as you see fit (while trying not to take all the fun out of it).

Interesting for us, many Juice Shop challenges also feature:
* a [mitigation link](https://owasp.org/www-project-juice-shop/) with pointers to the [OWASP cheat sheet](https://cheatsheetseries.owasp.org/) related to the vulnerability;
* a [coding challenge](https://pwning.owasp-juice.shop/part1/challenges.html) that will open a dialog containing the actual code snippet responsible for the security vulnerability behind the challenge and ask the challenger to understand the code and suggest the best fix.

There are various options to deploy an instance of Juice Shop, all listed in the GitHub [page](https://github.com/juice-shop).
For a quick start, you may [deploy on Heroku](https://github.com/juice-shop/juice-shop#deploy-on-heroku-free-0month-dyno) or create a [Docker container](https://github.com/juice-shop/juice-shop#docker-container). However, For some tasks (and maximum vulnerability!) you will need to install [from sources](https://github.com/juice-shop/juice-shop#from-sources).

Inside the [vm](../vm) folder, you may just type:
* `make run-docker-juiceshop` to build and run from a Docker container. An instance of Juice Shop will be readily listening at `http://localhost:3000`.
* `make build-juiceshop` to build from sources.
* `make run-juiceshop` to run from built sources. An instance of Juice Shop will be readily listening at `http://localhost:3000`.

## Dependency scanning

In a real software development life cycle, scanning for vulnerabilities within external libraries is a natural starting point. THis is not only useful information while choosing the right dependencies for your project, but also important during the development and testing of your applications. It wouldn't be very surprising to find a few of them in Juice Shop...

### [Snyk](https://snyk.io/)

Snyk is free-to-use comercial tool that can automatically search the dependencies of a project for known vulnerabilities.
To run it for Juice Shop, do the following inside the [vm](../vm) folder:
```ShellSession
$ make build-juiceshop #you may skip if already build
$ cd juice-shop
$ snyk auth # this will require you to authenticate with the snyk online service
$ snyk test --json | snyk-to-html -o report.html
```

How many dependency vulnerabilities will you find for Juice Shop? You may look at a pre-generated report [here](https://hpacheco.github.io/ses/labs/lab3/snyk_report.html).

### [OWASP Dependency Check](https://owasp.org/www-project-dependency-check/)

Dependency-Check is a OWASP tool that attempts to detect publicly disclosed vulnerabilities contained within a project’s dependencies. Although it may feature a higher rate of false positives, it provides a more detailed report linking to the associated CVE entries. 

In order to run Dependency-Check for Juice Shop, `cd` into your [vm][../vm] folder and run:
```Shell
make run-dependency-check
```

A pre-generated report for Juice Shop may be found [here](https://hpacheco.github.io/ses/labs/lab3/dependency-check-report.html).

## Server scanning

Before we look at specific web vulnerabilities, let's first make a preliminary recognition of the structure of our web page.
This is also useful for completing the JuiceShop [score board challenge](https://pwning.owasp-juice.shop/part1/challenges.html), which asks us to find a hidden web page which provides information about available challenges and keeps track of our challenge solving status.

### [nikto](https://cirt.net/Nikto2)

Nikto is a web server scanner which performs comprehensive tests against web servers for multiple items, including potentially dangerous files/programs and server configuration or version-specific problems. Nikto is also highly configurable. We can run a basic nikto scan on our web page as follows and obtain a HTML report:
```Shell
nikto -o report.html -h http://localhost:3000
```
You may check a previously-generated report for OWASP Juice Shop [here](https://hpacheco.github.io/ses/labs/lab3/nikto.html).

### [Browser development toolkits](https://pwning.owasp-juice.shop/part1/rules.html)

As you navigate through a web site, the Javascript console, the site debugger and the HTTP requests are a valuable source of information.
In Firefox, you can open the Development Panel by clicking `F12`.

Hints for finding the hidden score board:
* you may search all files in the current web page with (`CTRL+SHIFT+F` in Firefox with all files closed).
* you can also easily dump the content of a web page to your computer and then search locally, e.g., to recursively download a web page with wget just try:
```Shell
wget -r http://localhost:3000
```

## Dynamic Application Security Testing (DAST)

In the context of web applications, DAST is a testing methodology that analyses a running application by scanning and performing attacks on the client-side frontend. Since it is independent of the technologies used in the application's server-side backend, it is also termed as a black-box testing methodology [^1].

[^1]: White-box dynamic web application analysis is usually termed Interactive Application Security Testing (IAST).
Like traditional dynamic program analysis, IAST tools analyze running web applications by first instrumenting their code to better observe application behavior and data flow.
Unfortunately, IAST is very much dependent on used technologies since it requires significantly more integration with the host applications, are there are few open-source solutions (aside from hard to set up research prototypes) for us to experiment with. We will therefore focus on DAST.

### [OWASP ZAP](https://www.zaproxy.org/)

ZAP is an open-source OWASP-supported DAST tool for web applications.
ZAP provides automated scanners as well as a set of tools that allow you to find security vulnerabilities manually.
For further reference consult the [online documentation](https://www.zaproxy.org/docs/).
It essentially supports the following modes:
* *Passive Mode*, where it simply works as a proxy that intercepts all requests and analyzes them for finding vulnerabilites;
* *Active Mode*, where it actively crawls the visited web pages to search for new vulnerabilities.

Naturally, you can always combine both modes for maximum coverage.
For instance, start by running an *Automated Scan* on http://localhost:3000. 
However, a common hurdle for web scanners is that any vulnerability in a page that requires authentication will not be found by the *Automated Scan*, since ZAP will not be able to login into the page.
You may overcome this limitation by running a *Manual Explore* on http://localhost:3000.
It will launch a new browser instance proxied via ZAP network traffic monitors.
Turn on the *Attack Mode* and login into one of the user accounts; you may navigate through the site and run a traditional *Passive Spider* analysis to detect web pages; then run an *Active Scan* to detect further vulnerabilities.

For the case of Juice Shop, an interesting detail is that it comes with a large of end-to-end (E2E) tests. The main purpose of E2E testing is to test the end user's experience by simulation real scenarios using the web application's interface. For the case of Juice Shop, E2E tests attempt to exploit the web page to solve each challenge. Juice Shop's E2E tests are written using [Selenium](https://www.selenium.dev/) scripts to emulate user interactions with the browser.

So, a nice idea (originally from this [blog post](https://www.omerlh.info/2018/12/23/hacking-juice-shop-the-devsecops-way/)) to maximize vulnerability coverage would be to include these tests in ZAP scan to automate an otherwise manual search for known vulnerabilities. It turns out that the only thing that we need to do is compile Juice Shop from sources and proxy the E2E tests via ZAP.

First guarantee that ZAP Proxy is running at http://localhost:8080 (its default port). Then, in the [vm](../vm) folder, type:
```ShellSession
$ make build-juiceshop #you may skip this if already built
$ make e2e-juiceshop
```
After a likely slow compilation, a Selenium-controlled Google Chrome instance will open; you shall also see the HTTP requests being tracked in ZAP.

ZAP scans are likely to run for a really long time. A pre-generated report for Juice Shop, covering the E2E tests followed by an *Active Scan* can be found [here](https://hpacheco.github.io/ses/labs/lab3/2022-02-22-ZAP-Report-e2e-active.html).

## Static Application Security Testing (SAST)

In the context of web applications, SAST is a testing methodology that analyzes source code to find security vulnerabilities.
In contrast to DAST, it only analyses components when they are at rest. Since it is language-depend and may inspect the code of both the server-side backend and the client-side frontend, it is also termed as a white-box testing methodology.

Automation and integration with the software development process are key considerations for SAST, in order to you want to continuously identify quality defects and security vulnerabilities as code is written.
The natural down-side of being a static analysis approach is that it is less precise, and may lead to a high number of false positives This is particularly true for web applications, that often integrate multiple programming languages, have few static compile-time guarantees and have complex behaviours and information flow.

### Source code vulnerability scanners

We have seen before that there exist various commercial and open-source SAST analysis tools that we may use to analyse source code in various language and integrate with our development. Most of these tools are particularly well-versed for analysing web applications.

When solving Juice Shop challenges, Of course you can also cheat a bit and search the web page's [sources](https://github.com/juice-shop) for hints.
Even better, you may search for vulnerabilities using a SAST vulnerability scanner on the GitHub repository. This won't be necessary for the **Score Board** challenge, but keep the following pre-generated scans over Juice Shop as a reference for future tasks:
* [SonarCloud](https://sonarcloud.io/project/overview?id=hpacheco_juice-shop)
* [LGTM](https://lgtm.com/projects/g/juice-shop/juice-shop/?mode=list)
* [SemGrep](https://hpacheco.github.io/ses/labs/lab3/semgrep.html)

To scan your own code with these scanners, it is arguably more convenient to upload your code to a public git repository and run it through the online scanners. You may also fork the [juice-shop](https://github.com/juice-shop) git repository in order to test and analyse fixes to the `master` branch. Alternatively, you may also download the offline versions of [SonarQube](https://www.sonarqube.org/downloads/), [CodeQL](https://codeql.github.com/docs/codeql-for-visual-studio-code/analyzing-your-projects/) or [SemGrep](https://semgrep.dev/getting-started) and run them locally.

## Improper input validation

One of the most common vulnerabilities in any software application relates to the potentially devastating impact that user input can have on the intended behavior of the application. For web applications, inputs are typically passed as arguments to HTTP requests.

In Juice Shop, there are various challenges related to [improper input validation](https://pwning.owasp-juice.shop/part2/improper-input-validation.html).

### Zero Stars challenge

Let's have a look at the **Zero Stars** challenge, which asks us to submit a review with a 0-star rating.
You may start by writing a review for any product, but surprisingly the review form has no associated rating.
However, in the Juice Shop's side menu you may notice the `Customer Feedback` page, available at `http://localhost:3000/#/contact`.

Try submitting a regular customer review and inspect the (legitimate) HTTP POST request that is sent to the server; unfortunately, the UI does not allow us to submit a 0-start rating.

Solution:
* [Basic] You may use the browser developer tools to find the HTTP request together with its arguments in JSON format.
You will notice that the request contains a `rating` field; setting that to `0` should do the trick!
We can concoct such an illegitimate request using a simple command line tool such as `wget` or `curl`. 
* [Recommended] This simple attack is more convenient if we use a web monitoring tool such as OWASP ZAP or Burp Suite. If using ZAP, start a **Manual Explore** with url `http://localhost:3000/#/contact`. This will launch an instance of your browser extended with ZAP Proxy monitors, which will log all your HTTP requests. Submit a customer review, intercept the relevant request, and select the **Open/Resend with Request Editor** option to easily alter and resubmit your request.

### Admin Registration challenge

**Try to solve** the (very similar) **Admin Registration** challenge on your own.
After you have solved the challenge, follow the mitigation link to understand more about the associated vulnerability and solve the associated coding challenge.

## SQL injection

SQL injection (SQLi) is not of the most classical web attacks which may have devastating consequences on web applications suffering from associated vulnerabilities.
Juice Shop itself as a few challenges related to SQL injection vulnerabilities.

### Login Admin challenge

Let's start with the **Login Admin** challenge, which asks us login as an existing account with administrator privileges [^2].
If we navigate to `http://localhost:3000/#/login`, we can try to login by supplying an `email` (let's try `admin`) and a `password` (randomly `123`). We can also track the HTTP request sent to the server which shall look like:
```
POST http://localhost:3000/rest/user/login
{"email":"admin","password":"123"}
```
with response:
```OK
Invalid email and password.
```

[^2]: We can legitimately register a new user and login with it, and we can illegitimately make that user an administrator as we have seen before, but the goal here is to login with an existing administrator account without having its credentials.

Unsurprisingly, no luck so far. Now we need to start testing of the login fields are vulnerable to SQL injection.
A first attempt is usually to insert special characters in the request fields and see if that affects the response.
In SQL, strings are usually delimited with `'`.
So let's try sending a request with `email=admin'`. You shall get an error response with a `SQLITE_ERROR` (so we already know our backend DB is SQLite) and a description of the performed SQL query:
```SQL
SELECT * FROM Users WHERE email = 'admin'' AND password = '...' AND deletedAt IS NULL
```
This confirms our suspicion: a double enclosing delimiter in the email field leads to a syntax error.
We also learn something potentially dangerous about the query: the email selection comes before the match with the password, so can we comment out the password check? Yes we can, by sending a request:
```
POST http://localhost:3000/rest/user/login
{"email":"admin' --","password":"123"}
```
for which we get the response:
```OK
Invalid email and password.
```
Behind the scenes, the executed SQL query was:
```SQL
SELECT * FROM Users WHERE email = 'admin' -- AND password = '...' AND deletedAt IS NULL
```
We no longer get a syntax error since the query is valid. However, we do not get a valid login. This is because, by default, the server will log us as the first user that is returned by the selection; as it turns out that there is no user in the database with email `admin`, our selection is empty and we get a login error. You may check the source code for further clarification.

We can overcome this limitation easily, e.g., by returning all users in the `Users` database table, which is part of another challenge.
Let us inject SQL into the login field to bypass the login and login as the first user in the database, by sending the request:
```
POST http://localhost:3000/rest/user/login
{"email":"admin' OR TRUE --","password":"123"}
```
for which we get a successful login!
```
Behind the scenes, the executed SQL query was:
```SQL
SELECT * FROM Users WHERE email = 'admin' OR TRUE -- AND password = '698d51a19d8a121ce581499d7b701668' AND deletedAt IS NULL
```
Now the SQL query will check for `email = 'admin' OR TRUE` which is always `TRUE`, hence effectively selecting all users. If you check the `Account` in the Juice Shop, you will notice that you are logged in as `admin@juice-sh.op`; luckily for us, the administrator turned out to be the first user in the `Users` table.

#### [SQLmap](https://sqlmap.org/)

SQLMap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers. Try running SQLMap over our login page as follows:
```Shell
sqlmap -u 'http://localhost:3000/rest/user/login' --data=email=*&password=*" --level 5 --risk 3 -f --banner --ignore-code 401 --dbms='sqlite'
```
The `--data` options tells SQLMap to send a POST request; `*` is treated as a wildcard standing for any string that SQLMap will try to fill. SQLMap shall find a vulnerable input similar to our previous successful exploit.

#### Fuzzing with OWASP ZAP

We can also use ZAP to automatically fuzz HTTP requests.
For detailed info, check the [wiki](https://www.zaproxy.org/docs/desktop/addons/fuzzer/) or this video [tutorial](https://www.youtube.com/watch?v=uSfGeyJKIVA).

After finding the user POST login form with a ZAP scan, select `Open/Resend with Request Editor`. Then select the email field and right-click `Fuzz`.
Next, you need to provide ZAP with a list of fuzz vectors, which are strings of common exploits to vulnerabilities [^3]. Conveniently, ZAP already comes with some lists. Select `Add Payload > File Fuzzers > jbrofuzz > SQL Injection`.

An `OK` response with an authentication token in its content demonstrates that the login form is vulnerable to SQLi. Note that, unlike with active or passive scanners, ZAP will not generate any alerts from fuzz testing; you always need to interpret the results manually.

[^3]: It is important to note that ZAP does not perform fuzzing in the traditional sense: it simply automates the process of testing a list of user-given inputs, and it will not try to mutate the inputs to find new inputs.

<details>
<summary>Screenshots</summary>

![lab3/zap_sqli1.png](lab3/zap_sqli1.png)
![lab3/zap_sqli2.png](lab3/zap_sqli2.png)
![lab3/zap_sqli3.png](lab3/zap_sqli3.png)
![lab3/zap_sqli4.png](lab3/zap_sqli4.png)
![lab3/zap_sqli5.png](lab3/zap_sqli5.png)

</details>

#### Fuzzing with [wfuzz](https://www.kali.org/tools/wfuzz/)

Wfuzz is a command-line alternative to ZAP, that comes pre-installed in Kali Linux.
It is also popular for other vulnerabilities beyond SQLi.

We can fuzz the user login POST request with the following command:
```Shell
wfuzz -c -z file,/usr/share/wordlists/wfuzz/Injections/SQL.txt -d “email=FUZZ&password=any” -u http://localhost:3000/rest/user/login
```
The `-c` flag makes color output.
The `-z` flag specifies a list of payloads (inputs) to the fuzzer. 
The wfuzz tool will replace the keyword FUZZ with the words within the provided payload file; in this case, the `email` field of the POST data.

You will get an output similar to the shown below; successful logins can be distinguished form their `200 OK`responses.

<details>
<summary>Screenshots</summary>

![lab3/wfuzz_sqli.png](lab3/wfuzz_sqli.png)

</details>

### Other SQLi challenges

Juice Shop features a couple other SQL injection challenges.
**Try to solve by yourself two other challenges, one from each of the following pairs which are similar:**
* **Login Bender** or **Login Jim**: these challenges are very similar to the **Login Admin** and attack the login page, you just need to find the correct email first.
* **Database Schema** or **User Credentials**: these challenges require inferring some information about the database and attack the search page [^4].

After you have solved the challenges, follow the mitigation link to understand more about the associated vulnerability and solve the associated coding challenge.

[^4]: You shall be able to use SQLMap to easily assist you in leaking the whole database; explore the command-line options for more information on how to accomplish it. Note that Juice Shop may not be able to detect the SQLMap leak as a successful resolution of the challenge, because its detection mechanism is only looking out for certain queries.

#### GDPR Data Erasure challenge

The **GDPR Data Erasure** is another SQLi-related challenge that requires combining the exploits of the above two classes.
Nonetheless, its origin goes beyond the SQLi vulnerabilities and can be attributed to a lack of proper GDPR compliance in the data erasure process.

**Try to solve it** by yourself and to trace back the problem to the [source code](https://github.com/juice-shop/juice-shop) responsible for the data erasure process. Can this problem be detected by the automated tools?

## Cross-Site Scripting (XSS)

XSS is another very common web vulnerability related to lack of input sanitization, which can take several forms:
* Stored XSS, a persistent form where a user can store malicious data in the database that will affect further requests;
* Reflected XSS, a non-persistent form where the user sends a malicious payload to the server which is not stored but instantaneously reflected back to the client;
* DOM-based XSS, a simpler form than a reflected XSS, where the attack takes place instantaneously in the client-side browser, without server intervention. From a user perspective, it is usually indistinguishable from a reflected XSS attack.

### Dom XSS challenge

Juice Shop features a multitude of XSS challenges, the simplest being the **Dom XSS** challenge.
In this challenge, we are asked to again exploit the search page, this time by inserting not malicious SQL code but malicious HTML code.

Let's start with some static and benign HTML: insert the search string `<h1>apple</h1>` in the search form and check if your HTML code appears in the resulting page. If you inspect (using the browser's Developer mode) the resulting page's HTML source code, you shall easily find your inserted HTML code.

Looks good. Now let's try some JavaScript code: insert the search string `<script>alert('XSS')</script>` in the search form in order to open a popup with message `XSS`.
This time, nothing happens... is the search field immune to XSS? Not at all, it just happens that our script is being inserted inside a `innerHTML` element and according to the [W3 HTML standard](https://www.w3.org/TR/2008/WD-html5-20080610/dom.html#innerhtml0):
> script elements inserted using innerHTML do not execute when they are inserted.
Check this [post](https://security.stackexchange.com/a/199850) for more details.

Luckily, there are many other XSS payloads that we can try. For example, our script will run if put inside an `iframe`; inserting the search string `<iframe src="javascript:alert('XSS')">` in the search form shall produce the desired popup.
    
As you solve the coding challenge, you will realize that the search results page is constructed using an [Angular](https://angular.io/) template, and the user input form is used to construct the `innerHTML` of a HTML element in the template page; by default, Angular sanitizes all output rendered to an `innerHTML`; however, the call to `bypassSecurityTrustHtml` is telling Angular not to sanitize the output that is rendered on the search results page, leading to the vulnerability studied in this challenge. Check the logs of the automated tools: they will tell you a similar story.
    
#### Fuzzing with OWASP ZAP

We can also test XSS vulnerabilities using ZAP fuzz testing.

After finding the search GET request (<http://localhost:3000/rest/products/search?q=searchValue>) with a ZAP scan, select the search term in the `Request` tab and right-click `Fuzz`.
Select `Add Payload > File Fuzzers > jbrofuzz > XSS`.

Successful XSS attacks in ZAP are signaled by the yellow star-like `Reflected` symbol. You may quickly notice that only `500 Internal Server Error` requests are reflected, and there is no successful `200 OK` attack. This is precisely because an `OK` response will include a listing of matching items, and error responses will include the search query within the SQL error. **However, testing the REST API for this DOM-based XSS challenge is not a faithful representation of the attack**. If you carefully manually explore with ZAP the requests generated from an interaction with the browser, you will notice the request's `q` argument is independent of the search string! The frontend is always querying the whole database of items and performing a client-side filtering in the client-side using Javascript.

You may try fuzzing the frontend url <http://localhost:3000/#/search?q=searchValue>. Unfortunately, it will also not succeed in finding an attack, because it will lack the site's client-side item listing from the previous page. Analysing this vulnerability is in fact challenging, as much of the juice shop functionality is developed using [Angular](https://angular.io/) with complex dynamic Javascript code on the client side.

As a rule of thumb, **ZAP and other similar web vulnerability scanners (such as [wfuzz](https://www.kali.org/tools/wfuzz), [w3af](http://w3af.org/) or [XSSStrike](https://github.com/s0md3v/XSStrike)) only detect reflected XSS vulnerabilities**, by analysing HTTP requests and finding portions of text reflected in the HTTP responses. Finding stored XSS vulnerabilities is harder as they depend on the logic of the application and may only reveal themselves after many (often seemingly-unrelated) requests.

#### Dynamic taint analysis for JavaScript

Finding DOM-based XSS vulnerabilities requires analysing the data flow inside the client-side JavaScript code of the application.
However, statically analysing the data flows of highly-dynamic modern applications quickly become unfeasible, as in fact happens for juice shop that relies heavily on Angular [^5].
The most common approach for finding DOM-based XSS vulnerabilities in the large is therefore to perform dynamic taint analysis of JavaScript, where user inputs are the dangerous sources and DOM rendering functions such as innerHTML or document.write and sensitive sinks; taint propagation is then used to check if data originating from the sources may be flow to the sinks.

Performing taint analysis of JavaScript is an established research topic, and there exist numerous tools and approaches which mostly rely on instrumenting a JS runtime such as node.js (e.g.  [Augur](https://github.com/nuprl/augur)) or a particular browser (e.g. [Mystique](https://mystique.csc.ncsu.edu/about)). Unfortunately, these tools are often academic, heavy on resources (e.g., compiling a specifically patched Chrome) and quite complicated to setup.

As a toy demonstration, consider [Tainting Testing Tool](https://github.com/ollseg/ttt-ext), a simple Chrome extension to assist in finding DOM-based XSS vulnerabilities that injects specific strings into sources (e.g., form inputs, request arguments, page location or cookies) and insert JavaScript hooks that search for those strings in output sinks (e.g., `eval()` or `innerHTML`).

Install Google Chrome and the extension (`Extensions > Manage Extensions > Load unpacked > select the folder of the ttt-ext`).
Then open the `Developer Tools` and load the product search page <http://localhost:3000/#/search?q=searchValue> in Chrome.
You shall see a similar error log in the JavaScript `Console`. The relevant error is highlighted in the below screenshot: the user-provided GET request arguments ends up being rendered as the `innerHTML` of a HTML element with id `searchValue`.

[^5]: Simple analyses such as finding calls to `bypassSecurityTrustHtml` in the source code are always feasible, as we have witnessed above, but may lead to a high number of false positives if the complex information flows are not taken into account.

<details>
<summary>Screenshots</summary>

![lab3/ttt_domxss](lab3/ttt_domxss.png)

</details>

#### Restricting JavaScript flows with Trusted Types

Trusted Types is a new browser security mechanism spearheaded by Google security engineers that is evolving into a [W3C standard](https://w3c.github.io/webappsec-trusted-types/dist/spec/). It is currently supported by [recent versions of Google Chrome](https://chromestatus.com/feature/5650088592408576) and [a few other browsers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/trusted-types). For more information, I found [this tutorial](https://auth0.com/blog/securing-spa-with-trusted-types/) to be a great introduction.

The main problem leading to DOM-based XSS vulnerabilities is the inherently loose nature of JavaScript, that does not promote a clear distinction between user data and page code: user data can be stored in the JavaScript context, which in turn may dynamically influence how the page is rendered. This is particularly dangerous because both user inputs - e.g., coming from forms - and page rendering outputs are simply seen as strings in JavaScript, and various forms of string manipulations may take place in-between.
One possible approach to mitigate this problem is to use dynamic taint propagation: associate additional tainted information to each source string, and check if the tainted source annotations reach the sink data.
In other words, we need to add more structure to the data; instead of doing it dynamically, we can statically distinguish between different types of strings, as a strongly-typed programming language could do [^6]. This is exactly the proposal behind Trusted Types: to define a safe DOM API that **only** manipulates strings with specific types (see types as tags), and have the browser's JavaScript compiler validating those types before the code is executed. Since non-typed string assignments to safe DOM functions receiving typed arguments will lead to a compilation error, only typed data generated by safe DOM sanitizers will be allowed. This also has an important advantage of greatly reducing the focus of a security analysis: instead of tracking dynamic flows of information across all the code, only the code producing typed data can introduce vulnerabilities.

[^6]: Examples of with static typing disciplines for more secure web-development include [Pysa](https://pyre-check.org/docs/pysa-basics/) for Python, [Jif](https://www.cs.cornell.edu/jif/) for Java, or the Haskell-like functional [Ur](http://www.impredicative.com/ur/) language.

We can try out Trusted Types with our DOM-based challenge:
1. Open the page <http://localhost:3000/#/search?q=<iframe src="javascript:alert(`xss`)">> with Chrome; you shall see a `XSS` popup.
2. Enabled Trusted types and try again:
    * Edit the file [frontend/src/index.html](https://github.com/juice-shop/juice-shop/blob/master/frontend/src/index.html) and and insert the following code in the HMTL header
```HTML
<meta http-equiv="Content-Security-Policy: trusted-types; require-trusted-types-for 'script'">
```
to enable Trusted Types.
    * Rebuild Juice Shop (you may alternatively edit the `index.html` file in the `dist` folder to avoid rebuilding).
    * Open the page again; this time, you won't see a popup. In the `Developer Tools`, you shall see an error similar to the following:
<details>
<summary>Screenshots</summary>

![lab3/tt_angular1](lab3/tt_angular1.png)
</details>

3. Trusted Types allows users to control data sanitization by defining custom security policies. Conveniently, recent versions of Angular provide a built-in `angular` policy, in which Angular-internal sanitizers produce typed data respecting the safe DOM API. You may turn it on by changing the policy header in [frontend/src/index.html](https://github.com/juice-shop/juice-shop/blob/master/frontend/src/index.html) to:
```HTML
<meta http-equiv="Content-Security-Policy: trusted-types angular; require-trusted-types-for 'script'">
```
If you rebuild Juice Shop and reload the page, you shall see an error similar to the following:
<details>
<summary>Screenshots</summary>

![lab3/tt_angular2](lab3/tt_angular2.png)
</details>

This time, Trusted Types complains that, under the `angular` policy, the assignment of the output of `bypassSecurityTrustHtml` to a `innerHTML` is still unsafe. This is expected, as `bypassSecurityTrustHtml` does not perform any input sanitization and therefore its Angular output does not have a safe type.
4. If we fix the vulnerability as suggested in the code challenge, by removing the call to `bypassSecurityTrustHtml`, Angular will sanitise all data passed to a `innerHTML` and return an appropriately safe type.
    * Edit the file [frontend/src/app/search-result/search-result-component.ts](https://github.com/juice-shop/juice-shop/blob/master/frontend/src/app/search-result/search-result-component.ts) and fix the code by removing the call to `bypassSecurityTrustHtml`.
    * Rebuild Juice Shop.
    * Reload the page; this time, you shall not see the previous error.
    
### Other XSS challenges

Juice Shop features a couple other SQL injection challenges.
**Try to solve by yourself two other challenges from the ones described below.**
    
#### Reflected XSS challenge

Try solving the **Reflected XSS** challenge by yourself. You will need to find some form that is vulnerable to XSS attacks. Tip: order some product.

Even though this challenge does feature a coding challenge, we can make it so: find the code files and lines responsible for the bug and propose a solution.
Check the logs of the automated tools and the [source code](https://github.com/juice-shop/juice-shop) for hints.

#### API-only XSS

The **API-only XSS** challenge is an example of a stored XSS attack, where clients may call API methods that are not available in the web frontend. Hence, a successful attack will require listening to HTTP requests to extract information and sending a malicious HTTP request. Try to solve it by yourself. You can find various hints in the [guide](https://pwning.owasp-juice.shop/part2/xss.html).
Tip: check the information of a product.

After a successful attack, solve the associated coding challenge: it will refer to a vulnerable code location, even though this exploit is possible due to multiple vulnerabilities. Identify other vulnerable code locations that lead to this vulnerability.

#### Client-side XSS Protection challenge

The **Client-side XSS Protection** challenge is another example of a stored XSS attack.
This time, the web frontend performs some validation on inputs that is not double-checked before requests are processed by the server. Try to solve it by yourself. You can find various hints in the [guide](https://pwning.owasp-juice.shop/part2/xss.html). Tip: create a new user.

Even though this challenge does not feature a coding challenge, we can make it so: find the code files and lines responsible for the bug and propose a solution.
Check the logs of the automated tools and the [source code](https://github.com/juice-shop/juice-shop) for hints.

#### Server-side XSS Protection challenge

The **Server-side XSS Protection** challenge is another example of a stored XSS attack.
Try to solve it by yourself. You can find various hints in the [guide](https://pwning.owasp-juice.shop/part2/xss.html).

Even though this challenge does not feature a coding challenge, we can make it so: find the code files and lines responsible for the bug and propose a solution.
Check the logs of the automated tools and the [source code](https://github.com/juice-shop/juice-shop) for hints.
Tip: check for a vulnerable dependency.

## Tasks

**In your group's GitHub repository, create the markdown file `Lab3.md` to write a small report for this lab.**

Your report file shall cover the following:
* Give a brief description on how you solved the challenges proposed above, namely:
    - **Login Bender** or **Login Jim**
    - **Database Schema** or **User Credentials**
    - **GDPR Data Erasure**
    - two from **Reflected XSS**, **API-only XSS**, **Client-side XSS Protection** or **Server-side XSS Protection**
* Describe the general vulnerability class associated with each group of challenges, including relevant CWEs and typical mitigation and fixing strategies.
* Describe the specific vulnerabilities that allowed the attacks:
    - which lines of which code files were responsible for the vulnerabilities?
    - how can the code that led to these vulnerabilities be fixed? 
    - were the vulnerabilities detected by the automated analyses? why do you think that is the case?
    - you may patch the code and rerun the analyses. would the analysers no longer report the fixed code as vulnerabilities? why do you think that is the case?








    
