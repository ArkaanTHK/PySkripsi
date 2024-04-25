rule SQLi: mal 								// tag: mal
{
	meta: 								// meta: additional information
									// won't affect code
	    author = "Matthew Jang"
	    maltype = "SQL Injection for MySQL, Oracle, SQL Server, etc."
	    reference = "https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/#SyntaxBasicAttacks"
	    description = "YARA rule to detect the most common SQL injection commands/strings"

	strings:

	    $char1 = "1=1"						// 1=1 is always true
	    $char2 = "--" 						// line comments
	    $char3 = "#"
	    $str1 = "CONCAT" nocase    				// for MySQL
	    $str2 = "CHAR" nocase
	    $str3 = "Hex" nocase
	    $str4 = "admin' --"					// bypassing login screen
	    $str5 = "admin' #"
	    $str6 = "admin' /*"                                                                       
	    $str7 = "anotheruser" nocase
	    $str8 = "doesnt matter" nocase
	    $str9 = "MD5" nocase
	    $str10 = "HAVING" nocase 
	    $str11 = "ORDER BY" nocase
	    $str12 = "CAST" nocase
	    $str13 = "CONVERT" nocase
	    $str14 = "insert" nocase
	    $str15 = "@@version"
	    $str16 = "bcp" nocase
	    $str17 = "VERSION" nocase
	    $str18 = "WHERE" nocase
	    $str19 = "LIMIT" nocase
	    $str20 = "EXEC" nocase 
	    $str21 = "';shutdown --"
	    $str22 = "WAITFOR DELAY" nocase
	    $str23 = "NOT EXIST" nocase
	    $str24 = "NOT IN" nocase
	    $str25 = "BENCHMARK" nocase
	    $str26 = "pg_sleep"
	    $str27 = "sleep" 		 			// for MySQL
	    $str28 = "--sp_password" nocase
	    $str29 = "SHA1" nocase
	    $str30 = "PASSWORD" nocase
	    $str31 = "ENCODE" nocase
	    $str32 = "COMPRESS" nocase
	    $str33 = "SCHEME" nocase
	    $str34 = "ROW_COUNT" nocase
	    $str35 = "DROP members--" nocase
	    $str36 = "ASCII" nocase
	    $str37 = "UNION" nocase
	    $str38 = "UNION SELECT" nocase
	    $str39 = "INFORMATION" nocase
	    $str40 = "SCHEMA" nocase
	    $str41 = "INFORMATION_SCHEMA" nocase 

	condition: 

	    any of them

}



 /*

 Ruby Script to Detect SQL Injection
 ###########################
 ###  Union based  ###
 ###########################
        "Find Vulnerable Column Count by Union based"=>/(ORDER.BY.\d+(\-\-|\#))|(?!.*(CONCAT.*))(UNION.ALL.SELECT.(NULL|\d+).*(\-\-|\#))/i,
        "Find DBMS Version Infomation by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(VERSION\(|@@VERSION)/i,
        "Find Hostname by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(@@HOSTNAME)/i,
        "Find DB Administrator by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(super_priv.*FROM.*mysql.user)/i,
        "Find Privileges Count by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*COUNT.*(privilege_type|\*).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES/i,
        "Find Privileges Name by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(privilege_type|\*).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES/i,
        "Find User Count by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*COUNT.*(grantee).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES/i,
        "Find User Name by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(grantee).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES/i,
        "Find Database Count by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(COUNT.*(schema_name)).*FROM.*INFORMATION_SCHEMA.SCHEMATA/i,
        "Find Database Name by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(schema_name).*FROM.*INFORMATION_SCHEMA.SCHEMATA/i,
        "Find Current User by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(CURRENT_USER\()/i,
        "Find Current Database by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(DATABASE\()/i,
        "Find Table Count by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(COUNT.*(table_name|\*)).*FROM.*INFORMATION_SCHEMA.TABLES/i,
        "Find Table Name by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(table_name|\*).*FROM.*INFORMATION_SCHEMA.TABLES/i,
        "Find Column Count by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(COUNT.*(column_name|\*)).*FROM.*INFORMATION_SCHEMA.COLUMNS/i,
        "Find Column Name & Type by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(column_name|column_type).*FROM.*INFORMATION_SCHEMA.COLUMNS/i,
        "Find Column Data Count by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(CAST.*(COUNT\((\*|\w+)).*FROM.*\w+\.\w+)/i,
        "Find Column Data by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(SELECT.*(CAST.*(\w+).*FROM.*\w+\.\w+))/i,
        "Brute Force Table Name by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(SELECT.\d+.FROM.*\w+)/i,
        "Brute Force Column Name by Union based"=>/(?=.*(UNION.*ALL.*SELECT)).*(SELECT.(\`|)(\[|\]|)(\w+|(\w+\-)*\w+)(\[|\]|)(\`|).FROM.*\w+)/i,
        "Find Vulnerable Column Location by Union based"=>/(?=.*(CONCAT.*))(UNION.ALL.SELECT.(NULL|\w+).*(\-\-|\#))/i,

###########################
###  Error based  ###
###########################
        "Find Vulnerable Type by Error based"=>/(0x\w+.*((SELECT.*(ELT.*(\d+\=\d+)))|(SELECT.*(CASE.*WHEN.*(\d+\=(\s|\d+))))).*0x\w+)/i,
        "Find DBMS Version Infomation by Error based"=>/(0x\w+.*(MID.*(VERSION\(|@@VERSION)).*0x\w+)/i,
        "Find Hostname by Error based"=>/(0x\w+.*(MID.*(@@HOSTNAME)).*0x\w+)/i,
        "Find DB Administrator by Error based"=>/(0x\w+.*(SELECT.*super_priv.*FROM.*mysql.user).*0x\w+)/i,
        "Find User Count by Error based"=>/(0x\w+.*(SELECT.*(COUNT.*(grantee).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES)).*0x\w+)/i,
        "Find User Name by Error based"=>/(0x\w+.*(MID.*((grantee)).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES).*0x\w+)/i,
        "Find Privileges Count by Error based"=>/(0x\w+.*(SELECT.*(COUNT.*(privilege_type|\*).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES)).*0x\w+)/i,
        "Find Privileges Name by Error based"=>/(0x\w+.*(MID.*(privilege_type)).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES.*0x\w+)/i,
        "Find Database Count by Error based"=>/(0x\w+.*(SELECT.*(COUNT\((\w+|\*)).*FROM.*INFORMATION_SCHEMA.SCHEMATA).*0x\w+)/i,
        "Find Database Name by Error based"=>/(0x\w+.*(SELECT.*(\w+|\*).*FROM.*INFORMATION_SCHEMA.SCHEMATA).*0x\w+)/i,
        "Find Current User by Error based"=>/(0x\w+.*(MID.*(CURRENT_USER\()).*0x\w+)/i,
        "Find Current Database by Error based"=>/(0x\w+.*(MID.*(DATABASE\()).*0x\w+)/i,
        "Find Table Count by Error based"=>/(0x\w+.*(SELECT.*(COUNT\((\w+|\*)).*FROM.*INFORMATION_SCHEMA.TABLES.*0x\w+))/i,
        "Find Table Name by Error based"=>/(0x\w+.*(SELECT.*(\w+|\*).*FROM.*INFORMATION_SCHEMA.TABLES.*0x\w+))/i,
        "Find Column Count by Error based"=>/(0x\w+.*(SELECT.*(COUNT\((\w+|\*)).*FROM.*INFORMATION_SCHEMA.COLUMNS.*0x\w+))/i,
        "Find Column Type by Error based"=>/(0x\w+.*(SELECT.*MID.*(column_type)).*FROM.*INFORMATION_SCHEMA.COLUMNS.*0x\w+)/i,
        "Find Column Name by Error based"=>/(0x\w+.*(SELECT.*MID.*(column_name)).*FROM.*INFORMATION_SCHEMA.COLUMNS.*0x\w+)/i,
        "Find Column Data Count by Error based"=>/(0x\w+.*(SELECT.*(COUNT\((\*|\w+).*FROM.*\w+\.\w+).*0x\w+))/i,
        "Find Column Data by Error based"=>/(0x\w+.*(SELECT.*MID.*(CAST.*(\w+).*FROM.*\w+\.\w+).*\w+))/i,
        "Brute Force Table Name by Error based"=>/(0x\w+.*EXISTS.(SELECT.\d+.FROM.*\w+).*0x\w+)/i,
        "Brute Force Column Name by Error based"=>/(0x\w+.*EXISTS.(SELECT.(\`|)(\[|\]|)(\w+|(\w+\-)*\w+)(\[|\]|)(\`|).FROM.*\w+).*0x\w+)/i,
  	    "Check String Repeat by Error based"=>/(0x\w+.*(SELECT.*REPEAT.*0x\w+))/i,

###########################
###  Time blind based ###
###########################
        "Find DBMS Version Infomation by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*ORD.*(MID.*(VERSION\(|@@VERSION\()))/i,
        "Find Hostname by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*ORD.*(MID.*(@@HOSTNAME)))/i,
        "Find DB Administrator by Time based"=>/(SELECT.*super_priv.*FROM.*mysql.user)/i,
        "Find User Count by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*ORD.*(MID.*(SELECT.*(COUNT.*(grantee).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES))))/i,
        "Find User Name by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*ORD.*(MID.*(SELECT.*((grantee)).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES)))/i,
        "Find Privileges Count by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*ORD.*(MID.*(SELECT.*(COUNT.*(privilege_type).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES))))/i,
        "Find Privileges Name by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*ORD.*(MID.*(SELECT.*((privilege_type)).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES)))/i,
        "Find Database Count by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*ORD.*(MID.*(SELECT.*(COUNT\(.*(\w+|\*).*FROM.*INFORMATION_SCHEMA.SCHEMATA))))/i,
        "Find Database Name by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*ORD.*(MID.*(SELECT.*(\w+|\*).*FROM.*INFORMATION_SCHEMA.SCHEMATA)))/i,
        "Find Current User by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*ORD.*(MID.*(CURRENT_USER\()))/i,
        "Find Current Database by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*ORD.*(MID.*(DATABASE\()))/i,
        "Find Table Count by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*ORD.*(MID.*(SELECT.*(COUNT\((\w+|\*)).*FROM.*INFORMATION_SCHEMA.TABLES)))/i,
        "Find Table Name by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*ORD.*(MID.*(SELECT.*(\w+|\*).*FROM.*INFORMATION_SCHEMA.TABLES)))/i,
        "Find Column Count by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*ORD.*(MID.*(SELECT.*(COUNT\((\w+|\*)).*FROM.*INFORMATION_SCHEMA.COLUMNS)))/i,
        "Find Column Type by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*ORD.*(MID.*(SELECT.*(column_type).*FROM.*INFORMATION_SCHEMA.COLUMNS)))/i,
        "Find Column Name by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*ORD.*(MID.*(SELECT.*(column_name).*FROM.*INFORMATION_SCHEMA.COLUMNS)))/i,
	    "Find Column Data Count by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*ORD.*(MID.*(SELECT.*(COUNT\((\*|\w).*FROM.*\w+\.\w+))))/i,
	    "Find Column Data by Time based"=>/((?=.*(SLEEP\(\d|BENCHMARK\(\d)).*ORD.*(MID.*(SELECT.*\w+.*FROM.*\w+\.\w+)))/i,
        "Brute Force Table Name by Time based"=>/(?=.*(SLEEP\(\d|BENCHMARK\(\d)).*(EXISTS.(SELECT.\d+.FROM.*\w+))/i,
        "Brute Force Column Name by Time based"=>/(?=.*(SLEEP\(\d|BENCHMARK\(\d)).*(EXISTS.(SELECT.(\`|)(\[|\]|)(\w+|(\w+\-)*\w+)(\[|\]|)(\`|).FROM.*\w+))/i,
        "Find Vulnerable Type by Time based"=>/(SLEEP\(\d|BENCHMARK\(\d)/i,

###############################
###  Boolean blind based ###
###############################
	"Find Vulnerable Type by Boolean based"=>/(\d+.(\=|\s|\>)\d+)|(\d+\=.*\d+)/i,
	"Find DBMS Version Infomation by Boolean based"=>/(ORD.*(MID.*(VERSION\(|@@VERSION)))/i,
	"Find Hostname by Boolean based"=>/(ORD.*(MID.*(@@HOSTNAME)))/i,
	"Find DB Administrator by Boolean based"=>/(SELECT.*super_priv.*FROM.*mysql.user)/i,
	"Find User Count by Boolean based"=>/(ORD.*(MID.*(SELECT.*(COUNT.*(grantee).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES))))/i,
	"Find User Name by Boolean based"=>/(ORD.*(MID.*(SELECT.*((grantee)).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES)))/i,
	"Find Privileges Count by Boolean based"=>/(ORD.*(MID.*(SELECT.*(COUNT.*(privilege_type).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES))))/i,
	"Find Privileges Name by Boolean based"=>/(ORD.*(MID.*(SELECT.*((privilege_type)).*FROM.*INFORMATION_SCHEMA.USER_PRIVILEGES)))/i,
	"Find Database Count by Boolean based"=>/(ORD.*(MID.*(SELECT.*(COUNT\(.*(\w+|\*).*FROM.*INFORMATION_SCHEMA.SCHEMATA))))/i,
	"Find Database Name by Boolean based"=>/(ORD.*(MID.*(SELECT.*(\w+|\*).*FROM.*INFORMATION_SCHEMA.SCHEMATA)))/i,
	"Find Current User by Boolean based"=>/(ORD.*(MID.*(CURRENT_USER\()))/i,
	"Find Current Database by Boolean based"=>/(ORD.*(MID.*(DATABASE\()))/i,
	"Find Table Count by Boolean based"=>/(ORD.*(MID.*(SELECT.*(COUNT\((\w+|\*)).*FROM.*INFORMATION_SCHEMA.TABLES)))/i,
	"Find Table Name by Boolean based"=>/(ORD.*(MID.*(SELECT.*(\w+|\*).*FROM.*INFORMATION_SCHEMA.TABLES)))/i,
	"Find Column Count by Boolean based"=>/(ORD.*(MID.*(SELECT.*(COUNT\((\w+|\*)).*FROM.*INFORMATION_SCHEMA.COLUMNS)))/i,
	"Find Column Type by Boolean based"=>/(ORD.*(MID.*(SELECT.*(column_type).*FROM.*INFORMATION_SCHEMA.COLUMNS)))/i,
	"Find Column Name by Boolean based"=>/(ORD.*(MID.*(SELECT.*(column_name).*FROM.*INFORMATION_SCHEMA.COLUMNS)))/i,
	"Find Column Data Count by Boolean based"=>/(ORD.*(MID.*(SELECT.*(COUNT\((\*|\w).*FROM.*\w+\.\w+))))/i,
    "Find Column Data by Boolean based"=>/(ORD.*(MID.*(SELECT.*\w+.*FROM.*\w+\.\w+)))/i,
	"Brute Force Table Name by Boolean based"=>/(EXISTS.(SELECT.\d+.FROM.*\w+))/i,
	"Brute Force Column Name by Boolean based"=>/(EXISTS.(SELECT.(\`|)(\[|\]|)(\w+|(\w+\-)*\w+)(\[|\]|)(\`|).FROM.*\w+))/i,

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

    condition:
        any of ($xss_payload*) or any of ($xss_image_payload*) or any of ($xss_svg_payload*)
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