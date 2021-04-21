package funcs

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

func AddHistory(word string)  {
	//检测到漏洞时将漏洞信息写入history.txt
	var mu sync.Mutex
	mu.Lock()
	defer mu.Unlock()
	{
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
}

func VulnerabilityChecking(url, req, poc string)  {
	//验证是否存在漏洞
	switch {
	case strings.Contains(req,"Active Internet connections") == true:
		fmt.Printf("\033[1;31m%s\033[0m\n","[+]Linux目标存在"+poc+"漏洞")
		AddHistory(url+" find "+poc+" successfully\n")

	case strings.Contains(req,"Active Connections") == true || strings.Contains(req,"活动连接") == true:
		fmt.Printf("\033[1;31m%s\033[0m\n","[+]Windows目标存在"+poc+"漏洞")
		AddHistory(url+" find "+poc+" successfully\n")

	case strings.Contains(req,"LISTEN") == true:
		fmt.Printf("\033[1;31m%s\033[0m\n","[+]目标存在"+poc+"漏洞")
		AddHistory(url+" find "+poc+" successfully\n")

	default:
		fmt.Printf("\033[1;32m%s\033[0m\n","[-]目标不存在"+poc+"漏洞")
	}
}

func GetFileUrl(file string) map[int]string {
	fi, err := os.Open(file)
	if err != nil {
		fmt.Printf("\033[1;31m%s%v\033[0m\n","请输入正确的文件信息", err)
	}
	defer fi.Close()

	target := make(map[int]string)
	i := 0
	br := bufio.NewReader(fi)
	for  {
		urll, _, eof := br.ReadLine()
		if eof == io.EOF {
			break
		}
		target[i] = string(urll)
		i++
	}
	return target
}

func ConcurrentChecking(url, req, poc string)  {
	//验证是否存在漏洞
	switch {
	case strings.Contains(req,"Active Internet connections") == true:
		AddHistory(url+" find "+poc+" successfully\n")
		fmt.Printf("\033[1;31m%s\033[0m\n","[+]Linux目标" + url +"存在"+poc+"漏洞")

	case strings.Contains(req,"Active Connections") == true || strings.Contains(req,"活动连接") == true:
		AddHistory(url+" find "+poc+" successfully\n")
		fmt.Printf("\033[1;31m%s\033[0m\n","[+]Windows目标" + url +"存在"+poc+"漏洞")

	case strings.Contains(req,"LISTEN") == true:
		AddHistory(url+" find "+poc+" successfully\n")
		fmt.Printf("\033[1;31m%s\033[0m\n","[+]目标" + url +"存在"+poc+"漏洞")

	default:
		return
	}
}

func Menu()  {
	now := time.Now()
	fmt.Printf("\033[1;35m%s\033[0m\n", " ____  _              _           ____      ____                                  ")
	fmt.Printf("\033[1;35m%s\033[0m\n", "/ ___|| |_ _ __ _   _| |_ ___    |___ \\    / ___|  ___ __ _ _ __  _ __   ___ _ __ ")
	fmt.Printf("\033[1;35m%s\033[0m\n", "\\___ \\| __| '__| | | | __/ __|     __) |   \\___ \\ / __/ _` | '_ \\| '_ \\ / _ \\ '__|")
	fmt.Printf("\033[1;35m%s\033[0m\n", " ___) | |_| |  | |_| | |_\\__ \\    / __/     ___) | (_| (_| | | | | | | |  __/ |   ")
	fmt.Printf("\033[1;35m%s\033[0m\n", "|____/ \\__|_|   \\__,_|\\__|___/___|_____|___|____/ \\___\\__,_|_| |_|_| |_|\\___|_|   ")
	fmt.Printf("\033[1;35m%s\033[0m\n", "                            |_____|   |_____|                                     ")
	fmt.Printf("\033[1;35m%d-%02d-%02d %02d:%02d:%02d\033[0m\n", now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second())
}