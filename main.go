package main

import (
	"Struts2Scanner/concurrentTask"
	"Struts2Scanner/funcs"
	"Struts2Scanner/scanner"
	"Struts2Scanner/vars"
	"bufio"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
)

func init()  {
	runtime.GOMAXPROCS(runtime.NumCPU())
	flag.StringVar(&vars.URL,"u","","测试目标URL")
	flag.StringVar(&vars.NAME,"n","","漏洞名称（执行shell）")
	flag.StringVar(&vars.FILE, "f", "", "导入.txt文件批量检测")
}

func main()  {
	flag.Parse()
	funcs.Menu()
	for {
		switch {
		case vars.URL == "" && vars.NAME == "" && vars.FILE == "":
			fmt.Printf("\033[1;31m%s\033[0m\n","请输入完整信息，例如：Struts2Scanner -u http://127.0.0.1/struts2-showcase/index.action -n struts2-005 或者 Struts2Scanner -f ./test.txt")
			return

		case vars.URL != "" && vars.NAME == "":
			scanner.VulnerabilityScanner(vars.URL)
			return

		case vars.NAME != "" && vars.URL != "":
			fmt.Printf("%v", "shell>>")
			reader := bufio.NewReader(os.Stdin)
			command, err := reader.ReadString('\n')
			if err != nil {
				fmt.Println(err)
				return
			}
			cmd := strings.Replace(command, "\n", "", -1)
			if cmd == "exit" {
				return
			}
			scanner.CommandExecution(vars.URL, vars.NAME, cmd)

		case vars.FILE != "":
			concurrentTask.Concurrent()
			return

		default:
			fmt.Printf("\033[1;31m%s\033[0m\n","请输入完整信息，例如：Struts2Scanner -u http://127.0.0.1/struts2-showcase/index.action -n struts2-005")
			return
		}
	}
}
