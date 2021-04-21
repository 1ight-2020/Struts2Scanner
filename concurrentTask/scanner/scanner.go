package scanner

import (
	cvs "Struts2Scanner/concurrentTask/VulnerabilityScanner"
	"Struts2Scanner/funcs"
	"Struts2Scanner/vars"
	"sync"
)

//并发漏洞检测

func VulScanner(url string, wg *sync.WaitGroup) {
	wg.Add(20)
	go func() {
		req := cvs.Ppoc(vars.Poc["ST2_005"], url, vars.Header1)
		wg.Add(1)
		go func() {
			funcs.ConcurrentChecking(url, req,"struts2-005")
			wg.Done()
		}()
		wg.Done()
	}()

	go func() {
		req := cvs.Gpoc(vars.Poc["ST2_008_1"], url, vars.Header1)
		wg.Add(1)
		go func() {
			funcs.ConcurrentChecking(url, req,"struts2-008-1")
			wg.Done()
		}()
		wg.Done()
	}()

	go func() {
		req := cvs.Gpoc(vars.Poc["ST2_008_2"], url, vars.Header1)
		wg.Add(1)
		go func() {
			funcs.ConcurrentChecking(url, req,"struts2-008-2")
			wg.Done()
		}()
		wg.Done()
	}()

	go func() {
		req := cvs.Ppoc(vars.Poc["ST2_009"], url, vars.Header1)
		wg.Add(1)
		go func() {
			funcs.ConcurrentChecking(url, req,"struts2-009")
			wg.Done()
		}()
		wg.Done()
	}()

	go func() {
		req := cvs.Ppoc(vars.Poc["ST2_013"], url, vars.Header1)
		wg.Add(1)
		go func() {
			funcs.ConcurrentChecking(url, req,"struts2-013")
			wg.Done()
		}()
		wg.Done()
	}()

	go func() {
		req := cvs.Ppoc(vars.Poc["ST2_016"], url, vars.Header1)
		wg.Add(1)
		go func() {
			funcs.ConcurrentChecking(url, req,"struts2-016")
			wg.Done()
		}()
		wg.Done()
	}()

	go func() {
		cvs.Gpoc017(url, vars.Header1)
		wg.Done()
	}()

	go func() {
		req := cvs.Ppoc(vars.Poc["ST2_019"], url, vars.Header1)
		wg.Add(1)
		go func() {
			funcs.ConcurrentChecking(url, req,"struts2-019")
			wg.Done()
		}()
		wg.Done()
	}()

	go func() {
		req := cvs.Gpoc(vars.Poc["ST2_devmode"], url, vars.Header1)
		wg.Add(1)
		go func() {
			funcs.ConcurrentChecking(url, req,"struts2-devmode")
			wg.Done()
		}()
		wg.Done()
	}()

	go func() {
		req := cvs.Gpoc(vars.Poc["ST2_032"], url, vars.Header1)
		wg.Add(1)
		go func() {
			funcs.ConcurrentChecking(url, req,"struts2-032")
			wg.Done()
		}()
		wg.Done()
	}()

	go func() {
		req := cvs.Gpoc(vars.Poc["ST2_033"], url, vars.Header1)
		wg.Add(1)
		go func() {
			funcs.ConcurrentChecking(url, req,"struts2-033")
			wg.Done()
		}()
		wg.Done()
	}()

	go func() {
		req := cvs.Gpoc(vars.Poc["ST2_037"], url, vars.Header1)
		wg.Add(1)
		go func() {
			funcs.ConcurrentChecking(url, req,"struts2-037")
			wg.Done()
		}()
		wg.Done()
	}()

	go func() {
		req := cvs.Gpoc("", url, vars.Header2)
		wg.Add(1)
		go func() {
			funcs.ConcurrentChecking(url, req,"struts2-045")
			wg.Done()
		}()
		wg.Done()
	}()

	go func() {
		cvs.Gpoc0452(url)
		wg.Done()
	}()

	go func() {
		req := cvs.Ppoc046(url,vars.Header1)
		wg.Add(1)
		go func() {
			funcs.ConcurrentChecking(url, req,"struts2-046")
			wg.Done()
		}()
		wg.Done()
	}()

	go func() {
		req := cvs.Ppoc048(url, vars.Header1)
		wg.Add(1)
		go func() {
			funcs.ConcurrentChecking(url, req, "struts2-048")
			wg.Done()
		}()
		wg.Done()
	}()

	go func() {
		cvs.Ppoc020(url, vars.Header1)
		wg.Done()
	}()

	go func() {
		cvs.Ppoc052(url, vars.Header3)
		wg.Done()
	}()

	go func() {
		cvs.Gpoc053(url, vars.Header1)
		wg.Done()
	}()

	go func() {
		cvs.Gpoc057(url, vars.Header1)
		wg.Done()
	}()
}

