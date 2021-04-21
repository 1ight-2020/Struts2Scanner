package concurrentTask

import (
	sc "Struts2Scanner/concurrentTask/scanner"
	"Struts2Scanner/funcs"
	"Struts2Scanner/vars"
	"sync"
)

func Concurrent()  {
	url := funcs.GetFileUrl(vars.FILE)
	wg := &sync.WaitGroup{}
	wg.Add(vars.ThreadNum)
	taskChan := make(chan string, vars.ThreadNum)

	for i := 0; i < vars.ThreadNum ; i++ {
		go scan(wg, taskChan)
	}

	for _, target := range url{
		taskChan <- target
	}
	close(taskChan)
	wg.Wait()
}

func scan(wg *sync.WaitGroup, taskChan chan string)  {
	defer wg.Done()
	for {
		url, ok := <-taskChan
		if !ok {
			return
		}
		sc.VulScanner(url, wg)
	}
}