package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"strings"
	"subjack/subjack"
	"sync"
)

func main() {
	var domain string
	var file string
	flag.StringVar(&domain, "d", "", "domain to check")
	flag.StringVar(&file, "f", "", "file contain domains")
	flag.Parse()
	if domain != "" {
		fmt.Println(subjack.Runner(domain))
	} else if file != "" {
		content, err := ioutil.ReadFile(file)
		if err != nil {
			fmt.Println("file read error", err)
			return
		}
		domains := strings.Split(string(content), "\n")
		var wg sync.WaitGroup
		ch := make(chan bool, 5000)
		result := make(chan map[string]string, len(domains))
		for _, d := range domains {
			ch <- true
			wg.Add(1)
			go func(d string) {
				defer wg.Done()
				ret := subjack.Runner(d)
				if len(ret["type"]) > 0 {
					result <- ret
				}
				<-ch
			}(d)
		}
		wg.Wait()

		close(result)
		for r := range result {
			fmt.Println(r)
		}
	}

}
