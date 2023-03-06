package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"strings"
	"github.com/kuron3k0/subjack/subjack"
	"encoding/json"
	"net/http"
	"sync"
)

func main() {
	var domain string
	var file string
	var webhook string
	flag.StringVar(&domain, "d", "", "domain to check")
	flag.StringVar(&file, "f", "", "file contain domains")
	flag.StringVar(&webhook, "wh", "", "webhook url to post result")
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
				if len(ret["type"]) > 0 && ret["type"] != "nxdomain_cannot_register_with_no_fingerprint"{
					result <- ret
				}
				<-ch
			}(d)
		}
		wg.Wait()

		close(result)
		list := make([]map[string]string, len(result))
		for r := range result {
			append(list, r)
		}
		if webhook != "" {
			b, _ := json.Marshal(list)
			resp, err := http.Post(webhook,
				"application/json",
				bytes.NewBuffer(b))
			if err != nil {
				fmt.Println(err)
				return
			}
			defer resp.Body.Close()
			body, _ := ioutil.ReadAll(resp.Body)
			fmt.Println(string(body))
			return
		}else{
			fmt.Println(list)
		}

	}

}
