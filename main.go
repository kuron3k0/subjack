package main

import (
	"flag"
	"fmt"
	"bytes"
	"io/ioutil"
	"strings"
	"github.com/kuron3k0/subjack/subjack"
	"encoding/json"
	"net/http"
	"sync"
	"net/url"
)

func notify_webhook(r map[string]string, webhook string) {
	b, err := json.Marshal(r)
	if err != nil {
		fmt.Println(err)
		return
	}
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
}

func main() {
	var domain string
	var file string
	var webhook string
	var thread int
	flag.StringVar(&domain, "d", "", "domain to check")
	flag.StringVar(&file, "f", "", "file contain domains")
	flag.StringVar(&webhook, "wh", "", "webhook url to post result")
	flag.IntVar(&thread, "t", 100, "thread nums")
	flag.Parse()
	if domain != "" {
		takevoer_result := subjack.Runner(domain)
		if takevoer_result != nil && len(takevoer_result["type"]) > 0 && takevoer_result["type"] != "nxdomain_cannot_register_with_no_fingerprint"{
			if webhook != ""{
				notify_webhook(takevoer_result, webhook)
			}else{
				fmt.Println(takevoer_result)
			}
		}

	} else if file != "" {
		content, err := ioutil.ReadFile(file)
		if err != nil {
			fmt.Println("file read error", err)
			return
		}
		domains := strings.Split(string(content), "\n")
		var wg sync.WaitGroup
		ch := make(chan bool, thread)

		result := make(chan map[string]string, len(domains))
		for _, d := range domains {
			ch <- true
			wg.Add(1)
			go func(d string) {
				defer wg.Done()
				if strings.HasPrefix(d, "http") {
					u, err := url.Parse(d)
					if err != nil {
						fmt.Println(err)
						return
					}
					d = strings.Split(u.Host,":")[0]
				}
				ret := subjack.Runner(d)
				if ret != nil && len(ret["type"]) > 0 && ret["type"] != "nxdomain_cannot_register_with_no_fingerprint"{
					result <- ret
				}
				<-ch
			}(d)
		}
		wg.Wait()
		close(result)

		if webhook != "" {
			for r := range result{
				notify_webhook(r, webhook)
			}
			
			return
		}else{
			fmt.Println(result)
		}

	}

}
