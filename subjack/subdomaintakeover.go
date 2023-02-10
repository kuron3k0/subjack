package subjack

import (
	"crypto/tls"
	"fmt"
	"github.com/haccer/available"
	"github.com/miekg/dns"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type Fingerprints struct {
	Service          string   `json:"service"`
	Cname            []string `json:"cname"`
	Fingerprint      []string `json:"fingerprint"`
	Nxdomain         bool     `json:"nxdomain"`
	Must_match_cname bool     `json:"must_match_cname"`
}

var fingerprints = []Fingerprints{
	Fingerprints{Service: "leadpages", Cname: []string{"leadpages.net"}, Fingerprint: []string{"Double check that you have the right web address and give it another go!</p>"}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "appery.io", Cname: []string{}, Fingerprint: []string{"This page will be updated automatically when your app is published"}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "getcloudapp", Cname: []string{"custom.getcloudapp.com"}, Fingerprint: []string{"Screen Recording Software for Mac &amp; PC | CloudApp"}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "branch.io", Cname: []string{"custom.bnc.lt"}, Fingerprint: []string{"What Is app.link And How Does It Work? | Branch"}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "AnnounceKit", Cname: []string{"cname.announcekit.app"}, Fingerprint: []string{"Error 404 - AnnounceKit"}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "Meteor cloud", Cname: []string{"galaxy-ingress.meteor.com"}, Fingerprint: []string{"404 Not Found: No applications registered for host "}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "softr.io", Cname: []string{}, Fingerprint: []string{"The application you were looking for was built on Softr, <br>"}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "Feedpress", Cname: []string{}, Fingerprint: []string{"The feed has not been found."}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "Flywheel", Cname: []string{}, Fingerprint: []string{"We're sorry, you've landed on a page that is hosted by Flywheel"}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "easyredir", Cname: []string{}, Fingerprint: []string{"www.easyredircdn.com/pages/v2/404-host-not-found.html"}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "Worksites", Cname: []string{}, Fingerprint: []string{"Hello! Sorry, but the website you&rsquo;re looking for doesn&rsquo;t exist."}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "webflow", Cname: []string{"webflow.com"}, Fingerprint: []string{"Page not found"}, Nxdomain: false, Must_match_cname: true},
	Fingerprints{Service: "uptimerobot", Cname: []string{"stats.uptimerobot.com"}, Fingerprint: []string{"page not found"}, Nxdomain: false, Must_match_cname: true},
	Fingerprints{Service: "tilda", Cname: []string{}, Fingerprint: []string{"Please go to the site settings and put the domain name in the Domain tab."}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "SurveySparrow", Cname: []string{"surveysparrow.com"}, Fingerprint: []string{"Account not found."}, Nxdomain: false, Must_match_cname: true},
	Fingerprints{Service: "Strikingly", Cname: []string{"strikinglydns.com"}, Fingerprint: []string{"PAGE NOT FOUND"}, Nxdomain: false, Must_match_cname: true},
	Fingerprints{Service: "SmartJobBoard", Cname: []string{}, Fingerprint: []string{"This job board website is either expired or its domain name is invalid."}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "Short.io", Cname: []string{}, Fingerprint: []string{}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "Readthedocs", Cname: []string{"readthedocs.io"}, Fingerprint: []string{"is unknown to Read the Docs"}, Nxdomain: false, Must_match_cname: true},
	Fingerprints{Service: "Readme.io", Cname: []string{"readme.io", "readmessl.com"}, Fingerprint: []string{"<h1>Not Yet Active</h1>", "Project doesnt exist... yet!"}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "Pingdom", Cname: []string{"pingdom.com"}, Fingerprint: []string{">Public Report Not Activated</", "Sorry, couldn't find the status page"}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "Pantheon", Cname: []string{}, Fingerprint: []string{"404 error unknown site!"}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "Ngrok", Cname: []string{}, Fingerprint: []string{".ngrok.io not found"}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "netlify", Cname: []string{"netlify.app", "netlify.com", "netlifyglobalcdn.com"}, Fingerprint: []string{"Not Found - Request ID:"}, Nxdomain: false, Must_match_cname: true},
	Fingerprints{Service: "LaunchRock", Cname: []string{"example.launchrock.com"}, Fingerprint: []string{"It looks like you may have taken a wrong turn somewhere. Don't worry...it happens to all of us."}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "Helprace", Cname: []string{}, Fingerprint: []string{"Admin of this Helprace account needs to set up domain alias"}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "Help Scout", Cname: []string{"helpscoutdocs.com"}, Fingerprint: []string{"No settings were found for this company:"}, Nxdomain: false, Must_match_cname: true},
	Fingerprints{Service: "Help Juice", Cname: []string{"helpjuice.com"}, Fingerprint: []string{"We could not find what you're looking for."}, Nxdomain: false, Must_match_cname: true},
	Fingerprints{Service: "HatenaBlog", Cname: []string{"hatenablog.com"}, Fingerprint: []string{"404 Blog is not found"}, Nxdomain: false, Must_match_cname: true},
	Fingerprints{Service: "Gemfury", Cname: []string{"furyns.com"}, Fingerprint: []string{"404: This page could not be found."}, Nxdomain: false, Must_match_cname: true},
	Fingerprints{Service: "Digital Ocean", Cname: []string{}, Fingerprint: []string{"Domain uses DO name servers with no records in DO."}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "Cargo Collective", Cname: []string{"corgocollective"}, Fingerprint: []string{"404 Not Found"}, Nxdomain: false, Must_match_cname: true},
	Fingerprints{Service: "Canny", Cname: []string{}, Fingerprint: []string{"There is no such company. Did you enter the right URL?"}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "Campaign Monitor", Cname: []string{}, Fingerprint: []string{"Trying to access your account?"}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "Anima", Cname: []string{"animaapp.com"}, Fingerprint: []string{"If this is your website and you've just created it, try refreshing in a minute"}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "Airee.ru", Cname: []string{"airee.ru"}, Fingerprint: []string{"Ошибка 402. Сервис Айри.рф не оплачен"}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "Agile CRM", Cname: []string{"agilecrm.com"}, Fingerprint: []string{"Sorry, this page is no longer available.", "No landing page found."}, Nxdomain: false, Must_match_cname: true},
	Fingerprints{Service: "AWS/Elastic Beanstalk", Cname: []string{"elasticbeanstalk.com"}, Fingerprint: []string{}, Nxdomain: true, Must_match_cname: false},
	Fingerprints{Service: "fastly", Cname: []string{"fastly"}, Fingerprint: []string{"Fastly error: unknown domain"}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "github", Cname: []string{"github.io"}, Fingerprint: []string{"There isn't a GitHub Pages site here."}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "heroku", Cname: []string{"herokuapp"}, Fingerprint: []string{"herokucdn.com/error-pages/no-such-app.html"}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "pantheon", Cname: []string{"pantheonsite.io"}, Fingerprint: []string{"404 error unknown site!", "The gods are wise, but do not know of the site which you seek."}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "tumblr", Cname: []string{"domains.tumblr.com"}, Fingerprint: []string{"Whatever you were looking for doesn't currently exist at this address."}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "wordpress", Cname: []string{"wordpress.com"}, Fingerprint: []string{"Do you want to register"}, Nxdomain: false, Must_match_cname: true},
	Fingerprints{Service: "teamwork", Cname: []string{"teamwork.com"}, Fingerprint: []string{"Oops - We didn't find your site."}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "s3 bucket", Cname: []string{"amazonaws"}, Fingerprint: []string{"<Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message>", "<li>Message: The specified bucket does not exist</li>"}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "ghost", Cname: []string{"ghost.io"}, Fingerprint: []string{"The thing you were looking for is no longer here, or never was"}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "shopify", Cname: []string{"myshopify.com"}, Fingerprint: []string{"Sorry, this shop is currently unavailable."}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "uservoice", Cname: []string{"uservoice.com"}, Fingerprint: []string{"This UserVoice subdomain is currently available!"}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "surge", Cname: []string{"surge.sh"}, Fingerprint: []string{"project not found"}, Nxdomain: false, Must_match_cname: true},
	Fingerprints{Service: "bitbucket", Cname: []string{"bitbucket.io"}, Fingerprint: []string{"Repository not found"}, Nxdomain: false, Must_match_cname: true},
	Fingerprints{Service: "intercom", Cname: []string{"custom.intercom.help"}, Fingerprint: []string{"This page is reserved for artistic dogs.", "Uh oh. That page doesn't exist.</h1>"}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "webflow", Cname: []string{"proxy.webflow.com", "proxy-ssl.webflow.com"}, Fingerprint: []string{"<p class=\"description\">The page you are looking for doesn't exist or has been moved.</p>"}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "wishpond", Cname: []string{"wishpond.com"}, Fingerprint: []string{"https://www.wishpond.com/404?campaign=true"}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "aftership", Cname: []string{"aftership.com"}, Fingerprint: []string{"Oops.</h2><p class=\"text-muted text-tight\">The page you're looking for doesn't exist."}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "aha", Cname: []string{"ideas.aha.io"}, Fingerprint: []string{"There is no portal here ... sending you back to Aha!"}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "tictail", Cname: []string{"domains.tictail.com"}, Fingerprint: []string{"to target URL: <a href=\"https://tictail.com", "Start selling on Tictail."}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "brightcove", Cname: []string{"bcvp0rtal.com", "brightcovegallery.com", "gallery.video"}, Fingerprint: []string{"<p class=\"bc-gallery-error-code\">Error Code: 404</p>"}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "bigcartel", Cname: []string{"bigcartel.com"}, Fingerprint: []string{"<h1>Oops! We could&#8217;t find that page.</h1>"}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "campaignmonitor", Cname: []string{"createsend.com"}, Fingerprint: []string{"Double check the URL or <a href=\"mailto:help@createsend.com"}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "acquia", Cname: []string{"acquia-test.co"}, Fingerprint: []string{"The site you are looking for could not be found."}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "simplebooklet", Cname: []string{"simplebooklet.com"}, Fingerprint: []string{"We can't find this <a href=\"https://simplebooklet.com"}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "getresponse", Cname: []string{".gr8.com"}, Fingerprint: []string{"With GetResponse Landing Pages, lead generation has never been easier"}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "vend", Cname: []string{"vendecommerce.com"}, Fingerprint: []string{"Looks like you've traveled too far into cyberspace"}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "jetbrains", Cname: []string{"myjetbrains.com", "youtrack.cloud"}, Fingerprint: []string{"is not a registered InCloud YouTrack."}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "azure", Cname: []string{".azurewebsites.net", ".cloudapp.net", ".cloudapp.azure.com", ".trafficmanager.net", ".blob.core.windows.net", ".azure-api.net", ".azurehdinsight.net", ".azureedge.net"}, Fingerprint: []string{}, Nxdomain: true, Must_match_cname: false},
	Fingerprints{Service: "zendesk", Cname: []string{"zendesk.com"}, Fingerprint: []string{"Help Center Closed"}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "readme", Cname: []string{"readme.io"}, Fingerprint: []string{"Project doesnt exist... yet!"}, Nxdomain: false, Must_match_cname: false},
	Fingerprints{Service: "apigee", Cname: []string{"-portal.apigee.net"}, Fingerprint: []string{}, Nxdomain: true, Must_match_cname: false},
	Fingerprints{Service: "smugmug", Cname: []string{"domains.smugmug.com"}, Fingerprint: []string{}, Nxdomain: true, Must_match_cname: false},
	Fingerprints{Service: "worksites.net", Cname: []string{}, Fingerprint: []string{"Hello! Sorry, but the website you&rsquo;re looking for doesn&rsquo;t exist.</p>\n<a href=\"https://worksites.net/\">Learn more about Worksites.net"}, Nxdomain: false, Must_match_cname: false},
}

var nsFingerprints = map[string]*regexp.Regexp{
	"000Domains":           regexp.MustCompile(`(ns1|ns2|fwns1|fwns2)\.000domains\.com`),
	"Azure":                regexp.MustCompile(`ns(1|2|3|4)-[\w\-]+\.azure-dns\.(com|net|org|info)`),
	"Bizland":              regexp.MustCompile(`ns(1|2)\.bizland\.com|clickme2?\.click2site\.com`),
	"Cloudflare":           regexp.MustCompile(`ns\.cloudflare\.com`),
	"Digital Ocean":        regexp.MustCompile(`ns(1|2|3)\.digitalocean\.com`),
	"DNSMadeEasy":          regexp.MustCompile(`ns[\w\-]*\.dnsmadeeasy\.com`),
	"DNSimple":             regexp.MustCompile(`ns(1|2|3|4)\.dnsimple\.com`),
	"Domain.com":           regexp.MustCompile(`ns(1|2)\.domain\.com`),
	"Dotster":              regexp.MustCompile(`ns(1|2)\.dotster\.com|ns(1|2)\.nameresolve\.com`),
	"EasyDNS":              regexp.MustCompile(`dns(1|2|3|4)\.easydns\.(com|net|org|info)`),
	"Google Cloud":         regexp.MustCompile(`ns-cloud-[\w\-]+\.googledomains\.com`),
	"Hurricane Electric":   regexp.MustCompile(`ns(1|2|3|4|5)\.he\.net`),
	"Linode":               regexp.MustCompile(`ns(1|2)\.linode\.com`),
	"MyDomain":             regexp.MustCompile(`ns(1|2)\.mydomain\.com`),
	"Name.com":             regexp.MustCompile(`ns[\w\-]+\.name\.com`),
	"NS1":                  regexp.MustCompile(`dns(1|2|3|4)\.p[\w\-]+\.nsone\.net`),
	"TierraNet":            regexp.MustCompile(`ns(1|2)\.domaindiscover\.com`),
	"Reg.ru":               regexp.MustCompile(`ns(1|2)\.reg\.ru`),
	"Yahoo Small Business": regexp.MustCompile(`yns(1|2)\.yahoo\.com`),
}

func HttpGet(domain string) (string, error) {
	var body []byte
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   time.Second * 5,
	}
	resp, err := client.Get("http://" + domain)
	if err != nil {
		fmt.Println("http error:", err)
		resp, err = client.Get("https://" + domain)
		if err != nil {
			fmt.Println("https error:", err)
			return "", err
		} else {
			body, err = ioutil.ReadAll(resp.Body)
			return string(body), nil
		}

	}

	body, err = ioutil.ReadAll(resp.Body)
	return string(body), nil

}

func RecursionResolveNS(domain string) []string {
	items := strings.Split(domain, ".")
	items = items[len(items)-2:]
	ns := "8.8.8.8:53"
	d := new(dns.Msg)
	var ans []dns.RR
	var result_nameservers []string

	for i := len(items) - 1; i >= 0; i-- {
		fmt.Println(strings.Join(items[i:], "."))
		d.SetQuestion(dns.Fqdn(strings.Join(items[i:], ".")), dns.TypeNS)
		ret, err := dns.Exchange(d, ns)
		if err != nil {
			fmt.Println(err)
		}

		if len(ret.Answer) > 0 {
			ans = ret.Answer
		} else {
			ans = ret.Ns
		}

		for _, ns_result := range ans {
			tmp_ns := strings.Trim(strings.Split(ns_result.String(), ns_result.Header().String())[1], " ")
			if strings.HasSuffix(tmp_ns, ".") && len(tmp_ns) > 1 {
				ns = tmp_ns[:len(tmp_ns)-1] + ":53"
				break
			}
		}
	}

	for _, ns_result := range ans {
		tmp_ns := strings.Trim(strings.Split(ns_result.String(), ns_result.Header().String())[1], " ")
		if strings.HasSuffix(tmp_ns, ".") && len(tmp_ns) > 1 {
			result_nameservers = append(result_nameservers, tmp_ns[:len(tmp_ns)-1])
		}
	}

	return result_nameservers
}

func DomainResolveStatus(domain string) int8 {
	if _, err := net.LookupHost(domain); err != nil {
		switch e := err.(type) {
		case *net.DNSError:
			switch e.Err {
			case "no such host":
				return 1
			case "server fail":
				return 2
			case "server misbehaving":
				return 2
			default:
				fmt.Println(e.Err)
				return 3
			}
		default:
			fmt.Println(err.Error())
			return 3
		}
	}
	return 0
}

func CheckNameServer(domain string) map[string]string {
	// https://github.com/indianajson/can-i-take-over-dns
	res := make(map[string]string)
	nameservers := RecursionResolveNS(domain)
	for _, ns := range nameservers {
		for name, pattern := range nsFingerprints {
			if pattern.Match([]byte(ns)) {
				res["service"] = name
				res["nameserver"] = ns
				res["domain"] = domain
				res["type"] = "nameserver_with_fingerprint"
				return res
			}
		}
	}

	return res

}

func Runner(domain string) map[string]string {
	res := make(map[string]string)
	cname, _ := net.LookupCNAME(domain)
	if cname != "" && len(cname) < 5 {
		return res
	}
	body, err := HttpGet(domain)
	if err != nil {
		fmt.Println(err.Error())
	}
	status := DomainResolveStatus(cname)
	if status == 2 {
		return CheckNameServer(domain)
	}

	for f := range fingerprints {
		if status == 1 {
			dead := available.Domain(cname)
			if dead {
				res["cname"] = cname
				res["domain"] = domain
				res["type"] = "nxdomain_can_register_with_no_fingerprint"
				return res
			}

			if fingerprints[f].Nxdomain {
				for n := range fingerprints[f].Cname {
					if strings.Contains(cname, fingerprints[f].Cname[n]) {
						service := strings.ToUpper(fingerprints[f].Service)
						res["cname"] = cname
						res["service"] = service
						res["domain"] = domain
						res["type"] = "nxdomain_cannot_register_with_fingerprint"
						return res

					}
				}
			}

			if !dead && cname != "" {
				res["cname"] = cname
				res["domain"] = domain
				res["type"] = "nxdomain_cannot_register_with_no_fingerprint"
				return res
			}
		}

		for n := range fingerprints[f].Fingerprint {
			if strings.Contains(strings.ToLower(body), strings.ToLower(fingerprints[f].Fingerprint[n])) {
				if fingerprints[f].Must_match_cname {
					cflag := false
					for _, c := range fingerprints[f].Cname {
						if strings.Contains(cname, c) {
							cflag = true
							break
						}
					}
					for _, c := range fingerprints[f].Cname {
						if strings.Contains(domain, c) {
							cflag = true
							break
						}
					}
					if !cflag {
						continue
					}
				}
				service := strings.ToUpper(fingerprints[f].Service)
				res["cname"] = cname
				res["service"] = service
				res["domain"] = domain
				res["type"] = "common_domain_with_fingerprint"
				return res
			}
		}
	}

	return res
}
