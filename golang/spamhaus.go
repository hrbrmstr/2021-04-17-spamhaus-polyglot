package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

func reverse(ss []string) {
	last := len(ss) - 1
	for i := 0; i < len(ss)/2; i++ {
		ss[i], ss[last-i] = ss[last-i], ss[i]
	}
}

type ipRec struct {
	Ip string   `json:"ip"`
	Code string `json:"code"`
	Zone string `json:"zone"`
	Desc string `json:"desc"`
}

func jsonRec(rec ipRec) string {
	js, err := json.Marshal(rec)
	if err != nil {
		return("==>{}")
	}
	return(string(js))
}

func humanRec(rec ipRec) string {
	return(rec.Ip + " " + rec.Zone + " " + rec.Desc)
}

func isValidIPv4(ip string) bool {
	parsed := net.ParseIP(ip)
	if (parsed == nil) { return(false) }
	return(parsed.To4() != nil)
}

func classifySpamhaus(arg string) []ipRec {
	
	out := []ipRec{}
	
	if (!isValidIPv4(arg)) {
		out = append(out, ipRec{arg, "NA", "NA", "Not a valid IPv4 address"})
		return(out)
	}
	
	octets := strings.Split(arg, ".")
	reverse(octets)
	
	ip := (strings.Join(octets, ".")) + ".zen.spamhaus.org"
	
	ips, err := net.LookupIP(ip)
	
	if err != nil {
		out = append(out, ipRec{arg, "NA", "nbl", "Not on any Spamhaus blocklist"})
	} else {
		for _, res := range ips {
			switch res.String() {
				case  "127.0.0.2": out = append(out, ipRec{ arg, res.String(), "SBL", "Spamhaus SBL Data"})
				case  "127.0.0.3": out = append(out, ipRec{ arg, res.String(), "SBL", "Spamhaus SBL CSS Data"})
				case  "127.0.0.4": out = append(out, ipRec{ arg, res.String(), "XBL", "CBL Data"})
				case  "127.0.0.9": out = append(out, ipRec{ arg, res.String(), "SBL", "Spamhaus DROP/EDROP"})
				case "127.0.0.10": out = append(out, ipRec{ arg, res.String(), "PBL", "ISP Maintained"})
				case "127.0.0.11": out = append(out, ipRec{ arg, res.String(), "PBL", "Spamhaus Maintained"})
				default: out = append(out, ipRec{ arg, "nbl", "NA", "Not on any Spamhaus blocklist"})
			}
		}
	}
	
	return(out)
	
}
	
func main() {
	
	args := os.Args[1:]
	
	// input on stdin
	if (len(args) == 0) || ((len(args) == 1) && (args[0] == "-")) {
		
		stdin := bufio.NewScanner(os.Stdin)
		for stdin.Scan() {
			txt := stdin.Text()
			for _, out := range classifySpamhaus(txt) {
				fmt.Println(jsonRec(out))
			}
		}
		
	} else {
			
		for _, arg := range args {
			for _, out := range classifySpamhaus(arg) {
				fmt.Println(humanRec(out))
			}
		}
	}
		
}