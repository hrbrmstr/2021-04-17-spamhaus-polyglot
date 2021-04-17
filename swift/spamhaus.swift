import Foundation
import Network

// MARK: helper to lookup hostnames

func dig(_ host: String) -> [String] {

  let host = CFHostCreateWithName(nil, host as CFString).takeRetainedValue()
  CFHostStartInfoResolution(host, .addresses, nil)

  var success: DarwinBoolean = false
  var out: [String] = []

  if let addresses = CFHostGetAddressing(host, &success)?.takeUnretainedValue() as NSArray? {

    out.reserveCapacity(addresses.count)

    for case let addr as NSData in addresses {

      var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))

      let res = getnameinfo(
        addr.bytes.assumingMemoryBound(to: sockaddr.self), socklen_t(addr.length),
        &hostname, socklen_t(hostname.count), nil, 0, NI_NUMERICHOST
      )

      if res == 0 { out.append(String(cString: hostname)) }

    }

  } else {
    out = [ "nbl" ]
  }

  return(out)
  
}

// MARK: helper to turn a.b.c.d into d.c.b.a.zen.spamhaus.org
extension String {

  var spamhausPtr: String {
    self.split(separator: ".")
        .reversed()
        .joined(separator: ".")
        .appending(".zen.spamhaus.org")
  }

}

// MARK: holds our IP classification data; also has output helpers
struct ipRec: Codable {
  
  let ip: String
  let code: String
  let zone: String
  let desc: String
  
  var json: String {
    try! String(data: JSONEncoder().encode(self), encoding: .utf8) ?? "{}"
  }
  
  var description: String {
    return "\(ip) \(zone) \(desc)"
  }
  
}

// MARK: helper to do the IP classifications in a more functional way
extension Array where Element == String {
  func classifySpamhaus(_ ip: String) -> [ipRec] {
    self.map{ res in
      if let _ =  IPv4Address(ip) {
        switch res {
          case  "127.0.0.2": return(ipRec(ip: ip, code: res,   zone: "SBL", desc: "Spamhaus SBL Data"))
          case  "127.0.0.3": return(ipRec(ip: ip, code: res,   zone: "SBL", desc: "Spamhaus SBL CSS Data"))
          case  "127.0.0.4": return(ipRec(ip: ip, code: res,   zone: "XBL", desc: "CBL Data"))
          case  "127.0.0.9": return(ipRec(ip: ip, code: res,   zone: "SBL", desc: "Spamhaus DROP/EDROP"))
          case "127.0.0.10": return(ipRec(ip: ip, code: res,   zone: "PBL", desc: "ISP Maintained"))
          case "127.0.0.11": return(ipRec(ip: ip, code: res,   zone: "PBL", desc: "Spamhaus Maintained"))
                    default: return(ipRec(ip: ip, code: "nbl", zone: "NA",  desc: "Not on any Spamhaus blocklist"))
        }
      } else {
        return(ipRec(ip: ip, code: "NA", zone: "NA", desc: "Not a valid IPv4 address"))
      }
    }
  }
}

var args: [String] = CommandLine.arguments
args.removeFirst(1)

if ((args.count == 0) || ((args.count == 1) && (args[0] == "-"))) { // use stdin if no args or `-`
  while let ip = readLine() {
    dig(ip.spamhausPtr)
      .classifySpamhaus(ip)
      .compactMap{$0}
      .forEach{ print($0.json) }
  }
} else { // read from the supplied args
  args.map{ dig($0.spamhausPtr).classifySpamhaus($0)}
      .flatMap{$0}
      .forEach{ print($0.description) }
}
