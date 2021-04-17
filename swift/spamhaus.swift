import Foundation
import Network

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

extension String {

  var spamhausPtr: String {
    self.split(separator: ".").reversed().joined(separator: ".").appending(".zen.spamhaus.org")
  }

}

extension Array where Element == String {
  func classifySpamhouse(_ ip: String) -> [String] {
    self.map{ res in 
      if (IPv4Address(ip) != nil) {
        switch res {
          case "127.0.0.2": return("\(ip) SBL Spamhaus SBL Data")
          case "127.0.0.3": return("\(ip) SBL Spamhaus SBL CSS Data")
          case "127.0.0.4": return("\(ip) XBL CBL Data")
          case "127.0.0.9": return("\(ip) SBL Spamhaus DROP/EDROP")
          case "127.0.0.10" :return("\(ip) PBL ISP Maintained")
          case "127.0.0.11" :return("\(ip) PBL Spamhaus Maintained")
          default: return("\(ip) Not on any Spamhaus blocklist")
        }
      } else {
        return("\(ip) is not a valid IPv4 address")
      }
    }
  }
}

var args: [String] = CommandLine.arguments

args.removeFirst(1)

if (args.count > 0) {

  args.map{ dig($0.spamhausPtr).classifySpamhouse($0)}.flatMap{$0}.forEach{print($0)}

} else {

  while let ip = readLine() {
    dig(ip.spamhausPtr).classifySpamhouse(ip).compactMap{$0}.forEach{print($0)}
  }

}
