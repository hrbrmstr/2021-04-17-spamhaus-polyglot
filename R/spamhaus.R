#!env Rscript

library(httr)
library(ipaddress)
library(stringi)
library(gdns)

# get cmdline args to see if this is where ips are
args <- commandArgs(trailingOnly = TRUE)

is_stdin <- FALSE

# if no cmdline args assume stdin
if ((length(args) == 0) | (args[1] == "-")) { # read from stdin
  ips <- readLines(file("stdin"), warn = FALSE)
  is_stdin <- TRUE
} else {
  ips <- args
}

ips <- unique(ips)

if (!length(ips)) exit(0) # bail if nothing to do

# validate the IPs
validate <- suppressWarnings(ip_address(ips)) 
bad <- ips[is.na(validate) | (!is_ipv4(validate))]

if (length(bad)) {
  warning(scales::comma(length(bad), 1), " invalid IPv4 addresses in input.")
}

# the good stuff (if any)
ok  <- ip_address(ips[is_ipv4(validate)])
if (length(ok) == 0) exit(0) # bail if no ips

# turn them into what spamhaus needs
spamhaus_ptr <- sub("in-addr.arpa", "zen.spamhaus.org", reverse_pointer(ok), fixed = TRUE)

# do the thing
lapply(
  spamhaus_ptr,
  curl::nslookup, ipv4_only = TRUE, multiple = TRUE, error = FALSE
) -> res

# if any answers are empty, mark them as not on the spamhaus block list
res[lengths(res) == 0] <- "nbl"
res <- unlist(setNames(res, ok))

# make a tidy data frame
merge(
  data.frame(
    ip = names(res),
    code = as.character(res)
  ),
  data.frame( # https://www.spamhaus.org/faq/section/DNSBL%20Usage#200
    code = c("nbl", "127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.9", "127.0.0.10", "127.0.0.11"),
    zone = c(NA_character_, "SBL", "SBL", "XBL", "SBL", "PBL", "PBL"),
    desc = c("Not on any Spamhaus blocklist", "Spamhaus SBL Data", "Spamhaus SBL CSS Data", "CBL Data", "Spamhaus DROP/EDROP Data", "ISP Maintained", "Spamhaus Maintained")
  ),
  by = "code",
  all.x = TRUE
) -> res

# if we got stuff via stdin, chances are good we want programmatic output
# so return ndjson, otherwise print the data frame
if (is_stdin) {
  jsonlite::stream_out(res[,c("ip", "code", "zone", "desc")], stdout(), verbose = FALSE)
} else {
  print(res[,c("ip", "code", "zone", "desc")]), max = nrow(res))
}
