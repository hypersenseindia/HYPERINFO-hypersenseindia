# HYPERINFO

**Passive OSINT for an IP address or hostname**, written in Bash for Termux.

The original build. Given an address, it assembles what is already public &mdash; WHOIS, ASN and ISP, reverse DNS, geolocation, certificate transparency, and public contact addresses &mdash; and prints one readable report.

**Passive only.** No ports are probed and the host is never contacted beyond ordinary DNS and WHOIS queries.

## Run

```bash
pkg install -y git python whois
git clone https://github.com/hypersenseindia/HYPERINFO-hypersenseindia
cd HYPERINFO-hypersenseindia
bash HYPERINFO.sh
```

Run passcode: `321`

## Output

A single terminal report: network ownership, resolved names, geolocation, certificate hostnames and any public contacts found in the records.

## Editions

- **This repository** &mdash; the original
- [HYPERINFO-FINAL](https://github.com/hypersenseindia/HYPERINFO-FINAL) &mdash; final CLI build
- [HYPERINFO-PAGES](https://github.com/hypersenseindia/HYPERINFO-PAGES) &mdash; page-by-page GUI report

## Legal

Public-record collection only. Do not use it to harass or identify private individuals. Scanning systems you do not own may be illegal in your jurisdiction.
---

<p align="center">
  <sub>Built by <b>AG HYDRAXFF</b> &mdash; HYPERSENSEGLOBAL &middot;
  <a href="https://www.instagram.com/hydraxff_yt/">@hydraxff_yt</a></sub>
</p>