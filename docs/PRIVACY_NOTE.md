# Privacy note

## No real scan data in this repository

This repository contains no real scan data. There is no Nessus export, no raw HTML report and no file that lists real host names or IP addresses.

The toolkit was developed during an MS Cyber Security capstone project against scans from a six property hotel group in South India. The group is not named here because the author has no approval to name it. None of its scan files, host names, IP addresses, MAC addresses, domain names, user names, licence keys, property names, product names or staff names appear in the code, tests, configuration, documentation, outputs or images.

## What the repository contains instead

Everything the code, the tests, the dashboard and the charts show comes from synthetic sample data.

- `tools/make_sample_data.py` generates 19 invented Nessus style HTML exports into `sample_data/nessus_html/`. The output is deterministic.
- All sample hosts use addresses from the documentation ranges 192.0.2.0/24 and 198.51.100.0/24 (RFC 5737). These addresses are never routed on the internet.
- Properties carry the neutral labels PROP-A to PROP-F and systems carry labels such as PROP-A-PMS-01. Role names are generic (PMS, SQL server, AD, interface server and similar).
- Plugin names are generic scanner check names. Which check appears on which invented host is arbitrary.
- Everything in `data/` and `outputs/` was produced from the synthetic sample by the toolkit itself.

Because the sample is synthetic, results from this repository cannot be matched to the figures of any real organisation.

## How the parser treats raw exports

When you run the toolkit on your own exports, the parser reads host headings, addresses and similar identifiers only in memory, to recognise duplicates and alternative exports of one system. It writes labels only. File names are replaced by anonymous references (F01, F02 and so on) in `data/parse_log.csv`. The only value derived from a host heading is a salted hash that stays in memory.

## If you use your own data

- Keep raw exports outside the repository folder. The `.gitignore` blocks `.nessus` files and HTML files outside the sample and output folders.
- Check `data/` and `outputs/` before committing anything produced from real scans. Findings, plugin lists and counts per system can still point to an organisation even without names.
- Do not add real names, addresses or licence keys to the label rules in `src/labels.py`.

## Automated checks

The unit test `test_no_raw_identifiers_in_published_files` scans every text file in the repository for IPv4 addresses outside the two documentation ranges, MAC addresses and domain like strings. The only domain allowed is the GitHub link in the README and the citation file. A second test checks that every address in the sample exports sits inside the documentation ranges.

If you find real identifying data in this repository, please open an issue so that it can be removed.
