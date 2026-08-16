# Third-party software and research inputs

This repository does not vendor Python packages. `make setup` installs the
exact package versions in `requirements.txt`; each installed distribution
retains its own licence and notices. The two direct dependencies are:

| Package | Version | Licence reported by the installed distribution | Project |
| --- | --- | --- | --- |
| Matplotlib | 3.11.0 | Matplotlib licence | <https://matplotlib.org/> |
| pyasn | 1.6.2 | MIT | <https://github.com/hadiasghari/pyasn> |

Matplotlib also distributes fonts and other components under their respective
notices. Inspect the installed package metadata when redistributing package
files; this source repository does not copy those files.

The study uses or derives information from Apple's published Private Relay
egress catalogue, RIPEstat/RIS, and RouteViews/CAIDA routing data. These are
research inputs, not code dependencies. Their source URLs, retrieval dates,
hashes, attribution, and applicable redistribution terms must accompany any
separate data release. Inclusion of a hash or a derived statistic does not
grant redistribution permission.

See `docs/data-availability.md` and `docs/release-checklist.md` for the release
boundary. The methods repository contains no study findings or generated result
artifacts. Any separate data or output release needs its own applicable licence
and attribution statement.
