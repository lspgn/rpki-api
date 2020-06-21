# rpki-api

This application plugs itself on RPKI JSON files and 
provides a [GraphQL API](https://graphql.org/) to search ROAs
and even BGP routes.

## Use it

Grab the latest binary and launch (if you took Linux v0.2.1) with:
```bash
$ wget https://github.com/lspgn/rpki-api/releases/download/v0.2.1/rpki-api-v0.2.1-linux-x86_64
$ ./rpki-api-v0.2.1-linux-x86_64
```

If you have your own RPKI validator, you can plug this API
to use your own validation data. Use `-cache path-to-rpki.json` to do so.

**At the moment there is no front-end.**

### Add BGP data

To activate BGP data, pass the CLI argument `-bgp=true`.

You must have a file which contains at least two columns.
You can check the sample file [bgp.csv](bgp.csv).
```csv
route,asn
10.0.0.0/24,65001
```

The BGP CSV route file is not provided. You can build using data from collectors,
(by reading MRT dumps with [bgpdump](https://github.com/RIPE-NCC/bgpdump) for instance).
An alternative could be using the RIS dumps (currently used by [RIPE RPKI validator](https://github.com/RIPE-NCC/rpki-validator-3/blob/master/rpki-validator/src/main/resources/application.properties#L50)):
https://www.ris.ripe.net/dumps/

This file (or http link) will be refreshed after the rpki.json.

## Sample queries

You can access a GraphQL explorer at http://localhost:8080/api/graphql
The schema is provided in the "docs" part on the right side of the page.

#### ROA query

Query for a specific prefix
```graphql
{
  roas(prefixFilters: {prefix: "1.1.1.0/24"}) {
    asn
    maxLength
    prefix
    ta
  }
}
```
Using curl:
```bash
$ echo '{"query":"{
          roas(prefixFilters: {prefix: \"1.1.1.0/24\"}) {
            asn
            maxLength
            prefix
            ta
          }
        }"
      }' | curl -XPOST 'http://localhost:8080/api/graphql?' -H 'Content-Type: application/json' -d @-
```

Will return JSON
```json
{
  "data": {
    "roas": [
      {
        "asn": 13335,
        "maxLength": 24,
        "prefix": "1.1.1.0/24",
        "ta": "APNIC"
      }
    ]
  }
}
```
#### Validation query

Validate a prefix+ASN against the current ROAs table:

```graphql
{
  validation(prefix: "1.1.1.0/24", asn: 13335) {
    state
  }
}
```

Will return JSON
```json
{
  "data": {
    "validation": {
      "state": "Valid"
    }
  }
}
```

#### BGP

If you have BGP enabled:

You can fetch specific prefixes and their state.

```graphql
{
  bgp(prefixFilters: {prefix: "1.1.1.0/24"}) {
    asn
    prefix
    validation {
      state
      covering {
        asn
        maxLength
        prefix
        ta
      }
    }
  }
}
```

Will return JSON
```json
{
  "data": {
    "bgp": [
      {
        "asn": 13335,
        "prefix": "1.1.1.0/24",
        "validation": {
          "covering": [
            {
              "asn": 13335,
              "maxLength": 24,
              "prefix": "1.1.1.0/24",
              "ta": "APNIC"
            }
          ],
          "state": "Valid"
        }
      }
    ]
  }
}
```

#### Query ROAs which do not cover any BGP IP space

```graphql
{
  missing {
    asn
    prefix
  }
}
```
