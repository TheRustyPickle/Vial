# Vial Server

The server binary provides a REST API for storing and fetching encrypted secrets.
It uses `srv-lib` internally and can be self-hosted.

Except for CERT_LOCATION, the rest can be configured using the config file which is looked for in the OS config directory. Using ENV variables will override the config file.

## Environment Variables

| Variable        | Description                                                                     |
|-----------------|------------                                                                     |
| `DATABASE_URL`  | Connection URL to the Postgres database. Required.                              |
| `MAX_SIZE`      | Maximum secret payload size in bytes. Default: 5 MB + 200 bytes                          |
| `MAX_VIEW`      | Maximum secret view count. Default: 1000 |
| `MAX_DAY`| Number of days after which a secret will be automatically deleted and max allowed day count for a secret. Default: 30  |
| `PORT`          | TCP port for the server to bind to. Default: 8080                               |
| `ADDRESS`       | IP address / host to bind to. Default: 127.0.0.1                                |
| `CERT_LOCATION`      | Path to the SSL certificate file. Required for Postgres with SSL           |

## Running

**From source:**

```bash
cargo run --release --bin vial-server
```
