# Vial Server

The server binary provides a REST API for storing and fetching encrypted secrets.
It uses `srv-lib` internally and can be self-hosted.

## Environment Variables

| Variable        | Description                                                                     |
|-----------------|------------                                                                     |
| `DATABASE_URL`  | Connection URL to the Postgres database. Required.                              |
| `MAX_SECRET_DAY`| Number of days after which a secret will be automatically deleted. Default: 30  |
| `PORT`          | TCP port for the server to bind to. Default: 8080                               |
| `ADDRESS`       | IP address / host to bind to. Default: 127.0.0.1                                |
| `MAX_SIZE`      | Maximum secret payload size. Default: 5 MB + 200 bytes                          |
| `CERT_LOCATION`      | Path to the SSL certificate file. Required for Postgres with SSL           |

## Running

**From source:**

```bash
cargo run --release --bin vial-server
```
