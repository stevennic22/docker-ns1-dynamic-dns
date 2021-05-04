# Docker NS1 Dynamic DNS
This updates DNS records in NS1 with the current IP (from [ipify.org](https://www.ipify.org)) every 5 minutes. The script runs under `cron` inside a lightweight Alpine-based Docker container.

[NS1](https://ns1.com) is a DNS provider that offers a generous free plan (500k queries/month, 50 records) and an API.

## Usage
### docker run
```
docker run -d \
    -v /your/config.yml:/app/config/config.yml:ro \
    --env FREQUENCY=5 \
    stevennic22/ns1-dynamic-dns:latest
```

### docker-compose
```yaml
services:
  dynamic-dns:
    environment:
      - FREQUENCY=5
    image: stevennic22/ns1-dynamic-dns:latest
    volumes:
      - /your/config.yml:/app/config/config.yml:ro
    restart: unless-stopped
```

### custom frequency
You can change the value of the `FREQUENCY` environment variable to make the script run every `$FREQUENCY` minutes. The default is every 5 minutes.

### testing
To test the script, run it through `docker run` and append `/dynamic-dns.py`. This will run the script once, then kill the container. Example:

```
docker run --rm -v /your/config.yml:/app/config/config.yml:ro stevennic22/ns1-dynamic-dns:latest /dynamic-dns.py
```

## Config file
A `config.yml` file **must** be passed or the container won't be able to do anything. The format for the config file can be seen in `example-config.yml`.
