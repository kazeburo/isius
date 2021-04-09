# isius

Ping/TCP/HTTP/HTTPS monitoring agent server

# Usage

```
% ./isius -h
Usage:
  isius [OPTIONS]

Application Options:
  -v, --version                 Show version
  -l, --listen=                 address to bind (default: 0.0.0.0)
  -p, --port=                   Port number to bind (default: 3000)
      --access-log-dir=         directory to store logfiles
      --access-log-rotate=      Number of rotation before remove logs (default: 30)
      --access-log-rotate-time= Interval time between file rotation (default: 24h)
      --read-timeout=           timeout of reading request (default: 30s)
      --write-timeout=          timeout of writing response (default: 90s)
      --shutdown-timeout=       timeout to wait for all connections to be closed. (default: 1h)
      --mount-api-on=           url path to mount api on
      --default-user-agent=     default user-agent string for http monitor (default: isisu-monitor-agent)

Help Options:
  -h, --help                    Show this help message
```

# APIs

## X-Timeout

`X-Timeout` is exist in request, isisu use it as timeout seconds to monitor.

## Ping

`/check_ping/{ip}` or 
`/check_ping/{count:[0-9]+}/{interval:[0-9]+}/{timeout_per_ping:[0-9]+}/{ip}`

interval and timeout(timeout per ping) is millisenconds.

example

```
% curl -v localhost:3000/check_ping/3/10/1000/8.8.8.8 
*   Trying ::1...
* TCP_NODELAY set
* Connected to localhost (::1) port 3000 (#0)
> GET /check_ping/3/10/1000/8.8.8.8 HTTP/1.1
> Host: localhost:3000
> User-Agent: curl/7.64.1
> Accept: */*
> 
< HTTP/1.1 200 OK
< Date: Fri, 09 Apr 2021 02:48:37 GMT
< Content-Length: 108
< Content-Type: text/plain; charset=utf-8
< 
{"code":0,"metric":"success:3,error:0,max:21.080475,average:16.355943,90_percentile:21.080475","errors":[]}
* Connection #0 to host localhost left intact
* Closing connection 0
```

When all ping request/response was succeeded, isius return 200 OK and code with 0.
When all ping request/response was failed, isius return 500 Internal Server Error and code with 2.
Other, isius return 500 Internal Server Error and code with 1.

## TCP

`/check_tcp/{ip}/{port:[0-9]+}`

```
% curl -v -H 'X-Timeout: 5' localhost:3000/check_tcp/1.1.1.1/53 
*   Trying ::1...
* TCP_NODELAY set
* Connected to localhost (::1) port 3000 (#0)
> GET /check_tcp/1.1.1.1/53 HTTP/1.1
> Host: localhost:3000
> User-Agent: curl/7.64.1
> Accept: */*
> X-Timeout: 5
> 
< HTTP/1.1 200 OK
< Date: Fri, 09 Apr 2021 02:51:35 GMT
< Content-Length: 52
< Content-Type: text/plain; charset=utf-8
< 
{"code":0,"metric":"duration:0.100264","errors":[]}
* Connection #0 to host localhost left intact
* Closing connection 0
```

When error occured in connectiion, isius return 500 Internal Server Error and code with 2.

## HTTP

`/{http_scheme:check_https?}/{method:(?:GET|HEAD|get|head)}/{ip}/{port:[0-9]+}/{expected_status:[0-9][0-9][0-9]}` or 
`/{http_scheme:check_https?}/{method:(?:GET|HEAD|get|head)}/{ip}/{port:[0-9]+}/{expected_status:[0-9][0-9][0-9]}/{host}` or
`/{http_scheme:check_https?}/{method:(?:GET|HEAD|get|head)}/{ip}/{port:[0-9]+}/{expected_status:[0-9][0-9][0-9]}/{host}/{path:.*}`

If vhost is not required, give host `-`.

```
% curl -v localhost:3000/check_http/get/34.231.30.52/80/200/httpbin.org/ 
*   Trying ::1...
* TCP_NODELAY set
* Connected to localhost (::1) port 3000 (#0)
> GET /check_http/get/34.231.30.52/80/200/httpbin.org/ HTTP/1.1
> Host: localhost:3000
> User-Agent: curl/7.64.1
> Accept: */*
> 
< HTTP/1.1 200 OK
< Date: Fri, 09 Apr 2021 13:20:46 GMT
< Content-Length: 52
< Content-Type: text/plain; charset=utf-8
< 
{"code":0,"metric":"duration:0.360751","errors":[]}
* Connection #0 to host localhost left intact
* Closing connection 0
```

```
% curl -v -H 'X-Timeout: 5' localhost:3000/check_https/get/34.231.30.52/443/200/httpbin.org/delay/8
*   Trying ::1...
* TCP_NODELAY set
* Connected to localhost (::1) port 3000 (#0)
> GET /check_https/get/34.231.30.52/443/200/httpbin.org/delay/8 HTTP/1.1
> Host: localhost:3000
> User-Agent: curl/7.64.1
> Accept: */*
> X-Timeout: 5
>
< HTTP/1.1 500 Internal Server Error
< Date: Fri, 09 Apr 2021 13:18:23 GMT
< Content-Length: 120
< Content-Type: text/plain; charset=utf-8
<
{"code":2,"metric":"duration:5.003139","errors":["Get \"https://httpbin.org:443/delay/8\": context deadline exceeded"]}
* Connection #0 to host localhost left intact
* Closing connection 0
```

When error occured in request or could not get expected status code , isius return 500 Internal Server Error and code with 2.



