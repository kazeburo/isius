# isius

Ping/TCP/HTTP/HTTPS monitoring agent server

# APIs

## X-Timeout

`X-Timeout` is exist in request, isisu use it as timeout seconds to monitor.

## Ping

`/check_ping/{ip}` or `/check_ping/{count:[0-9]+}/{interval:[0-9]+}/{timeout:[0-9]+}/{ip}`

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

under construction.


