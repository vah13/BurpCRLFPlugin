# BurpCRLFPlugin
Another plugin for CRLF vulnerability detection

This plugin use next payload's
```
%0a
%0d
%0d%0a
%0d%0a%09
%0d%0a+
%0d%20
%0d+
%E5%98%8A%E5%98%8D
%E5%98%8A%E5%98%8D%E5%98%8A%E5%98%8D
\r 
\r\n
\r\n 
\r\n\t
\r\t
```
