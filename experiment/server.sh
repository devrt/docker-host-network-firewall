#!/bin/sh

socat -,raw,echo=0 tcp-listen:4545
