#!/usr/bin/env bash

# Please don't edit this file let others players have fun

cd /home/www/tiny-web-server/
ps aux | grep tiny | awk '{print $2}' | xargs kill -9
nohup ./tiny public_html/ 1111 2>&1 > /dev/null &


