#!/bin/bash
source env/bin/activate
waitress-serve --port=80 --ident Microsoft-IIS/8.5 honey_http.http_server:app