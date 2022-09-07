#!/bin/bash
env/bin/waitress-serve --port=80 --ident Microsoft-IIS/8.5 honey_http.http_server:app