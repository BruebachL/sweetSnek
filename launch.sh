#!/bin/bash
source env/bin/activate
waitress-serve --port=80 honey_http.http_server:app