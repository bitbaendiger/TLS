# TLS
DON'T YOU EVER USE THIS FOR ANY PRODUCTION PROJECT. I DARE YOU!

Basic implementation of the TLS 1.2 in pure PHP, asynchronous on top of qcEvents. There are some dependencies to hash and openssl, but only to do the tough cryptographic work - the wire protocol is pure PHP.

This is at the moment server-only and has no abilities to push data forward to the application layer. It just establishes a TLS 1.2-secured connection and keeps saying 'PONG!' whenever it receives some data on the application layer.

## Copyright & License
Copyright (C) 2018 Bernd Holzmüller

Licensed under the GNU General Public License v3.0 (GPL). This is free software: you are
free to change and redistribute it. There is NO WARRANTY, to the extent permitted by law.
