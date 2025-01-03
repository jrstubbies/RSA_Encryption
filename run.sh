#!/bin/bash
gnome-terminal --command='./secure_server/secure_server.out 1235'
gnome-terminal --command='./secure_client/secure_client.out localhost 1235'
