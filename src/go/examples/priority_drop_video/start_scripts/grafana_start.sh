#!/bin/bash

# Start Grafana
sudo systemctl start grafana-server

# Show Status
# sudo systemctl status grafana-server

sleep 1

# Open grafana in browser and focus on it
xdg-open http://localhost:3000 



# SETUP FOR MYSQL SHOULD LOOK LIKE THIS:

# CREATE USER 'username'@'localhost' IDENTIFIED BY 'password';
# GRANT ALL PRIVILEGES ON *.* TO 'username'@'localhost' WITH GRANT OPTION;
# CREATE DATABASE grafana;
# USE grafana;
# CREATE TABLE test (id INT NOT NULL AUTO_INCREMENT, time DATETIME, value DOUBLE, PRIMARY KEY (id));
# INSERT INTO test (time, value) VALUES (NOW(), 1.0);
# INSERT INTO test (time, value) VALUES (NOW(), 2.0);
# INSERT INTO test (time, value) VALUES (NOW(), 3.0);