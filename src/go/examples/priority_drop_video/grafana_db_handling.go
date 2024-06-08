package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/go-sql-driver/mysql"
)

type basic_table_entry struct {
	Timestamp string
	Value     uint64
}

type table_channels struct {
	ewma_chan            chan basic_table_entry
	delay_hist_chan      chan basic_table_entry
	jitter_hist_chan     chan basic_table_entry
	mov_avg_chan         chan basic_table_entry
	moving_variance_chan chan basic_table_entry
	std_dev_chan         chan basic_table_entry
}

/*
Make sure the local ip for the ethernet interface (for me 172.16.254.134) is set up in the mysql server:

 0. to find out the ip you can use "ip addr"
    the correct interface should contain a local ip and look something like this:

    3: enx00133bfbc2db: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:13:3b:fb:c2:db brd ff:ff:ff:ff:ff:ff
    inet 172.16.254.134/24 brd 172.16.254.255 scope global dynamic noprefixroute enx00133bfbc2db
    valid_lft 83941sec preferred_lft 83941sec
    inet6 fe80::b27e:3c82:c636:1e0f/64 scope link noprefixroute
    valid_lft forever preferred_lft forever

 1. change the bind-address in /etc/mysql/mysql.conf.d/mysqld.cnf and add ",172.16.254.134" after "127.0.0.1"

 2. restart the mysql server: sudo systemctl restart mysql

 3. make sure the user has the right permissions for all ip addresses. Execute within mysql:

    CREATE USER 'username'@'localhost' IDENTIFIED BY 'password';
    GRANT ALL PRIVILEGES ON *.* TO 'username'@'localhost' WITH GRANT OPTION;
    CREATE USER 'username'@'%' IDENTIFIED BY 'password';
    GRANT ALL PRIVILEGES ON *.* TO 'username'@'%' WITH GRANT OPTION;
    FLUSH PRIVILEGES;

 4. also make sure to update the gradana data source with the correct ip address.
*/
func get_db() *sql.DB {
	// Open a connection to the MySQL database
	db, err := sql.Open("mysql", "username:password@tcp(172.16.254.134:3306)/grafana")
	if err != nil {
		log.Fatal("Error opening the database: ", err)
	}
	fmt.Println("Opened the database")

	// Ping the database to verify the connection
	err = db.Ping()
	if err != nil {
		fmt.Println(err)
		log.Fatal("Error connecting to the database: ", err)
	}
	fmt.Println("Connected to the database")

	return db

}

func create_tables(db *sql.DB) table_channels {
	ewma_chan := create_basic_table(db, "ewma")
	delay_hist_chan := create_basic_table(db, "delay_hist")
	jitter_hist_chan := create_basic_table(db, "jitter_hist")
	mov_avg_chan := create_basic_table(db, "mov_avg")
	moving_variance_chan := create_basic_table(db, "moving_variance")
	std_dev_chan := create_basic_table(db, "std_dev")

	return table_channels{
		ewma_chan:            ewma_chan,
		delay_hist_chan:      delay_hist_chan,
		jitter_hist_chan:     jitter_hist_chan,
		mov_avg_chan:         mov_avg_chan,
		moving_variance_chan: moving_variance_chan,
		std_dev_chan:         std_dev_chan,
	}
}

func create_basic_table(db *sql.DB, table_name string) chan basic_table_entry {
	// Create the table if it doesn't exist
	_, err := db.Exec("CREATE TABLE IF NOT EXISTS " + table_name + " (id INT AUTO_INCREMENT PRIMARY KEY, value BIGINT, time DATETIME(6))")
	if err != nil {
		log.Fatal("Error creating table: ", err)
	}
	fmt.Println("Table", table_name, "created successfully")

	recv_chan := make(chan basic_table_entry)

	go func() {
		for {
			entry := <-recv_chan
			_, err := db.Exec("INSERT INTO "+table_name+" (value, time) VALUES (?, ?)", entry.Value, entry.Timestamp)
			if err != nil {
				log.Fatal("Error inserting into table: ", err)
			}

		}
	}()

	return recv_chan
}
