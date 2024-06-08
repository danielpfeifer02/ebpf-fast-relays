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

func get_db() *sql.DB {
	// Open a connection to the MySQL database
	db, err := sql.Open("mysql", "username:password@tcp(192.168.12.1:3306)/grafana")
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
