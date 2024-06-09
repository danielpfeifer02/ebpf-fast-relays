package main

import (
	"fmt"
	"math"
	"sync"
	"time"
)

/*

 * This file provides some metrics based on which the relay can decide to higher or
 * lower the priority threshold for a client (i.e. assume the clients congestion situation).
 * The metrics are based on an out of band connection that tells the relay when a packet
 * a packet was received by the client. The packet also knows from the BPF program when
 * the same packet was sent by the relay.

 * The provided metrics are:
 * 		- Packet delay variation (jitter)
 * 		- Exponential weighted moving average of the delay
 * 		- Standard deviation of the delay
 * 		- Moving average of the delay
 * 		- Moving variance of the delay

 TODO: 	- add a way to incorporate packet loss (i.e. there was no oob message for a packet)

 TODO:	- maybe visualize the metrics in a graph (e.g. using grafana)

*/

type ewma_entry struct {
	alpha float64
	ewma  uint64
}

type hist_entry struct {
	hist     []uint64
	max_size uint64
}

type client_indices struct {
	ewma_index uint64
	hist_index uint64
}

// Storage for the ewma values.
var ewma_storage map[uint64]ewma_entry

// Index for the ewma storage.
var ewma_storage_index = uint64(0)

// Lock for ewma storage.
var ewma_lock = sync.Mutex{}

// Storage for the hist values.
var hist_storage map[uint64]hist_entry

// Index for the hist storage.
var hist_storage_index = uint64(0)

// Lock for hist storage.
var hist_lock = sync.Mutex{}

func register_client(alpha float64, max_hist_size uint64) client_indices {
	ewma_idx := register_ewma(alpha)
	max_hist_idx := register_hist(max_hist_size)

	if relay_printing_congestion_analysis {
		go func() {

			for {
				ewma_lock.Lock()
				ewma := ewma_storage[ewma_idx].ewma
				ewma_lock.Unlock()
				fmt.Println("EWMA:", ewma)

				hist_lock.Lock()
				hist := hist_storage[max_hist_idx].hist
				hist_lock.Unlock()
				if len(hist) >= 2 {
					last_delay := hist[len(hist)-1]
					second_last_delay := hist[len(hist)-2]
					last_jitter := max(last_delay, second_last_delay) - min(last_delay, second_last_delay)

					avg_jitter := calc_avg_jitter(10, client_indices{ewma_index: ewma_idx, hist_index: max_hist_idx})
					fmt.Println("Average jitter:", avg_jitter)
					fmt.Println("Last jitter:", last_jitter)

					std_dev := calc_std_dev(10, client_indices{ewma_index: ewma_idx, hist_index: max_hist_idx})
					fmt.Println("Standard deviation:", std_dev)
				}

				time.Sleep(2 * time.Second)
			}

		}()
	}

	if grafana_usage {

		go func() {

			db := get_db()
			if db == nil {
				return
			}
			tables := create_tables(db)
			defer db.Close()

			for {

				ewma_lock.Lock()
				ewma := ewma_storage[ewma_idx].ewma
				ts := time.Now().UTC().Format("2006-01-02 15:04:05.000000000")
				ewma_lock.Unlock()

				ewma_entry := basic_table_entry{Timestamp: ts, Value: ewma}
				tables.ewma_chan <- ewma_entry

				hist_lock.Lock()
				hist := hist_storage[max_hist_idx].hist
				hist_lock.Unlock()
				if len(hist) >= 2 {

					window_size := 10

					avg_jitter := calc_avg_jitter(window_size, client_indices{ewma_index: ewma_idx, hist_index: max_hist_idx})
					tables.jitter_hist_chan <- basic_table_entry{Timestamp: ts, Value: avg_jitter}

					std_dev := calc_std_dev(window_size, client_indices{ewma_index: ewma_idx, hist_index: max_hist_idx})
					tables.std_dev_chan <- basic_table_entry{Timestamp: ts, Value: std_dev}
				}

				time.Sleep(99 * time.Millisecond)

			}

		}()

	}

	return client_indices{ewma_index: ewma_idx, hist_index: max_hist_idx}
}

func register_ewma(alpha float64) uint64 {
	if ewma_storage == nil {
		ewma_storage = make(map[uint64]ewma_entry)
	}
	ewma_lock.Lock()
	defer ewma_lock.Unlock()
	if _, ok := ewma_storage[ewma_storage_index]; ok {
		panic("Index already exists")
	}
	ewma_storage[ewma_storage_index] = ewma_entry{alpha: alpha, ewma: ewma_start_value}
	ewma_storage_index++
	return ewma_storage_index - 1
}

func register_hist(max_hist_size uint64) uint64 {
	if hist_storage == nil {
		hist_storage = make(map[uint64]hist_entry)
	}
	hist_lock.Lock()
	defer hist_lock.Unlock()
	if _, ok := hist_storage[hist_storage_index]; ok {
		panic("Index already exists")
	}
	hist_storage[hist_storage_index] = hist_entry{hist: make([]uint64, 0), max_size: max_hist_size}
	hist_storage_index++
	return hist_storage_index - 1
}

func ca_ts_handler(sent_ts, recv_ts uint64, packet_info pn_ts_struct, indices client_indices) {
	delay := recv_ts - sent_ts

	// fmt.Println("Client received packet with pn", packet_info.PacketNumber, "after", delay, "ns")
	add_delay(delay, indices)
}

// Adds a delay to the history
func add_delay(delay uint64, indices client_indices) {
	hist_lock.Lock()
	defer hist_lock.Unlock()
	entry := hist_storage[indices.hist_index]
	hist_delay := entry.hist
	hist_max_size := entry.max_size
	if len(hist_delay) == int(hist_max_size) {
		hist_delay = hist_delay[1:]
	}
	hist_delay = append(hist_delay, delay)
	entry.hist = hist_delay
	hist_storage[indices.hist_index] = entry
	update_ewma(delay, indices)
}

// Update the exponential weighted moving average of the delay.
func update_ewma(delay uint64, indices client_indices) {
	ewma_lock.Lock()
	defer ewma_lock.Unlock()
	entry := ewma_storage[indices.ewma_index]
	ewma := entry.ewma
	alpha := entry.alpha
	ewma = uint64(float64(delay)*alpha + float64(ewma)*(1-alpha))
	entry.ewma = ewma
	ewma_storage[indices.ewma_index] = entry
}

// Calculates the jitter of the delay for the last window_size packets.
func calc_avg_jitter(window_size int, indices client_indices) uint64 {
	var subset []uint64
	hist_lock.Lock()
	if hist, ok := hist_storage[indices.hist_index]; ok {
		size := min(window_size, len(hist.hist))
		subset = hist.hist[len(hist.hist)-size:]
	} else {
		panic("Invalid index")
	}
	hist_lock.Unlock()

	// Get differences between the delays
	var diffs []uint64
	for i := 1; i < len(subset); i++ {
		diffs = append(diffs, max(subset[i], subset[i-1])-(min(subset[i], subset[i-1])))
	}

	// Calculate the average of the differences
	var sum uint64
	for _, diff := range diffs {
		sum += diff
	}
	avg := sum / uint64(len(diffs))

	return avg

}

// Calculates the standard deviation of the delay for the last window_size packets.
func calc_std_dev(window_size int, indices client_indices) uint64 {
	var subset []uint64
	hist_lock.Lock()
	if hist, ok := hist_storage[indices.hist_index]; ok {
		size := min(window_size, len(hist.hist))
		subset = hist.hist[len(hist.hist)-size:]
	} else {
		panic("Invalid index")
	}
	hist_lock.Unlock()

	// Calculate the mean.
	var sum uint64
	for _, delay := range subset {
		sum += delay
	}
	mean := sum / uint64(len(subset))

	// Calculate the variance.
	var variance uint64
	for _, delay := range subset {
		variance += (delay - mean) * (delay - mean)
	}
	variance /= uint64(len(subset))

	// Calculate the standard deviation.
	std_dev := uint64(math.Sqrt(float64(variance)))
	return std_dev
}

// Calculates the moving average of the delay for the last window_size packets.
func calc_moving_avg(window_size int, indices client_indices) uint64 {
	return 0
}

// Calculates the moving variance of the delay for the last window_size packets.
func calc_moving_variance(window_size int, indices client_indices) uint64 {
	return 0
}
