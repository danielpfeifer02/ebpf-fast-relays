package main

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

// Storage for the hist values.
var hist_storage map[uint64]hist_entry

// Index for the hist storage.
var hist_storage_index = uint64(0)

func register_client(alpha float64, max_hist_size uint64) client_indices {
	return client_indices{ewma_index: register_ewma(alpha), hist_index: register_hist(max_hist_size)}
}

func register_ewma(alpha float64) uint64 {
	if ewma_storage == nil {
		ewma_storage = make(map[uint64]ewma_entry)
	}
	if _, ok := ewma_storage[ewma_storage_index]; ok {
		panic("Index already exists")
	}
	ewma_storage[ewma_storage_index] = ewma_entry{alpha: alpha, ewma: 0}
	ewma_storage_index++
	return ewma_storage_index - 1
}

func register_hist(max_hist_size uint64) uint64 {
	if hist_storage == nil {
		hist_storage = make(map[uint64]hist_entry)
	}
	if _, ok := hist_storage[hist_storage_index]; ok {
		panic("Index already exists")
	}
	hist_storage[hist_storage_index] = hist_entry{hist: make([]uint64, 0), max_size: max_hist_size}
	hist_storage_index++
	return hist_storage_index - 1
}

// Adds a delay to the history
func add_delay(delay uint64, indices client_indices) {
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
	entry := ewma_storage[indices.ewma_index]
	ewma := entry.ewma
	alpha := entry.alpha
	ewma = uint64(float64(delay)*alpha + float64(ewma)*(1-alpha))
	entry.ewma = ewma
	ewma_storage[indices.ewma_index] = entry
}

// Calculates the jitter of the delay for the last window_size packets.
func calc_jitter(window_size int, indices client_indices) uint64 {
	return 0
}

// Calculates the standard deviation of the delay for the last window_size packets.
func calc_std_dev(window_size int, indices client_indices) uint64 {
	return 0
}

// Calculates the moving average of the delay for the last window_size packets.
func calc_moving_avg(window_size int, indices client_indices) uint64 {
	return 0
}

// Calculates the moving variance of the delay for the last window_size packets.
func calc_moving_variance(window_size int, indices client_indices) uint64 {
	return 0
}
