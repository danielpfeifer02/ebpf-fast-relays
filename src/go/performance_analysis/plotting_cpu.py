import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
import enum


ns = ["server_ns", "relay_ns", "client_ns"]
types = ["user", "kernel"]
file_prefix = "output/cpu_usage_pids_"

cut_off_early_data = True
early_data_cut_off_threshold = 10

# Open file
tmp_name = file_prefix + ns[0] + "-" + types[1] + ".csv" # TODO: only for now since it's the only file that exists

# Read csv file
df = pd.read_csv(tmp_name, dtype={'pid': int, 'ts': int, 'cpu': float})

unq_pids = df['pid'].unique()

data_map = {}

for pid in unq_pids:
    data_map[pid] = df[df['pid'] == pid]

# Sort data by ts (should be sorted already)
for pid in unq_pids:
    data_map[pid].sort_values(by=['ts'])
    if cut_off_early_data:
        data_map[pid] = data_map[pid][early_data_cut_off_threshold:]
    if len(data_map[pid]) == 0:
        del data_map[pid]    
        unq_pids = unq_pids[unq_pids != pid]
    
# Plot data
for pid in unq_pids:
    plt.plot(data_map[pid]['ts'], data_map[pid]['cpu'], label=pid)

# Plot accumulated data
accumulated_data = pd.DataFrame()
accumulated_data['ts'] = []
accumulated_data['cpu'] = []
for pid in unq_pids:
    # Sum up the cpu usage of all pids if the ts is the same
    for i in range(len(data_map[pid])):
        ts = data_map[pid].iloc[i]['ts']
        cpu = data_map[pid].iloc[i]['cpu']
        # print(pid,ts)
        if ts in accumulated_data['ts']:
            print("already exists")
            accumulated_data.loc[accumulated_data['ts'] == ts, 'cpu'] += cpu
        else:
            row_to_append = pd.DataFrame({'ts': ts, 'cpu': cpu}, index=[0])
            accumulated_data = pd.concat([accumulated_data, row_to_append])
plt.plot(accumulated_data['ts'], accumulated_data['cpu'], label="Accumulated Data")

# print(accumulated_data.head())

plt.xlabel('Timestamp')
plt.ylabel('CPU Usage')
plt.title('CPU Usage over Time')
plt.legend()

plt.show()