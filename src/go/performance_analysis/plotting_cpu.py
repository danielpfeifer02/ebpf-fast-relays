import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
import enum
from scipy.interpolate import make_interp_spline, BSpline

class PlotType(enum.Enum):
    LINE = 1
    BAR = 2

ns = ["server_ns", "relay_ns", "client_ns"]
types = ["kernel", "user"]
file_prefix = "output/cpu_usage_pids_"

use_splines_for_smoothing = True
plot_separate_pids = True
cut_off_early_data = False
early_data_cut_off_threshold = 10
plot_type = PlotType.LINE

def pid_cpu_decreases(pid, df):

    cpu_arr = df[df['pid'] == pid]['cpu'].to_numpy()
    earliest_cpu = cpu_arr[0]
    last_cpu = cpu_arr[-1]
    return last_cpu < earliest_cpu

    # Not as easy as this since it can go up and down
    # count_limit = 10
    # counter = 0
    # for i in range(1, len(df)):
    #     if df['cpu'][i] < df['cpu'][i - 1]:
    #         if counter == count_limit:
    #             return True
    #         else:
    #             counter += 1
    #     else:
    #         counter = 0
    # return False

def create_plot_of_file(filename, kern_or_user):
    # Read csv file
    df = pd.read_csv(filename, dtype={'pid': int, 'ts': int, 'cpu': float})

    if cut_off_early_data:
        df = df[early_data_cut_off_threshold:]

    # Turn ts into seconds
    earliest_ts = df['ts'].min()
    df['ts'] = (df['ts'] - earliest_ts) // 1_000_000_000

    if plot_separate_pids:
        unq_pids = df['pid'].unique()

        non_decreasing_pids = []
        for pid in unq_pids:
            if not pid_cpu_decreases(pid, df):
                non_decreasing_pids.append(pid)
            else :
                print("Pid " + str(pid) + " has decreasing CPU usage")
        
        unq_pids = np.array(non_decreasing_pids)

        data_map = {}

        for pid in unq_pids:
            data_map[pid] = df[df['pid'] == pid]

        # Sort data by ts (should be sorted already)
        for pid in unq_pids:
            if len(data_map[pid]) == 0:
                del data_map[pid]    
                unq_pids = unq_pids[unq_pids != pid]
            
        # Plot data
        if plot_type == PlotType.LINE:
            for pid in unq_pids:
                if use_splines_for_smoothing:
                    xnew = np.linspace(data_map[pid]['ts'].min(), data_map[pid]['ts'].max(), 300)
                    spl = make_interp_spline(data_map[pid]['ts'], data_map[pid]['cpu'], k=3)
                    smoothed = spl(xnew)
                    plt.plot(np.linspace(data_map[pid]['ts'].min(), data_map[pid]['ts'].max(), 300), smoothed, label=f"Main Go Process (pid: {pid})")
                else:
                    plt.plot(data_map[pid]['ts'], data_map[pid]['cpu'], label=pid)
        elif plot_type == PlotType.BAR:
            for pid in unq_pids:
                # Create a bar plot
                sns.barplot(x='ts', y='cpu', data=data_map[pid], color='red', alpha=0.5)
            for i, label in enumerate(plt.gca().get_xticklabels()):
                label.set_visible(False)

    # Create accumulated data
    accumulated_data = pd.DataFrame()
    acc_map = {}
    for row in df.iterrows():
        pid, cpu, ts = row[1]
        if ts in acc_map:
            acc_map[ts] += cpu
        else:
            acc_map[ts] = cpu

    accumulated_data = pd.DataFrame(acc_map.items(), columns=['ts', 'cpu'])

    if plot_type == PlotType.LINE:
        if use_splines_for_smoothing:
            xnew = np.linspace(accumulated_data['ts'].min(), accumulated_data['ts'].max(), 300)
            spl = make_interp_spline(accumulated_data['ts'], accumulated_data['cpu'], k=3)
            smoothed = spl(xnew)
            plt.plot(np.linspace(accumulated_data['ts'].min(), accumulated_data['ts'].max(), 300), smoothed, label="Total CPU Usage (" + kern_or_user + ")")
        else:
            plt.plot(accumulated_data['ts'], accumulated_data['cpu'], label="Accumulated Data")
    elif plot_type == PlotType.BAR:
        # Create a bar plot
        # sns.barplot(x='ts', y='cpu', data=accumulated_data, color='blue', alpha=0.5)
        # Create bar plot with only 10 bars. since there are more than 10 datapoints do some averaging
        num_of_bars = 42
        average_data = pd.DataFrame()
        average_data['ts'] = np.linspace(accumulated_data['ts'].min(), accumulated_data['ts'].max(), num_of_bars)
        average_data['cpu'] = np.zeros(num_of_bars)
        for i in range(0, num_of_bars):
            start = int(i * len(accumulated_data) / num_of_bars)
            end = int((i + 1) * len(accumulated_data) / num_of_bars)
            average_data['cpu'][i] = accumulated_data['cpu'][start:end].mean()

        earliers_ts = accumulated_data['ts'].min()
        average_data['second'] = ((average_data['ts'] - earliers_ts) // 1_000_000_000)
        print(average_data['second'].head(10))
                                            
        # sns.barplot(x='second', y='cpu', data=average_data, color='blue', alpha=0.5)

    label_lim = 10
    for i, label in enumerate(plt.gca().get_xticklabels()):
        if i % label_lim != 0:
            label.set_visible(False)

for type in types:
    create_plot_of_file(file_prefix + ns[0] + "-" + type + ".csv", type) # TODO: only for now since it's the only file that exists

plt.xlabel('Timestamp')
plt.ylabel('CPU Usage')
plt.title('CPU Usage over Time')
plt.legend()

plt.show()