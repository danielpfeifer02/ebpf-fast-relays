# Create a simple python script that creates plots from data it reads from output/results.txt

import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
import enum

remove_outliers = True
num_of_bins_delay = 100
num_of_bins_diff = 100
num_of_outliers_removed = 5

# Read data from file
with open('output/results.txt', 'r') as f:
    data = f.readlines()

# Create two histograms for the delays between send and receive timestamps for each type of message
# Create a histogram for the difference between the two delays
histogram_1 = []
histogram_2 = []
histogram_difference = []

class DelayType(enum.Enum):
    USERSPCAE = 1
    KERNELSPACE = 2

def get_delay_type(t): # -> DelayType:
    if t == "Userspace":
        return DelayType.USERSPCAE
    elif t == "Kernel":
        return DelayType.KERNELSPACE
    else:
        raise ValueError("Invalid delay type")

# Extract data
for line in data:
    id, send_ts_1, recv_ts_1, type_1, send_ts_2, recv_ts_2, type_2, difference = line.split()
    
    send_ts_1 = int(send_ts_1)
    recv_ts_1 = int(recv_ts_1)
    send_ts_2 = int(send_ts_2)
    recv_ts_2 = int(recv_ts_2)

    difference = int(difference)

    delay_1 = recv_ts_1 - send_ts_1
    delay_2 = recv_ts_2 - send_ts_2

    histogram_1.append(delay_1)
    histogram_2.append(delay_2)
    histogram_difference.append(abs(delay_1 - delay_2))


if remove_outliers:
    histogram_1.sort()
    histogram_2.sort()
    histogram_difference.sort()

    # Remove outliers
    histogram_1 = histogram_1[num_of_outliers_removed:-num_of_outliers_removed]
    histogram_2 = histogram_2[num_of_outliers_removed:-num_of_outliers_removed]
    histogram_difference = histogram_difference[num_of_outliers_removed:-num_of_outliers_removed]


type_list = np.array([get_delay_type(type_1)] * len(histogram_1) + [get_delay_type(type_2)] * len(histogram_2))
all_delays = np.array(histogram_1 + histogram_2)

all_delays = all_delays / 1_000_000 # Convert to ms
histogram_difference = np.array(histogram_difference) / 1_000 # Convert to µs

df_plt_1 = pd.DataFrame({'Delay': all_delays, 'Type': type_list})
df_plt_2 = pd.DataFrame({'Difference': histogram_difference})

sns.set_style("darkgrid")

fig, axs = plt.subplots(2)
fig.suptitle('Delay analysis of messages with and without kernel-space forwarding')
fig.canvas.manager.set_window_title('Fast-Relays: Speedup Analysis')
fig.set_figheight(7)
fig.set_figwidth(10)

# Draw both arrays in the same histogram (one red, one blue)
sns.histplot(df_plt_1, bins=num_of_bins_delay, x='Delay', hue='Type', palette="tab10", kde=True, log_scale=False, ax=axs[0])
axs[0].set(title='Delays', xlabel='Delay (ms)', ylabel='Frequency')

sns.histplot(df_plt_2, bins=num_of_bins_diff, x='Difference', kde=True, log_scale=False, ax=axs[1], color='darkgreen') # or color='firebrick'
axs[1].set(title='Difference in Delays', xlabel='Difference (µs)', ylabel='Frequency')

plt.tight_layout()
plt.subplots_adjust(top=0.9)
plt.show()


# # Create plots (show all of them at the same time)
# fig, axs = plt.subplots(2)
# fig.suptitle('Delays between send and receive timestamps for each type of message')
# # Draw both arrays in the same histogram (one red, one blue)
# axs[0].hist(histogram_1, bins=100, color='red')
# axs[0].hist(histogram_2, bins=100, color='blue')
# axs[0].set_title('Type ' + type_1)
# axs[0].set_xlabel('Delay (ns)')
# axs[0].set_ylabel('Frequency')


# axs[1].hist(histogram_difference, bins=100)
# axs[1].set_title('Difference between delays')
# axs[1].set_xlabel('Difference (ns)')

# # Add more spacing between plots
# plt.tight_layout()
# plt.subplots_adjust(top=0.9)


# plt.show()


# plt.hist(histogram_1, bins=100)
# plt.title('Delay between send and receive timestamps for type ', type_1)
# plt.xlabel('Delay (ms)')
# plt.ylabel('Frequency')
# plt.show()

# plt.hist(histogram_2, bins=100)
# plt.title('Delay between send and receive timestamps for type ', type_2)
# plt.xlabel('Delay (ms)')
# plt.ylabel('Frequency')
# plt.show()

# plt.hist(histogram_difference, bins=100)
# plt.title('Difference in delays between message types')
# plt.xlabel('Difference (ms)')
# plt.ylabel('Frequency')
# plt.show()