import matplotlib.pyplot as plt
from matplotlib.font_manager import FontProperties

# Your raw data as a multiline string
data = """
.011,0,0
.011827932,3496,66472
.063394501,44936,283316
.079337981,55100,283316
.095908814,65132,283316
.112665885,72392,283712
.128855621,73604,285284
.145006436,73604,285284
.161156915,73604,285284
.177332171,75656,285284
.193524654,76184,285284
.210223893,76712,285284
.227014415,77240,285284
.243607451,77768,285284
.259414850,78296,285284
.274567052,78824,285284
.290409354,79352,285284
.306406977,79616,285284
.322805365,79616,285284
.338168552,79616,285284
.353759411,79616,285284
.369026208,79616,285284
.384983580,79616,285284
.406837822,79616,285284
.410651709,79616,285284
.414681788,79616,285284
.418581773,79616,285284
.422194690,79616,285284
.432194000,0,0
"""

# Parse the data
lines = data.strip().split("\n")
times = list(range(len(lines)))  # Sequential time steps starting at 0
rss_mb = []
vsz_mb = []

for line in lines:
    _, rss_kb, vsz_kb = map(float, line.strip().split(","))
    rss_mb.append(rss_kb / 1024)
    vsz_mb.append(vsz_kb / 1024)

# Plot
plt.figure(figsize=(10, 6))
plt.plot(times, rss_mb, 'o--', label="TDXplorer's memory that is currently in RAM", color="black")
plt.plot(times, vsz_mb, 's--', label="Total virtual memory allocated", color="black")
plt.xlabel("Time", fontsize=18)
plt.ylabel("Memory usage (MB)", fontsize=18)
#plt.title("Memory Usage Over Time")
# Increase font size for legend label
#plt.legend(fontsize=16)

# Increase font size for tick labels
plt.xticks(fontsize=18)
plt.yticks(fontsize=18)
font_properties = FontProperties(size=18)
plt.legend(fontsize=18, prop=font_properties)
#plt.legend()
plt.grid(True)
plt.tight_layout()
plt.show()


