"""Simple charts + summary tables from results/*.csv. Run: python -m ehrchain.charts"""
import glob
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

RES = os.path.join(os.path.dirname(__file__), "..", "results")
FIG = os.path.join(RES, "figures")
os.makedirs(FIG, exist_ok=True)


def rd(pattern):
    return pd.concat([pd.read_csv(f) for f in sorted(glob.glob(os.path.join(RES, pattern)))], ignore_index=True)


def save(name):
    plt.tight_layout()
    plt.savefig(os.path.join(FIG, name), dpi=130)
    plt.close()


pbft = rd("bench_pbft_n*.csv")
pow_ = pd.read_csv(os.path.join(RES, "bench_pow.csv"))
cen = pd.read_csv(os.path.join(RES, "bench_central.csv"))
fail = rd("bench_failures_n*.csv")
bits = pd.read_csv(os.path.join(RES, "bench_powbits.csv"))
fsz = pd.read_csv(os.path.join(RES, "bench_filesize.csv"))
ex = json.load(open(os.path.join(RES, "experiments.json")))


def line(metric, ylabel, title, fname, logy=False):
    plt.figure(figsize=(6.4, 4.2))
    for n in sorted(pbft.nodes.unique()):
        g = pbft[pbft.nodes == n].groupby("load")[metric].agg(["mean", "std"])
        plt.errorbar(g.index, g["mean"], yerr=g["std"], marker="o", capsize=3, label=f"PBFT {n} nodes")
    for df, lab, st in ((pow_, "PoW (16-bit)", "s--"), (cen, "Centralized DB", "k^:")):
        g = df.groupby("load")[metric].agg(["mean", "std"])
        plt.errorbar(g.index, g["mean"], yerr=g["std"], fmt=st, capsize=3, label=lab)
    plt.xscale("log")
    if logy:
        plt.yscale("log")
    plt.xlabel("Number of transactions (load)")
    plt.ylabel(ylabel)
    plt.title(title)
    plt.grid(True, alpha=0.3)
    plt.legend(fontsize=8)
    save(fname)


line("avg_tx_latency_ms", "Average latency per transaction (ms)", "Latency vs load (mean of 20 runs, bars = std)", "fig1_latency_vs_load.png", logy=True)
line("throughput_tps", "Throughput (transactions/second)", "Throughput vs load (mean of 20 runs, bars = std)", "fig2_throughput_vs_load.png")

# 3. block confirmation time vs nodes, per load
plt.figure(figsize=(6.4, 4.2))
for load in (100, 1000, 10000):
    g = pbft[pbft.load == load].groupby("nodes")["avg_block_confirm_ms"].agg(["mean", "std"])
    plt.errorbar(g.index, g["mean"], yerr=g["std"], marker="o", capsize=3, label=f"load {load}")
plt.xticks([4, 7, 10, 13])
plt.xlabel("Number of validator nodes")
plt.ylabel("Block confirmation time (ms)")
plt.title("Block confirmation time vs number of nodes")
plt.grid(True, alpha=0.3); plt.legend()
save("fig3_block_time_vs_nodes.png")

# 4. consensus overhead: messages per transaction and MB per 1000 tx
g = pbft[pbft.load == 1000].groupby("nodes")[["messages", "bytes"]].mean()
fig, ax = plt.subplots(1, 2, figsize=(9, 3.8))
ax[0].bar([str(i) for i in g.index], g["messages"], color="tab:blue")
ax[0].set_xlabel("Nodes"); ax[0].set_ylabel("Messages per 1000 tx"); ax[0].set_title("Consensus messages")
ax[1].bar([str(i) for i in g.index], g["bytes"] / 1e6, color="tab:orange")
ax[1].set_xlabel("Nodes"); ax[1].set_ylabel("MB per 1000 tx"); ax[1].set_title("Consensus traffic")
for a in ax:
    a.grid(True, axis="y", alpha=0.3)
save("fig4_consensus_overhead.png")

# 5. PoW difficulty
g = bits.groupby("bits")["avg_block_confirm_ms"].agg(["mean", "std"])
plt.figure(figsize=(6.4, 4.2))
plt.errorbar(g.index, g["mean"], yerr=g["std"], marker="o", capsize=3, color="tab:red", label="PoW")
pb = pbft[(pbft.nodes == 4) & (pbft.load == 1000)]["avg_block_confirm_ms"].mean()
plt.axhline(pb, color="tab:blue", linestyle="--", label="PBFT (4 nodes)")
plt.yscale("log"); plt.xlabel("PoW difficulty (leading zero bits)"); plt.ylabel("Block confirmation time (ms)")
plt.title("PoW difficulty vs block time (load 1000, 10 runs)"); plt.grid(True, alpha=0.3); plt.legend()
save("fig5_pow_difficulty.png")

# 6. file size
g = fsz.groupby("bytes")[["hash_ms", "encrypt_ms", "decrypt_ms"]].mean()
plt.figure(figsize=(6.4, 4.2))
for c, lab in (("hash_ms", "SHA-256"), ("encrypt_ms", "AES-GCM encrypt"), ("decrypt_ms", "AES-GCM decrypt")):
    plt.plot(g.index / 1e6, g[c], marker="o", label=lab)
plt.xscale("log"); plt.yscale("log"); plt.xlabel("File size (MB)"); plt.ylabel("Time (ms)")
plt.title("Hashing and encryption cost vs file size"); plt.grid(True, alpha=0.3); plt.legend()
save("fig6_file_size_cost.png")

# 7. node failures
plt.figure(figsize=(7.2, 4.2))
off = fail[fail.behavior == "offline"]
labels, vals, errs, cols = [], [], [], []
for n in sorted(off.nodes.unique()):
    f = int(off[off.nodes == n].f.iloc[0])
    for k in range(f + 2):
        d = off[(off.nodes == n) & (off.faulty == k)]
        stalled = d.stalled.mean() == 1
        labels.append(f"n={n}\n{k} off"); cols.append("tab:red" if stalled else "tab:green")
        vals.append(0 if stalled else d.throughput_tps.mean()); errs.append(0 if stalled else d.throughput_tps.std())
plt.bar(range(len(vals)), vals, yerr=errs, color=cols, capsize=2)
for i, c in enumerate(cols):
    if c == "tab:red":
        plt.text(i, 150, "stalled", rotation=90, color="red", ha="center", fontsize=8)
plt.xticks(range(len(vals)), labels, fontsize=6)
plt.ylabel("Throughput (tx/s), 0 = no progress"); plt.title("Offline nodes: green = works, red = stalled (more than f offline)")
plt.grid(True, axis="y", alpha=0.3)
save("fig7_node_failures.png")

# 8. storage overhead
s = ex["E8_storage"]
plt.figure(figsize=(5.2, 4))
plt.bar(["Off-chain\n(encrypted files)", "On-chain\n(whole ledger)"], [s["off_chain_ciphertext_bytes"] / 1e6, s["on_chain_bytes_total"] / 1e6], color=["tab:gray", "tab:blue"])
plt.yscale("log"); plt.ylabel("Size (MB, log scale)")
plt.title(f"Storage: {ex['patients']} patients, {s['records']} records\n(on-chain = {s['on_chain_share_of_data_pct']}% of all data)")
plt.grid(True, axis="y", alpha=0.3)
save("fig8_storage_overhead.png")

# 9. network-delay sensitivity (load 1000)
h50 = pd.read_csv(os.path.join(RES, "bench_pbft_hop50.csv"))
plt.figure(figsize=(6.4, 4.2))
for d, lab in ((pbft[pbft.load == 1000], "5 ms per hop (LAN)"), (h50, "50 ms per hop (WAN)")):
    g = d.groupby("nodes")["avg_tx_latency_ms"].agg(["mean", "std"])
    plt.errorbar(g.index, g["mean"], yerr=g["std"], marker="o", capsize=3, label=lab)
plt.xticks([4, 7, 10, 13]); plt.xlabel("Number of validator nodes"); plt.ylabel("Average latency per transaction (ms)")
plt.title("Effect of modelled network delay (load 1000, 20 runs)"); plt.grid(True, alpha=0.3); plt.legend()
save("fig9_network_delay.png")

# 10. real TCP processes vs in-process simulation (throughput, load 1000)
if os.path.exists(os.path.join(RES, "p2p_bench.csv")):
    real = pd.read_csv(os.path.join(RES, "p2p_bench.csv"))
    r = real[real.load == 1000].groupby("nodes")["throughput_tps"].agg(["mean", "std"])
    sm = pbft[pbft.load == 1000].groupby("nodes")["throughput_tps"].agg(["mean", "std"])
    plt.figure(figsize=(6.4, 4.2))
    plt.errorbar(sm.index, sm["mean"], yerr=sm["std"], marker="o", capsize=3, label="In-process simulation (5 ms/hop, parallel nodes)")
    plt.errorbar(r.index, r["mean"], yerr=r["std"].fillna(0), marker="s", capsize=3, label="Real TCP processes on one 4-core machine")
    plt.xticks([4, 7, 10, 13]); plt.xlabel("Number of validator nodes"); plt.ylabel("Throughput (tx/s)")
    plt.title("Simulation vs real socket run (load 1000)"); plt.grid(True, alpha=0.3); plt.legend(fontsize=8)
    save("fig10_simulation_vs_real_tcp.png")

# ---- summary tables (mean +- std) ----
def ms(d, c):
    return f"{d[c].mean():.1f} ± {d[c].std():.1f}"

rows = []
for load in sorted(pbft.load.unique()):
    for n in sorted(pbft.nodes.unique()):
        d = pbft[(pbft.nodes == n) & (pbft.load == load)]
        rows.append([load, f"PBFT-{n}", len(d), ms(d, "avg_tx_latency_ms"), ms(d, "throughput_tps"), ms(d, "avg_block_confirm_ms"), f"{d.messages.mean():.0f}", f"{d.bytes.mean() / 1e6:.2f}"])
    for df, lab in ((pow_, "PoW-16bit"), (cen, "Central-DB")):
        d = df[df.load == load]
        rows.append([load, lab, len(d), ms(d, "avg_tx_latency_ms"), ms(d, "throughput_tps"), ms(d, "avg_block_confirm_ms"), "-", "-"])
tab = pd.DataFrame(rows, columns=["load", "system", "runs", "latency_ms", "throughput_tps", "block_confirm_ms", "messages", "traffic_MB"])
tab.to_csv(os.path.join(RES, "summary_table.csv"), index=False)
with open(os.path.join(RES, "summary_table.md"), "w") as f:
    f.write("| " + " | ".join(tab.columns) + " |\n|" + "---|" * len(tab.columns) + "\n")
    for r in tab.itertuples(index=False):
        f.write("| " + " | ".join(str(x) for x in r) + " |\n")
print(tab.to_string())
print(os.listdir(FIG))
