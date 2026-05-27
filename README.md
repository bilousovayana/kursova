# Packet Loss Analyzer

Packet Loss Analyzer is a simple desktop application for analyzing ping log files. It calculates packet loss, received and lost packets, average/min/max latency, and provides a basic connection quality rating.

The app includes a table view of parsed packets, visual charts, and options to save a text report or export results to CSV.

## Features

- Open and analyze `.log` or `.txt` ping logs
- Detect received and lost packets
- Calculate packet loss percentage
- Show average, minimum, and maximum latency
- Display packet statistics in a table
- Generate charts with Matplotlib
- Save analysis as a text report
- Export packet data to CSV

## Requirements

- Python 3
- Tkinter
- Matplotlib

Install Matplotlib with:

```bash
pip install matplotlib
