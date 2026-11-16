# SOC Log Parser

This is a simple tool that reads a log file and shows suspicious IP addresses that keep failing login attempts.

## What it does

- Opens a log file you choose
- Looks for failed login lines
- Pulls out the IP address
- Finds repeated failures in a short time window
- Prints a warning report

## Set Up 
If there is not sample_auth.log file, follow the steps below to generate a file 

1. Open Terminal in the same folder as generate_logs.py / Right click in folder [NOT THE FILES] and click Open in Terminal

2. Type this:

py generate_logs.py

3. Press Enter

## How to use it

1. Open Terminal in the same folder as log_parser.py / Right click in folder and click Open in Terminal

2. Type this:

py log_parser.py

3. Press Enter

3. Enter the full path to your log file. OR copy and paste the path [DO NOT COPY & PASTE RELATIVE PATH] by right clicking file and click on "Copy as path"

Example: 
C:\Users\USER\Downloads\soc automation tools\sample_auth.log


4. To quit, type:

## It is not cap sensitive 
type q OR  quit

## Easy tips
- If the path has spaces, you can still paste it in normally.
- If the file is missing, double-check the path.
- This tool is meant to flag repeated failed attempts, not every single failed login.
