Date: 27-08-2024

Features Implemented:       

IP and Port Scanning:
    Scans a range of IP addresses and ports to identify open ports.

Service Detection:
    Identifies services running on commonly known ports (e.g., HTTP, HTTPS, FTP).

Multi-threading:
    Utilizes multi-threading to scan multiple IPs and ports concurrently, to speed up the scanning process.

Progress Reporting:
    Allows users to check the scanning progress by pressing 'Enter' (shows the percentage of completion).

Command-line Arguments:
    The tool accepts command-line arguments for IP range, port range, thread count, and output file location.

Goals for Further Development:

Enhanced Service Detection:
    Improve detection of more services by extending the banner-grabbing mechanism.

Output Formats:
    Add options to export scan results in various formats, such as JSON, XML, or CSV.

Advanced Scanning Techniques:
    Implement features like SYN scanning, OS fingerprinting, and vulnerability detection.

Interactive Mode:
    Add an interactive mode for real-time scanning and result analysis.

GUI Development:
    Develop a graphical user interface to make the scanner more user-friendly.

Network Mapping:
    Add functionality to map the network topology based on scanning results.