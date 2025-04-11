journalctl -g "INPUT_ACCEPT" -b >> fw_logs.txt
journalctl -g "INPUT_DROP" -b >> fw_logs.txt
journalctl -g "OUTPUT_ACCEPT" -b >> fw_logs.txt
journalctl -g "OUTPUT_DROP" -b >> fw_logs.txt
