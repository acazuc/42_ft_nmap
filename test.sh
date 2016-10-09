while true
do
	sudo ./ft_nmap --ip 127.0.0.1 --speedup 250 --scan SYN | grep Filtered
done
