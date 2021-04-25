if [ $# -eq 1 ]
then 
	BINARY=$1
	socat tcp-l:7777,reuseaddr,fork "system:gdbserver localhost\\:8888 $1"
else
	echo "Usage: ./gdbserver.sh <binary>" 	
fi
