all: tls-block 

tls-block: tls-block.cpp
	g++ -Wall -Wextra -o tls-block tls-block.cpp -lpcap 
     
clean: 
	rm -f tls-block
