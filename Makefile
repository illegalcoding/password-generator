CFLAGS = -Ofast -pipe -lm -pthread
all: password-generator
password-generator: password-generator.c
	$(CC) $(CFLAGS) -o password-generator password-generator.c
.PHONY.: clean
clean:
	rm password-generator passwords.txt
