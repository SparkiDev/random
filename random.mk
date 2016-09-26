
EXE=t_entropy t_random
# t_hash_drbg
all: $(EXE)

RANDOM_OBJ=random.o entropy.o random_hash.o $(HASH_OBJ)

%.o: src/%.c src/*.h include/*.h
	$(CC) -c $(CFLAGS) -o $@ $<

t_entropy.o: test/t_entropy.c
	$(CC) -c $(CFLAGS) -Isrc -o $@ $<
t_entropy: t_entropy.o $(RANDOM_OBJ)
	$(CC) -o $@ $^ $(LIBS) $(MATH_LIB)

t_random.o: test/t_random.c
	$(CC) -c $(CFLAGS) -Isrc -o $@ $<
t_random: t_random.o $(RANDOM_OBJ)
	$(CC) -o $@ $^ $(LIBS)

#test/t_hash_drbg.c: test/vectors/gen_test.rb
#	ruby test/vectors/gen_test.rb test/vectors/pr_false/Hash_DRBG.txt > test/t_hash_drbg.c
#t_hash_drbg.o: test/t_hash_drbg.c
#	$(CC) -c $(CFLAGS) -Isrc -o $@ $<
#t_hash_drbg: t_hash_drbg.o $(RANDOM_OBJ)
#	$(CC) -o $@ $^ $(LIBS)

clean:
	rm -f *.o
	rm $(EXE)

