

OBJ = btdaemon.o

%.o: %.c
	$(CC) -c -o $@ $< $(CXXFLAGS)

libbtdaemon.so: $(OBJ)
	$(CC) -o $@ -shared $^ $(CXXFLAGS) $(LDFLAGS)

clean:
	$(RM) *.o btdaemon
