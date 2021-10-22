
CFLAGS += -Wall -Werror 
LFLAGS += -lcrypto

DO_LIST = basic_cipher stream_hash multi_connections basic_hash

# ARG 1: arg
define gen_template
$(1).build: $(1).c
	$(CC) $(CFLAGS) -o $(1) ./$(1).c $(LFLAGS)

$(1).run: $(1).build
	./$(1)

$(1).clean: 
	rm -f ./$(1)

test: $(1).run

build: $(1).build

clean: $(1).clean

endef

$(foreach arg,$(DO_LIST),$(eval $(call gen_template,$(arg))))


.PHONY: test build clean
