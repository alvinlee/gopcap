DIRS = pcap	proto test dump

all: install
install: $(addsuffix .install, $(DIRS))
clean: $(addsuffix .clean, $(DIRS))
test: $(addsuffix .test, $(DIRS))
nuke: $(addsuffix .nuke, $(DIRS))

%.install:
	$(MAKE) -C $* $(MFLAGS) install

%.clean:
	$(MAKE) -C $* $(MFLAGS) clean

%.test:
	$(MAKE) -C $* $(MFLAGS) test

%.nuke:
	$(MAKE) -C $* $(MFLAGS) nuke
